<?php
/**
 * DbMover - database discovery (source) and content import (destination).
 *
 * DirectAdmin and cPanel both keep database passwords hashed, so credentials
 * cannot be read. Instead the migrator dumps over the source's MySQL root
 * socket and reloads into OLSpanel's MySQL as root, which sidesteps the
 * credential problem entirely.
 */

declare(strict_types=1);

class DbMover
{
    private Ssh $ssh;
    private Mysql $mysql;
    private array $transferCfg;
    private string $workDir;

    public function __construct(Ssh $ssh, Mysql $mysql, array $transferCfg, string $workDir)
    {
        $this->ssh = $ssh;
        $this->mysql = $mysql;
        $this->transferCfg = $transferCfg;
        $this->workDir = rtrim($workDir, '/');
        if (!is_dir($this->workDir)) {
            @mkdir($this->workDir, 0700, true);
        }
        @chmod($this->workDir, 0700);
    }

    /** Is the source database layer usable? */
    public function available(): bool
    {
        return $this->ssh->isConfigured() && Ssh::which('ssh') !== null;
    }

    /** Can we talk to the source MySQL directly from this server? */
    public function directAvailable(): bool
    {
        return (Ssh::which('mysqldump') !== null || Ssh::which('mariadb-dump') !== null)
            && Ssh::which('mysql') !== null
            && Ssh::which('gzip') !== null;
    }

    /**
     * Discover the databases a source MySQL user can see, without SSH.
     *
     * A plain (non-root) MySQL user is shown exactly the schemas it has
     * privileges on, which is what we want: the account's own databases.
     *
     * @return string[] schema names
     */
    public function discoverViaCredentials(array $cred, string $host, int $port): array
    {
        $res = $this->runSourceClient($cred, $host, $port, ['-N', '-B', '-e', 'SHOW DATABASES'], 45);
        if ($res['code'] !== 0) {
            Log::warn('db', 'Direct database discovery failed: ' . trim($res['err']));
            return [];
        }
        $names = [];
        foreach (explode("\n", $res['out']) as $line) {
            $line = trim($line);
            if ($line !== '' && preg_match('/^[A-Za-z0-9_]+$/', $line)
                && !in_array($line, ['mysql', 'information_schema', 'performance_schema', 'sys'], true)) {
                $names[] = $line;
            }
        }
        return array_values(array_unique($names));
    }

    /**
     * Dump one schema by connecting to the source MySQL directly, then gzip it
     * locally. Runs detached with a recorded exit status, exactly like the SSH
     * dump, so the engine can poll it.
     *
     * @return array{ok:bool,message:string,dump:string,remote_dump:string}
     */
    public function startDirectDump(array $cred, string $host, int $port, string $sourceDb, string $jobId): array
    {
        $fail = static function (string $m): array {
            return ['ok' => false, 'message' => $m, 'dump' => '', 'remote_dump' => ''];
        };

        if (!$this->directAvailable()) {
            return $fail('mysqldump, mysql or gzip is not installed on the OLSpanel server.');
        }
        if (!preg_match('/^[A-Za-z0-9_]+$/', $sourceDb)) {
            return $fail('Refusing to dump unsafe database name.');
        }
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $jobId)) {
            return $fail('Refusing unsafe job name.');
        }

        $dumpBin = Ssh::which('mysqldump') ?? Ssh::which('mariadb-dump');
        $defaults = $this->sourceDefaultsFile($cred, $host, $port);
        if ($defaults === null) {
            return $fail('Could not write the temporary MySQL credentials file.');
        }

        $base = $this->workDir . '/' . $jobId . '.db.' . $sourceDb;
        $gz = $base . '.sql.gz';
        $raw = $gz . '.raw';
        $errFile = $gz . '.err';
        $done = $gz . '.done';

        // mysqldump writes to a plain file first so a truncated dump cannot
        // look successful; the credentials file is removed whatever happens.
        $inner = sprintf(
            'st=0; { %s --defaults-extra-file=%s --single-transaction --quick --routines --triggers'
            . ' --events --skip-lock-tables --no-tablespaces --hex-blob --default-character-set=utf8mb4 %s'
            . ' > %s 2> %s || st=$?; }; if [ "$st" -eq 0 ]; then gzip -6 -c %s > %s || st=$?; fi;'
            . ' rm -f %s %s; printf "%%s" "$st" > %s',
            escapeshellarg((string)$dumpBin),
            escapeshellarg($defaults),
            escapeshellarg($sourceDb),
            escapeshellarg($raw),
            escapeshellarg($errFile),
            escapeshellarg($raw),
            escapeshellarg($gz),
            escapeshellarg($raw),
            escapeshellarg($defaults),
            escapeshellarg($done)
        );

        @unlink($done);
        // No wrapper status file: the command records its own, and the wrapper
        // would otherwise overwrite it with the exit code of the trailing rm.
        $res = FileMover::spawn($inner, $base . '.log', $base . '.pid', '');
        if (!$res['ok']) {
            @unlink($defaults);
            Log::error('db', 'Direct dump of ' . $sourceDb . ' could not be started: ' . $res['message']);
            return $fail($res['message']);
        }

        Log::info('db', 'Started direct mysqldump of ' . $sourceDb . ' from ' . $host);

        return [
            'ok' => true,
            'message' => 'Dumping ' . $sourceDb . ' from ' . $host . '.',
            'dump' => $gz,
            'remote_dump' => $gz,
        ];
    }

    /** Write a 0600 [client] defaults file for the source MySQL credentials. */
    private function sourceDefaultsFile(array $cred, string $host, int $port): ?string
    {
        $dir = sys_get_temp_dir() . '/olsmig';
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            return null;
        }
        @chmod($dir, 0700);
        $path = $dir . '/src-' . bin2hex(random_bytes(6)) . '.cnf';
        $lines = [
            '[client]',
            'host=' . $host,
            'port=' . $port,
            'user=' . (string)($cred['user'] ?? ''),
            'password="' . str_replace('"', '\\"', (string)($cred['password'] ?? '')) . '"',
        ];
        if (@file_put_contents($path, implode("\n", $lines) . "\n") === false) {
            return null;
        }
        @chmod($path, 0600);
        return $path;
    }

    /** Run the mysql client against the source, using a temporary defaults file. */
    private function runSourceClient(array $cred, string $host, int $port, array $args, int $timeout): array
    {
        $bin = Ssh::which('mysql');
        if ($bin === null) {
            return ['code' => 127, 'out' => '', 'err' => 'mysql client is not installed.'];
        }
        $defaults = $this->sourceDefaultsFile($cred, $host, $port);
        if ($defaults === null) {
            return ['code' => 126, 'out' => '', 'err' => 'Could not write the temporary credentials file.'];
        }

        $parts = [escapeshellarg($bin), escapeshellarg('--defaults-extra-file=' . $defaults)];
        foreach ($args as $a) {
            $parts[] = escapeshellarg((string)$a);
        }
        $cmd = implode(' ', $parts);

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $procs = @proc_open($cmd, $descriptors, $pipes, null, null);
        if (!is_resource($procs)) {
            @unlink($defaults);
            return ['code' => 126, 'out' => '', 'err' => 'Unable to start mysql client.'];
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $out = $err = '';
        $deadline = time() + $timeout;
        while (true) {
            $status = proc_get_status($procs);
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);
            if (!$status['running']) {
                break;
            }
            if (time() > $deadline) {
                proc_terminate($procs, 9);
                $err .= "\nTimed out";
                break;
            }
            usleep(100000);
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($procs);
        @unlink($defaults);

        return ['code' => $code, 'out' => $out, 'err' => $err];
    }

    /**
     * Discover every database the source account can actually use.
     *
     * @return string[] schema names
     */
    public function discoverSourceDatabases(string $username): array
    {
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
            return [];
        }

        $sql = sprintf(
            "SELECT DISTINCT `Db` FROM mysql.db WHERE `User` = '%s' AND `Db` NOT IN ('mysql','information_schema','performance_schema','sys')",
            addslashes($username)
        );
        $res = $this->ssh->run(
            'mysql --batch --skip-column-names -e ' . escapeshellarg($sql) . ' 2>/dev/null'
            . ' || mariadb --batch --skip-column-names -e ' . escapeshellarg($sql) . ' 2>/dev/null',
            45
        );

        $names = [];
        foreach (explode("\n", $res['out']) as $line) {
            $line = trim($line);
            if ($line === '' || !preg_match('/^[A-Za-z0-9_]+$/', $line)) {
                continue;
            }
            $names[] = $line;
        }

        if (!$names) {
            // Some hosts only expose privileges through information_schema.
            $sql2 = sprintf(
                "SELECT DISTINCT TABLE_SCHEMA FROM information_schema.SCHEMA_PRIVILEGES"
                . " WHERE GRANTEE LIKE '\\'%s\\'@\\'%%' AND TABLE_SCHEMA NOT IN"
                . " ('mysql','information_schema','performance_schema','sys')",
                addslashes($username)
            );
            $res2 = $this->ssh->run(
                'mysql --batch --skip-column-names -e ' . escapeshellarg($sql2) . ' 2>/dev/null',
                45
            );
            foreach (explode("\n", $res2['out']) as $line) {
                $line = trim($line);
                if ($line !== '' && preg_match('/^[A-Za-z0-9_]+$/', $line)) {
                    $names[] = $line;
                }
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Dump one source schema.
     *
     * The dump runs *on the source host*, detached, because dumping a large
     * database takes far longer than a PHP request may last. The remote
     * command writes its exit status to <remoteDump>.done, which is what
     * waitForDump() polls for.
     *
     * @return array{ok:bool,message:string,dump:string,remote_dump:string}
     */
    public function startDump(string $username, string $sourceDb, string $jobId): array
    {
        if (!$this->available()) {
            return ['ok' => false, 'message' => 'SSH is not configured.', 'dump' => '', 'remote_dump' => ''];
        }
        if (!preg_match('/^[A-Za-z0-9_]+$/', $sourceDb)) {
            return ['ok' => false, 'message' => 'Refusing to dump unsafe database name.', 'dump' => '', 'remote_dump' => ''];
        }
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $jobId)) {
            return ['ok' => false, 'message' => 'Refusing unsafe job name.', 'dump' => '', 'remote_dump' => ''];
        }

        $dumpPath = $this->workDir . '/' . $jobId . '.' . $sourceDb . '.sql.gz';
        $remoteDump = '/tmp/olsmig-' . $jobId . '-' . $sourceDb . '.sql.gz';
        $remoteRaw = $remoteDump . '.raw';
        $remoteErr = $remoteDump . '.err';
        $remoteDone = $remoteDump . '.done';

        // Dump to a plain file first so mysqldump's own exit status survives:
        // in a pipeline the status of the last command (gzip) would hide it and
        // a truncated dump would look successful. The braces keep the dump's
        // `||` from being pre-empted by the earlier `;`.
        $inner = sprintf(
            'st=0; { mysqldump --user=root --single-transaction --quick --routines --triggers --events'
            . ' --skip-lock-tables --no-tablespaces --hex-blob --default-character-set=utf8mb4 %s'
            . ' > %s 2> %s || st=$?; }; if [ "$st" -eq 0 ]; then gzip -6 -c %s > %s || st=$?; fi;'
            . ' rm -f %s;'
            . ' printf "%%s" "$st" > %s',
            escapeshellarg($sourceDb),
            escapeshellarg($remoteRaw),
            escapeshellarg($remoteErr),
            escapeshellarg($remoteRaw),
            escapeshellarg($remoteDump),
            escapeshellarg($remoteRaw),
            escapeshellarg($remoteDone)
        );

        $spawned = $this->ssh->background($inner);
        if (!$spawned['ok']) {
            Log::error('db', 'Dump of ' . $sourceDb . ' could not be started: ' . $spawned['message']);
            return ['ok' => false, 'message' => $spawned['message'], 'dump' => '', 'remote_dump' => ''];
        }

        Log::info('db', 'Started mysqldump of ' . $sourceDb . ' on ' . $this->ssh->host());

        return [
            'ok' => true,
            'message' => 'Dumping ' . $sourceDb . ' on the source server.',
            'dump' => $dumpPath,
            'remote_dump' => $remoteDump,
            'remote_done' => $remoteDone,
            'remote_err' => $remoteErr,
        ];
    }

    /**
     * Wait for a detached remote dump to finish.
     *
     * @return array{ok:bool,message:string,code:int,log:string}
     */
    public function waitForDump(string $remoteDump, int $timeout = 1800): array
    {
        $done = $remoteDump . '.done';
        $errFile = $remoteDump . '.err';
        $deadline = time() + $timeout;

        while (time() < $deadline) {
            if (is_file($done)) {
                break;
            }
            usleep(400000);
        }

        if (!is_file($done)) {
            return [
                'ok' => false,
                'code' => -1,
                'log' => '',
                'message' => 'The dump did not finish within ' . $timeout . 's.',
            ];
        }

        $code = (int)trim((string)@file_get_contents($done));
        $log = is_file($errFile) ? trim((string)@file_get_contents($errFile)) : '';

        if ($code !== 0) {
            return [
                'ok' => false,
                'code' => $code,
                'log' => $log,
                'message' => 'mysqldump failed with exit status ' . $code
                    . ($log !== '' ? ': ' . substr($log, 0, 300) : '.'),
            ];
        }
        return ['ok' => true, 'code' => 0, 'log' => $log, 'message' => 'Dump finished.'];
    }

    /**
     * Fetch a remote dump over SSH into a local file, then verify that the
     * archive is intact before anyone tries to load it.
     */
    public function fetchDump(string $remoteDump, string $localPath): array
    {
        if (!preg_match('#^/tmp/olsmig-[A-Za-z0-9._-]+$#', $remoteDump)) {
            return ['ok' => false, 'message' => 'Refusing unsafe remote path.'];
        }

        $cfg = $this->ssh->config();
        $cmd = sprintf(
            'ssh -p %d %s %s cat %s > %s',
            $this->ssh->port(),
            $this->sshOptions(),
            escapeshellarg($this->ssh->user() . '@' . $this->ssh->host()),
            escapeshellarg($remoteDump),
            escapeshellarg($localPath)
        );

        $descriptors = [1 => ['file', $localPath, 'w'], 2 => ['pipe', 'w']];
        $procs = @proc_open($cmd, $descriptors, $pipes, null, null);
        if (!is_resource($procs)) {
            return ['ok' => false, 'message' => 'Unable to start ssh.'];
        }
        $err = (string)stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $code = proc_close($procs);

        if ($code !== 0) {
            @unlink($localPath);
            return ['ok' => false, 'message' => 'Fetch failed: ' . (trim($err) !== '' ? trim($err) : 'ssh exit status ' . $code)];
        }

        $bytes = (int)@filesize($localPath);
        if ($bytes <= 0) {
            return ['ok' => false, 'message' => 'The fetched dump is empty.'];
        }

        // A truncated archive would import cleanly and silently lose rows.
        $check = [];
        $checkCode = 0;
        @exec('gzip -t ' . escapeshellarg($localPath) . ' 2>&1', $check, $checkCode);
        if ($checkCode !== 0) {
            return [
                'ok' => false,
                'message' => 'The fetched dump is corrupt: ' . substr(implode(' ', $check), 0, 200),
            ];
        }

        return ['ok' => true, 'message' => 'Fetched ' . Util::humanMb((int)round($bytes / 1048576))];
    }

    private function sshOptions(): string
    {
        $opts = [
            '-o ConnectTimeout=20',
            '-o ServerAliveInterval=30',
            '-o ServerAliveCountMax=10',
            '-o LogLevel=ERROR',
        ];
        $cfg = $this->ssh->config();
        if (($cfg['auth'] ?? 'key') === 'key' && ($cfg['key_path'] ?? '') !== '') {
            $opts[] = '-o IdentitiesOnly=yes';
            return implode(' ', $opts) . ' -i ' . escapeshellarg((string)$cfg['key_path']);
        }
        return implode(' ', $opts);
    }

    /**
     * Import a compressed dump into a destination schema.
     *
     * Schema-qualified references (views, routines) are rewritten from the
     * source schema name to the destination one, because OLSpanel prefixes
     * database names.
     */
    public function importDump(string $dumpFile, string $sourceDb, string $destSchema): array
    {
        if (!is_file($dumpFile)) {
            return ['ok' => false, 'message' => 'Dump file missing: ' . basename($dumpFile)];
        }
        $mysqlBin = Ssh::which('mysql');
        if ($mysqlBin === null) {
            return ['ok' => false, 'message' => 'mysql client is not installed on the OLSpanel server.'];
        }

        $creds = $this->mysql->cliPrefix();
        if ($creds === '') {
            return ['ok' => false, 'message' => 'No working local MySQL credentials.'];
        }

        $sed = sprintf(
            'sed -e %s',
            escapeshellarg('s/`' . preg_quote($sourceDb, '/') . '`/`' . preg_quote($destSchema, '/') . '`/g')
        );

        $cmd = sprintf(
            '%s %s %s',
            escapeshellarg('sh'),
            escapeshellarg('-c'),
            escapeshellarg(
                sprintf(
                    'gzip -dc %s | %s | %s %s',
                    escapeshellarg($dumpFile),
                    $sed,
                    $creds,
                    escapeshellarg($destSchema)
                )
            )
        );

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $procs = @proc_open($cmd, $descriptors, $pipes, null, null);
        if (!is_resource($procs)) {
            return ['ok' => false, 'message' => 'Unable to start mysql import.'];
        }
        // Read both pipes: mysql reports import errors on stderr, and leaving
        // stdout unread could block a verbose import on a full pipe buffer.
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $out = '';
        $err = '';
        while (true) {
            $status = proc_get_status($procs);
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);
            if (!$status['running']) {
                break;
            }
            usleep(150000);
        }
        $out .= (string)stream_get_contents($pipes[1]);
        $err .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($procs);

        if ($code !== 0) {
            $why = trim($err) !== '' ? trim($err) : trim($out);
            return [
                'ok' => false,
                'message' => 'Import failed: ' . ($why !== '' ? $why : 'mysql exit status ' . $code),
            ];
        }
        return ['ok' => true, 'message' => 'Imported into ' . $destSchema . '.'];
    }

    /** Remove a dump we no longer need. */
    public function cleanupDump(string $path): void
    {
        if ($path !== '' && is_file($path)) {
            @unlink($path);
        }
    }

    /** Delete a remote dump we created. */
    public function cleanupRemote(string $remoteDump): void
    {
        if ($remoteDump !== '' && preg_match('#^/tmp/olsmig-[A-Za-z0-9._-]+$#', $remoteDump)) {
            $this->ssh->run(
                'rm -f ' . implode(' ', array_map('escapeshellarg', [
                    $remoteDump,
                    $remoteDump . '.raw',
                    $remoteDump . '.err',
                    $remoteDump . '.done',
                ])),
                30
            );
        }
    }

    /** Row count for a table, used to verify an import. */
    public function destinationRowCount(string $schema, string $table): ?int
    {
        if (!preg_match('/^[A-Za-z0-9_]+$/', $schema) || !preg_match('/^[A-Za-z0-9_]+$/', $table)) {
            return null;
        }
        try {
            $value = $this->mysql->scalar(
                'SELECT COUNT(*) FROM `' . $table . '`',
                $schema
            );
            return $value === null ? null : (int)$value;
        } catch (Throwable $e) {
            return null;
        }
    }

    public function mysqlOrigin(): string
    {
        return $this->mysql->origin();
    }

    public function localMysql(): Mysql
    {
        return $this->mysql;
    }
}