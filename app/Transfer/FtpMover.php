<?php
/**
 * FtpMover - transfer an account's home directory over FTP/FTPS.
 *
 * This is the no-SSH alternative to FileMover. It logs in as the account's own
 * FTP user (DirectAdmin chroots that user to the account home) and mirrors the
 * tree with lftp. The password never reaches the process list: it is written to
 * a 0600 lftp script that is deleted as soon as the job exits.
 */

declare(strict_types=1);

class FtpMover
{
    private FileMover $files;
    private array $sourceCfg;
    private array $transferCfg;
    private string $workDir;

    public function __construct(FileMover $files, array $sourceCfg, array $transferCfg, string $workDir)
    {
        $this->files = $files;
        $this->sourceCfg = $sourceCfg;
        $this->transferCfg = $transferCfg;
        $this->workDir = rtrim($workDir, '/');
        if (!is_dir($this->workDir)) {
            @mkdir($this->workDir, 0700, true);
        }
        @chmod($this->workDir, 0700);
    }

    public function available(): bool
    {
        return Ssh::which('lftp') !== null;
    }

    public function host(): string
    {
        return (string)($this->sourceCfg['host'] ?? '');
    }

    public function port(): int
    {
        return (int)($this->sourceCfg['ftp_port'] ?? 21);
    }

    /** 'ftp' (FTP/FTPS) or 'sftp'. */
    public function protocol(): string
    {
        $p = strtolower(trim((string)($this->sourceCfg['ftp_protocol'] ?? 'ftp')));
        return $p === 'sftp' ? 'sftp' : 'ftp';
    }

    public function label(): string
    {
        return $this->protocol() === 'sftp' ? 'SFTP' : 'FTP';
    }

    /**
     * lftp's command parser is shell-like, but a value split across quotes is
     * ambiguous. Rather than risk a mangled login, refuse the few passwords it
     * cannot carry reliably and tell the operator to use SSH for that account.
     */
    public static function passwordSupported(string $password): bool
    {
        if ($password === '') {
            return false;
        }
        return preg_match('/[\x00-\x1f\x7f\'"\\\\]/', $password) !== 1;
    }

    /**
     * Start the mirror as a background job.
     *
     * @param string $login the FTP/SFTP login; '' uses the account username.
     * @return array{ok:bool,message:string,job:string,command:string}
     */
    public function startMirror(string $username, string $stage, string $jobId, string $password, string $login = ''): array
    {
        if (!$this->available()) {
            return ['ok' => false, 'message' => 'lftp is not installed on the OLSpanel server.', 'job' => '', 'command' => ''];
        }
        if ($this->host() === '') {
            return ['ok' => false, 'message' => 'The source host is not set.', 'job' => '', 'command' => ''];
        }
        if (!self::passwordSupported($password)) {
            return ['ok' => false, 'message' => 'This ' . $this->label() . ' password contains characters the client cannot pass safely; use SSH for this account.', 'job' => '', 'command' => ''];
        }

        $login = trim($login) !== '' ? trim($login) : $username;
        // lftp's script parser is shell-like: a quote or newline in the login
        // or host could add its own lftp commands. Refuse rather than risk it.
        if (preg_match('/[\x00-\x1f\'"\\\\]/', $login) || preg_match('/[\x00-\x1f\'"\\\\]/', $this->host())) {
            return ['ok' => false, 'message' => 'The FTP/SFTP login or host contains characters the client cannot pass safely; use SSH for this account.', 'job' => '', 'command' => ''];
        }

        $dest = $this->files->homeDir($username);
        if (!is_dir($dest)) {
            return ['ok' => false, 'message' => 'Destination directory ' . $dest . ' does not exist; create the account first.', 'job' => '', 'command' => ''];
        }

        $script = $this->workDir . '/' . $jobId . '.' . $stage . '.lftp';
        if (@file_put_contents($script, $this->script($login, $stage, $dest, $password)) === false) {
            return ['ok' => false, 'message' => 'Could not write the FTP job script.', 'job' => '', 'command' => ''];
        }
        @chmod($script, 0600);

        $lftp = Ssh::which('lftp');
        $logFile = $this->workDir . '/' . $jobId . '.' . $stage . '.log';
        $pidFile = $this->workDir . '/' . $jobId . '.' . $stage . '.pid';

        // The wrapper removes the credential-bearing script and fixes ownership
        // even when the transfer fails, then reports lftp's own exit status.
        $cmd = sprintf(
            '%s -f %s; st=$?; rm -f %s; chown -R %s %s 2>/dev/null; chmod 0755 %s 2>/dev/null; exit $st',
            escapeshellarg((string)$lftp),
            escapeshellarg($script),
            escapeshellarg($script),
            escapeshellarg($username . ':' . $username),
            escapeshellarg($dest),
            escapeshellarg($dest)
        );

        @unlink($logFile . '.done');
        @unlink($pidFile);

        $res = FileMover::spawn($cmd, $logFile, $pidFile, $logFile . '.done');
        if (!$res['ok']) {
            @unlink($script);
            return ['ok' => false, 'message' => 'Could not start lftp: ' . $res['message'], 'job' => '', 'command' => ''];
        }

        return [
            'ok' => true,
            'message' => ucfirst($stage) . ' ' . $this->label() . ' transfer running in the background.',
            'job' => $jobId . '.' . $stage,
            'command' => 'lftp -f ' . $script . ' (credentials hidden)',
        ];
    }

    /**
     * The connection lines for the lftp script: protocol settings, credentials
     * and the open command. Pure and side-effect free so it can be tested.
     *
     * @return string[]
     */
    public static function connectionLines(string $protocol, string $host, int $port, string $login, string $password, string $tls = 'auto', bool $verify = false): array
    {
        if ($protocol === 'sftp') {
            return [
                // Accept a new host key on first use, but do not disable host
                // verification entirely (that would allow a MITM to collect the
                // login). The key is kept in root's known_hosts.
                'set sftp:auto-confirm yes',
                'set sftp:connect-program "ssh -a -x -o StrictHostKeyChecking=accept-new"',
                "user '" . $login . "' '" . $password . "'",
                "open 'sftp://" . $host . ":" . $port . "'",
            ];
        }

        $lines = ['set ftp:passive-mode true'];
        if ($verify) {
            $lines[] = 'set ssl:verify-certificate yes';
            $lines[] = 'set ssl:check-hostname yes';
        } else {
            $lines[] = 'set ssl:verify-certificate no';
            $lines[] = 'set ssl:check-hostname no';
        }
        if ($tls === 'off') {
            $lines[] = 'set ftp:ssl-allow off';
        } else {
            $lines[] = 'set ftp:ssl-allow yes';
            $lines[] = 'set ftp:ssl-protect-data yes';
            $lines[] = $tls === 'force' ? 'set ftp:ssl-force true' : 'set ftp:ssl-force false';
        }
        $lines[] = "user '" . $login . "' '" . $password . "'";
        $lines[] = "open -p " . $port . " '" . $host . "'";
        return $lines;
    }

    /** Build the lftp command script. */
    private function script(string $login, string $stage, string $dest, string $password): string
    {
        $lines = [
            'set net:timeout 20',
            'set net:max-retries 2',
            'set net:persist-retries 2',
            'set cmd:fail-exit false',
            'set mirror:parallel-transfer-count 2',
        ];
        foreach (self::connectionLines($this->protocol(), $this->host(), $this->port(), $login, $password, (string)($this->sourceCfg['ftp_tls'] ?? 'auto'), !empty($this->sourceCfg['verify_tls'])) as $line) {
            $lines[] = $line;
        }

        $parallel = 2;
        $base = ['--verbose=1', '--parallel=' . $parallel, '--no-perms'];
        if (!empty($this->transferCfg['delete_after'])) {
            $base[] = '--delete';
        }
        foreach ($this->files->excludes($stage) as $pattern) {
            $rx = self::excludeRegex($pattern);
            if ($rx !== '') {
                $base[] = "-x '" . str_replace("'", '', $rx) . "'";
            }
        }
        $flags = implode(' ', $base);

        if ($stage === 'mail') {
            // DirectAdmin keeps mail under ~/mail; a Maildir layout keeps it at
            // the home root. Mirror whichever exists.
            $lines[] = "mirror $flags 'mail' " . escapeshellarg($dest . '/mail');
            $lines[] = "mirror $flags 'Maildir' " . escapeshellarg($dest . '/Maildir');
        } else {
            $lines[] = "mirror $flags './' " . escapeshellarg($dest . '/');
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * Turn a FileMover exclude (a path or component) into an lftp/PCRE exclude
     * that matches that component at any depth.
     */
    public static function excludeRegex(string $pattern): string
    {
        $p = trim(trim($pattern), '/');
        if ($p === '') {
            return '';
        }
        return '(^|/)' . preg_quote($p, '#') . '(/|$)';
    }
}
