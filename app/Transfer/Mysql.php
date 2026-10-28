<?php
/**
 * Mysql - local (OLSpanel server) MySQL access.
 *
 * OLSpanel exposes no API for importing database contents or granting
 * privileges, so the migrator uses the server's own root access. Credentials
 * are auto-discovered wherever possible so the admin does not have to paste
 * them; anything found manually lives in the encrypted config.
 */

declare(strict_types=1);

class Mysql
{
    /** @var array discovered credentials: ['args' => [...], 'origin' => string] */
    private ?array $creds = null;

    private array $config;

    public function __construct(array $mysqlConfig)
    {
        $this->config = $mysqlConfig;
    }

    /** Files that commonly hold OLSpanel's MySQL credentials. */
    private const CANDIDATE_FILES = [
        '/root/.my.cnf',
        '/usr/local/lsws/Example/html/mypanel/config.py',
        '/usr/local/lsws/Example/html/mypanel/mypanel/settings.py',
        '/usr/local/lsws/Example/html/mypanel/ols_settings.py',
        '/etc/my.cnf',
    ];

    /** Discover working local credentials. Returns origin string or null. */
    public function credentials(): ?array
    {
        if ($this->creds !== null) {
            return $this->creds;
        }

        // 1. Explicitly configured.
        if (($this->config['username'] ?? '') !== '' && empty($this->config['auto_detect'])) {
            $args = $this->buildArgs([
                'host' => (string)($this->config['host'] ?? 'localhost'),
                'user' => (string)$this->config['username'],
                'password' => (string)($this->config['root_password'] ?? ''),
                'socket' => (string)($this->config['socket'] ?? ''),
            ]);
            if ($this->canConnect($args)) {
                return $this->creds = ['args' => $args, 'origin' => 'configured'];
            }
        }

        // 2. my.cnf (used transparently by the mysql client).
        if (is_file('/root/.my.cnf') && $this->canConnect([])) {
            return $this->creds = ['args' => [], 'origin' => '/root/.my.cnf'];
        }

        // 3. Root socket / passwordless auth.
        if ($this->canConnect([])) {
            return $this->creds = ['args' => [], 'origin' => 'socket (passwordless)'];
        }

        // 4. Scrape OLSpanel / MariaDB config files for credentials.
        if (!empty($this->config['auto_detect'])) {
            foreach (self::CANDIDATE_FILES as $file) {
                if (!is_readable($file)) {
                    continue;
                }
                $found = $this->scrape($file);
                if ($found === null) {
                    continue;
                }
                $args = $this->buildArgs($found);
                if ($this->canConnect($args)) {
                    return $this->creds = ['args' => $args, 'origin' => $file];
                }
            }
        }

        return $this->creds = null;
    }

    private function buildArgs(array $c): array
    {
        $args = [];
        if (($c['socket'] ?? '') !== '') {
            $args[] = '--socket=' . $c['socket'];
        } elseif (($c['host'] ?? '') !== '' && $c['host'] !== 'localhost') {
            $args[] = '--host=' . $c['host'];
        }
        if (($c['user'] ?? '') !== '') {
            $args[] = '--user=' . $c['user'];
        }
        if (($c['password'] ?? '') !== '') {
            // Written to a private defaults file so the password never appears
            // in the process list or the migration log.
            $tmp = $this->defaultsFile($c['user'] ?? 'root', (string)$c['password'], $c['socket'] ?? '', $c['host'] ?? '');
            if ($tmp !== null) {
                $args = array_values(array_filter($args, static function ($a) {
                    return strpos($a, '--user=') !== 0;
                }));
                $args = ['--defaults-extra-file=' . $tmp];
                if (($c['host'] ?? '') !== '' && $c['host'] !== 'localhost') {
                    $args[] = '--host=' . $c['host'];
                }
            }
        }
        return $args;
    }

    private function defaultsFile(string $user, string $password, string $socket, string $host): ?string
    {
        $dir = sys_get_temp_dir() . '/olsmig';
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            return null;
        }
        $path = $dir . '/my-' . bin2hex(random_bytes(6)) . '.cnf';
        $lines = ['[client]'];
        $lines[] = 'user=' . $user;
        $lines[] = 'password="' . str_replace('"', '\\"', $password) . '"';
        if ($socket !== '') {
            $lines[] = 'socket=' . $socket;
        } elseif ($host !== '' && $host !== 'localhost') {
            $lines[] = 'host=' . $host;
        }
        if (@file_put_contents($path, implode("\n", $lines) . "\n") === false) {
            return null;
        }
        @chmod($path, 0600);
        return $path;
    }

    private function canConnect(array $args): bool
    {
        $res = $this->run(['SELECT 1'], $args, 20);
        return $res['code'] === 0;
    }

    /** Run a query, returning tab-separated rows. */
    public function query(string $sql, ?string $database = null): array
    {
        $creds = $this->credentials();
        if ($creds === null) {
            throw new RuntimeException('No working local MySQL credentials found.');
        }
        // -N suppresses the column-header row; keeping it even when a database
        // is named matters, otherwise scalar() reads the header as the value.
        $args = ['-N', '-B'];
        if ($database !== null) {
            $args[] = $database;
        }
        $args[] = '-e';
        $args[] = $sql;
        $res = $this->run($args, $creds['args'], 60);
        if ($res['code'] !== 0) {
            throw new RuntimeException('MySQL error: ' . trim($res['err']));
        }
        $rows = [];
        foreach (explode("\n", trim($res['out'])) as $line) {
            if ($line === '') {
                continue;
            }
            $rows[] = explode("\t", $line);
        }
        return $rows;
    }

    public function exec(string $sql, ?string $database = null): void
    {
        $creds = $this->credentials();
        if ($creds === null) {
            throw new RuntimeException('No working local MySQL credentials found.');
        }
        $args = ['-N', '-B'];
        if ($database !== null) {
            $args[] = $database;
        }
        $args[] = '-e';
        $args[] = $sql;
        $res = $this->run($args, $creds['args'], 60);
        if ($res['code'] !== 0) {
            throw new RuntimeException('MySQL error: ' . trim($res['err']));
        }
    }

    /** Column value from a single-row query. */
    public function scalar(string $sql, ?string $database = null): ?string
    {
        $rows = $this->query($sql, $database);
        return isset($rows[0][0]) ? (string)$rows[0][0] : null;
    }

    /**
     * Command prefix for shell pipelines (e.g. importing a dump).
     * Returns '' when no credentials work.
     */
    public function cliPrefix(): string
    {
        $creds = $this->credentials();
        if ($creds === null) {
            return '';
        }
        $bin = Ssh::which('mysql');
        if ($bin === null) {
            return '';
        }
        $parts = [escapeshellarg($bin)];
        foreach ($creds['args'] as $a) {
            $parts[] = escapeshellarg($a);
        }
        return implode(' ', $parts);
    }

    private function run(array $args, array $extraArgs, int $timeout): array
    {
        $bin = Ssh::which('mysql');
        if ($bin === null) {
            return ['code' => 127, 'out' => '', 'err' => 'mysql client is not installed.'];
        }
        $parts = [escapeshellarg($bin)];
        foreach (array_merge($extraArgs, $args) as $a) {
            $parts[] = escapeshellarg($a);
        }
        $cmd = implode(' ', $parts);

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $procs = @proc_open($cmd, $descriptors, $pipes, null, null);
        if (!is_resource($procs)) {
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

        return ['code' => $code, 'out' => $out, 'err' => $err];
    }

    /** Look for DB credentials in a config file. */
    private function scrape(string $file): ?array
    {
        $raw = @file_get_contents($file, false, null, 0, 262144);
        if ($raw === false) {
            return null;
        }

        // Each pattern is paired with the field it fills, so adding a pattern
        // can never silently shift the others.
        $patterns = [
            'password' => "/['\"]?(?:DB_PASSWORD|db_password|MYSQL_PASSWORD|database_password)['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]/i",
            'user' => "/['\"]?(?:DB_USER|db_user|MYSQL_USER|database_user)['\"]?\s*[:=]\s*['\"]([^'\"]{1,64})['\"]/i",
            'host' => "/['\"]?(?:DB_HOST|db_host|MYSQL_HOST|database_host)['\"]?\s*[:=]\s*['\"]([^'\"]{1,64})['\"]/i",
            // my.cnf style
            'password' => "/^\s*password\s*=\s*(.+)$/mi",
            'user' => "/^\s*user\s*=\s*(.+)$/mi",
        ];
        $found = [];
        foreach ($patterns as $field => $re) {
            if (preg_match($re, $raw, $m)) {
                $value = trim($m[1], " \t'\"");
                if ($value !== '' && stripos($value, 'CHANGE_ME') === false) {
                    $found[$field] = $value;
                }
            }
        }

        if (!isset($found['password'])) {
            return null;
        }
        $found['user'] = $found['user'] ?? 'root';
        $found['host'] = $found['host'] ?? 'localhost';
        return $found;
    }

    /**
     * Resolve the real schema name OLSpanel gave a logical database name.
     * OLSpanel prefixes database names, so the logical name we sent to
     * database_add is not the schema that exists on disk.
     */
    public function resolveSchema(string $logical): ?string
    {
        $escaped = str_replace(["\\", "%", "_", "'"], ["\\\\", "\\%", "\\_", "''"], $logical);
        $rows = $this->query(
            "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE '%" . $escaped . "'"
        );
        if (empty($rows)) {
            return null;
        }
        if (count($rows) === 1) {
            return (string)$rows[0][0];
        }
        // Prefer the tightest suffix match.
        usort($rows, static function ($a, $b) use ($logical) {
            return strlen((string)$a[0]) <=> strlen((string)$b[0]);
        });
        return (string)$rows[0][0];
    }

    /** Grant full privileges on a schema to a database user. */
    public function grant(string $schema, string $dbUser, string $dbHost = 'localhost'): void
    {
        if (!preg_match('/^[A-Za-z0-9_]+$/', $schema) || !preg_match('/^[A-Za-z0-9_]+$/', $dbUser)) {
            throw new RuntimeException('Refusing to grant privileges to unsafe identifier.');
        }
        if (!preg_match('/^[A-Za-z0-9_.%\-]{1,64}$/', $dbHost)) {
            throw new RuntimeException('Refusing to grant privileges to unsafe host.');
        }
        foreach ([$dbHost, 'localhost', '127.0.0.1'] as $h) {
            $this->exec(sprintf(
                "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s'",
                $schema,
                $dbUser,
                $h
            ));
        }
        $this->exec('FLUSH PRIVILEGES');
    }

    public function dropDatabase(string $schema): void
    {
        if (!preg_match('/^[A-Za-z0-9_]+$/', $schema)) {
            throw new RuntimeException('Refusing to drop unsafe schema name.');
        }
        $this->exec('DROP DATABASE IF EXISTS `' . $schema . '`');
    }

    public function origin(): string
    {
        $creds = $this->credentials();
        return $creds['origin'] ?? 'none';
    }
}