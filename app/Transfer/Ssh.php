<?php
/**
 * Ssh - command execution on the *source* server.
 *
 * Used for file/mail syncing, MySQL dumps and for reading the source control
 * panel's local metadata files (which expose far more detail than the panel
 * APIs do, e.g. every mailbox on a cPanel server).
 *
 * All remote commands are passed through sh -c with escapeshellarg so that no
 * request-supplied value can break out of its argument.
 */

declare(strict_types=1);

class Ssh
{
    private array $cfg;
    private string $host;
    private int $port;
    private string $user;

    public function __construct(array $sshConfig)
    {
        $this->cfg = $sshConfig;
        $this->host = (string)($sshConfig['host'] ?? '');
        $this->port = (int)($sshConfig['port'] ?? 22);
        $this->user = (string)($sshConfig['username'] ?? 'root');
        // Decided here rather than at run time: sshOptions() is consulted while
        // the command is being built, before the askpass helper exists.
        $this->passphrase = ($sshConfig['auth'] ?? 'key') === 'key'
            && (string)($sshConfig['key_passphrase'] ?? '') !== '';
    }

    public function isConfigured(): bool
    {
        return $this->host !== '' && Util::validHost($this->host);
    }

    public function host(): string { return $this->host; }
    public function port(): int { return $this->port; }
    public function user(): string { return $this->user; }

    /** Full transport settings (auth mode, key path, ...). */
    public function config(): array
    {
        return $this->cfg;
    }

    /** Check the local box has the tooling we rely on. */
    public static function localTools(): array
    {
        $out = [];
        foreach (['ssh', 'rsync', 'scp', 'mysqldump', 'mysql'] as $bin) {
            $out[$bin] = self::which($bin) !== null;
        }
        $out['sshpass'] = self::which('sshpass') !== null;
        return $out;
    }

    public static function which(string $bin): ?string
    {
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $bin)) {
            return null;
        }
        $out = [];
        $code = 0;
        @exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null', $out, $code);
        return ($code === 0 && !empty($out[0])) ? $out[0] : null;
    }

    /** Build the ssh option list. */
    private function sshOptions(): array
    {
        $opts = [
            '-p', (string)$this->port,
            '-o', 'ConnectTimeout=20',
            '-o', 'ServerAliveInterval=30',
            '-o', 'ServerAliveCountMax=6',
            '-o', 'LogLevel=ERROR',
            '-o', 'PreferredAuthentications=publickey,password',
        ];

        $strict = !empty($this->cfg['strict_host_key']);
        $opts[] = '-o';
        $opts[] = $strict ? 'StrictHostKeyChecking=yes' : 'StrictHostKeyChecking=accept-new';

        if (($this->cfg['auth'] ?? 'key') === 'key') {
            $key = (string)($this->cfg['key_path'] ?? '');
            if ($key !== '') {
                $opts[] = '-i';
                $opts[] = $key;
                $opts[] = '-o';
                $opts[] = 'IdentitiesOnly=yes';
            }
            if (!$this->passphrase) {
                $opts[] = '-o';
                $opts[] = 'BatchMode=yes';
            }
        } else {
            // Password auth needs an interactive askpass helper.
            $opts[] = '-o';
            $opts[] = 'PubkeyAuthentication=no';
            $opts[] = '-o';
            $opts[] = 'PreferredAuthentications=password,keyboard-interactive';
        }

        return $opts;
    }

    /**
     * Askpass helper used for a passphrase-protected private key.
     *
     * With BatchMode=yes the key can only be unlocked non-interactively, so a
     * one-shot script that echoes the passphrase is handed to ssh via
     * SSH_ASKPASS + SSH_ASKPASS_REQUIRE=force. The passphrase is written to a
     * 0600 file that is removed the moment this object is destroyed.
     */
    private function askpassEnv(): array
    {
        if (!$this->passphrase) {
            return [];
        }
        $this->writeAskpass();
        return [
            'SSH_ASKPASS' => $this->askpassScript,
            'SSH_ASKPASS_REQUIRE' => 'force',
            'DISPLAY' => ':0',
        ];
    }

    /**
     * Path to this instance's askpass helper. Fixed for the lifetime of the
     * object so the name handed to ssh is the name that was written.
     */
    private string $askpassScript = '';

    private function askpassPath(): string
    {
        if ($this->askpassScript === '') {
            $this->askpassScript = rtrim(sys_get_temp_dir(), '/')
                . '/olsmig-askpass-' . bin2hex(random_bytes(6));
        }
        return $this->askpassScript;
    }

    private function writeAskpass(): void
    {
        $file = $this->askpassPath();
        // escapeshellarg rather than a heredoc: a passphrase containing quotes,
        // $ or the delimiter itself must survive intact.
        $script = "#!/bin/sh\nprintf '%s\\n' " . escapeshellarg((string)$this->cfg['key_passphrase']) . "\n";
        if (@file_put_contents($file, $script, LOCK_EX) !== false) {
            @chmod($file, 0700);
        }
    }

    private function clearAskpass(): void
    {
        if ($this->askpassScript !== '' && is_file($this->askpassScript)) {
            @unlink($this->askpassScript);
        }
    }

    public function __destruct()
    {
        $this->clearAskpass();
    }

    /** Prefix for a remote command (must be followed by a single quoted command). */
    private function prefix(string $command): string
    {
        $opts = implode(' ', array_map('escapeshellarg', $this->sshOptions()));
        return sprintf('ssh %s %s@%s -- %s', $opts, escapeshellarg($this->user), escapeshellarg($this->host), $command);
    }

    /**
     * Environment overrides for a single ssh invocation.
     *
     * A passphrase unlocks the key, so BatchMode has to go for that run; the
     * passphrase itself is never passed on the command line where `ps` could
     * read it.
     */
    private function envForCommand(): array
    {
        return $this->askpassEnv();
    }

    /** @return array<string,string> */
    private static function currentEnv(): array
    {
        $env = [];
        foreach ($_SERVER as $k => $v) {
            if (is_string($k) && is_string($v) && preg_match('/^[A-Z_][A-Z0-9_]*$/', $k)) {
                $env[$k] = $v;
            }
        }
        return $env;
    }

    private bool $passphrase = false;

    /**
     * Run a command on the source host.
     *
     * @return array{code:int,out:string,err:string,cmd:string}
     */
    public function run(string $command, int $timeout = 300): array
    {
        $wrapped = 'sh -c ' . escapeshellarg($command);
        $full = $this->prefix($wrapped);

        if (($this->cfg['auth'] ?? 'key') === 'password') {
            $sshpass = self::which('sshpass');
            if ($sshpass === null) {
                return ['code' => 127, 'out' => '', 'err' => 'sshpass is not installed; cannot use password authentication.', 'cmd' => self::redact($full)];
            }
            $pass = (string)($this->cfg['password'] ?? '');
            $full = escapeshellarg($sshpass) . ' -p ' . escapeshellarg($pass) . ' ' . $full;
        }

        return $this->execLocal($full, $timeout);
    }

    /**
     * Start a command on the source host and detach it.
     *
     * The command must write its own completion marker (see
     * DbMover::startDump); the SSH connection only has to survive long enough
     * to launch it, which keeps PHP free to do other work meanwhile.
     *
     * @return array{ok:bool,message:string}
     */
    public function background(string $command): array
    {
        // nohup + & runs inside the remote shell, so the job outlives the SSH
        // session it was started from.
        $remote = 'nohup sh -c ' . escapeshellarg($command) . ' >/dev/null 2>&1 & echo started';
        $full = $this->prefix($remote);

        if (($this->cfg['auth'] ?? 'key') === 'password') {
            $sshpass = self::which('sshpass');
            if ($sshpass === null) {
                return ['ok' => false, 'message' => 'sshpass is not installed; cannot use password authentication.'];
            }
            $full = escapeshellarg($sshpass) . ' -p ' . escapeshellarg((string)($this->cfg['password'] ?? '')) . ' ' . $full;
        }

        $res = $this->execLocal($full, 60);
        if ($res['code'] !== 0) {
            $err = trim($res['err']) !== '' ? trim($res['err']) : ('exit status ' . $res['code']);
            return ['ok' => false, 'message' => 'Could not start the remote job: ' . $err];
        }
        return ['ok' => true, 'message' => trim($res['out'])];
    }

    /**
     * Run a command with stdin attached - used to stream pipes between servers.
     */
    public function runWithStdin(string $command, string $stdinFile, int $timeout = 0): array
    {
        $wrapped = 'sh -c ' . escapeshellarg($command);
        $full = $this->prefix($wrapped);
        if (($this->cfg['auth'] ?? 'key') === 'password') {
            $sshpass = self::which('sshpass');
            if ($sshpass === null) {
                return ['code' => 127, 'out' => '', 'err' => 'sshpass is not installed.', 'cmd' => self::redact($full)];
            }
            $full = escapeshellarg($sshpass) . ' -p ' . escapeshellarg((string)($this->cfg['password'] ?? '')) . ' ' . $full;
        }
        $full .= ' < ' . escapeshellarg($stdinFile);
        return $this->execLocal($full, $timeout);
    }

    /** Remove an sshpass password from a command string before returning it. */
    public static function redact(string $command): string
    {
        $redacted = preg_replace('/(sshpass\s+-p\s+)(\'[^\']*\'|"[^"]*"|\S+)/', '$1***', $command);
        return $redacted === null ? 'ssh (credentials hidden)' : $redacted;
    }

    private function execLocal(string $fullCmd, int $timeout): array
    {
        // proc_open() replaces the whole environment when $env is given, so
        // the current one is merged in to keep PATH and friends intact.
        $env = $this->envForCommand();
        if ($env !== []) {
            $env = array_merge(self::currentEnv(), $env);
        }

        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $procs = @proc_open($fullCmd, $descriptors, $pipes, null, $env === [] ? null : $env);
        if (!is_resource($procs)) {
            return ['code' => 126, 'out' => '', 'err' => 'Unable to start: ' . self::redact($fullCmd), 'cmd' => self::redact($fullCmd)];
        }
        fclose($pipes[0]);

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $out = '';
        $err = '';
        $deadline = $timeout > 0 ? time() + $timeout : null;

        while (true) {
            $status = proc_get_status($procs);
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);

            if (!$status['running']) {
                break;
            }
            if ($deadline !== null && time() > $deadline) {
                proc_terminate($procs, 9);
                $err .= "\nTimed out after {$timeout}s";
                break;
            }
            usleep(120000);
        }

        $out .= (string)stream_get_contents($pipes[1]);
        $err .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($procs);

        return ['code' => $code, 'out' => $out, 'err' => $err, 'cmd' => self::redact($fullCmd)];
    }

    /** Connectivity + privilege check. */
    public function test(): array
    {
        $res = $this->run('id -u && uname -s', 40);
        if ($res['code'] !== 0) {
            return ['ok' => false, 'message' => trim($res['err']) !== '' ? trim($res['err']) : 'SSH connection failed.'];
        }
        $lines = array_values(array_filter(array_map('trim', explode("\n", $res['out']))));
        $uid = (int)($lines[0] ?? -1);
        $os = $lines[1] ?? 'linux';
        return [
            'ok' => true,
            'message' => sprintf(
                'Connected to %s (%s) as %s, uid %d.',
                $this->host,
                $os,
                $this->user,
                $uid
            ),
            'uid' => $uid,
            'root' => $uid === 0,
            'os' => $os,
        ];
    }
}