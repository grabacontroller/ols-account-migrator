<?php
/**
 * FileMover - rsync based transfer of an account's home directory.
 *
 * Transfers run as detached background jobs because a large account easily
 * exceeds PHP's max_execution_time. Each job writes to its own log file which
 * the UI polls for progress.
 */

declare(strict_types=1);

class FileMover
{
    private Ssh $ssh;
    private array $transferCfg;
    private string $workDir;

    public function __construct(Ssh $ssh, array $transferCfg, string $workDir)
    {
        $this->ssh = $ssh;
        $this->transferCfg = $transferCfg;
        $this->workDir = rtrim($workDir, '/');
        if (!is_dir($this->workDir)) {
            @mkdir($this->workDir, 0700, true);
        }
        @chmod($this->workDir, 0700);
    }

    public function available(): bool
    {
        return Ssh::which('rsync') !== null && $this->ssh->isConfigured();
    }

    /**
     * Home directory on the OLSpanel server, e.g. /home/john
     *
     * The username is validated rather than merely quoted: it reaches us from
     * a remote panel and ends up in a shell command, so it must never be able
     * to carry a path traversal or a metacharacter.
     *
     * @throws InvalidArgumentException
     */
    public function homeDir(string $username): string
    {
        if (!Util::validUsername($username)) {
            throw new InvalidArgumentException('Refusing to build a path from an unsafe account name: ' . $username);
        }
        $tpl = (string)($this->transferCfg['user_home'] ?? '/home/%s');
        $dir = rtrim(sprintf($tpl, $username), '/');
        if ($dir === '' || strpos($dir, '/') !== 0) {
            throw new RuntimeException('transfer.user_home must be an absolute path, got: ' . $tpl);
        }
        return $dir;
    }

    /**
     * Home directory on the *source* server. It defaults to the same template
     * as the destination, which is what makes a same-layout migration work
     * without any extra configuration.
     *
     * @throws InvalidArgumentException
     */
    public function sourceHomeDir(string $username): string
    {
        if (!Util::validUsername($username)) {
            throw new InvalidArgumentException('Refusing to build a path from an unsafe account name: ' . $username);
        }
        $tpl = (string)($this->transferCfg['source_user_home'] ?? ($this->transferCfg['user_home'] ?? '/home/%s'));
        $dir = rtrim(sprintf($tpl, $username), '/');
        if ($dir === '' || strpos($dir, '/') !== 0) {
            throw new RuntimeException('transfer.source_user_home must be an absolute path, got: ' . $tpl);
        }
        return $dir;
    }

    /**
     * rsync -e options matching the Ssh transport.
     * Kept in one place so a manual copy/paste of the command works.
     */
    public function sshOptions(): string
    {
        $opts = [
            '-p ' . $this->ssh->port(),
            '-o ConnectTimeout=20',
            '-o ServerAliveInterval=30',
            '-o ServerAliveCountMax=10',
            '-o LogLevel=ERROR',
        ];
        $strict = !empty($this->sshConfig()['strict_host_key']);
        $opts[] = '-o ' . ($strict ? 'StrictHostKeyChecking=yes' : 'StrictHostKeyChecking=accept-new');

        $cfg = $this->sshConfig();
        if (($cfg['auth'] ?? 'key') === 'key' && ($cfg['key_path'] ?? '') !== '') {
            $opts[] = '-i ' . escapeshellarg((string)$cfg['key_path']);
            $opts[] = '-o IdentitiesOnly=yes';
        } else {
            $opts[] = '-o PreferredAuthentications=password,keyboard-interactive';
            $opts[] = '-o PubkeyAuthentication=no';
        }
        return implode(' ', $opts);
    }

    private function sshConfig(): array
    {
        return $this->ssh->config();
    }

    /** Human readable preview of exactly what will run. */
    public function previewCommand(string $username, string $stage): string
    {
        $dest = $this->homeDir($username);
        $src = $this->ssh->user() . '@' . $this->ssh->host() . ':' . $this->sourceHomeDir($username) . '/';

        $args = ['-a', '--partial', '--info=stats2'];
        if (!empty($this->transferCfg['delete_after'])) {
            $args[] = '--delete';
        }
        foreach ($this->excludes($stage) as $pattern) {
            $args[] = '--exclude=' . escapeshellarg($pattern);
        }

        $lim = (int)($this->transferCfg['bandwidth_limit'] ?? 0);
        if ($lim > 0) {
            $args[] = '--bwlimit=' . $lim;
        }

        $cmd = 'rsync ' . implode(' ', $args) . ' -e ' . escapeshellarg($this->sshOptions())
            . ' ' . escapeshellarg($src) . ' ' . escapeshellarg($dest . '/');

        if (($this->sshConfig()['auth'] ?? 'key') === 'password') {
            $sshpass = Ssh::which('sshpass');
            if ($sshpass) {
                $cmd = escapeshellarg($sshpass) . ' -p ' . escapeshellarg((string)$this->sshConfig()['password']) . ' ' . $cmd;
            }
        }
        return Ssh::redact($cmd);
    }

    /**
     * Exclusion list.
     *
     * @param string $stage 'files' (web content, no mail) or 'mail'
     */
    public function excludes(string $stage): array
    {
        $mailDirs = (array)($this->transferCfg['mail_dirs'] ?? ['mail', 'Maildir']);

        $excludes = [];
        if ($stage === 'files') {
            // Mail is synced separately so the website goes live sooner.
            foreach ($mailDirs as $dir) {
                $excludes[] = '/' . trim((string)$dir, '/') . '/';
            }
        }
        foreach ((array)($this->transferCfg['exclude'] ?? []) as $pattern) {
            $pattern = trim((string)$pattern);
            if ($pattern !== '') {
                $excludes[] = $pattern;
            }
        }
        // Control-panel metadata that would only confuse the destination.
        $excludes[] = '/.cpanel*';
        $excludes[] = '/.lastlogin';
        $excludes[] = '/.history';
        return array_values(array_unique($excludes));
    }

    /**
     * Start the transfer as a background job.
     *
     * The wrapper records rsync's exit status in <log>.done, which is the only
     * reliable way to tell a finished transfer from a failed one - the process
     * vanishing proves nothing.
     *
     * @return array{ok:bool,message:string,job:string,command:string}
     */
    public function startSync(string $username, string $stage, string $jobId): array
    {
        if (!$this->available()) {
            return ['ok' => false, 'message' => 'rsync is unavailable or SSH is not configured.', 'job' => '', 'command' => ''];
        }

        $dest = $this->homeDir($username);
        if (!is_dir($dest)) {
            return ['ok' => false, 'message' => 'Destination directory ' . $dest . ' does not exist; create the account first.', 'job' => '', 'command' => ''];
        }
        $src = $this->ssh->user() . '@' . $this->ssh->host() . ':' . $this->sourceHomeDir($username) . '/';

        $args = ['-a', '--partial', '--info=stats2', '--human-readable'];
        if (!empty($this->transferCfg['delete_after'])) {
            $args[] = '--delete';
        }
        foreach ($this->excludes($stage) as $pattern) {
            $args[] = '--exclude=' . escapeshellarg($pattern);
        }
        $lim = (int)($this->transferCfg['bandwidth_limit'] ?? 0);
        if ($lim > 0) {
            $args[] = '--bwlimit=' . $lim;
        }

        $rsyncBin = Ssh::which('rsync');
        $cmd = escapeshellarg($rsyncBin) . ' ' . implode(' ', $args)
            . ' -e ' . escapeshellarg($this->sshOptions())
            . ' ' . escapeshellarg($src)
            . ' ' . escapeshellarg($dest . '/');

        $cfg = $this->sshConfig();
        if (($cfg['auth'] ?? 'key') === 'password') {
            $sshpass = Ssh::which('sshpass');
            if ($sshpass === null) {
                return ['ok' => false, 'message' => 'sshpass is required for password-based transfers and is not installed.', 'job' => '', 'command' => ''];
            }
            $cmd = escapeshellarg($sshpass) . ' -p ' . escapeshellarg((string)($cfg['password'] ?? '')) . ' ' . $cmd;
        }

        // Ownership is corrected after the copy; rsync -a cannot know the
        // destination system user.
        $cmd .= ' && chown -R ' . escapeshellarg($username . ':' . $username) . ' ' . escapeshellarg($dest)
            . ' && chmod 0755 ' . escapeshellarg($dest);

        $logFile = $this->workDir . '/' . $jobId . '.' . $stage . '.log';
        $pidFile = $this->workDir . '/' . $jobId . '.' . $stage . '.pid';

        // A stale sentinel would make the next poll report a bogus result.
        @unlink($logFile . '.done');
        @unlink($pidFile);

        $res = self::spawn($cmd, $logFile, $pidFile, $logFile . '.done');
        if (!$res['ok']) {
            return ['ok' => false, 'message' => 'Could not start rsync: ' . $res['message'], 'job' => '', 'command' => ''];
        }

        return [
            'ok' => true,
            'message' => ucfirst($stage) . ' transfer running in the background.',
            'job' => $jobId . '.' . $stage,
            'command' => Ssh::redact($cmd),
        ];
    }

    /**
     * Generic detached-process launcher.
     *
     * When $statusFile is given, a wrapper records the command's exit status
     * there so a finished job can be told apart from a dead one. Commands that
     * record their own status (the dumps, which must ignore the exit code of a
     * trailing cleanup) pass an empty $statusFile so the true status is not
     * overwritten by the wrapper.
     *
     * @return array{ok:bool,message:string}
     */
    public static function spawn(string $command, string $logFile, string $pidFile, string $statusFile = ''): array
    {
        $wrapper = $command;
        if ($statusFile !== '') {
            $wrapper .= '; printf "%s" "$?" > ' . escapeshellarg($statusFile);
        }

        $full = sprintf(
            'nohup sh -c %s >> %s 2>&1 & pid=$!; echo "$pid" > %s; printf "%%s" "$pid"',
            escapeshellarg($wrapper),
            escapeshellarg($logFile),
            escapeshellarg($pidFile)
        );

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $procs = @proc_open($full, $descriptors, $pipes, null, null);
        if (!is_resource($procs)) {
            return ['ok' => false, 'message' => 'proc_open failed.'];
        }
        $out = (string)stream_get_contents($pipes[1]);
        $err = (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($procs);

        if (trim($err) !== '') {
            return ['ok' => false, 'message' => trim($err)];
        }
        if (trim($out) === '' || (int)trim($out) <= 0) {
            return ['ok' => false, 'message' => 'The background job did not report a pid.'];
        }
        return ['ok' => true, 'message' => trim($out)];
    }

    /** Is a previously started job still running? */
    public static function jobRunning(string $pidFile): bool
    {
        if (!is_file($pidFile)) {
            return false;
        }
        $pid = (int)trim((string)@file_get_contents($pidFile));
        if ($pid <= 0) {
            return false;
        }
        return is_dir('/proc/' . $pid);
    }

    /**
     * Exit status recorded by the wrapper shell.
     * Returns null while the job is still running or if it never reported.
     */
    public static function jobStatus(string $statusFile): ?int
    {
        if (!is_file($statusFile)) {
            return null;
        }
        $raw = trim((string)@file_get_contents($statusFile));
        return preg_match('/^-?\d+$/', $raw) ? (int)$raw : null;
    }

    public function logTail(string $jobId, string $stage, int $lines = 60): string
    {
        $file = $this->workDir . '/' . $jobId . '.' . $stage . '.log';
        if (!is_file($file)) {
            return '';
        }
        $raw = @file($file, FILE_IGNORE_NEW_LINES) ?: [];
        return implode("\n", array_slice($raw, -$lines));
    }

    /**
     * Verify what actually landed on disk.
     * @return array{files:int,size_mb:float,has_public_html:bool,mail_mb:float}
     */
    public function measure(string $username): array
    {
        $dest = $this->homeDir($username);
        $files = 0;
        $bytes = 0;
        $mailBytes = 0;
        $hasPublic = is_dir($dest . '/public_html');

        if (is_dir($dest)) {
            $out = [];
            $code = 0;
            @exec(
                'du -sb ' . escapeshellarg($dest) . ' 2>/dev/null; find ' . escapeshellarg($dest)
                . ' -type f 2>/dev/null | wc -l',
                $out,
                $code
            );
            $du = $out[0] ?? '';
            if (preg_match('/^(\d+)/', $du, $m)) {
                $bytes = (int)$m[1];
            }
            $files = (int)trim($out[1] ?? '0');

            foreach ((array)($this->transferCfg['mail_dirs'] ?? []) as $dir) {
                $mailDir = $dest . '/' . trim((string)$dir, '/');
                if (!is_dir($mailDir)) {
                    continue;
                }
                $mout = [];
                $mcode = 0;
                @exec('du -sb ' . escapeshellarg($mailDir) . ' 2>/dev/null', $mout, $mcode);
                if (preg_match('/^(\d+)/', $mout[0] ?? '', $mm)) {
                    $mailBytes += (int)$mm[1];
                }
            }
        }

        return [
            'files' => $files,
            'size_mb' => round($bytes / 1048576, 2),
            'has_public_html' => $hasPublic,
            'mail_mb' => round($mailBytes / 1048576, 2),
        ];
    }
}