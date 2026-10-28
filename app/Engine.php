<?php
/**
 * Engine - executes a reviewed plan against OLSpanel.
 *
 * Design notes:
 *  - Each step is idempotent. Re-running the engine after a partial failure
 *    picks up where it stopped instead of duplicating resources.
 *  - Long operations (rsync, mysqldump) run as detached background jobs and
 *    are polled by the UI, so PHP's max_execution_time is never the bottleneck.
 *  - Nothing is deleted on the source. Migration is copy-only by design.
 */

declare(strict_types=1);

class Engine
{
    private Config $config;
    private OlsApi $ols;
    private ?SourcePanel $source;
    private Ssh $ssh;
    private Mysql $mysql;
    private FileMover $fileMover;
    private FtpMover $ftpMover;
    private DbMover $dbMover;
    private string $workDir;

    public function __construct(Config $config, OlsApi $ols, ?SourcePanel $source, string $workDir)
    {
        $this->config = $config;
        $this->ols = $ols;
        $this->source = $source;
        $this->workDir = rtrim($workDir, '/');

        $sshCfg = (array)$config->get('ssh', []);
        $this->ssh = new Ssh($sshCfg);
        $this->mysql = new Mysql((array)$config->get('mysql', []));
        $this->fileMover = new FileMover($this->ssh, (array)$config->get('transfer', []), $this->workDir);
        $this->ftpMover = new FtpMover($this->fileMover, (array)$config->get('source', []), (array)$config->get('transfer', []), $this->workDir);
        $this->dbMover = new DbMover($this->ssh, $this->mysql, (array)$config->get('transfer', []), $this->workDir);
    }

    public function fileMover(): FileMover { return $this->fileMover; }
    public function ssh(): Ssh { return $this->ssh; }
    public function dbMover(): DbMover { return $this->dbMover; }
    public function mysql(): Mysql { return $this->mysql; }
    public function source(): ?SourcePanel { return $this->source; }
    public function ols(): OlsApi { return $this->ols; }

    /**
     * Reject a plan that would put an unvalidated value into a command or an
     * API call.
     *
     * The plan is built by the planner, but the browser posts it back when a
     * step is run, so it is untrusted input at this point: target_user lands in
     * a shell path, and domain/schema/db-user names are sent to the panel and
     * to MySQL. Everything the steps dereference is checked here, once, rather
     * than being trusted per call site.
     *
     * @throws InvalidArgumentException
     */
    public static function validatePlan(array $plan): void
    {
        $user = (string)($plan['target_user'] ?? '');
        if (!Util::validUsername($user)) {
            throw new InvalidArgumentException('Invalid target user name in the plan: ' . ($plan['target_user'] ?? '(missing)'));
        }

        $domains = $plan['domains'] ?? [];
        if (!is_array($domains)) {
            throw new InvalidArgumentException('The plan\'s domain list is not a list.');
        }
        foreach (array_keys($domains) as $domain) {
            if (!Util::validDomain((string)$domain)) {
                throw new InvalidArgumentException('Invalid domain in the plan: ' . $domain);
            }
        }

        $main = (string)($plan['main_domain'] ?? '');
        if ($main !== '' && !Util::validDomain($main)) {
            throw new InvalidArgumentException('Invalid main domain in the plan: ' . $main);
        }

        foreach ((array)($plan['emails'] ?? []) as $address => $meta) {
            if (!is_string($address) || !Util::validEmail((string)$address)) {
                throw new InvalidArgumentException('Invalid email address in the plan: ' . $address);
            }
        }

        foreach ((array)($plan['databases'] ?? []) as $db => $meta) {
            // Source schemas travel into mysqldump arguments and into the OLSpanel
            // API, which prefixes them itself.
            if (!Util::validIdentifier((string)$db, true)) {
                throw new InvalidArgumentException('Invalid database name in the plan: ' . $db);
            }
            $dbUser = (string)(is_array($meta) ? ($meta['db_user'] ?? '') : '');
            if ($dbUser === '' || !Util::validIdentifier($dbUser, false)) {
                throw new InvalidArgumentException('Invalid database user in the plan: ' . $dbUser);
            }
        }

        foreach ((array)($plan['cron'] ?? []) as $job) {
            if (!is_array($job)) {
                throw new InvalidArgumentException('A cron entry in the plan is not an object.');
            }
            foreach (['minute', 'hour', 'day', 'month', 'weekday'] as $field) {
                $value = (string)($job[$field] ?? '');
                if ($value === '' || !preg_match('/^[\d*,\/-]+$/', $value)) {
                    throw new InvalidArgumentException('Invalid cron ' . $field . ' field: ' . $value);
                }
            }
            $command = (string)($job['command'] ?? '');
            if (trim($command) === '' || strpos($command, "\0") !== false) {
                throw new InvalidArgumentException('Invalid cron command in the plan.');
            }
        }

        $pkgName = (string)(is_array($plan['package'] ?? null) ? ($plan['package']['name'] ?? '') : '');
        if ($pkgName !== '' && (strlen($pkgName) > 64 || preg_match('/[\x00-\x1f]/', $pkgName))) {
            throw new InvalidArgumentException('Invalid package name in the plan: ' . $pkgName);
        }
    }

    /**
     * Execute one step of one account.
     *
     * @return array{status:string,message:string,extra:array}
     */
    public function runStep(array $plan, string $stepId, array $options): array
    {
        try {
            self::validatePlan($plan);
            return $this->dispatch($plan, $stepId, $options);
        } catch (Throwable $e) {
            // A step must always answer with a status so the runner can carry on
            // (or stop) rather than losing the whole batch to one exception.
            Log::error('step', 'Step "' . $stepId . '" for "'
                . (string)($plan['target_user'] ?? '?') . '" threw: ' . $e->getMessage());
            return ['status' => 'failed', 'message' => $e->getMessage(), 'extra' => []];
        }
    }

    private function dispatch(array $plan, string $stepId, array $options): array
    {
        switch ($stepId) {
            case 'package':
                return $this->stepPackage($plan);

            case 'account':
                return $this->stepAccount($plan, $options);

            case 'domains':
                return $this->stepDomains($plan, $options);

            case 'files':
                return $this->stepFiles($plan, 'files', $options);

            case 'mail':
                return $this->stepFiles($plan, 'mail', $options);

            case 'fixperms':
                return $this->stepFixPerms($plan);

            case 'databases':
                return $this->stepDatabases($plan, $options);

            case 'email':
                return $this->stepEmail($plan, $options);

            case 'ftp':
                return $this->stepFtp($plan, $options);

            case 'cron':
                return $this->stepCron($plan, $options);

            case 'suspend':
                return $this->stepSuspend($plan);

            case 'ssl':
                return $this->stepSsl($plan);

            case 'verify':
                return $this->stepVerify($plan);

            default:
                return ['status' => 'skipped', 'message' => 'Unknown step: ' . $stepId, 'extra' => []];
        }
    }

    // ------------------------------------------------------------------ steps

    private function stepPackage(array $plan): array
    {
        if ($plan['package']['action'] !== 'create') {
            return ['status' => 'skipped', 'message' => 'No package to create.', 'extra' => []];
        }
        $res = $this->ols->createPackage($plan['package']['name'], $plan['package']['limits']);
        if ($res['ok']) {
            return ['status' => 'done', 'message' => 'Package "' . $plan['package']['name'] . '" created.', 'extra' => []];
        }
        if (!empty($res['already_exists'])) {
            return ['status' => 'done', 'message' => 'Package already existed.', 'extra' => []];
        }
        return ['status' => 'failed', 'message' => 'Could not create package: ' . $res['message'], 'extra' => []];
    }

    private function stepAccount(array $plan, array $options): array
    {
        $targetUser = $plan['target_user'];

        if ($this->ols->userExists($targetUser)) {
            return ['status' => 'skipped', 'message' => 'Account already exists; reusing it.', 'extra' => ['existing' => true]];
        }

        $password = (string)($options['generated_password'] ?? '');
        if (strlen($password) < 8) {
            return ['status' => 'failed', 'message' => 'No usable password was generated for this account.', 'extra' => []];
        }

        [$first, $last] = $this->splitName($plan['email']);

        $res = $this->ols->addUser([
            'username' => $targetUser,
            'first_name' => $first,
            'last_name' => $last,
            'email' => $plan['email'],
            'password' => $password,
            'pkg_id' => (int)$plan['package']['id'],
            'domain' => $plan['main_domain'],
            'php_version' => (string)($options['php_version'] ?? '8.2'),
        ]);

        if ($res['ok'] || $res['already_exists']) {
            return [
                'status' => 'done',
                'message' => 'Account "' . $targetUser . '" created.',
                'extra' => ['user_id' => $res['user_id'], 'password' => $password],
            ];
        }

        // A missing package id is the most common failure; retry once by name.
        if (stripos($res['message'], 'package') !== false) {
            $this->stepPackage($plan);
            $packages = $this->ols->packages();
            foreach ($packages as $p) {
                if (strcasecmp((string)$p['name'], $plan['package']['name']) === 0) {
                    $plan['package']['id'] = (int)$p['id'];
                    $retry = $this->ols->addUser([
                        'username' => $targetUser,
                        'first_name' => $first,
                        'last_name' => $last,
                        'email' => $plan['email'],
                        'password' => $password,
                        'pkg_id' => (int)$p['id'],
                        'domain' => $plan['main_domain'],
                        'php_version' => (string)($options['php_version'] ?? '8.2'),
                    ]);
                    if ($retry['ok']) {
                        return ['status' => 'done', 'message' => 'Account created after resolving the package.', 'extra' => ['password' => $password]];
                    }
                }
            }
        }

        return ['status' => 'failed', 'message' => $res['message'], 'extra' => []];
    }

    private function stepDomains(array $plan, array $options): array
    {
        $targetUser = $plan['target_user'];
        $phpVersion = (string)($options['php_version'] ?? '8.2');
        $existing = array_change_key_case($this->ols->domainPaths($targetUser), CASE_LOWER);

        $added = [];
        $failed = [];

        foreach ($plan['domains'] as $domain => $meta) {
            if (isset($existing[strtolower($domain)])) {
                continue;
            }
            $res = $this->ols->addDomain($targetUser, $domain, $phpVersion);
            if ($res['ok'] || $res['already_exists']) {
                $added[] = $domain;
            } else {
                $failed[$domain] = $res['message'];
            }
        }

        $message = sprintf('%d domain(s) added.', count($added));
        if ($failed) {
            $detail = [];
            foreach ($failed as $d => $why) {
                $detail[] = $d . ': ' . $why;
            }
            return [
                'status' => count($added) > 0 ? 'partial' : 'failed',
                'message' => $message . ' Failed: ' . implode('; ', $detail),
                'extra' => ['added' => $added, 'failed' => $failed],
            ];
        }
        return ['status' => 'done', 'message' => $message, 'extra' => ['added' => $added]];
    }

    private function stepFiles(array $plan, string $stage, array $options): array
    {
        $useSsh = $this->sshAvailable();
        $ftpPassword = $this->ftpPassword($options);

        if ($useSsh) {
            if (!$this->fileMover->available()) {
                return ['status' => 'blocked', 'message' => 'rsync or SSH is unavailable.', 'extra' => []];
            }
        } else {
            if (!$this->ftpMover->available()) {
                return ['status' => 'blocked', 'message' => 'lftp is not installed on this server, so files cannot be copied over FTP.', 'extra' => []];
            }
            if ($ftpPassword === '') {
                return ['status' => 'blocked', 'message' => 'No SSH access and no FTP/SFTP password was supplied for this account.', 'extra' => []];
            }
        }

        $jobId = $this->jobId($plan, $stage);
        $current = $this->transferStatus($plan, $stage);

        if ($current['status'] === 'running') {
            return [
                'status' => 'running',
                'message' => ucfirst($stage) . ' transfer is already running.',
                'extra' => ['job' => $jobId . '.' . $stage],
            ];
        }

        // Skip a finished, successful job so re-runs stay cheap.
        if ($current['status'] === 'done') {
            return [
                'status' => 'done',
                'message' => ucfirst($stage) . ' transfer already completed.',
                'extra' => ['job' => $jobId . '.' . $stage],
            ];
        }

        if ($useSsh) {
            $res = $this->fileMover->startSync($plan['target_user'], $stage, $jobId);
        } else {
            $res = $this->ftpMover->startMirror($plan['target_user'], $stage, $jobId, $ftpPassword, $this->ftpLogin($plan, $options));
        }
        if (!$res['ok']) {
            return ['status' => 'failed', 'message' => $res['message'], 'extra' => []];
        }

        Log::info('transfer', 'Started the ' . $stage . ' ' . ($useSsh ? 'rsync' : 'FTP') . ' transfer for '
            . $plan['target_user'] . ' (job ' . $res['job'] . ')');

        return [
            'status' => 'running',
            'message' => ucfirst($stage) . ' transfer started in the background.',
            'extra' => ['job' => $res['job'], 'command' => $res['command'] ?? ''],
        ];
    }

    /** Is root SSH on the source configured and enabled? */
    private function sshAvailable(): bool
    {
        return !empty($this->config->get('ssh.enabled')) && $this->ssh->isConfigured();
    }

    private function ftpPassword(array $options): string
    {
        return (string)($options['source_ftp_password'] ?? '');
    }

    /**
     * The FTP/SFTP login for this account.
     *
     * FTP and SFTP logins are usually the account name, but a managed SFTP
     * account can use a different (even email-shaped) login. A per-account
     * value wins, then a configured template, then the source account name.
     */
    private function ftpLogin(array $plan, array $options): string
    {
        $explicit = trim((string)($options['source_ftp_user'] ?? ''));
        if ($explicit !== '') {
            return $explicit;
        }
        $tpl = trim((string)$this->config->get('source.ftp_login', ''));
        if ($tpl !== '') {
            return (string)str_replace(
                ['{user}', '{domain}'],
                [(string)($plan['source_user'] ?? $plan['target_user']), (string)($plan['main_domain'] ?? '')],
                $tpl
            );
        }
        return (string)($plan['source_user'] ?? $plan['target_user']);
    }

    /**
     * The account's own MySQL credentials, for a direct (no-SSH) dump.
     *
     * @return array{user:string,password:string}|null
     */
    private function dbCredential(array $options): ?array
    {
        $user = trim((string)($options['source_db_user'] ?? ''));
        $password = (string)($options['source_db_password'] ?? '');
        if ($user === '' || $password === '' || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', $user)) {
            return null;
        }
        return ['user' => $user, 'password' => $password];
    }

    /** Source MySQL host: a dedicated db_host, else the panel host. */
    private function sourceDbHost(): string
    {
        $host = trim((string)$this->config->get('source.db_host', ''));
        return $host !== '' ? $host : trim((string)$this->config->get('source.host', ''));
    }

    private function sourceDbPort(): int
    {
        return (int)$this->config->get('source.db_port', 3306) ?: 3306;
    }

    /**
     * Inspect a background rsync job.
     *
     * A vanished process proves nothing on its own, so the wrapper shell's
     * recorded exit status is what decides the outcome.
     *
     * @return array{status:string,message:string,extra:array}
     */
    public function pollTransfer(array $plan, string $stage): array
    {
        $jobId = $this->jobId($plan, $stage);
        $status = $this->transferStatus($plan, $stage);
        $status['extra']['job'] = $jobId . '.' . $stage;
        return $status;
    }

    /** @return array{status:string,message:string,extra:array} */
    private function transferStatus(array $plan, string $stage): array
    {
        $jobId = $this->jobId($plan, $stage);
        $logFile = $this->workDir . '/' . $jobId . '.' . $stage . '.log';
        $pidFile = $this->workDir . '/' . $jobId . '.' . $stage . '.pid';
        $doneFile = $logFile . '.done';

        $tail = $this->fileMover->logTail($jobId, $stage, 40);

        if (FileMover::jobRunning($pidFile)) {
            return [
                'status' => 'running',
                'message' => ucfirst($stage) . ' transfer in progress.',
                'extra' => ['log' => $tail],
            ];
        }

        if (!is_file($logFile)) {
            return [
                'status' => 'pending',
                'message' => ucfirst($stage) . ' transfer has not started.',
                'extra' => ['log' => ''],
            ];
        }

        $code = FileMover::jobStatus($doneFile);
        if ($code === null) {
            // Gone, and no status was recorded: killed, or the host rebooted
            // mid-transfer. That is not a success.
            return [
                'status' => 'failed',
                'message' => ucfirst($stage) . ' transfer stopped without reporting a result (killed, or the server restarted) - see the log.',
                'extra' => ['log' => $tail, 'exit_code' => null],
            ];
        }

        return [
            'status' => $code === 0 ? 'done' : 'failed',
            'message' => $code === 0
                ? ucfirst($stage) . ' transfer finished.'
                : ucfirst($stage) . ' transfer failed with exit status ' . $code . ' - see the log.',
            'extra' => ['log' => $tail, 'exit_code' => $code],
        ];
    }

    private function stepFixPerms(array $plan): array
    {
        $home = $this->fileMover->homeDir($plan['target_user']);
        if (!is_dir($home)) {
            return ['status' => 'failed', 'message' => 'Home directory ' . $home . ' is missing.', 'extra' => []];
        }
        // rsync -a preserves the source's ownership; hand everything to the
        // OLSpanel account user.
        $cmd = sprintf(
            'chown -R %s %s 2>/dev/null; chmod 0755 %s 2>/dev/null',
            escapeshellarg($plan['target_user'] . ':' . $plan['target_user']),
            escapeshellarg($home),
            escapeshellarg($home)
        );
        $out = [];
        $code = 0;
        exec($cmd . ' 2>&1', $out, $code);

        return [
            'status' => $code === 0 ? 'done' : 'partial',
            'message' => $code === 0 ? 'Ownership fixed.' : 'chown reported errors: ' . implode(' ', array_slice($out, 0, 3)),
            'extra' => [],
        ];
    }

    private function stepDatabases(array $plan, array $options): array
    {
        if (empty($plan['databases'])) {
            return ['status' => 'skipped', 'message' => 'No databases to create.', 'extra' => []];
        }

        $targetUser = $plan['target_user'];
        $created = [];
        $skipped = [];
        $failed = [];
        $results = [];

        $directCred = $this->dbCredential($options);
        $canImport = $this->sshAvailable()
            || ($directCred !== null && $this->dbMover->directAvailable() && $this->sourceDbHost() !== '');

        foreach ($plan['databases'] as $sourceDb => $meta) {
            $dbUser = (string)$meta['db_user'];

            // OLSpanel requires at least 8 characters, so never forward a
            // value the admin typed that the API would reject.
            $dbPass = (string)($options['db_password'] ?? '');
            if (strlen($dbPass) < 8) {
                $dbPass = Util::genPassword(14);
            }

            $res = $this->ols->addDatabase($targetUser, $sourceDb, $dbUser, $dbPass);
            if (!$res['ok']) {
                $failed[$sourceDb] = $res['message'];
                continue;
            }
            $created[] = $sourceDb;
            $results[$sourceDb] = ['db_user' => $dbUser, 'db_pass' => $dbPass];

            // Import the contents when SSH or direct DB credentials are available.
            if (!empty($meta['import_data']) && $canImport) {
                $import = $this->importDatabase($plan, $sourceDb, $dbUser, $results[$sourceDb], $options);
                $results[$sourceDb]['import'] = $import;
                if (empty($import['ok'])) {
                    $failed[$sourceDb . ' (data)'] = $import['message'];
                }
            }
        }

        $message = sprintf('%d database(s) created.', count($created));
        if ($failed) {
            $parts = [];
            foreach ($failed as $db => $why) {
                $parts[] = $db . ': ' . $why;
            }
            return [
                'status' => count($created) > 0 ? 'partial' : 'failed',
                'message' => $message . ' Problems: ' . implode('; ', $parts),
                'extra' => ['created' => $created, 'failed' => $failed, 'credentials' => $results],
            ];
        }

        return [
            'status' => 'done',
            'message' => $message,
            'extra' => ['created' => $created, 'credentials' => $results],
        ];
    }

    /** Dump on the source (over SSH or a direct MySQL connection), then load it into OLSpanel's MySQL. */
    private function importDatabase(array $plan, string $sourceDb, string $dbUser, array &$slot, array $options): array
    {
        $jobId = $this->jobId($plan, 'db.' . $sourceDb);
        $directCred = $this->dbCredential($options);
        $useSsh = $this->sshAvailable();
        $useDirect = !$useSsh && $directCred !== null
            && $this->dbMover->directAvailable() && $this->sourceDbHost() !== '';

        // 1. Dump the schema (detached, either remote over SSH or locally
        //    against the source MySQL).
        if ($useSsh) {
            $dump = $this->dbMover->startDump($plan['target_user'], $sourceDb, $jobId);
        } elseif ($useDirect) {
            $dump = $this->dbMover->startDirectDump($directCred, $this->sourceDbHost(), $this->sourceDbPort(), $sourceDb, $jobId);
        } else {
            return ['ok' => false, 'message' => 'No SSH access and no working database credentials for this account.'];
        }
        if (!$dump['ok']) {
            return ['ok' => false, 'message' => $dump['message']];
        }

        // 2. Wait for it. A large schema legitimately takes minutes; the
        // status file is the only trustworthy "finished" signal.
        $wait = $this->dbMover->waitForDump($dump['remote_dump']);
        if (!$wait['ok']) {
            if ($useSsh) {
                $this->dbMover->cleanupRemote($dump['remote_dump']);
            }
            return ['ok' => false, 'message' => $wait['message']];
        }

        // 3. Over SSH the dump must be pulled down and verified; a direct dump
        //    is already a local file.
        if ($useSsh) {
            $fetched = $this->dbMover->fetchDump($dump['remote_dump'], $dump['dump']);
            if (!$fetched['ok']) {
                $this->dbMover->cleanupRemote($dump['remote_dump']);
                return ['ok' => false, 'message' => $fetched['message']];
            }
            $this->dbMover->cleanupRemote($dump['remote_dump']);
        }

        // 4. Resolve the schema name OLSpanel actually assigned.
        $schema = $this->mysql->resolveSchema($sourceDb);
        if ($schema === null) {
            $this->dbMover->cleanupDump($dump['dump']);
            return [
                'ok' => false,
                'message' => 'Created the database but could not find its schema on this server; the data was not loaded.',
            ];
        }
        $slot['schema'] = $schema;

        // 5. Load it.
        $imported = $this->dbMover->importDump($dump['dump'], $sourceDb, $schema);
        $this->dbMover->cleanupDump($dump['dump']);

        if (!$imported['ok']) {
            return ['ok' => false, 'message' => $imported['message']];
        }

        // 6. Make sure the OLSpanel database user can actually use the schema.
        try {
            $this->mysql->grant($schema, $dbUser);
        } catch (Throwable $e) {
            return [
                'ok' => false,
                'message' => 'Data imported to ' . $schema . ' but granting privileges failed: ' . $e->getMessage(),
            ];
        }

        return ['ok' => true, 'message' => 'Data imported into ' . $schema . '.'];
    }

    private function stepEmail(array $plan, array $options): array
    {
        if (empty($plan['emails'])) {
            return ['status' => 'skipped', 'message' => 'No email accounts to create.', 'extra' => []];
        }
        if (!$this->ols->hasCapability('email_add')) {
            return [
                'status' => 'blocked',
                'message' => 'OLSpanel has no email-account API on this build. Create these mailboxes by hand: ' . implode(', ', array_keys($plan['emails'])),
                'extra' => ['manual' => array_keys($plan['emails'])],
            ];
        }

        $password = (string)($options['generated_password'] ?? Util::genPassword(14));
        $made = [];
        $failed = [];

        foreach ($plan['emails'] as $address => $meta) {
            $res = $this->ols->createEmailAccount($plan['target_user'], (string)$address, $password);
            if ($res['ok']) {
                $made[] = $address;
            } else {
                $failed[$address] = $res['message'];
            }
        }

        if ($failed) {
            $parts = [];
            foreach ($failed as $a => $why) {
                $parts[] = $a . ': ' . $why;
            }
            return [
                'status' => count($made) > 0 ? 'partial' : 'failed',
                'message' => count($made) . ' mailbox(es) created. Failed: ' . implode('; ', $parts),
                'extra' => ['created' => $made, 'password' => $password],
            ];
        }
        return ['status' => 'done', 'message' => count($made) . ' mailbox(es) created.', 'extra' => ['created' => $made, 'password' => $password]];
    }

    private function stepFtp(array $plan, array $options): array
    {
        if (!$this->ols->hasCapability('ftp_add')) {
            return [
                'status' => 'blocked',
                'message' => 'OLSpanel has no FTP-account API on this build. Create FTP sub-accounts by hand.',
                'extra' => [],
            ];
        }
        $password = (string)($options['generated_password'] ?? Util::genPassword(14));
        $res = $this->ols->createFtpAccount(
            $plan['target_user'],
            $plan['target_user'],
            $password,
            $plan['main_domain']
        );
        return [
            'status' => $res['ok'] ? 'done' : ($res['skipped'] ? 'blocked' : 'failed'),
            'message' => $res['message'],
            'extra' => ['password' => $password],
        ];
    }

    /**
     * Re-create cron jobs through the documented api/cronjob_add/ endpoint.
     *
     * That endpoint authenticates as the account, so it needs the password the
     * account step just set.
     */
    private function stepCron(array $plan, array $options): array
    {
        $jobs = (array)($plan['cron'] ?? []);
        if (!$jobs) {
            return ['status' => 'skipped', 'message' => 'No cron jobs to add.', 'extra' => []];
        }

        $password = (string)($options['generated_password'] ?? '');
        if ($password === '') {
            return [
                'status' => 'blocked',
                'message' => 'The cron API authenticates as the account, so the new account password is required. Re-run the account step first.',
                'extra' => [],
            ];
        }

        $added = [];
        $failed = [];
        foreach ($jobs as $job) {
            $res = $this->ols->createCron($plan['target_user'], $password, $job);
            if ($res['ok']) {
                $added[] = $job['command'] ?? '';
            } else {
                $failed[] = ($job['command'] ?? '?') . ': ' . $res['message'];
            }
        }

        if ($failed) {
            return [
                'status' => count($added) > 0 ? 'partial' : 'failed',
                'message' => sprintf('%d cron job(s) added. Failed: %s', count($added), implode('; ', array_slice($failed, 0, 5))),
                'extra' => ['added' => $added, 'failed' => $failed],
            ];
        }
        return ['status' => 'done', 'message' => count($added) . ' cron job(s) added.', 'extra' => ['added' => $added]];
    }

    private function stepSuspend(array $plan): array
    {
        if (empty($plan['suspended'])) {
            return ['status' => 'skipped', 'message' => 'Source account is active; leaving the new account active.', 'extra' => []];
        }
        $res = $this->ols->state($plan['target_user'], 'SUSPEND');
        return [
            'status' => $res['ok'] ? 'done' : 'failed',
            'message' => $res['ok'] ? 'Account suspended to match the source.' : $res['message'],
            'extra' => [],
        ];
    }

    private function stepSsl(array $plan): array
    {
        $results = [];
        $failed = [];
        foreach (array_keys($plan['domains']) as $domain) {
            $res = $this->ols->issueSsl($domain);
            if ($res['ok']) {
                $results[] = $domain;
            } else {
                $failed[$domain] = $res['message'];
            }
        }
        if ($failed) {
            $parts = [];
            foreach ($failed as $d => $why) {
                $parts[] = $d . ': ' . $why;
            }
            return [
                'status' => 'partial',
                'message' => count($results) . ' certificate(s) issued. Failed: ' . implode('; ', $parts),
                'extra' => ['issued' => $results],
            ];
        }
        return ['status' => 'done', 'message' => count($results) . ' certificate(s) issued.', 'extra' => ['issued' => $results]];
    }

    private function stepVerify(array $plan): array
    {
        $info = $this->ols->accountInfo($plan['target_user']);
        $measure = $this->fileMover->measure($plan['target_user']);

        $findings = [];
        if (empty($info)) {
            $findings[] = 'The account was not found in OLSpanel after the run.';
        } else {
            $findings[] = 'Package: ' . ($info['package_name'] ?? '?')
                . ' (' . ($info['disk_limit'] ?? '?') . ' limit, ' . ($info['disk_used'] ?? '?') . ' used)';
            $findings[] = sprintf(
                'Domains: %s / %s, Email: %s / %s, Databases: %s / %s',
                $info['domain_used'] ?? '?', $info['domain_limit'] ?? '?',
                $info['email_used'] ?? '?', $info['email_limit'] ?? '?',
                $info['db_used'] ?? '?', $info['db_limit'] ?? '?'
            );
        }
        $findings[] = sprintf('Files on disk: %d file(s), %s, public_html %s', $measure['files'], Util::humanMb((int)round($measure['size_mb'])), $measure['has_public_html'] ? 'present' : 'MISSING');
        if ($measure['mail_mb'] > 0) {
            $findings[] = 'Mail data: ' . Util::humanMb((int)round($measure['mail_mb']));
        }

        $ok = !empty($info) && $measure['has_public_html'];

        return [
            'status' => $ok ? 'done' : 'partial',
            'message' => $ok ? 'Verified.' : 'Verification found issues - review below.',
            'extra' => ['findings' => $findings, 'measure' => $measure, 'info' => $info],
        ];
    }

    // ---------------------------------------------------------------- helpers

    private function jobId(array $plan, string $stage): string
    {
        $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $plan['target_user'] . '-' . $stage);
        return (string)$safe;
    }

    /** Derive a display name from the account email. */
    private function splitName(string $email): array
    {
        $local = strstr($email, '@', true);
        if ($local === false || $local === '') {
            return ['', ''];
        }
        $local = preg_replace('/[._-]+/', ' ', $local) ?? $local;
        $parts = preg_split('/\s+/', trim($local)) ?: [];
        $first = $parts[0] ?? '';
        $last = count($parts) > 1 ? end($parts) : '';
        return [ucfirst($first), ucfirst($last)];
    }

    /**
     * Human readable cutover checklist for one account.
     */
    public function checklist(array $plan): array
    {
        $items = [];
        foreach (array_keys($plan['domains']) as $domain) {
            $items[] = 'Point the A record for ' . $domain . ' to ' . ($this->config->get('server_ip') ?: 'the OLSpanel server IP');
        }
        if (empty($plan['emails'])) {
            // nothing to say
        }
        $items[] = 'Test each site and mailbox on the new server';
        $items[] = 'Update any application config files that hardcode the old server IP or paths (/home/USER/...)';
        if (!empty($plan['inventory']['notes'])) {
            $items[] = 'Review source notes: ' . implode('; ', $plan['inventory']['notes']);
        }
        return $items;
    }

    /** Verify the destination prerequisites. */
    public function preflight(): array
    {
        $checks = [];

        $tools = Ssh::localTools();
        $missing = [];
        foreach (['rsync', 'ssh'] as $bin) {
            if (empty($tools[$bin])) {
                $missing[] = $bin;
            }
        }
        $checks[] = [
            'name' => 'Local tools (rsync, ssh)',
            'ok' => $missing === [],
            'detail' => $missing === [] ? 'Present.' : 'Missing: ' . implode(', ', $missing),
        ];

        $sshCfg = (array)$this->config->get('ssh', []);
        if (empty($sshCfg['enabled'])) {
            $checks[] = [
                'name' => 'Source SSH access',
                'ok' => false,
                'detail' => 'Disabled. Accounts will be created but files, mail and database contents will not be transferred.',
            ];
        } else {
            $res = $this->ssh->test();
            $checks[] = [
                'name' => 'Source SSH access',
                'ok' => !empty($res['ok']),
                'detail' => (string)($res['message'] ?? 'Failed'),
            ];
            if (!empty($res['ok']) && empty($res['root'])) {
                $checks[] = [
                    'name' => 'SSH privileges',
                    'ok' => false,
                    'detail' => 'Connected as a non-root user. You need root on the source server for database dumps and cPanel metadata.',
                ];
            }
        }

        // Source SSH password auth needs sshpass.
        if (!empty($sshCfg['enabled']) && ($sshCfg['auth'] ?? '') === 'password' && empty($tools['sshpass'])) {
            $checks[] = [
                'name' => 'sshpass',
                'ok' => false,
                'detail' => 'Password-based SSH was selected but sshpass is not installed. Use key authentication instead.',
            ];
        }

        // OLSpanel API.
        $packages = $this->ols->packages();
        $checks[] = [
            'name' => 'OLSpanel API',
            'ok' => $packages !== [],
            'detail' => $packages === []
                ? 'No packages returned. Check the admin credentials or whether at least one hosting package exists.'
                : count($packages) . ' package(s) available.',
        ];

        // Optional capabilities, reported honestly.
        foreach (['email_add', 'ftp_add'] as $cap) {
            $available = $this->ols->hasCapability($cap);
            $checks[] = [
                'name' => 'OLSpanel ' . ucfirst(str_replace('_add', '', $cap)) . ' API',
                'ok' => $available,
                'detail' => $available
                    ? 'Available - these resources will be created automatically.'
                    : 'Not exposed by this OLSpanel build; those resources need manual creation.',
                'severity' => 'info',
            ];
        }

        // Cron jobs go through a documented endpoint, so this is a statement
        // rather than a probe.
        $checks[] = [
            'name' => 'OLSpanel Cron API',
            'ok' => true,
            'detail' => 'api/cronjob_add/ is part of the published user API. Cron jobs are replayed as the new account.',
            'severity' => 'info',
        ];

        // Reseller Manager support: lets a migrated reseller be recreated and
        // its customers attached, rather than arriving as plain accounts.
        $resellerManager = $this->ols->resellerManagerAvailable();
        $checks[] = [
            'name' => 'Reseller Manager plugin',
            'ok' => $resellerManager,
            'detail' => $resellerManager
                ? 'Installed - a migrated reseller can be recreated and its customers attached under it.'
                : 'Not installed. Reseller accounts are migrated as ordinary accounts.',
            'severity' => 'info',
        ];

        // Local MySQL.
        $origin = $this->mysql->origin();
        $checks[] = [
            'name' => 'Local MySQL access',
            'ok' => $origin !== 'none',
            'detail' => $origin === 'none'
                ? 'No working MySQL credentials found. Set them in Settings to import database contents.'
                : 'Connected via ' . $origin . '.',
        ];

        // Home directory layout.
        $homeRoot = (string)$this->config->get('transfer.home_root', '/home');
        $checks[] = [
            'name' => 'Home directory',
            'ok' => is_dir($homeRoot),
            'detail' => is_dir($homeRoot)
                ? $homeRoot . ' exists, ' . Util::humanMb((int)round(@disk_free_space($homeRoot) / 1048576)) . ' free.'
                : $homeRoot . ' does not exist; adjust the path in Settings.',
        ];

        // The migrator must run as root to chown files and use MySQL root.
        $checks[] = [
            'name' => 'Process privileges',
            'ok' => function_exists('posix_geteuid') ? posix_geteuid() === 0 : null,
            'detail' => function_exists('posix_geteuid') && posix_geteuid() !== 0
                ? 'Not running as root. File ownership fixes and database imports will fail.'
                : 'Running with the privileges needed for transfers.',
        ];

        return $checks;
    }
}