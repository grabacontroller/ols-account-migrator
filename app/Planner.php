<?php
/**
 * Planner - turns a source inventory into a reviewable, per-account plan.
 *
 * The planner is deliberately pure: it only reads state and returns a
 * description of what would happen. Nothing is created until the admin
 * approves the plan, which is what makes dry-run trustworthy.
 */

declare(strict_types=1);

class Planner
{
    private Config $config;
    private OlsApi $ols;
    private array $olsPackages;
    private array $sourcePackages;
    private string $serverIp;
    private ?float $freeDiskMb;

    public function __construct(Config $config, OlsApi $ols, array $sourcePackages)
    {
        $this->config = $config;
        $this->ols = $ols;
        $this->sourcePackages = $sourcePackages;
        $this->olsPackages = $ols->packages();
        $this->serverIp = (string)$config->get('server_ip', '');
        $this->freeDiskMb = $this->detectFreeDiskMb();
    }

    public function olsPackages(): array
    {
        return $this->olsPackages;
    }

    private function detectFreeDiskMb(): ?float
    {
        $homeRoot = (string)$this->config->get('transfer.home_root', '/home');
        $free = @disk_free_space($homeRoot);
        return ($free === false) ? null : round($free / 1048576, 1);
    }

    /**
     * Build the plan for one account.
     *
     * @return array{
     *   source_user:string, target_user:string, main_domain:string, email:string,
     *   package:array, steps:array, warnings:string[], blockers:string[],
     *   inventory:array, selected:bool
     * }
     */
    public function planAccount(array $inv, array $options): array
    {
        $sourceUser = (string)$inv['username'];
        $targetUser = (string)($options['target_user'] ?? '');
        $warnings = [];
        $blockers = [];
        $steps = [];

        // The browser sends these per account, but an API client (or an older
        // UI) may omit them. Fall back to the configured defaults so the plan
        // matches the ticked boxes the admin sees instead of silently skipping.
        $includeFiles = $this->optBool($options, 'include_files', false);
        $includeDatabases = $this->optBool($options, 'include_databases', (bool)$this->config->get('defaults.generate_databases', true));
        $importDbData = $this->optBool($options, 'import_database_data', (bool)$this->config->get('defaults.import_database_data', true));
        $includeEmail = $this->optBool($options, 'include_email', (bool)$this->config->get('defaults.create_email_accounts', true));
        $includeFtp = $this->optBool($options, 'include_ftp', false);
        $issueSsl = $this->optBool($options, 'issue_ssl', (bool)$this->config->get('defaults.issue_ssl', false));

        // ---------------------------------------------------------------- user
        if ($targetUser === '') {
            $targetUser = Util::validUsername($sourceUser) ? $sourceUser : 'user' . substr(bin2hex(random_bytes(3)), 0, 5);
        }
        if (!Util::validUsername($targetUser)) {
            $blockers[] = sprintf('"%s" is not a valid OLSpanel username (letters, digits, dot, dash, underscore).', $targetUser);
        }

        $exists = $this->ols->userExists($targetUser);
        if ($exists) {
            $steps[] = $this->step('account', 'Account', 'exists', 'The OLSpanel account already exists and will not be recreated.');
            $warnings[] = sprintf('Account "%s" already exists on OLSpanel - existing resources will be reused.', $targetUser);
        } else {
            $steps[] = $this->step('account', 'Create account', 'pending',
                sprintf('Create "%s" with domain %s.', $targetUser, $inv['domain']));
        }

        // ------------------------------------------------------------- package
        $packageChoice = $this->resolvePackage($inv, $options);
        if (!empty($packageChoice['blocker'])) {
            $blockers[] = $packageChoice['blocker'];
        }
        foreach ($packageChoice['warnings'] as $w) {
            $warnings[] = $w;
        }

        if ($packageChoice['action'] === 'create') {
            $steps[] = $this->step('package', 'Create package', 'pending',
                sprintf('Create package "%s" mirroring the source limits.', $packageChoice['name']));
        } elseif ($packageChoice['action'] === 'use') {
            $steps[] = $this->step('package', 'Package', 'ready',
                sprintf('Assign existing package "%s" (id %d).', $packageChoice['name'], $packageChoice['id']));
        }

        // ------------------------------------------------------------- domains
        $domains = [];
        foreach ($inv['domains'] as $d) {
            $domains[$d] = ['domain' => $d, 'primary' => ($d === $inv['domain'])];
        }
        $limitDomains = (int)($packageChoice['limits']['domains'] ?? 0);
        $toAdd = array_keys($domains);
        if (!$exists && $limitDomains > 0 && count($toAdd) > $limitDomains) {
            $warnings[] = sprintf(
                'Account has %d domains but package "%s" allows %d. Only the first %d will be created; add a bigger package first.',
                count($toAdd),
                $packageChoice['name'],
                $limitDomains,
                $limitDomains
            );
            $toAdd = array_slice($toAdd, 0, $limitDomains);
        }
        if (!$exists) {
            $steps[] = $this->step('domains', 'Add domains', 'pending',
                sprintf('Add %d domain(s) as virtual hosts.', count($toAdd)));
        }

        $domainPlans = [];
        foreach ($toAdd as $d) {
            $domainPlans[$d] = [
                'primary' => ($d === $inv['domain']),
                'dns_ok' => $this->domainPointsHere($d),
                'in_package_limit' => true,
            ];
            if (!$this->domainPointsHere($d)) {
                $warnings[] = sprintf('Domain %s does not resolve to %s yet. Update its A record before cutover.', $d, $this->serverIp ?: 'this server');
            }
        }

        // ------------------------------------------------------------ subdomains
        if ($inv['subdomains'] && !empty($options['include_subdomains'])) {
            $steps[] = $this->step('subdomains', 'Subdomains', 'skipped',
                sprintf('%d subdomain(s) found - they are not separate vhosts on OLSpanel.', count($inv['subdomains'])));
        }

        // ---------------------------------------------------------- databases
        $dbPlans = [];
        $wantDbs = $includeDatabases && $inv['databases'];
        if ($wantDbs) {
            $steps[] = $this->step('databases', 'Databases', 'pending',
                sprintf('Create %d database(s) and user(s).', count($inv['databases'])));
            $importData = $importDbData && $this->dbTransferReady($options);
            if (!$importData) {
                $warnings[] = 'Database contents are not imported: configure SSH access, or paste this account\'s '
                    . 'MySQL credentials, to copy the data. The schema will be created empty.';
            }
            foreach ($inv['databases'] as $db) {
                $dbPlans[$db] = [
                    'create' => true,
                    'import_data' => $importData,
                    'db_user' => $this->deriveDbUser($db, $options),
                ];
            }
        } elseif ($inv['databases']) {
            $steps[] = $this->step('databases', 'Databases', 'skipped',
                sprintf('%d database(s) found on the source but not selected.', count($inv['databases'])));
        }

        // --------------------------------------------------------------- email
        $emailPlans = [];
        if ($includeEmail) {
            if ($this->ols->hasCapability('email_add')) {
                $steps[] = $this->step('email', 'Email accounts', 'pending',
                    sprintf('Create %d mailbox(es).', count($inv['emails'])));
            } else {
                // Be explicit rather than silently dropping mail.
                $steps[] = $this->step('email', 'Email accounts', 'blocked',
                    'This OLSpanel build has no API for creating email accounts. Mail data will still be copied; create the mailboxes by hand afterwards.');
                $warnings[] = sprintf(
                    'OLSpanel exposes no email-account API, so %d mailbox(es) must be created manually. Their mail directories will still be transferred.',
                    count($inv['emails'])
                );
            }
            foreach ($inv['emails'] as $addr) {
                $emailPlans[$addr] = ['create' => true];
            }
        }

        // ----------------------------------------------------------------- ftp
        if ($includeFtp && (int)($inv['usage']['ftp'] ?? 0) > 0) {
            if ($this->ols->hasCapability('ftp_add')) {
                $steps[] = $this->step('ftp', 'FTP accounts', 'pending', 'Create FTP sub-accounts.');
            } else {
                $steps[] = $this->step('ftp', 'FTP accounts', 'blocked', 'No API for FTP accounts on this OLSpanel build.');
            }
        }

        // ---------------------------------------------------------------- cron
        $cronJobs = [];
        if (!empty($inv['cron_raw'])) {
            $parsed = Util::parseCrontab((array)$inv['cron_raw']);
            $cronJobs = $parsed['jobs'];
            if ($cronJobs) {
                $steps[] = $this->step('cron', 'Cron jobs', 'pending',
                    sprintf('Add %d cron job(s).', count($cronJobs)));
            }
            if ($parsed['unsupported']) {
                $warnings[] = sprintf(
                    '%d cron %s could not be translated and must be added by hand: %s',
                    count($parsed['unsupported']),
                    count($parsed['unsupported']) === 1 ? 'entry' : 'entries',
                    implode(' | ', array_slice($parsed['unsupported'], 0, 3))
                );
            }
        }

        // ----------------------------------------------------------------- SSL
        if ($issueSsl) {
            $steps[] = $this->step('ssl', 'SSL', 'pending',
                'Request certificates after DNS has been switched to this server.');
        }

        // ------------------------------------------------------------- suspend
        if (!empty($inv['suspended'])) {
            $steps[] = $this->step('suspend', 'Suspend', 'pending',
                'Source account is suspended - it will be suspended on OLSpanel too.');
        }

        // ---------------------------------------------------------- disk space
        $needMb = (float)($inv['usage']['disk_mb'] ?? 0);
        if ($needMb > 0 && $this->freeDiskMb !== null && $needMb > $this->freeDiskMb) {
            $warnings[] = sprintf(
                'This account needs about %s of disk but only %s is free under %s.',
                Util::humanMb((int)round($needMb)),
                Util::humanMb((int)round($this->freeDiskMb)),
                $this->config->get('transfer.home_root', '/home')
            );
        }

        // --------------------------------------------------------------- files
        if ($includeFiles) {
            if ($this->fileTransferReady($options)) {
                $steps[] = $this->step('files', 'Copy files', 'pending',
                    $this->sshEnabled($options)
                        ? 'rsync the home directory from the source server.'
                        : 'Mirror the home directory over FTP/SFTP with the account credentials.');
                $steps[] = $this->step('mail', 'Copy mail', 'pending',
                    $this->sshEnabled($options)
                        ? 'rsync the mail directories separately so mail arrives with the site.'
                        : 'Mirror the mail directories over FTP/SFTP.');
            } else {
                $steps[] = $this->step('files', 'Copy files', 'blocked',
                    'File transfer needs either SSH access or this account\'s FTP password.');
                $warnings[] = 'File transfer is skipped: no SSH and no FTP password for this account. The account will be created but empty.';
            }
        }

        return [
            'source_user' => $sourceUser,
            'target_user' => $targetUser,
            'main_domain' => $inv['domain'],
            'email' => $inv['email'],
            'suspended' => (bool)$inv['suspended'],
            'package' => $packageChoice,
            'domains' => $domainPlans,
            'databases' => $dbPlans,
            'emails' => $emailPlans,
            'cron' => $cronJobs,
            'steps' => $steps,
            'warnings' => $warnings,
            'blockers' => $blockers,
            'inventory' => [
                'limits' => $inv['limits'],
                'usage' => $inv['usage'],
                'domain_count' => count($inv['domains']),
                'subdomain_count' => count($inv['subdomains']),
                'email_count' => count($inv['emails']),
                'database_count' => count($inv['databases']),
                'notes' => $inv['notes'] ?? [],
                'package' => $inv['package'],
            ],
            'selected' => !empty($options['selected']),
        ];
    }

    private function step(string $id, string $title, string $status, string $detail): array
    {
        return ['id' => $id, 'title' => $title, 'status' => $status, 'detail' => $detail];
    }

    /**
     * An option's boolean value, or the supplied default when it is absent.
     * A key present but false must stay false, so array_key_exists is used
     * rather than a null-coalesce.
     */
    private function optBool(array $options, string $key, bool $default): bool
    {
        return array_key_exists($key, $options) ? !empty($options[$key]) : $default;
    }

    private function sshEnabled(array $options): bool
    {
        return !empty($options['ssh_enabled']);
    }

    /** Can files be copied for this account: SSH, or an FTP password? */
    private function fileTransferReady(array $options): bool
    {
        return $this->sshEnabled($options) || (string)($options['source_ftp_password'] ?? '') !== '';
    }

    /** Can database contents be copied: SSH, or the account's MySQL credentials? */
    private function dbTransferReady(array $options): bool
    {
        if ($this->sshEnabled($options)) {
            return true;
        }
        return trim((string)($options['source_db_user'] ?? '')) !== ''
            && (string)($options['source_db_password'] ?? '') !== '';
    }

    /**
     * Decide which OLSpanel package to use.
     *
     * Preference order: an explicit admin choice, then an exact name match,
     * then the cheapest package that still covers every source limit.
     */
    private function resolvePackage(array $inv, array $options): array
    {
        $warnings = [];
        $sourceLimits = $inv['limits'];

        // 1. Admin pinned a package id.
        $pinned = (int)($options['pkg_id'] ?? 0);
        if ($pinned > 0) {
            foreach ($this->olsPackages as $p) {
                if ((int)($p['id'] ?? 0) === $pinned) {
                    $short = $this->compareLimits($sourceLimits, $this->packageLimits($p));
                    foreach ($short as $s) {
                        $warnings[] = sprintf('Package "%s" is below the source limit for %s.', $p['name'], $s);
                    }
                    return [
                        'action' => 'use',
                        'id' => $pinned,
                        'name' => (string)$p['name'],
                        'limits' => $this->packageLimits($p),
                        'warnings' => $warnings,
                        'blocker' => '',
                    ];
                }
            }
            return [
                'action' => 'none',
                'id' => 0,
                'name' => '',
                'limits' => [],
                'warnings' => $warnings,
                'blocker' => 'The selected package id does not exist in OLSpanel.',
            ];
        }

        // 2. Exact name match.
        $sourceName = (string)$inv['package'];
        foreach ($this->olsPackages as $p) {
            if (strcasecmp((string)($p['name'] ?? ''), $sourceName) === 0) {
                return [
                    'action' => 'use',
                    'id' => (int)$p['id'],
                    'name' => (string)$p['name'],
                    'limits' => $this->packageLimits($p),
                    'warnings' => $warnings,
                    'blocker' => '',
                ];
            }
        }

        // 3. Package on the source whose limits we can mirror exactly.
        $sourcePkg = $this->sourcePackages[$sourceName] ?? null;
        $targetLimits = $sourcePkg['limits'] ?? $sourceLimits;

        // 4. Otherwise the smallest OLSpanel package that covers the source.
        $candidates = [];
        foreach ($this->olsPackages as $p) {
            $limits = $this->packageLimits($p);
            $short = $this->compareLimits($targetLimits, $limits);
            if ($short === []) {
                $candidates[] = [
                    'id' => (int)$p['id'],
                    'name' => (string)$p['name'],
                    'limits' => $limits,
                    'cost' => $this->packageCost($limits),
                ];
            }
        }
        if ($candidates) {
            usort($candidates, static function ($a, $b) {
                return $a['cost'] <=> $b['cost'];
            });
            $best = $candidates[0];
            $warnings[] = sprintf(
                'No package named "%s" on OLSpanel; using the smallest plan that covers the source limits: "%s".',
                $sourceName,
                $best['name']
            );
            return [
                'action' => 'use',
                'id' => $best['id'],
                'name' => $best['name'],
                'limits' => $best['limits'],
                'warnings' => $warnings,
                'blocker' => '',
            ];
        }

        // 5. Create a package mirroring the source.
        $tpl = (string)$this->config->get('defaults.new_package_naming', 'DA {source_package}');
        $name = str_replace(['{source_package}', '{username}'], [$sourceName !== '' ? $sourceName : 'custom', $inv['username']], $tpl);
        $name = trim(preg_replace('/[^A-Za-z0-9 ._-]/', '', $name) ?? 'Migrated');
        if ($name === '') {
            $name = 'Migrated ' . $inv['package'];
        }
        foreach ($this->olsPackages as $p) {
            if (strcasecmp((string)($p['name'] ?? ''), $name) === 0) {
                return [
                    'action' => 'use',
                    'id' => (int)$p['id'],
                    'name' => $name,
                    'limits' => $this->packageLimits($p),
                    'warnings' => $warnings,
                    'blocker' => '',
                ];
            }
        }

        return [
            'action' => 'create',
            'id' => 0,
            'name' => $name,
            'limits' => $targetLimits,
            'warnings' => $warnings,
            'blocker' => '',
        ];
    }

    /** Normalise an OLSpanel package record into the migrator's limit shape. */
    private function packageLimits(array $p): array
    {
        return [
            'disk_mb' => Util::toMb($p['disk_space'] ?? null),
            'bandwidth_mb' => Util::toMb($p['bandwidth'] ?? null),
            'domains' => Util::limitValue($p['allowed_domains'] ?? 0),
            'subdomains' => Util::limitValue($p['allowed_subdomains'] ?? 0),
            'emails' => Util::limitValue($p['email_accounts'] ?? 0),
            'databases' => Util::limitValue($p['databases'] ?? 0),
            'ftp' => Util::limitValue($p['ftp_accounts'] ?? 0),
        ];
    }

    /**
     * Which source limits exceed the destination limits?
     * A limit of 0 on the destination means unlimited, so it never "shorts".
     *
     * @return string[] human readable field names
     */
    private function compareLimits(array $source, array $dest): array
    {
        $labels = [
            'disk_mb' => 'disk space',
            'bandwidth_mb' => 'bandwidth',
            'domains' => 'domains',
            'subdomains' => 'subdomains',
            'emails' => 'email accounts',
            'databases' => 'databases',
            'ftp' => 'FTP accounts',
        ];
        $short = [];
        foreach ($labels as $field => $label) {
            $want = $source[$field] ?? null;
            $have = $dest[$field] ?? 0;
            if ($want === null || $want === '') {
                continue;   // source is unlimited; nothing to violate
            }
            if ((float)$have === 0.0) {
                continue;   // destination is unlimited
            }
            if ((float)$want > (float)$have) {
                $short[] = $label;
            }
        }
        return $short;
    }

    /**
     * Rough cost metric so "smallest sufficient plan" is well defined.
     *
     * OLSpanel uses 0 for "unlimited", which Util::toMb() normalises to null.
     * An unlimited dimension must make a package look *bigger*, not free -
     * otherwise the unlimited plan always wins and every account lands on it.
     */
    private function packageCost(array $limits): float
    {
        $unlimited = 1000000000.0; // any real limit is under a million
        $weight = [
            'disk_mb' => 1.0,
            'bandwidth_mb' => 0.1,
            'emails' => 10.0,
            'databases' => 25.0,
            'domains' => 15.0,
        ];

        $cost = 0.0;
        foreach ($weight as $field => $factor) {
            $value = $limits[$field] ?? null;
            $cost += $value === null ? $unlimited * $factor : (float)$value * $factor;
        }
        return $cost;
    }

    /** Does the domain already resolve to this server? */
    private function domainPointsHere(string $domain): bool
    {
        if ($this->serverIp === '') {
            return false;
        }
        $records = @dns_get_record($domain, DNS_A);
        if (!is_array($records)) {
            return false;
        }
        foreach ($records as $r) {
            if (isset($r['ip']) && $r['ip'] === $this->serverIp) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build a valid MySQL user name from a source database name.
     *
     * MySQL caps user names at 16 characters, so a naive truncation would map
     * two similarly-named schemas onto one user and quietly merge their
     * privileges. A short digest of the full name keeps them apart while
     * staying deterministic across re-runs.
     */
    private function deriveDbUser(string $db, array $options): string
    {
        $explicit = trim((string)($options['db_user_prefix'] ?? ''));
        $base = $explicit !== '' ? $explicit : $db;
        $clean = preg_replace('/[^A-Za-z0-9_]/', '_', $base) ?? 'dbuser';
        $clean = ltrim($clean, '0123456789');
        if ($clean === '' || $clean === false) {
            $clean = 'u' . substr(md5($db), 0, 6);
        }
        if (strlen($clean) > 16) {
            $clean = substr($clean, 0, 10) . '_' . substr(md5($db), 0, 5);
        }
        return $clean;
    }

    /** Server-wide summary used to show totals before running. */
    public function summary(array $plans): array
    {
        $totals = [
            'accounts' => 0,
            'domains' => 0,
            'databases' => 0,
            'emails' => 0,
            'disk_mb' => 0,
            'blocked' => 0,
            'warnings' => 0,
        ];
        foreach ($plans as $p) {
            if (empty($p['selected'])) {
                continue;
            }
            $totals['accounts']++;
            $totals['domains'] += count($p['domains']);
            $totals['databases'] += count($p['databases']);
            $totals['emails'] += count($p['emails']);
            $totals['disk_mb'] += (int)($p['inventory']['usage']['disk_mb'] ?? 0);
            $totals['warnings'] += count($p['warnings']);
            if ($p['blockers']) {
                $totals['blocked']++;
            }
        }
        return $totals;
    }
}