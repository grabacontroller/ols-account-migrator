<?php
/**
 * CpanelFiles - reads cPanel's on-disk account metadata over SSH.
 *
 * WHM's API deliberately exposes no server-wide listing of mailboxes, aliases
 * or cron jobs, but cPanel keeps that information in plain files under
 * /var/cpanel. Reading them directly is the only reliable way to enumerate a
 * whole server's mailboxes, and it needs no per-account API token.
 */

declare(strict_types=1);

class CpanelFiles
{
    private Ssh $ssh;

    public function __construct(Ssh $ssh)
    {
        $this->ssh = $ssh;
    }

    public function available(): bool
    {
        return $this->ssh->isConfigured();
    }

    /** Detect whether the SSH host actually runs cPanel. */
    public function looksLikeCpanel(): bool
    {
        $res = $this->ssh->run('test -d /var/cpanel && echo yes || echo no', 20);
        return strpos($res['out'], 'yes') !== false;
    }

    /**
     * Full inventory from the filesystem.
     *
     * @return array{domains:string[],subdomains:string[],emails:string[],aliases:string[],cron:string[],ok:bool,note:string}
     */
    public function inventory(string $username): array
    {
        $result = [
            'domains' => [],
            'subdomains' => [],
            'emails' => [],
            'aliases' => [],
            'cron' => [],
            'ok' => false,
            'note' => '',
        ];

        if (!preg_match('/^[A-Za-z0-9._-]+$/', $username)) {
            $result['note'] = 'Unsafe account name.';
            return $result;
        }

        // --- domains: the account's own domain file -------------------
        $domainFile = '/var/cpanel/accounts/' . $username;
        $res = $this->ssh->run(
            'test -f ' . escapeshellarg($domainFile) . ' && cat ' . escapeshellarg($domainFile) . ' || true',
            30
        );
        if (trim($res['out']) === '') {
            $result['note'] = 'No /var/cpanel/accounts/' . $username . ' on the source host.';
            return $result;
        }

        // The file is KEY=VALUE per line, so parse it directly rather than
        // letting parse_str mangle keys that contain dots.
        $pairs = [];
        foreach (explode("\n", $res['out']) as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '=') === false) {
                continue;
            }
            [$k, $v] = explode('=', $line, 2);
            $pairs[strtolower(trim($k))] = trim($v);
        }

        $main = strtolower($pairs['domain'] ?? '');
        if ($main !== '' && Util::validDomain($main)) {
            $result['domains'][] = $main;
        }

        // cPanel's authoritative list of additional domains for the account
        // lives in <user>.aliases, one per line. Entries that sit under the
        // main domain are subdomains: OLSpanel serves those from a folder
        // inside public_html, so they must not become separate vhosts.
        $aliasDomains = $this->ssh->run(
            'cat ' . escapeshellarg('/var/cpanel/accounts/' . $username . '.aliases') . ' 2>/dev/null',
            30
        );
        foreach (preg_split('/[\s,]+/', (string)$aliasDomains['out']) as $candidate) {
            $d = strtolower(trim($candidate));
            if ($d === '' || !Util::validDomain($d)) {
                continue;
            }
            if ($main !== '' && (substr($d, -(strlen($main) + 1)) === '.' . $main)) {
                $result['subdomains'][] = $d;
            } else {
                $result['domains'][] = $d;
            }
        }

        // Fall back to whatever the account file itself declares.
        foreach (['addons', 'subdomains'] as $field) {
            $value = $pairs[$field] ?? '';
            if ($value === '') {
                continue;
            }
            foreach (preg_split('/[\s,]+/', $value) as $d) {
                $d = strtolower(trim($d));
                if ($d === '' || !Util::validDomain($d)) {
                    continue;
                }
                if ($field === 'subdomains') {
                    $result['subdomains'][] = $d;
                } else {
                    $result['domains'][] = $d;
                }
            }
        }
        $result['domains'] = array_values(array_unique($result['domains']));
        $result['subdomains'] = array_values(array_unique($result['subdomains']));

        // --- mailboxes: one <domain>.pop per hosted domain -------------
        $popList = $this->ssh->run(
            'ls -1 /var/cpanel/userdomains/' . escapeshellarg($username) . '/*.pop 2>/dev/null',
            30
        );
        foreach (array_filter(array_map('trim', explode("\n", $popList['out']))) as $file) {
            $domain = basename($file, '.pop');
            if (!Util::validDomain($domain)) {
                continue;
            }
            $in = $this->ssh->run('cat ' . escapeshellarg($file) . ' 2>/dev/null', 30);
            foreach (explode("\n", $in['out']) as $line) {
                $line = trim($line);
                if ($line === '' || strpos($line, ':') === false) {
                    continue;
                }
                $local = strtolower(trim(explode(':', $line)[0]));
                if ($local !== '' && preg_match('/^[a-z0-9._%+\'-]+$/', $local)) {
                    $result['emails'][] = $local . '@' . $domain;
                }
            }
        }
        $result['emails'] = array_values(array_unique($result['emails']));

        // --- aliases / forwarders --------------------------------------
        $aliasList = $this->ssh->run(
            'ls -1 /var/cpanel/userdomains/' . escapeshellarg($username) . '/*.aliases 2>/dev/null',
            30
        );
        foreach (array_filter(array_map('trim', explode("\n", $aliasList['out']))) as $file) {
            $domain = basename($file, '.aliases');
            if (!Util::validDomain($domain)) {
                continue;
            }
            $in = $this->ssh->run('cat ' . escapeshellarg($file) . ' 2>/dev/null', 30);
            foreach (explode("\n", $in['out']) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#' || strpos($line, ':') === false) {
                    continue;
                }
                [$source, $target] = explode(':', $line, 2);
                $source = strtolower(trim($source));
                $target = trim($target);
                if ($source !== '' && strpos($source, '@') !== false && $target !== '') {
                    $result['aliases'][] = $source . ' -> ' . $target;
                }
            }
        }
        $result['aliases'] = array_values(array_unique($result['aliases']));

        // --- cron jobs --------------------------------------------------
        $cron = $this->ssh->run('cat ' . escapeshellarg('/var/spool/cron/' . $username) . ' 2>/dev/null', 30);
        foreach (explode("\n", $cron['out']) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $result['cron'][] = $line;
        }

        $result['ok'] = true;
        return $result;
    }

    /**
     * Merge filesystem findings into an adapter inventory, without ever
     * discarding data the API already found.
     *
     * Keys are initialised so callers can rely on them even when the SSH read
     * failed or returned nothing.
     */
    public static function merge(array $account, array $inventory): array
    {
        $account['cron_raw'] = $account['cron_raw'] ?? [];
        $account['aliases_raw'] = $account['aliases_raw'] ?? [];
        $account['notes'] = $account['notes'] ?? [];

        if (!$inventory['ok']) {
            if ($inventory['note'] !== '') {
                $account['notes'][] = $inventory['note'];
            }
            return $account;
        }

        $account['domains'] = array_values(array_unique(array_merge($account['domains'] ?? [], $inventory['domains'])));
        $account['subdomains'] = array_values(array_unique(array_merge($account['subdomains'] ?? [], $inventory['subdomains'])));
        $account['emails'] = array_values(array_unique(array_merge($account['emails'] ?? [], $inventory['emails'])));
        $account['cron_raw'] = $inventory['cron'];
        $account['aliases_raw'] = $inventory['aliases'];

        if ($inventory['emails'] !== []) {
            $account['usage']['emails'] = max($account['usage']['emails'], count($inventory['emails']));
        }
        $account['usage']['domains'] = max($account['usage']['domains'], count($inventory['domains']));

        if ($inventory['note'] !== '') {
            $account['notes'][] = $inventory['note'];
        }
        return $account;
    }
}