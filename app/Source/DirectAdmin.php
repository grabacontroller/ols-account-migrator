<?php
/**
 * DirectAdmin - source adapter.
 *
 * Talks the legacy CMD_API over HTTPS on port 2222 with HTTP basic auth.
 *
 * Only a few of the commands we need accept a "user=" argument at admin level;
 * for everything else we use DirectAdmin's documented impersonation syntax
 * ("admin|username" as the basic-auth user) so the command runs in the target
 * account's own context. That is what makes domain, mailbox and database
 * listings possible.
 */

declare(strict_types=1);

class DirectAdmin extends SourcePanel
{
    private function authUser(): string
    {
        return (string)($this->cfg['username'] ?? 'admin');
    }

    /**
     * Issue one DirectAdmin API call.
     *
     * $asUser runs the command inside that account's context using DirectAdmin's
     * impersonation syntax ("admin|username").
     */
    private function call(string $command, array $params = [], ?string $asUser = null): array
    {
        $user = $this->authUser();
        if ($asUser !== null && $asUser !== '') {
            $user .= '|' . $asUser;
        }

        $http = new Http(
            $this->base(),
            [],
            !empty($this->cfg['verify_tls']),
            90,
            [$user, (string)($this->cfg['password'] ?? '')]
        );

        $params['json'] = 'yes';
        $res = $http->request($command, 'GET', $params);

        if ($res['error'] !== '') {
            return ['status' => 0, 'body' => '', 'error' => $res['error'], 'data' => null, 'ok' => false, 'auth_failed' => false];
        }

        $body = $res['body'];
        $data = $this->decode($body);
        $authFailed = stripos($body, 'unauthorized') !== false
            || (is_array($data) && isset($data['error']) && (string)$data['error'] === '1' && !isset($data['text']));

        return [
            'status' => $res['status'],
            'body' => $body,
            'error' => '',
            'data' => $data,
            'ok' => $res['status'] >= 200 && $res['status'] < 400 && !$authFailed,
            'auth_failed' => $authFailed,
        ];
    }

    /** Tolerantly decode the several shapes DirectAdmin returns. */
    private function decode(string $body)
    {
        $body = trim($body);
        if ($body === '') {
            return null;
        }
        $json = json_decode($body, true);
        if (is_array($json)) {
            return $json;
        }
        // Legacy url-encoded payloads.
        $out = [];
        parse_str($body, $out);
        return $out ?: ['text' => $body];
    }

    public function label(): string
    {
        return 'DirectAdmin';
    }

    public function capabilities(): array
    {
        return [
            'limits' => 'Full',
            'usage' => 'Full',
            'domains' => 'Full (via account impersonation)',
            'mailboxes' => 'Full (via account impersonation)',
            'databases' => 'Best effort via API, authoritative over SSH',
            'subdomains' => 'Full (via account impersonation)',
            'resellers' => 'Full - list resellers and migrate every account they own',
            'cron' => 'Not migrated',
        ];
    }

    public function test(): array
    {
        $res = $this->call('CMD_API_SHOW_ALL_USERS');
        if (!$res['ok']) {
            // Older builds may not expose SHOW_ALL_USERS to this account; fall back.
            $res2 = $this->call('CMD_API_ADMIN_STATS');
            if ($res2['ok']) {
                return ['ok' => true, 'message' => 'Connected to DirectAdmin at ' . $this->cfg['host'] . ':' . $this->cfg['port'] . '.'];
            }
            $msg = trim((string)($res['error'] ?: $res['body']));
            if ($res['auth_failed']) {
                $msg = 'Authentication rejected - check the DirectAdmin admin username, password and that port 2222 is reachable.';
            }
            return ['ok' => false, 'message' => $msg !== '' ? $msg : 'Could not reach the DirectAdmin API.'];
        }

        $count = is_array($res['data']) ? count($res['data']) : 0;
        return [
            'ok' => true,
            'message' => sprintf(
                'Connected to DirectAdmin at %s:%s as %s. %d account(s) visible.',
                $this->cfg['host'],
                $this->cfg['port'] ?? 2222,
                $this->authUser(),
                $count
            ),
            'accounts' => $count,
        ];
    }

    public function listResellers(): array
    {
        $res = $this->call('CMD_API_SHOW_RESELLERS');
        return self::extractNames($res['data']);
    }

    public function listAccounts(string $reseller = ''): array
    {
        $reseller = trim($reseller);
        if ($reseller === '') {
            $reseller = trim((string)($this->cfg['reseller'] ?? ''));
        }

        // A reseller's own users are listed by CMD_API_SHOW_USERS with
        // reseller=X; SHOW_ALL_USERS returns every user the admin can see.
        if ($reseller !== '') {
            $res = $this->call('CMD_API_SHOW_USERS', ['reseller' => $reseller]);
            return self::extractNames($res['data']);
        }

        $res = $this->call('CMD_API_SHOW_ALL_USERS');
        $names = self::extractNames($res['data']);
        if (!$names && $res['ok']) {
            $res2 = $this->call('CMD_API_SHOW_USERS');
            $names = self::extractNames($res2['data']);
        }
        return $names;
    }

    /**
     * Pull usernames out of the several shapes a DirectAdmin list command
     * returns: a bare list of names, {"list":[...]}, or a list of records with
     * a "username" key. Kept static and side-effect free so it is unit-testable.
     */
    public static function extractNames($data): array
    {
        if (!is_array($data)) {
            return [];
        }
        // Legacy commands answer list[]=... and json=yes nests it under "list".
        if (isset($data['list']) && is_array($data['list'])) {
            $data = $data['list'];
        }

        $names = [];
        foreach ($data as $entry) {
            $name = is_array($entry) ? ($entry['username'] ?? ($entry['name'] ?? null)) : $entry;
            if (is_string($name) && Util::validUsername($name)) {
                $names[] = $name;
            }
        }
        return array_values(array_unique($names));
    }

    public function fetchAccount(string $username): array
    {
        $acct = $this->blankAccount($username);

        // ---- limits / config -------------------------------------------------
        $cfgRes = $this->call('CMD_API_SHOW_USER_CONFIG', ['user' => $username]);
        $cfg = is_array($cfgRes['data']) ? $cfgRes['data'] : [];
        if (!$cfgRes['ok'] && !$cfg) {
            $acct['notes'][] = 'Could not read account config: ' . trim((string)($cfgRes['error'] ?: $cfgRes['body']));
        }

        $acct['domain'] = (string)($cfg['domain'] ?? '');
        $acct['email'] = (string)($cfg['email'] ?? '');
        $acct['package'] = (string)($cfg['package'] ?? 'custom');
        $acct['suspended'] = in_array(strtolower((string)($cfg['suspended'] ?? 'no')), ['yes', '1', 'on'], true)
            || strtolower((string)($cfg['account'] ?? 'on')) === 'off';

        $acct['limits'] = [
            'disk_mb' => Util::toMb($cfg['quota'] ?? null),
            'bandwidth_mb' => Util::toMb($cfg['bandwidth'] ?? null),
            'domains' => Util::limitValue($cfg['vdomains'] ?? 0),
            'subdomains' => Util::limitValue($cfg['nsubdomains'] ?? 0),
            'emails' => Util::limitValue($cfg['nemails'] ?? 0),
            'databases' => Util::limitValue($cfg['mysql'] ?? 0),
            'ftp' => Util::limitValue($cfg['ftp'] ?? 0),
        ];

        // ---- usage -----------------------------------------------------------
        $useRes = $this->call('CMD_API_SHOW_USER_USAGE', ['user' => $username]);
        $use = is_array($useRes['data']) ? $useRes['data'] : [];
        $acct['usage'] = [
            'disk_mb' => (int) round((float)($use['quota'] ?? 0)),
            'domains' => (int)($use['vdomains'] ?? 0),
            'emails' => (int)($use['nemails'] ?? 0),
            'databases' => (int)($use['mysql'] ?? 0),
            'ftp' => (int)($use['ftp'] ?? 0),
        ];

        // ---- domains (impersonation gives us the account-scoped view) -------
        $domRes = $this->call('CMD_API_SHOW_DOMAINS', [], $username);
        if ($domRes['ok'] && is_array($domRes['data'])) {
            foreach ($domRes['data'] as $d) {
                $name = is_array($d) ? (string)($d['domain'] ?? '') : (string)$d;
                if (Util::validDomain($name)) {
                    $acct['domains'][] = strtolower($name);
                }
            }
        } else {
            $acct['notes'][] = 'Domain list unavailable from the API (falling back to the account domain only).';
        }
        if ($acct['domain'] !== '' && !in_array(strtolower($acct['domain']), $acct['domains'], true)) {
            $acct['domains'][] = strtolower($acct['domain']);
        }
        $acct['domains'] = array_values(array_unique($acct['domains']));

        // ---- subdomains ------------------------------------------------------
        foreach ($acct['domains'] as $domain) {
            $subRes = $this->call('CMD_API_SUBDOMAINS', ['domain' => $domain], $username);
            if ($subRes['ok'] && is_array($subRes['data'])) {
                foreach ($subRes['data'] as $s) {
                    $name = is_array($s) ? (string)($s['name'] ?? '') : (string)$s;
                    if ($name !== '' && Util::validDomain($name)) {
                        $acct['subdomains'][] = strtolower($name);
                    }
                }
            }
        }
        $acct['subdomains'] = array_values(array_unique($acct['subdomains']));

        // ---- mailboxes -------------------------------------------------------
        foreach ($acct['domains'] as $domain) {
            $popRes = $this->call('CMD_API_POP', ['action' => 'list', 'domain' => $domain], $username);
            if ($popRes['ok'] && is_array($popRes['data'])) {
                foreach ($popRes['data'] as $p) {
                    $local = is_array($p) ? (string)($p['user'] ?? '') : (string)$p;
                    if ($local !== '' && preg_match('/^[a-zA-Z0-9._%+-]+$/', $local)) {
                        $acct['emails'][] = strtolower($local . '@' . $domain);
                    }
                }
            }
        }
        // The main account mailbox always exists.
        if ($acct['domain'] !== '' && $acct['email'] !== '') {
            $acct['emails'][] = strtolower($acct['email']);
        }
        $acct['emails'] = array_values(array_unique($acct['emails']));

        // ---- databases -------------------------------------------------------
        $dbRes = $this->call('CMD_API_DATABASES', ['domain' => $username], $username);
        if ($dbRes['ok'] && is_array($dbRes['data'])) {
            foreach ($dbRes['data'] as $d) {
                $name = is_array($d) ? (string)($d['db'] ?? ($d['database'] ?? '')) : (string)$d;
                if ($name !== '' && preg_match('/^[A-Za-z0-9_]+$/', $name)) {
                    $acct['databases'][] = $name;
                }
            }
        }
        if (!$acct['databases']) {
            $acct['notes'][] = 'Database list unavailable from the DirectAdmin API; will be discovered over SSH at transfer time.';
        }
        $acct['databases'] = array_values(array_unique($acct['databases']));

        if ($acct['domain'] === '') {
            $acct['domain'] = $username . '.example.com';
            $acct['notes'][] = 'No main domain reported by DirectAdmin - review the substituted domain before running.';
        }
        if ($acct['email'] === '' && $acct['domain'] !== '') {
            $acct['email'] = 'admin@' . $acct['domain'];
        }

        return $acct;
    }

    /**
     * The reseller's own account plus the users it owns.
     *
     * DirectAdmin exposes a reseller as an ordinary account that owns users, so
     * its own inventory is fetched the same way as any account and its
     * allocation is that account's own package limits.
     */
    public function fetchReseller(string $name): ?array
    {
        $name = trim($name);
        if ($name === '' || !Util::validUsername($name)) {
            return null;
        }
        $cfgRes = $this->call('CMD_API_SHOW_USER_CONFIG', ['user' => $name]);
        if (!$cfgRes['ok'] || !is_array($cfgRes['data']) || !$cfgRes['data']) {
            return null;
        }

        $acct = $this->fetchAccount($name);
        $usersRes = $this->call('CMD_API_SHOW_USERS', ['reseller' => $name]);
        $users = self::extractNames($usersRes['data']);

        $acct['reseller'] = [
            'name' => $name,
            'login' => $name,
            'email' => $acct['email'],
            'allocation' => $acct['limits'],
            'users' => $users,
        ];
        return $acct;
    }

    public function listPackages(): array
    {
        $res = $this->call('CMD_API_PACKAGES_USER');
        $packages = [];
        if (!$res['ok'] || !is_array($res['data'])) {
            return $packages;
        }

        foreach ($res['data'] as $entry) {
            $name = is_array($entry) ? (string)($entry['name'] ?? '') : (string)$entry;
            if ($name === '') {
                continue;
            }
            $detail = $this->call('CMD_API_PACKAGES_USER', ['package' => $name]);
            $d = is_array($detail['data']) ? $detail['data'] : $entry;
            $packages[$name] = [
                'name' => $name,
                'limits' => [
                    'disk_mb' => Util::toMb($d['quota'] ?? null),
                    'bandwidth_mb' => Util::toMb($d['bandwidth'] ?? null),
                    'domains' => Util::limitValue($d['vdomains'] ?? 0),
                    'subdomains' => Util::limitValue($d['nsubdomains'] ?? 0),
                    'emails' => Util::limitValue($d['nemails'] ?? 0),
                    'databases' => Util::limitValue($d['mysql'] ?? 0),
                    'ftp' => Util::limitValue($d['ftp'] ?? 0),
                ],
            ];
        }
        return $packages;
    }
}