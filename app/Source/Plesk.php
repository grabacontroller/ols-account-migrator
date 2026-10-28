<?php
/**
 * Plesk - source adapter.
 *
 * Talks the Plesk REST API v2 over HTTPS on port 8443 with either an API key
 * (X-API-Key, recommended) or HTTP basic authentication.
 *
 * Plesk models hosting as: a *client* (admin / reseller / customer) owns a
 * *subscription* (service plan + limits) which owns one or more *domains*. This
 * adapter treats each subscription as one migratable account, keyed by a
 * sanitised form of its primary domain, because a subscription maps cleanly
 * onto an OLSpanel account + package + domains.
 *
 * The REST API is not uniform across Plesk builds, so every collection read is
 * best effort: anything that cannot be read is reported in the account notes
 * rather than failing the scan.
 */

declare(strict_types=1);

class Plesk extends SourcePanel
{
    private ?array $subscriptions = null;
    private ?array $domains = null;
    private ?array $clients = null;

    // ------------------------------------------------------------------ HTTP

    private function authHeaders(): array
    {
        $key = trim((string)($this->cfg['token'] ?? ''));
        if ($key !== '') {
            return ['X-API-Key: ' . $key];
        }
        return [];
    }

    private function basicAuth(): ?array
    {
        if (trim((string)($this->cfg['token'] ?? '')) !== '') {
            return null;
        }
        $user = trim((string)($this->cfg['username'] ?? 'root'));
        return [$user, (string)($this->cfg['password'] ?? '')];
    }

    /** @return array{ok:bool,status:int,error:string,data:mixed,body:string} */
    private function get(string $path, array $query = []): array
    {
        $http = new Http(
            $this->base(8443),
            array_merge(['Accept: application/json', 'Content-Type: application/json'], $this->authHeaders()),
            !empty($this->cfg['verify_tls']),
            90,
            $this->basicAuth()
        );
        $res = $http->request('api/v2/' . ltrim($path, '/'), 'GET', $query);
        if ($res['error'] !== '') {
            return ['ok' => false, 'status' => 0, 'error' => $res['error'], 'data' => null, 'body' => ''];
        }
        $ok = $res['status'] >= 200 && $res['status'] < 300;
        return [
            'ok' => $ok,
            'status' => (int)$res['status'],
            'error' => $ok ? '' : ('HTTP ' . $res['status']),
            'data' => $res['json'],
            'body' => (string)$res['body'],
        ];
    }

    /**
     * Fetch a collection and normalise the response into a plain list.
     *
     * Plesk answers with a bare JSON array; some endpoints wrap it in an
     * object or an "_embedded" map. All three shapes are accepted.
     */
    private function collection(string $path, array $query = []): array
    {
        $res = $this->get($path, $query);
        if (!$res['ok']) {
            return [];
        }
        return self::asList($res['data']);
    }

    /** Pure: turn any Plesk collection response into a list of records. */
    public static function asList($data): array
    {
        if (!is_array($data)) {
            return [];
        }
        if ($data === [] || array_keys($data) === range(0, count($data) - 1)) {
            return array_values(array_filter($data, 'is_array'));
        }
        if (isset($data['_embedded']) && is_array($data['_embedded'])) {
            foreach ($data['_embedded'] as $value) {
                if (is_array($value)) {
                    return array_values(array_filter($value, 'is_array'));
                }
            }
        }
        // A single record, or a keyed map of records.
        foreach ($data as $value) {
            if (is_array($value)) {
                return array_values(array_filter($data, 'is_array'));
            }
        }
        return [$data];
    }

    // -------------------------------------------------------------- naming

    /** A valid account key derived from a subscription's primary domain. */
    public static function accountKey(string $name): string
    {
        $key = strtolower(trim($name));
        $key = preg_replace('/[^a-z0-9._-]+/', '-', $key) ?? '';
        $key = trim($key, '.-_');
        if (strlen($key) < 2) {
            $key = 'sub' . substr(md5($name), 0, 6);
        }
        if (strlen($key) > 32) {
            $key = substr($key, 0, 26) . '-' . substr(md5($name), 0, 5);
        }
        return $key;
    }

    private function subscriptions(): array
    {
        if ($this->subscriptions === null) {
            $this->subscriptions = $this->collection('subscriptions');
        }
        return $this->subscriptions;
    }

    private function domains(): array
    {
        if ($this->domains === null) {
            $this->domains = $this->collection('domains');
        }
        return $this->domains;
    }

    private function clients(): array
    {
        if ($this->clients === null) {
            $this->clients = $this->collection('clients');
        }
        return $this->clients;
    }

    private function findSubscription(string $key): ?array
    {
        foreach ($this->subscriptions() as $sub) {
            if (self::accountKey(self::subName($sub)) === $key) {
                return $sub;
            }
        }
        return null;
    }

    private static function subName(array $sub): string
    {
        foreach (['name', 'ascii_name', 'domain'] as $field) {
            if (!empty($sub[$field]) && is_string($sub[$field])) {
                return $sub[$field];
            }
        }
        return '';
    }

    // --------------------------------------------------------------- API

    public function label(): string
    {
        return 'Plesk';
    }

    public function capabilities(): array
    {
        return [
            'limits' => 'Best effort (subscription / service plan)',
            'usage' => 'Best effort',
            'domains' => 'Full via REST',
            'mailboxes' => 'Best effort via REST, authoritative over SSH',
            'databases' => 'Best effort via REST, authoritative over SSH',
            'subdomains' => 'Full via REST',
            'resellers' => 'Plesk clients can be listed',
            'cron' => 'Not migrated',
        ];
    }

    public function test(): array
    {
        $res = $this->get('server');
        if (!$res['ok']) {
            $msg = $res['error'];
            if ($res['status'] === 401 || $res['status'] === 403) {
                $msg = 'Authentication rejected - check the Plesk API key (or administrator credentials) and that port 8443 is reachable.';
            }
            return ['ok' => false, 'message' => $msg !== '' ? $msg : 'Could not reach the Plesk REST API.'];
        }
        $domains = count($this->domains());
        return [
            'ok' => true,
            'message' => sprintf(
                'Connected to Plesk at %s:%s. %d domain(s) visible.',
                $this->cfg['host'],
                $this->cfg['port'] ?? 8443,
                $domains
            ),
            'domains' => $domains,
        ];
    }

    public function listResellers(): array
    {
        $out = [];
        foreach ($this->clients() as $client) {
            $type = strtolower((string)($client['type'] ?? ''));
            if ($type !== 'reseller') {
                continue;
            }
            $name = self::clientName($client);
            if ($name !== '') {
                $out[] = $name;
            }
        }
        return array_values(array_unique($out));
    }

    private static function clientName(array $client): string
    {
        foreach (['login', 'name', 'email'] as $field) {
            if (!empty($client[$field]) && is_string($client[$field])) {
                return $client[$field];
            }
        }
        return '';
    }

    public function listAccounts(string $reseller = ''): array
    {
        $reseller = trim($reseller) !== '' ? trim($reseller) : trim((string)($this->cfg['reseller'] ?? ''));
        $ownerIds = [];
        if ($reseller !== '') {
            foreach ($this->clients() as $client) {
                if (strcasecmp(self::clientName($client), $reseller) === 0) {
                    $ownerIds[] = (string)($client['id'] ?? '');
                    $ownerIds[] = self::clientName($client);
                    break;
                }
            }
        }

        // A reseller was requested but no client matched it: returning every
        // account would silently migrate other resellers' customers, so return
        // nothing and let the operator correct the name.
        if ($reseller !== '' && !$ownerIds) {
            return [];
        }

        $accounts = [];
        foreach ($this->subscriptions() as $sub) {
            $name = self::subName($sub);
            if ($name === '') {
                continue;
            }
            if ($ownerIds) {
                $owner = (string)($sub['owner_id'] ?? ($sub['client_id'] ?? ''));
                if ($owner !== '' && !in_array($owner, $ownerIds, true)) {
                    continue;
                }
            }
            $key = self::accountKey($name);
            if (Util::validUsername($key)) {
                $accounts[] = $key;
            }
        }

        // No subscriptions endpoint (older builds): fall back to domains.
        if (!$accounts) {
            foreach ($this->domains() as $domain) {
                $name = (string)($domain['name'] ?? '');
                if ($name === '') {
                    continue;
                }
                $key = self::accountKey($name);
                if (Util::validUsername($key) && !in_array($key, $accounts, true)) {
                    $accounts[] = $key;
                }
            }
        }
        return array_values(array_unique($accounts));
    }

    public function fetchAccount(string $username): array
    {
        $acct = $this->blankAccount($username);
        $sub = $this->findSubscription($username);
        if ($sub === null) {
            $acct['notes'][] = 'No Plesk subscription matched "' . $username . '".';
            return $acct;
        }

        $name = self::subName($sub);
        $acct['domain'] = strtolower($name);
        $acct['package'] = (string)($sub['service_plan_name'] ?? ($sub['plan_name'] ?? ($sub['name'] ?? 'custom')));

        $subId = (string)($sub['id'] ?? '');
        $ownerId = (string)($sub['owner_id'] ?? ($sub['client_id'] ?? ''));

        // ---- owner / email ---------------------------------------------------
        foreach ($this->clients() as $client) {
            if ((string)($client['id'] ?? '') === $ownerId || strcasecmp(self::clientName($client), $ownerId) === 0) {
                $acct['email'] = (string)($client['email'] ?? '');
                $acct['notes'][] = 'Plesk owner: ' . self::clientName($client) . ' (' . (string)($client['type'] ?? 'client') . ')';
                break;
            }
        }

        // ---- domains ---------------------------------------------------------
        foreach ($this->domains() as $domain) {
            $dName = strtolower((string)($domain['name'] ?? ''));
            if ($dName === '' || !Util::validDomain($dName)) {
                continue;
            }
            if (!$this->domainBelongsTo($domain, $sub)) {
                continue;
            }
            $parent = (string)($domain['parent_domain_id'] ?? ($domain['base_domain_id'] ?? ''));
            if ($parent !== '' && $parent !== '0') {
                $acct['subdomains'][] = $dName;
            } else {
                $acct['domains'][] = $dName;
            }
        }
        $acct['domains'] = array_values(array_unique($acct['domains']));
        $acct['subdomains'] = array_values(array_unique($acct['subdomains']));
        if ($acct['domain'] !== '' && !in_array($acct['domain'], $acct['domains'], true)) {
            array_unshift($acct['domains'], $acct['domain']);
            $acct['domains'] = array_values(array_unique($acct['domains']));
        }

        // ---- limits ----------------------------------------------------------
        $planId = (string)($sub['service_plan_id'] ?? ($sub['plan_id'] ?? ''));
        $limits = $this->planLimits($planId, $sub);
        $acct['limits'] = $limits;
        if ($planId === '' && $limits === $this->baseLimits()) {
            $acct['notes'][] = 'Could not read the subscription limits; review the target package before running.';
        }

        // ---- usage (best effort) ---------------------------------------------
        foreach (['name', 'disk_space', 'disk_usage', 'traffic', 'traffic_usage'] as $field) {
            if (isset($sub[$field]) && is_numeric($sub[$field])) {
                if ($field === 'disk_usage') {
                    $acct['usage']['disk_mb'] = (int)round((float)$sub[$field]);
                }
            }
        }

        // ---- databases / mail (best effort) ----------------------------------
        $acct['databases'] = $this->databasesFor($sub, $acct['domains']);
        if ($acct['databases'] === []) {
            $acct['notes'][] = 'No databases read from the Plesk REST API; they will be discovered over SSH at transfer time.';
        }
        $acct['emails'] = $this->mailboxesFor($acct['domains']);
        if ($acct['emails'] === []) {
            $acct['notes'][] = 'No mailboxes read from the Plesk REST API; they will be discovered over SSH at transfer time.';
        }

        if ($acct['email'] === '' && $acct['domain'] !== '') {
            $acct['email'] = 'admin@' . $acct['domain'];
        }

        return $acct;
    }

    /** Does a domain record belong to this subscription? */
    private function domainBelongsTo(array $domain, array $sub): bool
    {
        $subId = (string)($sub['id'] ?? '');
        foreach (['subscription_id', 'webspace_id', 'service_plan_id', 'owner_id', 'client_id'] as $field) {
            if (isset($domain[$field]) && (string)$domain[$field] === $subId) {
                return true;
            }
        }
        // Fall back to name matching when the API omits the relationship.
        $dName = strtolower((string)($domain['name'] ?? ''));
        $sName = strtolower(self::subName($sub));
        return $dName !== '' && $sName !== '' && ($dName === $sName || substr($dName, -strlen('.' . $sName)) === '.' . $sName);
    }

    private function planLimits(string $planId, array $sub): array
    {
        $limits = $this->baseLimits();
        $plan = [];
        if ($planId !== '') {
            $res = $this->get('service-plans/' . rawurlencode($planId));
            if ($res['ok'] && is_array($res['data'])) {
                $plan = $res['data'];
            }
        }
        if (!$plan) {
            $plan = $sub;
        }

        $limits['disk_mb'] = Util::toMb(self::firstNum($plan, ['disk_space', 'disk_space_limit', 'max_disk_space']));
        $limits['bandwidth_mb'] = Util::toMb(self::firstNum($plan, ['traffic', 'traffic_limit', 'max_traffic', 'bandwidth']));
        $limits['domains'] = Util::limitValue(self::firstNum($plan, ['max_domains', 'domains', 'max_domains_number']) ?? 0);
        $limits['subdomains'] = Util::limitValue(self::firstNum($plan, ['max_subdomains', 'subdomains']) ?? 0);
        $limits['emails'] = Util::limitValue(self::firstNum($plan, ['max_mailboxes', 'mailboxes', 'max_mail_accounts']) ?? 0);
        $limits['databases'] = Util::limitValue(self::firstNum($plan, ['max_databases', 'databases']) ?? 0);
        $limits['ftp'] = Util::limitValue(self::firstNum($plan, ['max_ftp_accounts', 'ftp_accounts']) ?? 0);
        return $limits;
    }

    private static function firstNum(array $row, array $keys)
    {
        foreach ($keys as $k) {
            if (isset($row[$k]) && is_numeric($row[$k])) {
                return $row[$k];
            }
        }
        return null;
    }

    private function databasesFor(array $sub, array $domains): array
    {
        $names = [];
        foreach ($this->collection('databases') as $db) {
            $name = (string)($db['name'] ?? '');
            if ($name === '' || !preg_match('/^[A-Za-z0-9_]+$/', $name)) {
                continue;
            }
            $owner = (string)($db['webspace_id'] ?? ($db['subscription_id'] ?? ($db['domain_id'] ?? '')));
            if ($owner !== '' && $owner !== (string)($sub['id'] ?? '')) {
                continue;
            }
            $names[] = $name;
        }
        return array_values(array_unique($names));
    }

    private function mailboxesFor(array $domains): array
    {
        $out = [];
        foreach (['mail-accounts', 'mail'] as $path) {
            foreach ($this->collection($path) as $mail) {
                $email = strtolower((string)($mail['email'] ?? ($mail['name'] ?? '')));
                if (!Util::validEmail($email)) {
                    continue;
                }
                $out[] = $email;
            }
            if ($out) {
                break;
            }
        }
        return array_values(array_unique($out));
    }

    public function listPackages(): array
    {
        $packages = [];
        foreach ($this->collection('service-plans') as $plan) {
            $name = (string)($plan['name'] ?? '');
            if ($name === '') {
                continue;
            }
            $packages[$name] = [
                'name' => $name,
                'limits' => $this->planLimits((string)($plan['id'] ?? ''), $plan),
            ];
        }
        return $packages;
    }

    /**
     * The reseller's own account and allocation.
     *
     * Plesk does not have a single "reseller account" the way DirectAdmin does;
     * a reseller owns subscriptions. The reseller's own inventory is therefore
     * the first subscription they own, and the allocation is its plan.
     */
    public function fetchReseller(string $name): ?array
    {
        $client = null;
        foreach ($this->clients() as $c) {
            if (strcasecmp(self::clientName($c), $name) === 0) {
                $client = $c;
                break;
            }
        }
        if ($client === null || strtolower((string)($client['type'] ?? '')) !== 'reseller') {
            return null;
        }

        $owned = [];
        foreach ($this->subscriptions() as $sub) {
            if ((string)($sub['owner_id'] ?? '') === (string)($client['id'] ?? '')) {
                $owned[] = self::accountKey(self::subName($sub));
            }
        }
        if (!$owned) {
            return null;
        }
        $account = $this->fetchAccount($owned[0]);
        $account['reseller'] = [
            'name' => $name,
            'login' => self::clientName($client),
            'email' => (string)($client['email'] ?? ''),
            'allocation' => $account['limits'],
            'users' => $owned,
        ];
        return $account;
    }
}
