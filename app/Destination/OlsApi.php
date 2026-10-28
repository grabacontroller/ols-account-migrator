<?php
/**
 * OlsApi - client for the OLSpanel admin API (the migration destination).
 *
 * Only the endpoints documented at olspanel.com/api_documents are treated as
 * guaranteed. OLSpanel does not publish endpoints for email accounts, FTP
 * accounts or cron jobs, so this class probes for optional routes at run time
 * and reports honestly when a capability is unavailable instead of silently
 * producing a half-migrated account.
 */

declare(strict_types=1);

class OlsApi
{
    private string $base;
    private array $auth;
    private Http $http;

    /** Cache of capability probes for this request. */
    private static array $probeCache = [];

    public function __construct(array $config, array $auth)
    {
        $this->auth = $auth;
        $this->base = self::resolveBaseUrl($config);

        // OLSpanel reads the admin credentials from request headers. Basic
        // auth is sent too because older builds accept only that.
        $this->http = new Http($this->base, [
            'username: ' . (string)$auth['user'],
            'password: ' . (string)$auth['token'],
        ], true, 180, [
            (string)$auth['user'],
            (string)$auth['token'],
        ]);
    }

    /**
     * Where the OLSpanel admin API lives.
     *
     * An explicit host in Settings wins; otherwise the API is assumed to be
     * the very panel serving this request.
     */
    private static function resolveBaseUrl(array $config): string
    {
        $host = trim((string)($config['host'] ?? ''));
        if ($host !== '') {
            $host = preg_replace('#^https?://#', '', $host) ?? $host;
            $host = rtrim($host, '/');
            if (strpos($host, ':') !== false) {
                return 'https://' . $host;
            }
            $port = $config['port'] ?? null;
            return $port ? 'https://' . $host . ':' . (int)$port : 'https://' . $host;
        }

        // With no explicit host, prefer the panel's own loopback app. Calling
        // back through the public URL from inside a plugin request goes through
        // the single-threaded front proxy, which is still busy serving this
        // request: that deadlocks (or resets) the proxy. The loopback app also
        // avoids TLS verification against the panel's public certificate.
        $local = Auth::localPanelBaseUrl();
        if ($local !== '') {
            return $local;
        }
        $derived = Auth::panelBaseUrl();
        if ($derived !== '') {
            return $derived;
        }
        return 'https://127.0.0.1';
    }

    public function baseUrl(): string
    {
        return $this->base;
    }

    /**
     * Raw call to admin_api.
     *
     * Most documented endpoints answer {"success":bool,"message":string}. The
     * account-information endpoint at admin_api/ has no success key at all and
     * signals problems with {"error":...} - see accountInfo() for that.
     *
     * @return array{ok:bool,message:string,data:array|null,status:int}
     */
    public function call(string $endpoint, array $post = []): array
    {
        $path = 'admin_api/' . trim($endpoint, '/');
        if ($endpoint !== '') {
            $path .= '/';
        }
        $res = $this->http->request($path, 'POST', $post);
        return $this->interpret($res);
    }

    /**
     * Raw call to the Reseller Manager panel extension (admin_api_resellers/).
     *
     * That extension ships with the Reseller Manager plugin and exposes the
     * operations the documented API does not: setting a package's owner,
     * promoting an account to reseller, and reading an account's package.
     *
     * @return array{ok:bool,message:string,data:array|null,status:int}
     */
    public function callReseller(string $endpoint, array $post = []): array
    {
        $path = 'admin_api_resellers/' . trim($endpoint, '/') . '/';
        $res = $this->http->request($path, 'POST', $post);
        return $this->interpret($res);
    }

    /** @return array{ok:bool,message:string,data:array|null,status:int} */
    private function interpret(array $res): array
    {
        if ($res['error'] !== '') {
            return ['ok' => false, 'message' => $res['error'], 'data' => null, 'status' => 0];
        }

        $json = $res['json'];
        if (!is_array($json)) {
            return [
                'ok' => false,
                'message' => 'Unexpected response (HTTP ' . $res['status'] . '): ' . substr(trim($res['body']), 0, 300),
                'data' => null,
                'status' => $res['status'],
            ];
        }

        if (isset($json['error']) && !isset($json['success'])) {
            return ['ok' => false, 'message' => (string)$json['error'], 'data' => $json, 'status' => $res['status']];
        }

        $ok = !empty($json['success']);
        $msg = (string)($json['message'] ?? ($json['error'] ?? ($ok ? 'OK' : 'Request failed')));
        return ['ok' => $ok, 'message' => $msg, 'data' => $json, 'status' => $res['status']];
    }

    /** Call a documented endpoint, tolerating the "already exists" outcomes. */
    public function tryCall(string $endpoint, array $post): array
    {
        $res = $this->call($endpoint, $post);
        $already = stripos($res['message'], 'already exists') !== false
            || stripos($res['message'], 'already exist') !== false;
        return $res + ['already_exists' => $already];
    }

    // ---------------------------------------------------------------- packages

    public function packages(): array
    {
        $res = $this->call('packages_list');
        if (!$res['ok'] || !is_array($res['data']['packages'] ?? null)) {
            return [];
        }
        return $res['data']['packages'];
    }

    /** Resolve a package id by exact name through the Reseller Manager extension. */
    public function packageIdByName(string $name): int
    {
        $res = $this->callReseller('package_by_name', ['name' => $name]);
        return $res['ok'] ? (int)($res['data']['id'] ?? 0) : 0;
    }

    public function createPackage(string $name, array $limits): array
    {
        return $this->tryCall('new_package', [
            'name' => $name,
            'disk_space' => Util::limitValue($limits['disk_mb'] ?? 0),
            'bandwidth' => Util::limitValue($limits['bandwidth_mb'] ?? 0),
            'email_accounts' => Util::limitValue($limits['emails'] ?? 0),
            'databases' => Util::limitValue($limits['databases'] ?? 0),
            'ftp_accounts' => Util::limitValue($limits['ftp'] ?? 0),
            'allowed_domains' => Util::limitValue($limits['domains'] ?? 0),
            'allowed_subdomains' => Util::limitValue($limits['subdomains'] ?? 0),
            'limit_action' => true,
        ]);
    }

    // ------------------------------------------------------------------ users

    /** @return array{ok:bool,message:string,user_id:?int} */
    public function addUser(array $args): array
    {
        $res = $this->tryCall('add_user', [
            'username' => $args['username'],
            'first_name' => $args['first_name'] ?? '',
            'last_name' => $args['last_name'] ?? '',
            'email' => $args['email'],
            'password' => $args['password'],
            'pkg_id' => $args['pkg_id'],
            'domain' => $args['domain'],
            'php_version' => $args['php_version'] ?? '8.2',
        ]);
        return [
            'ok' => $res['ok'],
            'message' => $res['message'],
            'user_id' => isset($res['data']['user_id']) ? (int)$res['data']['user_id'] : null,
            'already_exists' => (bool)($res['already_exists'] ?? false),
        ];
    }

    public function updateUser(string $username, array $fields): array
    {
        return $this->tryCall('update_user', ['username' => $username] + $fields);
    }

    /**
     * Account details from the documented POST admin_api/ endpoint.
     *
     * That endpoint is the odd one out: it has no "success" key, returns the
     * account record directly, and reports problems with {"error": ...}.
     */
    public function accountInfo(string $username): array
    {
        $res = $this->call('', ['username' => $username]);
        if (!$res['ok'] || $res['data'] === null) {
            return [];
        }
        $data = $res['data'];
        unset($data['error'], $data['message'], $data['success']);
        return $data;
    }

    public function userExists(string $username): bool
    {
        $info = $this->accountInfo($username);
        return $info !== [] && !isset($info['error']);
    }

    public function state(string $username, string $state): array
    {
        return $this->tryCall('suspend_user', ['username' => $username, 'state' => $state]);
    }

    // ---------------------------------------------------------------- domains

    public function addDomain(string $username, string $domain, string $phpVersion, string $path = 'public_html'): array
    {
        return $this->tryCall('add_domain', [
            'username' => $username,
            'domain' => $domain,
            'php_version' => $phpVersion,
            'path' => $path,
        ]);
    }

    public function issueSsl(string $domain): array
    {
        return $this->tryCall('issue_ssl', ['domain' => $domain]);
    }

    /** Detect the vhost path OLSpanel actually used for an account. */
    public function domainPaths(string $username): array
    {
        $res = $this->http->request('api/domain_list/', 'POST', ['username' => $username]);
        if ($res['json'] === null || !is_array($res['json'])) {
            return [];
        }
        if (isset($res['json']['error'])) {
            return [];
        }
        $out = [];
        foreach ($res['json'] as $row) {
            if (is_array($row) && isset($row['domain'])) {
                $out[(string)$row['domain']] = (string)($row['path'] ?? '');
            }
        }
        return $out;
    }

    // ------------------------------------------------------------- databases

    /**
     * Create a database plus its user through the documented endpoint.
     *
     * @return array{ok:bool,message:string}
     */
    public function addDatabase(string $username, string $db, string $dbUser, string $dbPass): array
    {
        $res = $this->tryCall('database_add', [
            'username' => $username,
            'db' => $db,
            'dbuser' => $dbUser,
            'dbpass' => $dbPass,
            'dbpassc' => $dbPass,
        ]);
        return ['ok' => $res['ok'] || !empty($res['already_exists']), 'message' => $res['message']];
    }

    // ------------------------------------------------- optional capabilities

    /**
     * Endpoints OLSpanel may expose beyond the documented set.
     * Each candidate is probed; the first that answers sensibly wins.
     *
     * Cron jobs are NOT here: api/cronjob_add/ is part of the published user
     * API, so cron is migrated through the documented route instead.
     */
    private const OPTIONAL_ROUTES = [
        'email_add' => [
            'admin' => ['admin_api/email_add', 'admin_api/email_account_add', 'admin_api/mail_account_add', 'admin_api/add_email_account'],
            'user' => ['api/email_add', 'api/email_account_add', 'api/mail_add'],
        ],
        'ftp_add' => [
            'admin' => ['admin_api/ftp_add', 'admin_api/ftp_account_add', 'admin_api/add_ftp_account'],
            'user' => ['api/ftp_add', 'api/ftp_account_add'],
        ],
    ];

    /**
     * Probe for a capability. A route is considered present when OLSpanel
     * answers with a validation complaint (rather than a 404 / HTML page),
     * which is the signature of a live endpoint rejecting an empty payload.
     */
    public function hasCapability(string $capability): bool
    {
        if (array_key_exists($capability, self::$probeCache)) {
            return self::$probeCache[$capability];
        }

        $routes = self::OPTIONAL_ROUTES[$capability] ?? [];
        foreach ($routes as $scopeRoutes) {
            foreach ($scopeRoutes as $route) {
                $res = $this->http->request($route . '/', 'POST', ['__probe__' => '1']);
                if ($this->looksLikeLiveEndpoint($res)) {
                    Log::info('ols', "Optional capability '$capability' available at $route");
                    return self::$probeCache[$capability] = true;
                }
            }
        }
        Log::warn('ols', "Optional capability '$capability' is not exposed by this OLSpanel build");
        return self::$probeCache[$capability] = false;
    }

    private function looksLikeLiveEndpoint(array $res): bool
    {
        if ($res['error'] !== '') {
            return false;
        }
        if ($res['status'] === 404 || $res['status'] === 405) {
            return false;
        }
        $body = trim($res['body']);
        if ($body === '' || stripos($body, '<html') !== false) {
            return false;
        }
        $json = $res['json'];
        if (is_array($json)) {
            // A validation complaint means the route exists and parsed our
            // request, which is exactly the signature a probe looks for.
            $text = trim((string)($json['message'] ?? '')) . ' ' . (string)($json['error'] ?? '');
            if ($text !== '') {
                return true;
            }
            // Some routes reject with a bare success:false and no wording.
            if (array_key_exists('success', $json) && $json['success'] === false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Create an email account if the OLSpanel build supports it.
     * @return array{ok:bool,message:string,skipped:bool}
     */
    public function createEmailAccount(string $username, string $address, string $password): array
    {
        if (!$this->hasCapability('email_add')) {
            return [
                'ok' => false,
                'skipped' => true,
                'message' => 'This OLSpanel build exposes no admin API for email accounts.',
            ];
        }
        $routes = self::OPTIONAL_ROUTES['email_add'];
        foreach ($routes as $routesForScope) {
            foreach ($routesForScope as $route) {
                $res = $this->http->request($route . '/', 'POST', [
                    'username' => $username,
                    'email' => $address,
                    'password' => $password,
                    'domain' => substr($address, (int)strpos($address, '@') + 1),
                    'user' => substr($address, 0, (int)strpos($address, '@')),
                ]);
                $json = $res['json'];
                if (is_array($json) && !empty($json['success'])) {
                    return ['ok' => true, 'skipped' => false, 'message' => 'Created via ' . $route];
                }
                $msg = is_array($json)
                    ? (string)($json['message'] ?? $json['error'] ?? '')
                    : substr($res['body'], 0, 200);
                if (stripos($msg, 'already exists') !== false) {
                    return ['ok' => true, 'skipped' => false, 'message' => 'Already exists.'];
                }
            }
        }
        return ['ok' => false, 'skipped' => false, 'message' => 'Email account creation was refused by the panel.'];
    }

    /**
     * Create an FTP account if supported.
     * @return array{ok:bool,message:string,skipped:bool}
     */
    public function createFtpAccount(string $username, string $ftpUser, string $password, string $domain = ''): array
    {
        if (!$this->hasCapability('ftp_add')) {
            return [
                'ok' => false,
                'skipped' => true,
                'message' => 'This OLSpanel build exposes no admin API for FTP accounts.',
            ];
        }
        foreach (self::OPTIONAL_ROUTES['ftp_add'] as $routesForScope) {
            foreach ($routesForScope as $route) {
                $res = $this->http->request($route . '/', 'POST', [
                    'username' => $username,
                    'ftpuser' => $ftpUser,
                    'user' => $ftpUser,
                    'password' => $password,
                    'domain' => $domain,
                ]);
                $json = $res['json'];
                if (is_array($json) && !empty($json['success'])) {
                    return ['ok' => true, 'skipped' => false, 'message' => 'Created via ' . $route];
                }
                $msg = is_array($json)
                    ? (string)($json['message'] ?? $json['error'] ?? '')
                    : substr($res['body'], 0, 200);
                if (stripos($msg, 'already exists') !== false) {
                    return ['ok' => true, 'skipped' => false, 'message' => 'Already exists.'];
                }
            }
        }
        return ['ok' => false, 'skipped' => false, 'message' => 'FTP account creation was refused by the panel.'];
    }

    /**
     * Add a cron job through the documented user-level endpoint.
     *
     * api/cronjob_add/ authenticates as the *account*, not as the admin, so
     * the call is made with the account credentials the migrator just set.
     *
     * @return array{ok:bool,skipped:bool,message:string}
     */
    public function createCron(string $accountUser, string $accountPassword, array $job): array
    {
        if ($accountUser === '' || $accountPassword === '') {
            return ['ok' => false, 'skipped' => true, 'message' => 'No account credentials available for the cron API.'];
        }

        $http = new Http($this->base, [
            'username: ' . $accountUser,
            'password: ' . $accountPassword,
        ], true, 60, [$accountUser, $accountPassword]);

        $res = $http->request('api/cronjob_add/', 'POST', [
            'minute' => (string)($job['minute'] ?? '*'),
            'hour' => (string)($job['hour'] ?? '*'),
            'day' => (string)($job['day'] ?? '*'),
            'month' => (string)($job['month'] ?? '*'),
            'weekday' => (string)($job['weekday'] ?? '*'),
            'comm' => (string)($job['command'] ?? ''),
        ]);

        $json = $res['json'];
        if (is_array($json) && !empty($json['success'])) {
            return ['ok' => true, 'skipped' => false, 'message' => (string)($json['message'] ?? 'Added.')];
        }

        $msg = is_array($json)
            ? (string)($json['message'] ?? $json['error'] ?? 'Unknown response')
            : ($res['error'] !== '' ? $res['error'] : substr($res['body'], 0, 200));

        // Re-adding an identical job is not a failure for our purposes.
        if (stripos($msg, 'already exists') !== false) {
            return ['ok' => true, 'skipped' => false, 'message' => 'Already exists.'];
        }
        return ['ok' => false, 'skipped' => false, 'message' => $msg];
    }

    // ------------------------------------------------ reseller manager plugin

    /**
     * Is the Reseller Manager plugin's panel extension installed?
     *
     * The extension lives at admin_api_resellers/ and answers its own
     * capabilities route. Without it an account cannot be turned into a
     * reseller, so the migration falls back to plain accounts.
     */
    public function resellerManagerAvailable(): bool
    {
        if (array_key_exists('reseller_manager', self::$probeCache)) {
            return self::$probeCache['reseller_manager'];
        }
        $res = $this->callReseller('capabilities', ['__probe__' => '1']);
        $ok = $res['ok'] && !empty($res['data']['capabilities']);
        Log::info('ols', 'Reseller Manager panel extension ' . ($ok ? 'detected' : 'not detected'));
        return self::$probeCache['reseller_manager'] = $ok;
    }

    /** Full account row (id, pkg_id, owns_package_id) from the extension. */
    public function resellerUserDetail(string $username): ?array
    {
        $res = $this->callReseller('user_detail', ['username' => $username]);
        if ($res['ok'] && !empty($res['data']['exists'])) {
            return (array)($res['data']['user'] ?? []);
        }
        return null;
    }

    /**
     * Create (or reuse) an allocation package and record the account as its
     * owner, so the Reseller Manager treats the account as a reseller.
     *
     * @return array{ok:bool,message:string,package_id:int,package_name:string}
     */
    public function promoteReseller(array $args): array
    {
        $res = $this->callReseller('promote_reseller', [
            'username' => (string)($args['username'] ?? ''),
            'package_name' => (string)($args['package_name'] ?? ''),
            'unlimited_everything' => !empty($args['unlimited_everything']) ? 1 : 0,
            'disk_space' => Util::limitValue($args['disk_space'] ?? 0),
            'bandwidth' => Util::limitValue($args['bandwidth'] ?? 0),
            'email_accounts' => Util::limitValue($args['email_accounts'] ?? 0),
            'databases' => Util::limitValue($args['databases'] ?? 0),
            'ftp_accounts' => Util::limitValue($args['ftp_accounts'] ?? 0),
            'allowed_domains' => Util::limitValue($args['allowed_domains'] ?? 0),
            'allowed_subdomains' => Util::limitValue($args['allowed_subdomains'] ?? 0),
        ]);
        // Re-running the attachment must be safe: an account that is already a
        // reseller is a success, and its existing allocation package is reused.
        $already = stripos($res['message'], 'already a reseller') !== false;
        $packageName = (string)($res['data']['package_name'] ?? ($args['package_name'] ?? ''));
        $packageId = (int)($res['data']['package_id'] ?? 0);
        if ($already && $packageId <= 0 && $packageName !== '') {
            $found = $this->packageIdByName($packageName);
            if ($found > 0) {
                $packageId = $found;
            }
        }
        return [
            'ok' => $res['ok'] || $already,
            'message' => $res['message'],
            'package_id' => $packageId,
            'package_name' => $packageName,
            'already' => $already,
        ];
    }

    /** Hand a package to a reseller so its customers appear in their portal. */
    public function setPackageOwner(int $packageId, int $userId): array
    {
        $res = $this->callReseller('set_package_owner', ['id' => $packageId, 'userid' => $userId]);
        return ['ok' => $res['ok'], 'message' => $res['message']];
    }

    /** Reset the memoised probe results (used by the "re-detect" action). */
    public static function resetProbes(): void
    {
        self::$probeCache = [];
    }
}