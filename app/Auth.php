<?php
/**
 * Auth - gate keeping the migrator reachable by OLSpanel administrators only.
 *
 * The plugin is launched from the panel, which forwards the signed-in user's
 * identity in HTTP headers (see plugin_account_migrator.conf).  Those headers
 * are only present for requests that originate from an authenticated panel
 * session, so they cannot be replayed by someone who simply browses to
 * /3rdparty/.../index.php directly.
 *
 * The forwarded identity is then verified against the panel's own admin API
 * with a read-only call (packages_list) to prove the caller really holds admin
 * rights rather than being an ordinary hosting user.
 */

declare(strict_types=1);

class Auth
{
    private static ?array $identity = null;
    private static ?string $masterKey = null;

    public static function forwardedUser(): string
    {
        return (string)($_SERVER['HTTP_AUTOLOGINUSER'] ?? '');
    }

    public static function forwardedToken(): string
    {
        return (string)($_SERVER['HTTP_AUTOLOGINTOKEN'] ?? $_SERVER['HTTP_AUTOLOGINPASS'] ?? '');
    }

    /** Base URL of the panel serving this request. */
    public static function panelBaseUrl(): string
    {
        $host = (string)($_SERVER['HTTP_HOST'] ?? '');
        if ($host === '') {
            return '';
        }
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return $scheme . '://' . $host;
    }

    /**
     * Verify admin access.
     *
     * @return array{user:string,method:string}
     * @throws RuntimeException when the caller is not an administrator.
     */
    public static function requireAdmin(Config $config): array
    {
        if (self::$identity !== null) {
            return self::$identity;
        }

        // 1. Identity forwarded by the panel session.
        $user = self::forwardedUser();
        $token = self::forwardedToken();
        if ($user !== '' && $token !== '') {
            // The panel forwards %usertoken% encoded (see decodeForwardedToken);
            // decode it before judging or using it.
            $credential = self::decodeForwardedToken($token);
            if (self::isForwardedTokenBroken($credential)) {
                // Probing with this would send an English sentence to the API
                // and report a misleading authentication failure.
                Log::warn('auth', 'The panel forwarded "' . $credential . '" instead of a credential '
                    . '(etc/_' . $user . ' is missing on the panel). Sign in again, or set a master '
                    . 'passphrase on the migrator.');
            }
            $identity = self::probePanel($user, $credential);
            if ($identity !== null) {
                self::$identity = $identity;
                self::hardenSession();
                Log::info('auth', 'Authenticated via panel session as ' . $user);
                return $identity;
            }
            Log::warn('auth', 'Forwarded identity for "' . $user . '" was rejected by the panel API');
        }

        // 2. Emergency master passphrase (used when the panel cannot forward a token).
        if (self::checkMasterKey($config)) {
            self::$identity = ['user' => 'master-key', 'method' => 'master-key'];
            self::hardenSession();
            Log::info('auth', 'Authenticated via master passphrase');
            return self::$identity;
        }

        throw new RuntimeException(
            'Administrator authentication required. Open this tool from the OLSpanel admin '
            . 'panel (Admin -> 3rd-party -> Account Migrator), or set a master passphrase in '
            . 'data/config.json under "master_key" as a sha256 hash.'
        );
    }

    /**
     * Give an authenticated session a fresh id once, so a planted session id
     * cannot be used to reach an authenticated page (session fixation).
     */
    private static function hardenSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return;
        }
        if (empty($_SESSION['_auth_session'])) {
            session_regenerate_id(true);
            $_SESSION['_auth_session'] = true;
        }
    }

    /**
     * Non-destructive proof that the forwarded identity has admin rights.
     * packages_list is read-only and rejects non-admin credentials.
     *
     * The panel's front proxy is single-threaded, so calling back to the public
     * panel URL from inside a plugin request deadlocks it: the proxy is still
     * busy with this request and cannot answer the probe, which makes the
     * admin check flap. Prefer the panel's loopback Django app when it is
     * listening, and only fall back to the public URL otherwise.
     */
    private static function probePanel(string $user, string $token): ?array
    {
        $bases = [];
        $local = self::localPanelBaseUrl();
        if ($local !== '') {
            $bases[] = $local;
        }
        $public = self::panelBaseUrl();
        if ($public !== '' && $public !== $local) {
            $bases[] = $public;
        }
        if (!$bases) {
            return null;
        }

        foreach ($bases as $base) {
            foreach ([['apikey', $token], ['password', $token]] as $authHeader) {
                $http = new Http($base, [
                    'username: ' . $user,
                    $authHeader[0] . ': ' . $authHeader[1],
                ], false, 15);

                $res = $http->request('admin_api/packages_list/', 'POST');
                $json = $res['json'];
                if (is_array($json) && !empty($json['success'])) {
                    return ['user' => $user, 'method' => 'panel-session:' . $authHeader[0]];
                }
            }
        }
        return null;
    }

    /**
     * Loopback base URL of the panel's own WSGI app, when one is listening.
     * OLSpanel forks a Django dev server on 127.0.0.1:8001; using it avoids the
     * single-threaded front proxy entirely.
     */
    public static function localPanelBaseUrl(): string
    {
        foreach ([8001, 8000] as $port) {
            $fp = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.4);
            if (is_resource($fp)) {
                fclose($fp);
                return 'http://127.0.0.1:' . $port;
            }
        }
        return '';
    }

    /**
     * Master passphrase fallback.
     *
     * Deliberately independent of the forwarded headers: the panel derives
     * %usertoken% from etc/_<user>, and an install where that file is missing
     * forwards the literal string "Password file for user ... not found."
     * instead of a token. Requiring the headers to be absent would lock the
     * operator out of their own migrator in exactly that situation, so the
     * passphrase is accepted whenever it is presented and correct.
     */
    private static function checkMasterKey(Config $config): bool
    {
        $stored = (string)$config->get('master_key', '');
        if ($stored === '') {
            return false;
        }
        $body = Util::requestBody();
        $sent = (string)($_POST['master_key']
            ?? $body['master_key']
            ?? $_SERVER['HTTP_X_MASTER_KEY']
            ?? '');
        if ($sent === '') {
            return false;
        }
        $candidate = hash('sha256', $sent);
        return hash_equals($stored, $candidate);
    }

    /**
     * Decode the credential the panel forwards in %usertoken%.
     *
     * users/views.py passes it through users.function.encode(), which is five
     * random lowercase letters followed by base64(real password).  Using the
     * encoded blob as an API password fails authentication, so it is unwrapped
     * here.  The base64 round trip is verified so an ordinary password that
     * merely looks base64-ish is returned unchanged.
     */
    public static function decodeForwardedToken(string $token): string
    {
        $token = trim($token);
        if (strlen($token) <= 5) {
            return $token;
        }
        $body = substr($token, 5);
        $decoded = base64_decode($body, true);
        if ($decoded !== false && base64_encode($decoded) === $body) {
            return $decoded;
        }
        return $token;
    }

    /**
     * True when the panel forwarded one of its own error sentences instead of
     * a credential.
     *
     * %usertoken% expands to get_auto_login_password(), which returns the
     * decoded contents of etc/_<user> and, when that file is missing, the
     * sentence "Password file for user <name> not found." (users/function.py).
     * That sentence is then encoded by the panel, so both the raw and the
     * decoded form are recognised here.  A real token is the administrator's
     * own password and may be any string, so it cannot be recognised by shape -
     * only the two known sentences can be recognised, and that is what this
     * does.
     */
    public static function isForwardedTokenBroken(string $token): bool
    {
        $token = trim($token);
        if ($token === '') {
            return false;
        }
        if (self::looksLikePanelError($token)) {
            return true;
        }
        $decoded = self::decodeForwardedToken($token);
        return $decoded !== $token && self::looksLikePanelError($decoded);
    }

    private static function looksLikePanelError(string $token): bool
    {
        return (bool) preg_match(
            '/^(Password file for user .* not found\\.|An error occurred: .*)$/',
            $token
        );
    }

    /** Identity used for calls to the OLSpanel admin API made by the migrator. */
    public static function apiCredentials(Config $config): array
    {
        $fwdUser = self::forwardedUser();
        $fwdToken = self::decodeForwardedToken(self::forwardedToken());
        if ($fwdUser !== '' && $fwdToken !== '' && !self::isForwardedTokenBroken($fwdToken)) {
            return ['user' => $fwdUser, 'token' => $fwdToken];
        }
        if (self::isForwardedTokenBroken($fwdToken)) {
            Log::warn('auth', 'The panel forwarded "' . $fwdToken . '" instead of a credential '
                . '(etc/_' . $fwdUser . ' is missing on the panel); using the configured OLSpanel '
                . 'credentials for API calls.');
        }
        return [
            'user' => (string)$config->get('ols.username', ''),
            'token' => (string)$config->get('ols.token', '') ?: (string)$config->get('ols.password', ''),
        ];
    }
}