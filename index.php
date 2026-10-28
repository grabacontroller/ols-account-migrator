<?php
/**
 * OLSpanel Account Migrator
 *
 * Transfers hosting accounts from a DirectAdmin or cPanel/WHM server into
 * OLSpanel: account, domains, files, mailboxes, databases and mail data.
 *
 * Entry point for the OLSpanel 3rd-party plugin system. Every action is a POST
 * guarded by a CSRF token plus an OLSpanel admin check (see Auth.php).
 */

declare(strict_types=1);

require_once __DIR__ . '/app/bootstrap.php';

ini_set('session.use_strict_mode', '1');
session_name('olsmig');
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Strict',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

$config = new Config(MIG_DATA_DIR);
Log::init(MIG_DATA_DIR);

// The UI posts a JSON body, which PHP does not decode into $_REQUEST, so the
// action and the CSRF token both have to be read from the raw body as well.
// readJsonBody() caches the decode, so php://input is only consumed once.
$action = (string)($_REQUEST['action'] ?? readJsonBody()['action'] ?? '');
Util::setRequestBody(mig_body());

// ---------------------------------------------------------------- no JS page

if ($action === '') {
    try {
        Auth::requireAdmin($config);
    } catch (Throwable $e) {
        renderAccessDenied($e->getMessage());
        exit;
    }
    renderApp($config);
    exit;
}

// -------------------------------------------------------------- JSON actions

try {
    $identity = Auth::requireAdmin($config);
} catch (Throwable $e) {
    Util::fail($e->getMessage(), 403);
}

// Every state-changing action requires a CSRF token.
    $readOnlyActions = ['settings_get', 'preflight', 'scan', 'inventory', 'resellers', 'reseller_info', 'credentials', 'test_source', 'test_ssh', 'test_ols', 'poll', 'log', 'capabilities', 'update_check'];
if (!in_array($action, $readOnlyActions, true)) {
    Util::requireCsrf();
}

Log::setJob('web');

try {
    switch ($action) {

        // ------------------------------------------------------------ settings
        case 'settings_get':
            Util::ok([
                'settings' => $config->forUi(),
                'server_ip' => (string)$config->get('server_ip', detectServerIp()),
                'identity' => $identity,
            ]);
            break;

        case 'settings_save':
            $payload = readJsonBody();
            applySettings($config, $payload);
            Util::ok(['message' => 'Settings saved.']);
            break;

        case 'test_source':
            $src = buildSource($config);
            Util::ok(['result' => $src->test()]);
            break;

        case 'test_ssh':
            $ssh = new Ssh((array)$config->get('ssh', []));
            if (!$ssh->isConfigured()) {
                Util::fail('SSH is not configured.');
            }
            Util::ok(['result' => $ssh->test(), 'tools' => Ssh::localTools()]);
            break;

        case 'test_ols':
            $ols = buildOls($config);
            $packages = $ols->packages();
            if (!$packages) {
                Util::fail('The OLSpanel API returned no packages. Check the admin credentials.');
            }
            Util::ok([
                'message' => 'Connected to OLSpanel at ' . $ols->baseUrl() . ' - ' . count($packages) . ' package(s) available.',
                'packages' => $packages,
            ]);
            break;

        case 'preflight':
            $engine = buildEngine($config);
            Util::ok(['checks' => $engine->preflight()]);
            break;

        // ------------------------------------------------------------- scanning
        case 'resellers':
            // Panels with a reseller concept (DirectAdmin) answer with the list
            // of resellers so the UI can offer to migrate a whole reseller.
            $src = buildSource($config);
            $resellers = [];
            try {
                $resellers = $src->listResellers();
            } catch (Throwable $e) {
                Log::warn('scan', 'Could not list resellers: ' . $e->getMessage());
            }
            Util::ok(['resellers' => $resellers, 'panel' => $src->label()]);
            break;

        case 'reseller_info':
            // The reseller's own account and allocation, so it can be recreated
            // through the Reseller Manager plugin after its customers migrate.
            $payload = readJsonBody();
            $name = trim((string)($payload['reseller'] ?? ($config->get('source.reseller', ''))));
            if ($name === '') {
                Util::fail('Pick a reseller first.');
            }
            $src = buildSource($config);
            $ols = buildOls($config);
            $info = $src->fetchReseller($name);
            if ($info === null) {
                Util::fail('Could not read reseller "' . $name . '" from ' . $src->label() . '.');
            }
            $manager = $ols->resellerManagerAvailable();
            Util::ok([
                'reseller' => $info['reseller'] ?? [
                    'name' => $name,
                    'login' => $name,
                    'email' => $info['email'] ?? '',
                    'allocation' => $info['limits'] ?? [],
                    'users' => [],
                ],
                'account' => $info,
                'reseller_manager' => $manager,
                'note' => $manager
                    ? ''
                    : 'The Reseller Manager plugin is not installed on this OLSpanel server, so the reseller account cannot be recreated. The customers will still be migrated as ordinary accounts.',
            ]);
            break;

        case 'attach_reseller':
            $payload = readJsonBody();
            $ols = buildOls($config);
            Util::ok(['result' => attachReseller($ols, $payload)]);
            break;

        case 'scan':
            $src = buildSource($config);
            $payload = readJsonBody();
            $reseller = trim((string)($payload['reseller'] ?? ($_REQUEST['reseller'] ?? '')));
            $users = $src->listAccounts($reseller);
            if (!$users) {
                Util::fail('No accounts found. Check the panel credentials and permissions.');
            }
            Util::ok([
                'users' => $users,
                'panel' => $src->label(),
                'reseller' => $reseller,
                'capabilities' => $src->capabilities(),
            ]);
            break;

        case 'credentials':
            // Parse the bulk "user:ftp_password:db_user:db_password" paste.
            $payload = readJsonBody();
            Util::ok(['credentials' => Util::parseCredentialLines((string)($payload['text'] ?? ''))]);
            break;

        case 'inventory':
            // Detailed inventory for a selection of accounts.
            $payload = readJsonBody();
            $users = readJsonArray('users');
            if (!$users) {
                Util::fail('No accounts selected.');
            }
            $options = (array)($payload['options'] ?? []);
            $src = buildSource($config);
            $sourcePackages = safeSourcePackages($src);

            $ssh = new Ssh((array)$config->get('ssh', []));
            $sshUsable = $ssh->isConfigured() && !empty($config->get('ssh.enabled'));
            $mysql = new Mysql((array)$config->get('mysql', []));
            $cpFiles = null;
            $dbMover = null;
            if ($sshUsable) {
                $cpFiles = new CpanelFiles($ssh);
            }
            $dbMover = new DbMover($ssh, $mysql, (array)$config->get('transfer', []), MIG_WORK_DIR);

            $sourceDbHost = trim((string)$config->get('source.db_host', ''));
            if ($sourceDbHost === '') {
                $sourceDbHost = trim((string)$config->get('source.host', ''));
            }
            $sourceDbPort = (int)$config->get('source.db_port', 3306) ?: 3306;

            $inventories = [];
            foreach (array_slice($users, 0, 100) as $user) {
                $user = (string)$user;
                if (!Util::validUsername($user)) {
                    continue;
                }
                try {
                    $inv = $src->fetchAccount($user);

                    // cPanel keeps the richest inventory in local files.
                    if ($cpFiles !== null && $src->label() === 'cPanel / WHM') {
                        $inv = CpanelFiles::merge($inv, $cpFiles->inventory($user));
                    }

                    // Neither panel's API lists every schema an account can
                    // use, so ask the source's own MySQL. Over SSH when we have
                    // it, otherwise from this server with the account's own
                    // MySQL credentials.
                    if ($inv['databases'] === []) {
                        $opts = (array)($options[$user] ?? []);
                        if ($sshUsable) {
                            $found = $dbMover->discoverSourceDatabases($user);
                        } else {
                            $cred = directDbCredential($opts);
                            $found = ($cred !== null && $sourceDbHost !== '')
                                ? $dbMover->discoverViaCredentials($cred, $sourceDbHost, $sourceDbPort)
                                : [];
                        }
                        if ($found) {
                            $inv['databases'] = $found;
                            $inv['usage']['databases'] = count($found);
                        }
                    }

                    $inventories[$user] = $inv;
                } catch (Throwable $e) {
                    Log::warn('inventory', 'Could not inventory "' . $user . '": ' . $e->getMessage());
                    $inventories[$user] = ['error' => $e->getMessage(), 'username' => $user];
                }
            }

            Util::ok(['inventory' => $inventories, 'source_packages' => $sourcePackages]);
            break;

        case 'plan':
            // Build a full, reviewable plan from inventories + options.
            $payload = readJsonBody();
            $inv = (array)($payload['inventory'] ?? []);
            $options = (array)($payload['options'] ?? []);
            $ols = buildOls($config);
            $sourcePackages = (array)($payload['source_packages'] ?? []);
            $planner = new Planner($config, $ols, $sourcePackages);

            $plans = [];
            foreach ($inv as $user => $account) {
                $perAccount = (array)($options[$user] ?? []);
                $plans[$user] = $planner->planAccount((array)$account, $perAccount);
            }

            Util::ok([
                'plans' => $plans,
                'summary' => $planner->summary($plans),
                'ols_packages' => $ols->packages(),
            ]);
            break;

        case 'run_step':
            $payload = readJsonBody();
            $plan = (array)($payload['plan'] ?? []);
            $stepId = (string)($payload['step'] ?? '');
            $options = (array)($payload['options'] ?? []);
            if (!$plan || $stepId === '') {
                Util::fail('Missing plan or step.');
            }
            $engine = buildEngine($config);
            $result = $engine->runStep($plan, $stepId, $options);
            Util::ok(['result' => $result, 'log' => Log::buffer()]);
            break;

        case 'poll':
            $payload = readJsonBody();
            $plan = (array)($payload['plan'] ?? []);
            $stage = (string)($payload['stage'] ?? 'files');
            $engine = buildEngine($config);
            Util::ok(['result' => $engine->pollTransfer($plan, $stage)]);
            break;

        case 'log':
            $logFile = (string)($_GET['file'] ?? '');
            // Only ever serve logs from our own work directory.
            $safe = basename($logFile);
            $path = MIG_WORK_DIR . '/' . $safe;
            if (!is_file($path)) {
                Util::fail('No such log.');
            }
            Util::ok(['name' => $safe, 'content' => (string)file_get_contents($path)]);
            break;

        case 'capabilities':
            $ols = buildOls($config);
            OlsApi::resetProbes();
            $caps = [];
            foreach (['email_add', 'ftp_add'] as $cap) {
                $caps[$cap] = $ols->hasCapability($cap);
            }
            $caps['cron_add'] = true;   // api/cronjob_add/ is a documented route
            $caps['reseller_manager'] = $ols->resellerManagerAvailable();
            Util::ok(['capabilities' => $caps]);
            break;

        case 'update_check':
            Util::ok(['update' => checkForUpdate($config)]);
            break;

        case 'update_install':
            Util::ok(['result' => installUpdate($config, readJsonBody())]);
            break;

        default:
            Util::fail('Unknown action: ' . $action, 404);
    }
} catch (Throwable $e) {
    Log::error($action, $e->getMessage());
    Util::fail($e->getMessage(), 500);
}

// ------------------------------------------------------------------ helpers

/**
 * Assemble the source adapter from the current settings.
 */
function buildSource(Config $config): SourcePanel
{
    $cfg = (array)$config->get('source', []);
    $host = trim((string)($cfg['host'] ?? ''));
    if ($host === '') {
        throw new RuntimeException('Set the source panel host in Settings first.');
    }

    switch ((string)($cfg['panel'] ?? '')) {
        case 'directadmin':
            if ((string)($cfg['password'] ?? '') === '') {
                throw new RuntimeException('Set the DirectAdmin admin password in Settings first.');
            }
            return new DirectAdmin($cfg);
        case 'cpanel':
            if ((string)(($cfg['token'] ?? '') ?: ($cfg['password'] ?? '')) === '') {
                throw new RuntimeException('Set the WHM API token (or root password) in Settings first.');
            }
            return new CpanelWhm($cfg);
        case 'plesk':
            if ((string)(($cfg['token'] ?? '') ?: ($cfg['password'] ?? '')) === '') {
                throw new RuntimeException('Set the Plesk API key (or administrator password) in Settings first.');
            }
            // Plesk listens on 8443; tolerate the DirectAdmin default being left in place.
            if ((int)($cfg['port'] ?? 0) === 0 || (int)$cfg['port'] === 2222) {
                $cfg['port'] = 8443;
            }
            return new Plesk($cfg);
        default:
            throw new RuntimeException('Unknown source panel type.');
    }
}

function buildOls(Config $config): OlsApi
{
    return new OlsApi((array)$config->get('ols', []), Auth::apiCredentials($config));
}

function buildEngine(Config $config): Engine
{
    // The source adapter is only needed to read the old panel. Preflight has to
    // work before the source is configured, so its absence is tolerated here
    // rather than aborting the whole engine.
    $source = null;
    try {
        $source = buildSource($config);
    } catch (Throwable $e) {
        Log::info('engine', 'Source panel adapter unavailable: ' . $e->getMessage());
    }
    return new Engine($config, buildOls($config), $source, MIG_WORK_DIR);
}

/** Package discovery must never abort a scan. */
function safeSourcePackages(SourcePanel $src): array
{
    try {
        return $src->listPackages();
    } catch (Throwable $e) {
        Log::warn('scan', 'Could not read source packages: ' . $e->getMessage());
        return [];
    }
}

/**
 * The account's own MySQL credentials, when both fields were supplied.
 *
 * @return array{user:string,password:string}|null
 */
function directDbCredential(array $options): ?array
{
    $user = trim((string)($options['source_db_user'] ?? ''));
    $password = (string)($options['source_db_password'] ?? '');
    if ($user === '' || $password === '' || !preg_match('/^[A-Za-z0-9._-]{1,64}$/', $user)) {
        return null;
    }
    return ['user' => $user, 'password' => $password];
}

/** Derive a display name from an account email (first/last may be empty). */
function splitName(string $email): array
{
    $local = strstr($email, '@', true);
    if ($local === false || $local === '') {
        return ['Reseller', 'Account'];
    }
    $local = preg_replace('/[._-]+/', ' ', $local) ?? $local;
    $parts = array_values(array_filter(preg_split('/\s+/', trim($local)) ?: [], 'strlen'));
    $first = ucfirst($parts[0] ?? 'Reseller');
    $last = count($parts) > 1 ? ucfirst((string)end($parts)) : 'Account';
    return [$first !== '' ? $first : 'Reseller', $last !== '' ? $last : 'Account'];
}

/**
 * Recreate a reseller on OLSpanel and attach its migrated customers.
 *
 * Uses the Reseller Manager plugin's panel extension: the reseller's own
 * account is created (if needed), promoted so it owns an allocation package,
 * and every migrated customer is moved onto a reseller-owned plan capped by
 * that allocation - so the reseller can manage them from its portal.
 *
 * @return array{ok:bool,reseller:string,package_id:int,attached:array,failed:array,password:string,message:string}
 */
function attachReseller(OlsApi $ols, array $p): array
{
    if (!$ols->resellerManagerAvailable()) {
        throw new RuntimeException(
            'The Reseller Manager plugin is not installed on this OLSpanel server, so the reseller cannot be recreated.'
        );
    }

    $r = (array)($p['reseller'] ?? []);
    $username = trim((string)($r['username'] ?? ''));
    if (!Util::validUsername($username)) {
        throw new RuntimeException('Choose a valid OLSpanel username for the reseller account.');
    }

    $allocation = Util::normaliseAllocation((array)($r['allocation'] ?? []));
    if (!empty($r['unlimited_everything'])) {
        $allocation = array_fill_keys(array_keys($allocation), null);
    }

    $domain = trim((string)($r['domain'] ?? ''));
    $email = trim((string)($r['email'] ?? ''));
    if ($email === '' && $domain !== '') {
        $email = 'admin@' . $domain;
    }
    if (!Util::validEmail($email)) {
        throw new RuntimeException('A valid email address is required for the reseller account.');
    }
    $phpVersion = trim((string)($r['php_version'] ?? '8.2')) ?: '8.2';
    $packageName = trim((string)($r['package_name'] ?? ''));
    if ($packageName === '') {
        $packageName = 'reseller-' . $username;
    }

    $messages = [];

    // 1. Make sure the reseller's own account exists.
    $detail = $ols->resellerUserDetail($username);
    if ($detail === null) {
        if (!Util::validDomain($domain)) {
            throw new RuntimeException('A valid primary domain is required to create the reseller account "' . $username . '".');
        }
        $password = (string)($r['password'] ?? '');
        if (strlen($password) < 8) {
            $password = Util::genPassword((int)($r['password_length'] ?? 14) ?: 14);
        }
        $pkg = $ols->createPackage($packageName, $allocation);
        if (!$pkg['ok'] && empty($pkg['already_exists'])) {
            throw new RuntimeException('Could not create the allocation package: ' . $pkg['message']);
        }
        $pkgId = $ols->packageIdByName($packageName);
        if ($pkgId <= 0) {
            throw new RuntimeException('Created the allocation package but could not resolve its id.');
        }
        [$first, $last] = splitName($email);
        $created = $ols->addUser([
            'username' => $username,
            'first_name' => $first,
            'last_name' => $last,
            'email' => $email,
            'password' => $password,
            'pkg_id' => $pkgId,
            'domain' => $domain,
            'php_version' => $phpVersion,
        ]);
        if (!$created['ok'] && empty($created['already_exists'])) {
            throw new RuntimeException('Could not create the reseller account: ' . $created['message']);
        }
        $r['password'] = $password;
        $messages[] = 'Reseller account created (password shown in the report).';
        $detail = $ols->resellerUserDetail($username);
    }

    // 2. Promote: create/reuse the allocation package and record ownership.
    $promote = $ols->promoteReseller([
        'username' => $username,
        'package_name' => $packageName,
        'unlimited_everything' => !empty($r['unlimited_everything']),
        'disk_space' => $allocation['disk_mb'],
        'bandwidth' => $allocation['bandwidth_mb'],
        'allowed_domains' => $allocation['domains'],
        'allowed_subdomains' => $allocation['subdomains'],
        'email_accounts' => $allocation['emails'],
        'databases' => $allocation['databases'],
        'ftp_accounts' => $allocation['ftp'],
    ]);
    if (!$promote['ok']) {
        throw new RuntimeException('Could not register the reseller: ' . $promote['message']);
    }
    $messages[] = 'Reseller registered with allocation package "' . ($promote['package_name'] ?: $packageName) . '".';

    $resellerId = (int)($detail['id'] ?? 0);
    if ($resellerId <= 0) {
        $fresh = $ols->resellerUserDetail($username);
        $resellerId = (int)($fresh['id'] ?? 0);
    }

    // 3. Attach each migrated customer to a reseller-owned plan.
    $attached = [];
    $failed = [];
    foreach ((array)($p['customers'] ?? []) as $c) {
        if (!is_array($c)) {
            continue;
        }
        $cu = trim((string)($c['username'] ?? ''));
        if ($cu === '' || !Util::validUsername($cu) || $cu === $username) {
            continue;
        }
        if ($ols->resellerUserDetail($cu) === null) {
            $failed[$cu] = 'No such account on OLSpanel.';
            continue;
        }

        $limits = Util::capLimits(Util::normaliseAllocation((array)($c['limits'] ?? [])), $allocation);
        $planName = trim((string)($c['package_name'] ?? ''));
        if ($planName === '') {
            $src = trim((string)($c['source_package'] ?? ''));
            $planName = $src !== '' ? ('Reseller ' . $username . ' - ' . $src) : ('Reseller ' . $username . ' plan');
        }
        $planName = trim(preg_replace('/[^A-Za-z0-9 ._-]/', '', $planName) ?? '');
        if ($planName === '') {
            $planName = 'Reseller ' . $username . ' plan';
        }
        $planName = substr($planName, 0, 50);

        $pkgId = $ols->packageIdByName($planName);
        if ($pkgId <= 0) {
            $mk = $ols->createPackage($planName, $limits);
            if (!$mk['ok'] && empty($mk['already_exists'])) {
                $failed[$cu] = 'Could not create plan "' . $planName . '": ' . $mk['message'];
                continue;
            }
            $pkgId = $ols->packageIdByName($planName);
        }
        if ($pkgId <= 0) {
            $failed[$cu] = 'Could not resolve the plan id for "' . $planName . '".';
            continue;
        }
        if ($resellerId > 0) {
            $ols->setPackageOwner($pkgId, $resellerId);
        }
        $upd = $ols->updateUser($cu, ['pkg_id' => $pkgId]);
        if (!$upd['ok']) {
            $failed[$cu] = 'Could not move to plan: ' . $upd['message'];
            continue;
        }
        $attached[$cu] = $planName;
    }

    $message = implode(' ', $messages) . ' ' . count($attached) . ' customer(s) attached.';
    if ($failed) {
        $parts = [];
        foreach ($failed as $u => $why) {
            $parts[] = $u . ': ' . $why;
        }
        $message .= ' Failed: ' . implode('; ', $parts);
    }

    return [
        'ok' => true,
        'reseller' => $username,
        'package_id' => (int)$promote['package_id'],
        'attached' => $attached,
        'failed' => $failed,
        'password' => (string)($r['password'] ?? ''),
        'message' => $message,
    ];
}

/** Best guess at this server's public IP. */
function detectServerIp(): string
{
    $configured = getenv('OLSMIG_SERVER_IP');
    if (is_string($configured) && $configured !== '') {
        return $configured;
    }
    $addr = (string)($_SERVER['SERVER_ADDR'] ?? '');
    if ($addr !== '' && strpos($addr, ':') === false) {
        return $addr;
    }
    return '';
}

/* ------------------------------------------------------------- self-update */

/** Where the update manifest lives (HTTPS only). */
function updateManifestUrl(Config $config): string
{
    $url = trim((string)$config->get('updates.manifest_url', ''));
    return $url !== '' ? $url : 'https://dev3.vgs1st.com/account_migrator-version.json';
}

/** Resolve a possibly-relative bundle path against the manifest's directory. */
function updateBundleUrl(string $manifestUrl, string $bundle): string
{
    if (preg_match('#^https://#i', $bundle)) {
        return $bundle;
    }
    $parts = parse_url($manifestUrl);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        throw new RuntimeException('The update manifest URL is not a valid HTTPS URL.');
    }
    $base = $parts['scheme'] . '://' . $parts['host'];
    if (!empty($parts['port'])) {
        $base .= ':' . (int)$parts['port'];
    }
    $dir = isset($parts['path']) ? rtrim(dirname($parts['path']), '/') : '';
    return $base . $dir . '/' . ltrim($bundle, '/');
}

/** Fetch and decode the update manifest. Throws on any failure. */
function fetchUpdateManifest(Config $config): array
{
    $url = updateManifestUrl($config);
    if (!preg_match('#^https://#i', $url)) {
        throw new RuntimeException('The update manifest URL must use HTTPS.');
    }
    $http = new Http('', [], true, 30);
    $res = $http->absolute($url, 'GET');
    if ($res['error'] !== '') {
        throw new RuntimeException('Could not reach the update server: ' . $res['error']);
    }
    if ((int)$res['status'] !== 200 || !is_array($res['json'])) {
        throw new RuntimeException('The update server returned an unexpected response (HTTP ' . $res['status'] . ').');
    }
    return $res['json'];
}

/** Compare the installed version with the published one. */
function checkForUpdate(Config $config): array
{
    $manifest = fetchUpdateManifest($config);
    $latest = trim((string)($manifest['version'] ?? ''));
    $bundle = trim((string)($manifest['bundle'] ?? 'account_migrator_bundle.zip'));
    return [
        'current' => MIG_VERSION,
        'latest' => $latest,
        'updated' => trim((string)($manifest['updated'] ?? '')),
        'available' => $latest !== '' && version_compare($latest, MIG_VERSION, '>'),
        'url' => updateBundleUrl(updateManifestUrl($config), $bundle),
        'sha256' => strtolower(trim((string)($manifest['sha256'] ?? ''))),
        'notes' => trim((string)($manifest['notes'] ?? '')),
        'manifest_url' => updateManifestUrl($config),
    ];
}

/**
 * Download and install the published bundle.
 *
 * The bundle is downloaded over HTTPS, its checksum is verified when the
 * manifest publishes one, and its own install.sh is run (it is idempotent and
 * preserves settings). This needs root: if the plugin process is not root the
 * download still happens but the install step is reported as unavailable.
 */
function installUpdate(Config $config, array $p): array
{
    if (empty($p['confirm'])) {
        throw new RuntimeException('Confirm the update before installing it.');
    }
    $info = checkForUpdate($config);
    if (empty($info['available'])) {
        throw new RuntimeException('Already up to date (v' . MIG_VERSION . ').');
    }
    $url = (string)$info['url'];
    if (!preg_match('#^https://#i', $url)) {
        throw new RuntimeException('The bundle URL must use HTTPS.');
    }

    $work = MIG_WORK_DIR . '/update-' . bin2hex(random_bytes(4));
    if (!@mkdir($work, 0700, true)) {
        throw new RuntimeException('Could not create a working directory for the update.');
    }

    try {
        $http = new Http('', [], true, 180);
        $res = $http->absolute($url, 'GET');
        if ($res['error'] !== '') {
            throw new RuntimeException('Could not download the update: ' . $res['error']);
        }
        if ((int)$res['status'] !== 200) {
            throw new RuntimeException('The update download failed (HTTP ' . $res['status'] . ').');
        }
        $bytes = (string)$res['body'];
        if (strlen($bytes) < 512) {
            throw new RuntimeException('The downloaded update looks truncated.');
        }
        $sha = strtolower(trim((string)$info['sha256']));
        if (!preg_match('/^[a-f0-9]{64}$/', $sha)) {
            throw new RuntimeException('The update manifest does not publish a valid SHA-256; refusing to install.');
        }
        if (!hash_equals($sha, hash('sha256', $bytes))) {
            throw new RuntimeException('The downloaded update failed its checksum.');
        }

        $zipPath = $work . '/bundle.zip';
        if (@file_put_contents($zipPath, $bytes) === false) {
            throw new RuntimeException('Could not write the downloaded update to disk.');
        }

        $extract = $work . '/unpacked';
        @mkdir($extract, 0700, true);
        if (!extractZip($zipPath, $extract)) {
            throw new RuntimeException('Could not unpack the update archive.');
        }

        $script = $extract . '/account_migrator/install.sh';
        $realScript = realpath($script);
        $realBase = realpath($extract);
        if (is_link($script) || $realScript === false || $realBase === false
            || strpos($realScript, $realBase . DIRECTORY_SEPARATOR) !== 0) {
            throw new RuntimeException('The update archive contained an unsafe install.sh.');
        }
        if (!is_file($script)) {
            throw new RuntimeException('The update archive did not contain install.sh.');
        }

        $euid = function_exists('posix_geteuid') ? posix_geteuid() : null;
        if (!function_exists('shell_exec')) {
            return [
                'ok' => true,
                'installed' => false,
                'version' => $info['latest'],
                'message' => 'Update v' . $info['latest'] . ' downloaded and verified, but shell execution is '
                    . 'disabled in PHP. Run the installer over SSH: bash install.sh',
                'output' => '',
            ];
        }
        if ($euid !== null && $euid !== 0) {
            return [
                'ok' => true,
                'installed' => false,
                'version' => $info['latest'],
                'message' => 'Update v' . $info['latest'] . ' downloaded and verified, but the plugin process is '
                    . 'not root so it cannot install itself. Run: bash ' . $script,
                'output' => '',
            ];
        }

        Log::info('update', 'Installing v' . $info['latest'] . ' from ' . $url);
        $cmd = 'bash ' . escapeshellarg($script) . ' 2>&1';
        $output = (string)@shell_exec($cmd);

        return [
            'ok' => true,
            'installed' => true,
            'version' => $info['latest'],
            'message' => 'Updated to v' . $info['latest'] . '. Reload the page to use the new version.',
            'output' => substr($output, -4000),
        ];
    } finally {
        removeTree($work);
    }
}

/** Extract a zip using ZipArchive, falling back to the unzip binary. */
function extractZip(string $zipPath, string $dest): bool
{
    if (class_exists('ZipArchive')) {
        $zip = new ZipArchive();
        if ($zip->open($zipPath) === true) {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $name = (string)$zip->getNameIndex($i);
                if ($name === '' || $name[0] === '/'
                    || preg_match('#(^|/)\.\.(/|$)#', $name)
                    || preg_match('#^[A-Za-z]:[\\\\/]#', $name)) {
                    $zip->close();
                    return false;
                }
                $opsys = 0;
                $attr = 0;
                if ($zip->getExternalAttributesIndex($i, $opsys, $attr)
                    && (($attr >> 16) & 0xF000) === 0xA000) {
                    $zip->close();
                    return false;
                }
            }
            $ok = $zip->extractTo($dest);
            $zip->close();
            if ($ok) {
                return true;
            }
        }
    }
    if (!function_exists('shell_exec')) {
        return false;
    }
    foreach (['unzip -oq %s -d %s', 'bsdtar -xf %s -C %s'] as $tpl) {
        $cmd = sprintf($tpl, escapeshellarg($zipPath), escapeshellarg($dest));
        @shell_exec($cmd . ' 2>&1');
        if (is_dir($dest) && is_file($dest . '/account_migrator/install.sh')) {
            return true;
        }
    }
    return false;
}

/** Recursively delete a directory (best effort). */
function removeTree(string $path): void
{
    if ($path === '' || !is_dir($path)) {
        return;
    }
    $items = @scandir($path) ?: [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $full = $path . '/' . $item;
        if (is_dir($full) && !is_link($full)) {
            removeTree($full);
        } else {
            @unlink($full);
        }
    }
    @rmdir($path);
}

/**
 * Apply a settings payload from the UI.
 *
 * Secrets are only overwritten when a new value is supplied, so the browser
 * never needs to receive the existing password to leave it alone.
 */
function applySettings(Config $config, array $payload): void
{
    $writable = [
        'source.panel', 'source.host', 'source.port', 'source.tls', 'source.verify_tls',
        'source.username', 'source.password', 'source.token', 'source.reseller',
        'source.ftp_protocol', 'source.ftp_port', 'source.ftp_tls', 'source.ftp_login', 'source.db_host', 'source.db_port',
        'ssh.enabled', 'ssh.host', 'ssh.port', 'ssh.username', 'ssh.auth',
        'ssh.key_path', 'ssh.key_passphrase', 'ssh.password', 'ssh.strict_host_key',
        'ols.host', 'ols.port', 'ols.username', 'ols.password', 'ols.token',
        'transfer.home_root', 'transfer.user_home', 'transfer.source_user_home', 'transfer.bandwidth_limit',
        'transfer.delete_after',
        'defaults.php_version', 'defaults.new_package_naming', 'defaults.password_length',
        'defaults.generate_databases', 'defaults.import_database_data',
        'defaults.create_email_accounts', 'defaults.issue_ssl',
        'mysql.auto_detect', 'mysql.host', 'mysql.username', 'mysql.root_password', 'mysql.socket',
        'updates.manifest_url',
        'server_ip',
    ];

    // The browser posts flat dotted keys ("ols.host"), but a hand-written API
    // client is as likely to nest them the way settings_get returns them
    // ({"ols":{"host":...}}). Accept both, and reject unknown top-level keys
    // loudly rather than reporting a save that changed nothing.
    $payload = flattenSettingsPayload($payload);
    $ignored = [];

    foreach ($payload as $key => $value) {
        if (is_array($value)) {
            $ignored[] = $key;
            continue;
        }
        if (!in_array($key, $writable, true)) {
            $ignored[] = $key;
            continue;
        }

        // Masked secrets mean "keep the current value".
        if ($value === '__set__' || $value === '__keep__') {
            continue;
        }

        // Type coercion per key.
        if (strpos($key, '.port') !== false || $key === 'transfer.bandwidth_limit' || $key === 'defaults.password_length' || $key === 'source.ftp_port' || $key === 'source.db_port') {
            $value = (int)$value;
        } elseif (preg_match('/\.(tls|verify_tls|enabled|strict_host_key|delete_after|generate_databases|import_database_data|create_email_accounts|issue_ssl|auto_detect)$/', $key)) {
            $value = (bool)$value;
        } elseif (is_string($value)) {
            $value = trim($value);
        }

        // Refuse a host that is not a plain hostname or IP.
        if (in_array($key, ['source.host', 'source.db_host', 'ssh.host'], true) && is_string($value) && $value !== '') {
            if (!Util::validHost($value)) {
                throw new RuntimeException('"' . $value . '" is not a valid hostname or IP for ' . $key . '.');
            }
        }
        if ($key === 'ols.host' && is_string($value) && $value !== '') {
            $bare = preg_replace('#^https?://#', '', $value) ?? $value;
            $bare = rtrim($bare, '/');
            if (!Util::validHost(explode(':', $bare)[0])) {
                throw new RuntimeException('"' . $value . '" is not a valid OLSpanel host.');
            }
            $value = $bare;
        }
        if ($key === 'transfer.user_home' && is_string($value) && $value !== '' && substr($value, -1) === '/') {
            $value = rtrim($value, '/');
        }
        if ($key === 'transfer.source_user_home' && is_string($value) && $value !== '' && substr($value, -1) === '/') {
            $value = rtrim($value, '/');
        }
        if ($key === 'source.ftp_protocol') {
            $value = strtolower(trim((string)$value));
            if (!in_array($value, ['ftp', 'sftp'], true)) {
                throw new RuntimeException('The transfer protocol must be "ftp" or "sftp".');
            }
        }

        $config->set($key, $value);
    }

    // Normalise the mail directory list.
    if (isset($payload['transfer.mail_dirs'])) {
        $dirs = [];
        foreach (preg_split('/[\s,]+/', (string)$payload['transfer.mail_dirs']) as $d) {
            $d = trim($d, " \t/");
            if ($d !== '' && preg_match('/^[A-Za-z0-9._-]+$/', $d)) {
                $dirs[] = $d;
            }
        }
        $config->set('transfer.mail_dirs', $dirs !== [] ? $dirs : ['mail', 'Maildir']);
    }

    if (isset($payload['transfer.exclude'])) {
        $list = [];
        foreach (preg_split('/[\s,]+/', (string)$payload['transfer.exclude']) as $e) {
            $e = trim($e);
            if ($e !== '' && preg_match('#^[A-Za-z0-9._/ \*\?\-]+$#', $e)) {
                $list[] = $e;
            }
        }
        $config->set('transfer.exclude', $list);
    }

    $config->save();

    if ($ignored !== []) {
        // Only complain about keys that look like settings. Anything else in the
        // body (_csrf, action, stray client state) is simply not ours.
        $suspect = array_values(array_filter($ignored, function ($k) {
            // Match a dotted segment, so "ols.host" is caught whether it was
            // posted flat, nested, or wrapped in {"settings": {...}}.
            return (bool)preg_match('/(^|\.)(source|ssh|ols|transfer|defaults|mysql)(\.|$)|^server_ip$/', $k);
        }));
        if ($suspect !== []) {
            throw new RuntimeException(
                'Refusing to save: unknown setting(s) ' . implode(', ', array_slice($suspect, 0, 5))
                . '. Nothing was written.'
            );
        }
    }
}

/**
 * Turn {"ols":{"host":"x"}} into ["ols.host" => "x"] so nested and flat
 * payloads are equivalent. Lists (transfer.exclude, mail_dirs) are joined
 * because they are consumed as strings further up.
 */
/** True for a zero-indexed array. Written out because array_is_list() is 8.1+. */
function isList(array $a): bool
{
    $i = 0;
    foreach ($a as $k => $_) {
        if ($k !== $i++) {
            return false;
        }
    }
    return true;
}

function flattenSettingsPayload(array $payload): array
{
    // Some clients wrap the settings in {"settings": {...}}. The browser does
    // not, but accepting both costs nothing once the keys are flattened.
    if (isset($payload['settings']) && is_array($payload['settings'])) {
        $wrapped = $payload['settings'];
        unset($payload['settings']);
        $payload = array_merge($payload, $wrapped);
    }

    $out = [];
    foreach ($payload as $key => $value) {
        if (is_array($value) && !isList($value)) {
            foreach (flattenSettingsPayload($value) as $subKey => $subValue) {
                $out[$key . '.' . $subKey] = $subValue;
            }
            continue;
        }
        if (is_array($value)) {
            // A list is a leaf (transfer.exclude, transfer.mail_dirs) and those
            // are normalised from a string further up.
            $value = implode(',', array_map('strval', $value));
        }
        $out[$key] = $value;
    }
    return $out;
}

/** Decoded request body, cached for the life of the request. */
function mig_body(): array
{
    static $body = null;
    if ($body === null) {
        $raw = (string)file_get_contents('php://input');
        $decoded = $raw !== '' ? json_decode($raw, true) : null;
        $body = is_array($decoded) ? $decoded : $_POST;
    }
    return $body;
}

/** Decode a JSON request body (falls back to form fields). */
function readJsonBody(): array
{
    return mig_body();
}

function readJsonArray(string $key): array
{
    $body = readJsonBody();
    $value = $body[$key] ?? [];
    if (is_string($value)) {
        $decoded = json_decode($value, true);
        $value = is_array($decoded) ? $decoded : array_filter(array_map('trim', explode(',', $value)));
    }
    return is_array($value) ? $value : [];
}

// -------------------------------------------------------------------- views

function renderAccessDenied(string $message): void
{
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><head><meta charset="utf-8">'
        . '<title>Account Migrator - access denied</title>'
        . '<style>body{font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0;'
        . 'display:flex;align-items:center;justify-content:center;height:100vh;margin:0}'
        . '.box{max-width:620px;padding:32px;background:#1e293b;border:1px solid #334155;border-radius:12px}'
        . 'h1{font-size:20px;margin:0 0 12px}'
        . 'code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:13px}'
        . '</style></head><body><div class="box">'
        . '<h1>Administrator access required</h1>'
        . '<p>' . Util::h($message) . '</p>'
        . '<p>Open this tool from the OLSpanel admin panel, under <strong>3rd-party &rarr; Account Migrator</strong>.</p>'
        . '</div></body></html>';
}

function renderApp(Config $config): void
{
    $token = Util::csrfToken();
    $settings = $config->forUi();
    $identity = [
        'user' => (string)($_SERVER['HTTP_AUTOLOGINUSER'] ?? 'master-key'),
        'method' => Auth::forwardedUser() !== '' ? 'panel session' : 'master passphrase',
    ];
    $assetVersion = mig_asset_version();
    $bootstrap = [
        'csrf' => $token,
        'settings' => $settings,
        'identity' => $identity,
        'serverIp' => (string)$config->get('server_ip', detectServerIp()),
        'version' => MIG_VERSION,
        'assetVersion' => $assetVersion,
    ];

    header('Content-Type: text/html; charset=utf-8');
    header('X-Frame-Options: SAMEORIGIN');
    header('Cache-Control: no-store');
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Account Migrator</title>
<link rel="stylesheet" href="ui/app.css?v=<?= Util::h($assetVersion) ?>">
</head>
<body>
<div id="app">
    <header class="topbar">
        <div class="brand">
            <span class="logo">M</span>
            <div>
                <h1>Account Migrator</h1>
                <p>DirectAdmin / cPanel / Plesk &rarr; OLSpanel</p>
            </div>
        </div>
        <div class="topmeta">
            <span class="chip" id="identityChip"></span>
            <span class="chip" id="serverChip"></span>
        </div>
    </header>

    <nav class="tabs" id="tabs">
        <button class="tab active" data-tab="settings">Settings</button>
        <button class="tab" data-tab="preflight">Preflight</button>
        <button class="tab" data-tab="scan">Select accounts</button>
        <button class="tab" data-tab="plan">Review plan</button>
        <button class="tab" data-tab="run">Run</button>
        <button class="tab" data-tab="report">Report</button>
        <button class="tab" data-tab="updater">Plugin update</button>
    </nav>

    <main id="panels">
        <section class="panel active" id="panel-settings"><div class="loading">Loading settings&hellip;</div></section>
        <section class="panel" id="panel-preflight"><div class="loading">Run preflight to check the environment.</div></section>
        <section class="panel" id="panel-scan"><div class="loading">Scan the source panel to list accounts.</div></section>
        <section class="panel" id="panel-plan"></section>
        <section class="panel" id="panel-run"></section>
        <section class="panel" id="panel-report"><div class="loading">Nothing to report yet.</div></section>
        <section class="panel" id="panel-updater"><div class="loading">Checking for updates&hellip;</div></section>
    </main>

    <div id="toast" class="toast" hidden></div>
</div>

<script>window.MIG = <?= json_encode($bootstrap, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP) ?>;</script>
<script src="ui/app.js?v=<?= Util::h($assetVersion) ?>"></script>
</body>
</html>
<?php
}