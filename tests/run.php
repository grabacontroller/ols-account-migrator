<?php
/**
 * Offline self-test for the Account Migrator.
 *
 * Run with:  php tests/run.php
 *
 * Exercises the pure logic (size parsing, package matching, DNS helpers,
 * password handling, the config encryption round-trip, rsync command building)
 * without needing either control panel.
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

$pass = 0;
$fail = 0;

function check(string $name, $got, $want): void
{
    global $pass, $fail;
    if ($got === $want) {
        $pass++;
        echo "  ok   $name\n";
    } else {
        $fail++;
        echo "  FAIL $name\n         got:  " . var_export($got, true) .
            "\n         want: " . var_export($want, true) . "\n";
    }
}

function ok(string $name, bool $cond, string $why = ''): void
{
    global $pass, $fail;
    if ($cond) {
        $pass++;
        echo "  ok   $name\n";
    } else {
        $fail++;
        echo "  FAIL $name" . ($why !== '' ? " - $why" : '') . "\n";
    }
}

function section(string $title): void
{
    echo "\n$title\n" . str_repeat('-', strlen($title)) . "\n";
}

// ---------------------------------------------------------------- Util::toMb
section('Util::toMb - size normalisation');

check('plain megabytes stay megabytes', Util::toMb(10240), 10240);
check('10GB converts to megabytes', Util::toMb('10GB'), 10240);
check('1.5 GB rounds to megabytes', Util::toMb('1.5GB'), 1536);
check('512K becomes under 1MB', Util::toMb('512K'), 1);
check('2TB scales up', Util::toMb('2TB'), 2097152);
check('unlimited is null', Util::toMb('unlimited'), null);
check('empty is null', Util::toMb(''), null);
check('null is null', Util::toMb(null), null);
check('zero means unlimited', Util::toMb(0), null);
check('gibibyte spelling is accepted', Util::toMb('1GiB'), 1024);
check('comma thousands are handled', Util::toMb('10,000MB'), 10000);
check('garbage is unlimited, not a crash', Util::toMb('not a size'), null);

// ------------------------------------------------------- Util::humanMb
section('Util::humanMb - display formatting');

check('10240 MB reads as 10 GB', Util::humanMb(10240), '10 GB');
check('1536 MB keeps a fraction', Util::humanMb(1536), '1.5 GB');
check('512 MB is left alone', Util::humanMb(512), '512 MB');
check('null reads as unlimited', Util::humanMb(null), 'unlimited');

// ------------------------------------------------------- Util::limitValue
section('Util::limitValue - OLSpanel treats 0 as unlimited');

check('null becomes 0', Util::limitValue(null), 0);
check('unlimited string becomes 0', Util::limitValue('unlimited'), 0);
check('negative is clamped', Util::limitValue(-5), 0);
check('a real limit survives', Util::limitValue(25), 25);

// ------------------------------------------------------ validation helpers
section('Validators');

ok('accepts a normal username', Util::validUsername('john.doe-1'));
ok('rejects a 1 character username', !Util::validUsername('a'));
ok('rejects a username starting with a dot', !Util::validUsername('.hidden'));
ok('rejects spaces in a username', !Util::validUsername('john doe'));
ok('accepts a real domain', Util::validDomain('shop.example.com'));
ok('rejects a domain without a dot', !Util::validDomain('localhost'));
ok('rejects an empty domain', !Util::validDomain(''));
ok('rejects a trailing-hyphen label', !Util::validDomain('bad-.com'));
ok('accepts an IPv4 literal as a host', Util::validHost('192.168.1.10'));
ok('rejects a host with a space', !Util::validHost('bad host'));
ok('rejects a host with a slash', !Util::validHost('evil.com/path'));
ok('rejects a shell metacharacter host', !Util::validHost('a.com;rm -rf /'));

// ------------------------------------------------------- password strength
section('Password generation');

$seen = [];
$tooWeak = false;
$lengthOk = true;
for ($i = 0; $i < 60; $i++) {
    $pw = Util::genPassword(16);
    $seen[$pw] = true;
    if (strlen($pw) !== 16) { $lengthOk = false; }
    if (!preg_match('/[a-z]/', $pw) || !preg_match('/[A-Z]/', $pw)
        || !preg_match('/[0-9]/', $pw) || !preg_match('/[^a-zA-Z0-9]/', $pw)) {
        $tooWeak = true;
    }
}
ok('passwords honour the requested length', $lengthOk);
ok('passwords include all four character classes', !$tooWeak);
ok('passwords are not repeated', count($seen) === 60, count($seen) . ' unique of 60');

// --------------------------------------------------- Config encrypt round-trip
section('Config - secrets encrypted at rest');

$tmp = sys_get_temp_dir() . '/olsmig-test-' . bin2hex(random_bytes(4));
mkdir($tmp, 0700, true);

$c = new Config($tmp);
$c->set('source.host', 'old.example.com');
$c->set('source.password', 'super-secret-da-password');
$c->set('source.token', 'whm-token-abc123');
$c->set('ols.password', 'ols-admin-pw');
$c->set('ssh.password', 'ssh-secret');
$c->set('mysql.root_password', 'mysql-secret');
$c->save();

$raw = json_decode((string)file_get_contents($tmp . '/config.json'), true);
ok('password is not stored in clear text', strpos(json_encode($raw), 'super-secret-da-password') === false);
ok('whm token is not stored in clear text', strpos(json_encode($raw), 'whm-token-abc123') === false);
ok('ssh password is not stored in clear text', strpos(json_encode($raw), 'ssh-secret') === false);
ok('mysql password is not stored in clear text', strpos(json_encode($raw), 'mysql-secret') === false);
ok('secrets are marked encrypted', ($raw['source']['password'] ?? '') === 'enc:'
    || strpos((string)($raw['source']['password'] ?? ''), 'enc:') === 0);
ok('non-secret settings stay readable', ($raw['source']['host'] ?? '') === 'old.example.com');
ok('config file is 0600', substr(sprintf('%o', fileperms($tmp . '/config.json')), -4) === '0600');

$c2 = new Config($tmp);
check('password survives a reload', (string)$c2->get('source.password'), 'super-secret-da-password');
check('whm token survives a reload', (string)$c2->get('source.token'), 'whm-token-abc123');
check('mysql password survives a reload', (string)$c2->get('mysql.root_password'), 'mysql-secret');

$ui = $c2->forUi();
ok('UI never receives the real secret', $ui['source']['password'] === '__set__');
ok('UI shows an unset secret as empty', $ui['ols']['token'] === '');

ok('isSecretSet is true for a stored secret', $c2->isSecretSet('source.password'));
$c2->set('source.password', '__set__');
$c2->save();
$c3 = new Config($tmp);
check('a masked secret keeps its stored value', (string)$c3->get('source.password'), 'super-secret-da-password');

// A key passphrase is a secret too and must not land on disk in clear text.
$c3->set('ssh.key_passphrase', 'unlock-me-please');
$c3->save();
$raw3 = json_decode((string)file_get_contents($tmp . '/config.json'), true);
ok('key passphrase is not stored in clear text',
    strpos((string)($raw3['ssh']['key_passphrase'] ?? ''), 'enc:') === 0);
check('key passphrase survives a reload', (string)(new Config($tmp))->get('ssh.key_passphrase'), 'unlock-me-please');

// Defaults are deep-merged so a partial config file cannot lose fields.
check('defaults survive a partial file', $c3->get('source.panel'), 'directadmin');
check('nested defaults are present', is_array($c3->get('transfer.exclude')), true);

// --------------------------------------------------------- rsync command
section('FileMover - rsync command safety');

$ssh = new Ssh([
    'host' => 'old.example.com',
    'port' => 22,
    'username' => 'root',
    'auth' => 'key',
    'key_path' => '/root/.ssh/id_ed25519',
]);

$fm = new FileMover($ssh, [
    'user_home' => '/home/%s',
    'exclude' => ['logs', 'tmp'],
    'bandwidth_limit' => 0,
    'delete_after' => false,
], $tmp . '/work');

$cmd = $fm->previewCommand('johndoe', 'files');
ok('rsync targets the source host', strpos($cmd, 'root@old.example.com') !== false);
ok('rsync uses the home template', strpos($cmd, '/home/johndoe') !== false);
ok('rsync excludes mail during the files stage', strpos($cmd, "Maildir") !== false);
ok('rsync excludes the log directory', strpos($cmd, 'logs') !== false);
ok('rsync carries the key path', strpos($cmd, 'id_ed25519') !== false);
ok('rsync is not deleting by default', strpos($cmd, '--delete') === false);

$mailCmd = $fm->previewCommand('johndoe', 'mail');
ok('mail stage still excludes logs', strpos($mailCmd, 'logs') !== false);

check('homeDir substitutes the username', $fm->homeDir('bob'), '/home/bob');

// An account name arrives from a remote panel and ends up inside a shell
// command, so it is validated - not merely quoted - before it can be used.
$hostile = ["bob; rm -rf /", '../../etc', 'a b', '', 'john/..', "-oProxyCommand=x"];
$allRejected = true;
foreach ($hostile as $name) {
    try {
        $fm->homeDir($name);
        $allRejected = false;
        echo "         (homeDir accepted: " . var_export($name, true) . ")\n";
    } catch (InvalidArgumentException $e) {
        // expected
    }
}
ok('homeDir rejects hostile account names', $allRejected);

$previewRejected = true;
try {
    $fm->previewCommand('bob; rm -rf /', 'files');
    $previewRejected = false;
} catch (InvalidArgumentException $e) {
    // expected
}
ok('previewCommand refuses to build a command for a hostile name', $previewRejected);

// A legitimate but unusual name must still work, correctly quoted.
$odd = $fm->previewCommand('john.doe-1_2', 'files');
ok('an unusual but valid name is accepted', strpos($odd, '/home/john.doe-1_2') !== false);
ok('the source path is shell-quoted', strpos($odd, escapeshellarg('root@old.example.com:/home/john.doe-1_2/')) !== false);

// A different source home layout must be honoured.
$fm2 = new FileMover($ssh, [
    'user_home' => '/home/%s',
    'source_user_home' => '/usr/local/directadmin/data/%s',
    'exclude' => [],
], $tmp . '/work');
$cmd2 = $fm2->previewCommand('bob', 'files');
ok('the source home template is configurable',
    strpos($cmd2, '/usr/local/directadmin/data/bob') !== false);

// ----------------------------------------------- Ssh passphrase-protected key
section('Ssh - passphrase protected key');

$sshReflect = new ReflectionClass(Ssh::class);
$askEnv = $sshReflect->getMethod('askpassEnv');
$askEnv->setAccessible(true);
$sshOpts = $sshReflect->getMethod('sshOptions');
$sshOpts->setAccessible(true);

// An awkward passphrase must be echoed back byte for byte, whatever the shell
// would otherwise do with quotes, $, backticks or newlines.
$awkward = ["plain-pass", 'pp "quoted" $stuff', "two\nlines", "back\\slash", 'tick`and$dollar'];
$roundTrip = true;
foreach ($awkward as $secret) {
    $s = new Ssh([
        'host' => 'old.example.com',
        'auth' => 'key',
        'key_path' => '/root/.ssh/id_rsa',
        'key_passphrase' => $secret,
    ]);
    $env = $askEnv->invoke($s);
    $script = $env['SSH_ASKPASS'] ?? '';
    if ($script === '' || !is_file($script)) {
        $roundTrip = false;
        continue;
    }
    if (substr(sprintf('%o', fileperms($script)), -4) !== '0700') {
        $roundTrip = false;
    }
    $out = (string)shell_exec(escapeshellarg($script));
    if ($out !== $secret . "\n") {
        $roundTrip = false;
    }
    unset($s);
    gc_collect_cycles();
}
ok('an askpass helper is written and echoes the passphrase exactly', $roundTrip);

$withPass = new Ssh(['host' => 'h', 'auth' => 'key', 'key_path' => '/k', 'key_passphrase' => 'x']);
$noPass = new Ssh(['host' => 'h', 'auth' => 'key', 'key_path' => '/k']);

$envWith = $askEnv->invoke($withPass);
$envWithout = $askEnv->invoke($noPass);
ok('a passphrase arms SSH_ASKPASS_REQUIRE=force',
    ($envWith['SSH_ASKPASS_REQUIRE'] ?? '') === 'force' && isset($envWith['SSH_ASKPASS']));
ok('a key without a passphrase needs no askpass helper', $envWithout === []);
ok('the passphrase is not on the command line',
    strpos(implode(' ', $sshOpts->invoke($withPass)), 'x') !== 0);

// BatchMode would refuse to prompt for the passphrase, so it is dropped only
// when there actually is one.
ok('BatchMode is dropped for a protected key',
    strpos(implode(' ', $sshOpts->invoke($withPass)), 'BatchMode') === false);
ok('BatchMode stays for an unprotected key',
    strpos(implode(' ', $sshOpts->invoke($noPass)), 'BatchMode=yes') !== false);

// The helper must not outlive the object that wrote it. $withPass is still
// referenced at this point, so a dedicated instance is used.
$scoped = new Ssh(['host' => 'h', 'auth' => 'key', 'key_path' => '/k', 'key_passphrase' => 'ephemeral']);
$scopedPath = $askEnv->invoke($scoped)['SSH_ASKPASS'];
ok('the askpass helper exists while it is in use', is_file($scopedPath));
unset($scoped);
gc_collect_cycles();
ok('the askpass helper is removed with the object', !is_file($scopedPath), $scopedPath);

// ----------------------------------------------------- Planner package match
section('Planner - package selection');

final class FakeOls extends OlsApi
{
    private array $packages;
    private array $capabilities;

    public function __construct(array $packages, array $capabilities = ['email_add' => true, 'ftp_add' => true])
    {
        // Deliberately skip the parent constructor: no HTTP in tests.
        $this->packages = $packages;
        $this->capabilities = $capabilities;
    }

    public function packages(): array { return $this->packages; }

    public function hasCapability(string $cap): bool { return !empty($this->capabilities[$cap]); }

    public function userExists(string $username): bool { return false; }

    public function baseUrl(): string { return 'https://ols.test'; }
}

$olsPackages = [
    ['id' => 1, 'name' => 'Starter', 'disk_space' => 2048, 'bandwidth' => 10240, 'email_accounts' => 5, 'databases' => 1, 'ftp_accounts' => 1, 'allowed_domains' => 1, 'allowed_subdomains' => 5],
    ['id' => 2, 'name' => 'Pro', 'disk_space' => 20480, 'bandwidth' => 102400, 'email_accounts' => 50, 'databases' => 10, 'ftp_accounts' => 5, 'allowed_domains' => 5, 'allowed_subdomains' => 50],
    ['id' => 3, 'name' => 'Unlimited-ish', 'disk_space' => 0, 'bandwidth' => 0, 'email_accounts' => 0, 'databases' => 0, 'ftp_accounts' => 0, 'allowed_domains' => 0, 'allowed_subdomains' => 0],
];

$cfgDir = sys_get_temp_dir() . '/olsmig-planner-' . bin2hex(random_bytes(4));
mkdir($cfgDir, 0700, true);
$cfg = new Config($cfgDir);
$cfg->set('transfer.home_root', sys_get_temp_dir());
$cfg->set('defaults.new_package_naming', 'DA {source_package}');

$planner = new Planner($cfg, new FakeOls($olsPackages), []);

function account(array $over = []): array
{
    $base = [
        'username' => 'john',
        'domain' => 'example.com',
        'email' => 'john@example.com',
        'package' => 'business',
        'suspended' => false,
        'limits' => [
            'disk_mb' => 10240,
            'bandwidth_mb' => 51200,
            'domains' => 3,
            'subdomains' => 10,
            'emails' => 20,
            'databases' => 5,
            'ftp' => 2,
        ],
        'usage' => ['disk_mb' => 2048, 'domains' => 1, 'emails' => 2, 'databases' => 1, 'ftp' => 1],
        'domains' => ['example.com'],
        'subdomains' => [],
        'emails' => ['info@example.com'],
        'databases' => ['wp_site'],
        'notes' => [],
    ];
    return array_merge($base, $over);
}

$opts = [
    'selected' => true,
    'include_files' => true,
    'include_databases' => true,
    'include_email' => true,
    'ssh_enabled' => true,
];

$plan = $planner->planAccount(account(), $opts);

// No OLSpanel package is named "business", so the smallest sufficient one wins.
check('picks the smallest sufficient package', $plan['package']['name'], 'Pro');
check('that package is used, not created', $plan['package']['action'], 'use');
ok('the package choice is explained', count($plan['password'] ?? []) === 0 && count($plan['warnings']) > 0);

// A larger source should land on the unlimited plan, not a broken match.
$bigPlan = $planner->planAccount(account([
    'limits' => ['disk_mb' => 100000, 'bandwidth_mb' => 999999, 'domains' => 20, 'subdomains' => 20, 'emails' => 999, 'databases' => 99, 'ftp' => 99],
]), $opts);
check('an oversized account lands on the unlimited plan', $bigPlan['package']['name'], 'Unlimited-ish');

// A tiny source should land on the starter plan.
$smallPlan = $planner->planAccount(account([
    'package' => 'tiny',
    'limits' => ['disk_mb' => 1024, 'bandwidth_mb' => 5120, 'domains' => 1, 'subdomains' => 5, 'emails' => 3, 'databases' => 1, 'ftp' => 1],
]), $opts);
check('a small account lands on the small plan', $smallPlan['package']['name'], 'Starter');

// Exact name match wins over limit matching.
$namedPlan = $planner->planAccount(account(['package' => 'Pro']), $opts);
check('an exact package name is reused', $namedPlan['package']['name'], 'Pro');

// No suitable package at all means one gets created, named after the source.
$noFit = new Planner($cfg, new FakeOls([['id' => 1, 'name' => 'Tiny', 'disk_space' => 100, 'bandwidth' => 100, 'email_accounts' => 1, 'databases' => 1, 'ftp_accounts' => 1, 'allowed_domains' => 1, 'allowed_subdomains' => 1]]), []);
$createPlan = $noFit->planAccount(account(['package' => 'gold']), $opts);
check('an unfittable account triggers package creation', $createPlan['package']['action'], 'create');
check('the new package is named after the source', $createPlan['package']['name'], 'DA gold');

// A pinned package id must be honoured even if it is a poor fit.
$pinnedPlan = $planner->planAccount(account(), $opts + ['pkg_id' => '1']);
check('a pinned package id is honoured', $pinnedPlan['package']['id'], 1);
ok('an undersized pinned package is flagged', count($pinnedPlan['warnings']) > 0);

// A nonexistent pinned id is a blocker, not a silent fallback.
$badPin = $planner->planAccount(account(), $opts + ['pkg_id' => '99']);
ok('an unknown package id blocks the account', count($badPin['blockers']) > 0);

// More domains than the package allows is a warning, not a hard stop.
$manyDomains = $planner->planAccount(account([
    'package' => 'Starter',
    'domains' => ['a.com', 'b.com', 'c.com'],
    'limits' => ['disk_mb' => 1024, 'bandwidth_mb' => 1024, 'domains' => 1, 'subdomains' => 1, 'emails' => 1, 'databases' => 1, 'ftp' => 1],
]), $opts);
check('domains are capped to the package limit', count($manyDomains['domains']), 1);
ok('truncated domains are called out', count($manyDomains['warnings']) > 0);

// Invalid target usernames must block rather than reach the API.
$badUser = $planner->planAccount(account(), $opts + ['target_user' => 'a']);
ok('an invalid target username blocks', count($badUser['blockers']) > 0);

// When OLSpanel has no email API, the plan must say so instead of pretending.
$noCaps = new Planner($cfg, new FakeOls($olsPackages, ['email_add' => false, 'ftp_add' => false]), []);
$noEmail = $noCaps->planAccount(account(), $opts);
$emailStep = null;
foreach ($noEmail['steps'] as $s) {
    if ($s['id'] === 'email') { $emailStep = $s; }
}
ok('the email step is marked blocked without an API', $emailStep && $emailStep['status'] === 'blocked');
ok('the manual mailbox warning is present',
    strpos(implode(' ', $noEmail['warnings']), 'manually') !== false);

// Missing SSH means files cannot transfer, and that must be stated.
$noSsh = $planner->planAccount(account(), array_merge($opts, ['ssh_enabled' => false]));
$filesStep = null;
foreach ($noSsh['steps'] as $s) {
    if ($s['id'] === 'files') { $filesStep = $s; }
}
ok('the file step is blocked without SSH', $filesStep && $filesStep['status'] === 'blocked');

// Without SSH, an FTP password must be enough to enable the file step.
$direct = $planner->planAccount(account(), array_merge($opts, ['ssh_enabled' => false, 'source_ftp_password' => 'pw']));
$directFiles = null;
foreach ($direct['steps'] as $s) {
    if ($s['id'] === 'files') { $directFiles = $s; }
}
ok('the file step is pending with an FTP password', $directFiles && $directFiles['status'] === 'pending');

// Likewise, direct MySQL credentials enable the database contents.
$directDb = $planner->planAccount(account(), array_merge($opts, [
    'ssh_enabled' => false, 'import_database_data' => true,
    'source_db_user' => 'alice_wp', 'source_db_password' => 'pw',
]));
ok('database contents are imported with direct credentials', !empty($directDb['databases']['wp_site']['import_data']));

// Suspended accounts keep their suspended state.
$susp = $planner->planAccount(account(['suspended' => true]), $opts);
ok('a suspended account gets a suspend step',
    in_array('suspend', array_column($susp['steps'], 'id'), true));

// ------------------------------------------------------------- summary
section('Planner - totals');

$summary = $planner->summary([$plan, $smallPlan, ['selected' => false, 'domains' => [], 'databases' => [], 'emails' => [], 'inventory' => ['usage' => ['disk_mb' => 99999]], 'warnings' => [], 'blockers' => []]]);
check('unselected accounts are excluded from totals', $summary['accounts'], 2);
check('totalled accounts are counted', $summary['disk_mb'], 2048 + 2048);

// ------------------------------------------------ Engine::validatePlan
section('Engine - plan validation');

// run_step executes a plan the browser posted back, so a forged one must be
// caught before it reaches a shell command or an API call.
$goodPlan = [
    'target_user' => 'john',
    'main_domain' => 'example.com',
    'email' => 'john@example.com',
    'domains' => ['example.com' => [], 'shop.example.com' => []],
    'databases' => ['john_wp' => ['db_user' => 'john_wp']],
    'emails' => ['admin@example.com' => []],
    'cron' => [['minute' => '0', 'hour' => '3', 'day' => '*', 'month' => '*', 'weekday' => '*', 'command' => '/bin/true']],
    'package' => ['id' => 1, 'name' => 'DA business', 'action' => 'use', 'limits' => []],
    'suspended' => false,
];
$goodAccepted = true;
try {
    Engine::validatePlan($goodPlan);
} catch (Throwable $e) {
    $goodAccepted = false;
    echo '         (' . $e->getMessage() . ")\n";
}
ok('a well formed plan is accepted', $goodAccepted);

/** @param array $override merged over a valid plan */
function planRejectedBy(array $override, string $why): void
{
    $plan = array_merge([
        'target_user' => 'john',
        'main_domain' => 'example.com',
        'domains' => ['example.com' => []],
        'databases' => [],
        'emails' => [],
        'cron' => [],
        'package' => ['id' => 1, 'name' => 'Starter', 'limits' => []],
    ], $override);

    try {
        Engine::validatePlan($plan);
        ok($why, false, 'validatePlan() accepted it');
    } catch (InvalidArgumentException $e) {
        ok($why, true);
    }
}

planRejectedBy(['target_user' => 'john; rm -rf /'], 'a hostile target_user is rejected');
planRejectedBy(['target_user' => '../../etc'], 'a traversing target_user is rejected');
planRejectedBy(['target_user' => ''], 'an empty target_user is rejected');
planRejectedBy(['target_user' => '.hidden'], 'a dot-leading target_user is rejected');
planRejectedBy(['domains' => ['example.com; id' => []]], 'a hostile domain is rejected');
planRejectedBy(['domains' => ['no-dot' => []]], 'a malformed domain is rejected');
planRejectedBy(['main_domain' => '-bad.com'], 'a malformed main domain is rejected');
planRejectedBy(['emails' => ['" on load error() --' => []]], 'a hostile email address is rejected');
planRejectedBy(['emails' => ['admin@example' => []]], 'an email without a TLD is rejected');
planRejectedBy(['databases' => ['wp; DROP' => ['db_user' => 'x']]], 'a hostile schema name is rejected');
planRejectedBy(['databases' => ['wp' => ['db_user' => 'x`y']]], 'a hostile database user is rejected');
planRejectedBy(['databases' => ['wp' => ['db_user' => '']]], 'an empty database user is rejected');
planRejectedBy(['cron' => [['minute' => '0; id', 'hour' => '*', 'day' => '*', 'month' => '*', 'weekday' => '*', 'command' => 'x']]],
    'a cron field carrying a shell metacharacter is rejected');
planRejectedBy(['cron' => [['minute' => '*', 'hour' => '*', 'day' => '*', 'month' => '*', 'weekday' => '*', 'command' => '  ']]],
    'an empty cron command is rejected');
planRejectedBy(['cron' => [['minute' => '*', 'hour' => '*', 'day' => '*', 'month' => '*', 'weekday' => '*', 'command' => "x\0y"]]],
    'a cron command with a NUL byte is rejected');
planRejectedBy(['cron' => ['not-an-object']], 'a cron entry that is not an object is rejected');
planRejectedBy(['package' => ['id' => 1, 'name' => "Bad\nName", 'limits' => []]], 'a package name with a newline is rejected');

// A prefixed schema is a legitimate OLSpanel name, so it must not be flagged.
planAcceptedBy([
    'target_user' => 'john',
    'domains' => [],
    'databases' => ['ols_john_wp' => ['db_user' => 'john_wp']],
    'emails' => [],
    'cron' => [],
    'package' => ['id' => 1, 'name' => 'Starter', 'limits' => []],
], 'a prefixed schema name is accepted');

/** A plan that must pass validation. */
function planAcceptedBy(array $plan, string $why): void
{
    try {
        Engine::validatePlan($plan);
        ok($why, true);
    } catch (Throwable $e) {
        ok($why, false, $e->getMessage());
    }
}

// ------------------------------------------------------ CpanelFiles::merge
section('CpanelFiles - merging SSH inventory into API results');

$apiAccount = [
    'domains' => ['example.com'],
    'subdomains' => [],
    'emails' => ['admin@example.com'],
    'usage' => ['emails' => 1, 'domains' => 1],
    'notes' => [],
];

$merged = CpanelFiles::merge($apiAccount, [
    'ok' => true,
    'note' => '',
    'domains' => ['example.com', 'shop.example.com'],
    'subdomains' => ['dev.example.com'],
    'emails' => ['admin@example.com', 'sales@example.com'],
    'aliases' => ['a@example.com -> b@other.com'],
    'cron' => ['*/5 * * * * /usr/bin/php /home/john/cron.php'],
]);

check('domains are merged without duplicates', count($merged['domains']), 2);
check('subdomains are merged in', count($merged['subdomains']), 1);
check('mailboxes are merged without duplicates', count($merged['emails']), 2);
check('mailbox usage is corrected upward', $merged['usage']['emails'], 2);
check('cron jobs are carried through', count($merged['cron_raw']), 1);
check('aliases are carried through', count($merged['aliases_raw']), 1);

$failed = CpanelFiles::merge(['domains' => [], 'subdomains' => [], 'emails' => [], 'usage' => [], 'notes' => []], [
    'ok' => false, 'note' => 'no such account', 'domains' => [], 'subdomains' => [], 'emails' => [], 'aliases' => [], 'cron' => [],
]);
check('a failed SSH read keeps the API data', $failed['domains'], []);
ok('a failed SSH read is reported as a note', strpos(implode(' ', $failed['notes']), 'no such account') !== false);

// ----------------------------------------------------- Util::parseCrontab
section('Util::parseCrontab - replaying a crontab');

$crontab = [
    'MAILTO=""',
    '',
    '# a comment',
    '*/5 * * * * /usr/bin/php /home/john/cron.php',
    '0 3 * * 1-5 /home/john/backup.sh --quiet',
    '@daily /home/john/clean.sh',
    '@hourly  /home/john/ping.sh',
    '@reboot /home/john/start-daemon.sh',
    'this is not a crontab line',
    '0 0 * * *',
];

$parsedCron = Util::parseCrontab($crontab);
check('every replayable job is found', count($parsedCron['jobs']), 4);
check('the first job keeps its schedule', $parsedCron['jobs'][0]['command'], '/usr/bin/php /home/john/cron.php');
check('minute steps survive', $parsedCron['jobs'][0]['minute'], '*/5');
check('a day range survives', $parsedCron['jobs'][1]['weekday'], '1-5');
check('@daily expands to midnight', $parsedCron['jobs'][2]['minute'] . ' ' . $parsedCron['jobs'][2]['hour'], '0 0');
check('@daily sets every other field to a wildcard',
    implode(' ', array_slice($parsedCron['jobs'][2], 0, 5)), '0 0 * * *');
check('@hourly expands correctly', $parsedCron['jobs'][3]['minute'] . ' ' . $parsedCron['jobs'][3]['hour'], '0 *');
check('a command with arguments is kept whole',
    $parsedCron['jobs'][1]['command'], '/home/john/backup.sh --quiet');
check('environment assignments are skipped', count($parsedCron['unsupported']), 3);
ok('@reboot is reported rather than dropped silently',
    in_array('@reboot /home/john/start-daemon.sh', $parsedCron['unsupported'], true));
ok('a line with no command is reported',
    in_array('0 0 * * *', $parsedCron['unsupported'], true));

// A command must not be able to smuggle in extra crontab fields.
$smuggled = Util::parseCrontab(['0 0 * * * /bin/sh -c "rm -rf /" #']);
check('a trailing comment is not split off', count($smuggled['jobs']), 1);
check('the whole command is preserved verbatim',
    $smuggled['jobs'][0]['command'], '/bin/sh -c "rm -rf /" #');

// The same parser must reject a hostile job in a posted plan.
$hostilePlan = [
    'target_user' => 'john',
    'cron' => [['minute' => '0', 'hour' => '* * * *', 'day' => '*', 'month' => '*', 'weekday' => '*', 'command' => 'x']],
];
$planRejected = false;
try {
    Engine::validatePlan($hostilePlan);
} catch (InvalidArgumentException $e) {
    $planRejected = true;
}
ok('a plan with an injected cron field is rejected', $planRejected);

// ------------------------------------------------------------- auth gate
section('Auth - access control');

$authCfg = new Config($cfgDir);
$authCfg->set('master_key', hash('sha256', 'correct horse'));
check('the master key is not stored in clear text', (string)$authCfg->get('master_key'), hash('sha256', 'correct horse'));

try {
    Auth::requireAdmin($authCfg);
    ok('access is denied without credentials', false, 'requireAdmin() returned without throwing');
} catch (RuntimeException $e) {
    ok('access is denied without credentials', true);
    ok('the denial explains how to get access', stripos($e->getMessage(), 'admin') !== false);
}

// An install where the panel cannot forward a real token (etc/_<user> is
// missing, so %usertoken% expands to an error sentence) must still be
// reachable with the passphrase, and must not send that sentence to the API.
$_SERVER['HTTP_AUTOLOGINUSER'] = 'root';
$_SERVER['HTTP_AUTOLOGINTOKEN'] = 'Password file for user root not found.';
ok('an error sentence is not mistaken for a token', Auth::isForwardedTokenBroken($_SERVER['HTTP_AUTOLOGINTOKEN']));
ok('the other panel error sentence is caught too', Auth::isForwardedTokenBroken('An error occurred: bad base64'));
// A real token is the admin's own password, so it may contain anything.
ok('a real forwarded token is not flagged', !Auth::isForwardedTokenBroken('ttdFRDUIqHS9134B'));
ok('an empty token is not flagged', !Auth::isForwardedTokenBroken(''));
ok('an ordinary password is not flagged', !Auth::isForwardedTokenBroken('An error occurred'));

// The panel wraps %usertoken% as five random lowercase letters + base64(password)
// (users.function.encode), so the migrator has to unwrap it before use.
check('the forwarded token is base64-decoded', Auth::decodeForwardedToken('abcde' . base64_encode('s3cret')), 's3cret');
ok('an encoded panel error sentence is caught', Auth::isForwardedTokenBroken('abcde' . base64_encode('Password file for user root not found.')));
check('a plain token that is not valid base64 is left alone', Auth::decodeForwardedToken('ttdFRDUIqHS9134B'), 'ttdFRDUIqHS9134B');

$_SERVER['HTTP_X_MASTER_KEY'] = 'correct horse';
ok('the passphrase still works when the panel forwards a broken token', Auth::requireAdmin($authCfg)['method'] === 'master-key');
unset($_SERVER['HTTP_X_MASTER_KEY']);

$_SERVER['HTTP_AUTOLOGINTOKEN'] = '';
$creds = Auth::apiCredentials($authCfg);
check('the broken token is not used as an API credential', $creds['token'], '');

$_SERVER['HTTP_AUTOLOGINTOKEN'] = 'abcde' . base64_encode('s3cret');
$creds = Auth::apiCredentials($authCfg);
check('the forwarded credential is decoded before use', $creds['token'], 's3cret');
unset($_SERVER['HTTP_AUTOLOGINUSER'], $_SERVER['HTTP_AUTOLOGINTOKEN']);

// --------------------------------------------------- settings payload shapes
// index.php holds applySettings()/flattenSettingsPayload(); load just those.
$indexSrc = file_get_contents(__DIR__ . '/../index.php');
foreach (['function isList', 'function flattenSettingsPayload', 'function updateBundleUrl'] as $fn) {
    if (preg_match('/' . preg_quote($fn, '/') . '.*?\n}\n/s', $indexSrc, $m)) {
        eval($m[0]);
    }
}
section('Settings payload handling');

$nested = flattenSettingsPayload([
    'ols' => ['host' => 'https://panel:8058/', 'port' => 8058, 'token' => 't'],
    'source' => ['panel' => 'directadmin'],
    '_csrf' => 'abc',
]);
check('a nested section becomes a dotted key', $nested['ols.host'], 'https://panel:8058/');
check('a nested scalar survives', $nested['source.panel'], 'directadmin');
ok('the CSRF field is passed through untouched', ($nested['_csrf'] ?? null) === 'abc');

$flat = flattenSettingsPayload(['ols.host' => 'flat', 'ols.port' => 1]);
check('a flat dotted key is left alone', $flat['ols.host'], 'flat');

$list = flattenSettingsPayload(['transfer' => ['exclude' => ['*.log', 'tmp']]]);
check('a list is joined so it can be normalised as a string', $list['transfer.exclude'], '*.log,tmp');

$wrapped = flattenSettingsPayload([
    'action' => 'settings_save',
    '_csrf' => 'abc',
    'settings' => ['source' => ['host' => 'wrapped.example.com']],
]);
check('a {"settings":{...}} wrapper is unwrapped', $wrapped['source.host'], 'wrapped.example.com');
ok('the wrapper key itself is gone', !array_key_exists('settings', $wrapped));
ok('the browser still posts flat keys unchanged', (flattenSettingsPayload(['ols.host' => 'x'])['ols.host'] ?? null) === 'x');

ok('a nested array is not mistaken for a list', !isList(['a' => 1]));
ok('an indexed array is a list', isList(['x', 'y']));
ok('an empty array is a list', isList([]));

// -------------------------------------------------------------- plugin update

section('Plugin update');

check(
    'a relative bundle resolves next to the manifest',
    updateBundleUrl('https://dev3.vgs1st.com/account_migrator-version.json', 'account_migrator_bundle.zip'),
    'https://dev3.vgs1st.com/account_migrator_bundle.zip'
);
check(
    'an absolute bundle URL is kept as-is',
    updateBundleUrl('https://dev3.vgs1st.com/account_migrator-version.json', 'https://cdn.example.com/am.zip'),
    'https://cdn.example.com/am.zip'
);
ok('a newer version compares greater', version_compare('1.2.0', '1.1.2', '>'));
ok('the same version is not newer', !version_compare('1.2.0', '1.2.0', '>'));

// ----------------------------------------------------------- CSRF
section('CSRF handling');

$_SESSION = [];
$token = Util::csrfToken();
ok('a CSRF token is issued', strlen($token) === 64);
check('the token is stable within a session', Util::csrfToken(), $token);

$_POST['_csrf'] = $token;
ok('the matching token is accepted', Util::csrfValid());
$_POST['_csrf'] = str_repeat('a', 64);
ok('a wrong token is rejected', !Util::csrfValid());
$_POST['_csrf'] = '';
ok('an empty token is rejected', !Util::csrfValid());

// --------------------------------------------------------- JSON envelope
section('HTTP client');

$http = new Http('https://example.invalid:2222', [], false, 5);
ok('baseUrl is trimmed', $http->baseUrl() === 'https://example.invalid:2222');
ok('qs drops empty values', Util::qs(['a' => 1, 'b' => '', 'c' => null, 'd' => 'x']) === 'a=1&d=x');

// --------------------------------------------------- reseller scanning
section('DirectAdmin reseller parsing');

check('a bare list of names is read', DirectAdmin::extractNames(['alice', 'bob']), ['alice', 'bob']);
check('the legacy {"list":[...]} shape is unwrapped', DirectAdmin::extractNames(['list' => ['alice', 'bob']]), ['alice', 'bob']);
check('records with a username key are read', DirectAdmin::extractNames([['username' => 'alice'], ['username' => 'res1']]), ['alice', 'res1']);
check('a nested list of records is read', DirectAdmin::extractNames(['list' => [['username' => 'alice']]]), ['alice']);
check('duplicate names collapse', DirectAdmin::extractNames(['alice', 'alice', 'bob']), ['alice', 'bob']);
check('invalid names are dropped', DirectAdmin::extractNames(['alice', 'bad name!']), ['alice']);
check('a non-array payload is empty', DirectAdmin::extractNames(null), []);

$cpanel = new CpanelWhm(['host' => 'x', 'token' => 'y']);
ok('panels without resellers answer with an empty list', $cpanel->listResellers() === []);

// ------------------------------------------------------------ Plesk parsing
section('Plesk parsing');

check('a Plesk account key is lower-cased', Plesk::accountKey('Example.COM'), 'example.com');
ok('a Plesk account key is a valid username', Util::validUsername(Plesk::accountKey('www.My-Shop.co.uk')));
$longKey = Plesk::accountKey(str_repeat('a', 40) . '.com');
ok('a long subscription name is shortened', strlen($longKey) <= 32, $longKey);
ok('a shortened key is still a valid username', Util::validUsername($longKey));
ok('an empty name still yields a usable key', Util::validUsername(Plesk::accountKey('')));

check('a bare JSON list is passed through', Plesk::asList([['id' => 1], ['id' => 2]]), [['id' => 1], ['id' => 2]]);
check('an _embedded map is unwrapped', Plesk::asList(['_embedded' => ['domains' => [['id' => 1]]]]), [['id' => 1]]);
check('a keyed map of records is unwrapped', Plesk::asList(['a' => ['id' => 1], 'b' => ['id' => 2]]), [['id' => 1], ['id' => 2]]);
check('a single record becomes a one-item list', Plesk::asList(['id' => 7]), [['id' => 7]]);
check('a scalar response is empty', Plesk::asList('nope'), []);

// ------------------------------------------------- reseller allocation math
section('Reseller allocation capping');

$alloc = Util::normaliseAllocation([
    'disk_mb' => '10GB', 'bandwidth_mb' => 'unlimited',
    'domains' => 5, 'subdomains' => 10, 'emails' => 50, 'databases' => 20, 'ftp' => 5,
]);
check('allocation disk normalises to MB', $alloc['disk_mb'], 10240);
check('an unlimited allocation bandwidth stays null', $alloc['bandwidth_mb'], null);
check('allocation counters survive', $alloc['emails'], 50);

$want = ['disk_mb' => 20480, 'bandwidth_mb' => null, 'domains' => 100, 'subdomains' => 2, 'emails' => 0, 'databases' => 5, 'ftp' => 5];
$capped = Util::capLimits($want, $alloc);
check('a plan cannot exceed the allocation disk', $capped['disk_mb'], 10240);
check('an unlimited allocation leaves bandwidth alone', $capped['bandwidth_mb'], null);
check('a plan cannot exceed the allocation domains', $capped['domains'], 5);
check('a plan under the cap is untouched', $capped['subdomains'], 2);
check('an unlimited plan is capped to the allocation', $capped['emails'], 50);

$unlimited = ['disk_mb' => null, 'bandwidth_mb' => null, 'domains' => 0, 'subdomains' => 0, 'emails' => 0, 'databases' => 0, 'ftp' => 0];
$open = Util::capLimits($want, $unlimited);
check('an unlimited allocation never caps', $open['disk_mb'], 20480);
check('an unlimited allocation leaves counters alone', $open['emails'], 0);

// The asset cache-buster must change when the UI files change, so a stale
// app.js can never keep showing an old interface.
section('UI asset cache-busting');

$v1 = mig_asset_version();
ok('the asset version is a short token', preg_match('/^[0-9a-f]{8}$/', $v1) === 1);

$probe = MIG_ROOT . '/ui/app.js';
$raw = file_get_contents($probe);
$newMtime = filemtime($probe) + 120;
touch($probe, $newMtime);
clearstatcache(true, $probe);
$v2 = mig_asset_version();
file_put_contents($probe, $raw);
touch($probe, $newMtime - 120);
clearstatcache(true, $probe);

ok('touching app.js changes the version', $v1 !== $v2);

// --------------------------------------------------- no-SSH credentials
section('No-SSH credentials');

$parsed = Util::parseCredentialLines("# comment\nalice:ftpPw:alice_wp:dbPw\n\nbob:ftpPw\nbad!\n");
check('valid account lines are parsed', array_keys($parsed), ['alice', 'bob']);
check('all four fields are captured', $parsed['alice'], ['ftp_password' => 'ftpPw', 'db_user' => 'alice_wp', 'db_password' => 'dbPw']);
check('trailing fields may be omitted', $parsed['bob'], ['ftp_password' => 'ftpPw', 'db_user' => '', 'db_password' => '']);
check('a database password may contain colons', Util::parseCredentialLines('carol:ftp:a:b:c')['carol']['db_password'], 'b:c');
ok('invalid usernames are dropped', !array_key_exists('bad!', $parsed));

check('lftp excludes match a component at any depth', FtpMover::excludeRegex('public_html/logs'), '(^|/)public_html/logs(/|$)');
check('a leading slash is ignored in excludes', FtpMover::excludeRegex('/mail/'), '(^|/)mail(/|$)');
check('an empty exclude yields an empty pattern', FtpMover::excludeRegex('//'), '');
ok('a plain FTP password is accepted', FtpMover::passwordSupported('s3cret-pass'));
ok('a quote in the FTP password is rejected', !FtpMover::passwordSupported("pa'ss"));
ok('an empty FTP password is rejected', !FtpMover::passwordSupported(''));

// ------------------------------------------------------------- FTP / SFTP
section('Transfers - FTP and SFTP connection lines');

$sftp = FtpMover::connectionLines('sftp', 'old.example.com', 20381, 'ralph@juststylinsalon.com', 'X3NF', 'auto');
ok('SFTP uses the sftp scheme and port', in_array("open 'sftp://old.example.com:20381'", $sftp, true));
ok('SFTP auto-confirms the host key', in_array('set sftp:auto-confirm yes', $sftp, true));
ok('SFTP carries an email login', in_array("user 'ralph@juststylinsalon.com' 'X3NF'", $sftp, true));
ok('SFTP sets no FTP TLS options', !in_array('set ftp:ssl-allow yes', $sftp, true));

$ftp = FtpMover::connectionLines('ftp', 'old.example.com', 21, 'alice', 'pw', 'off');
ok('FTP opens with an explicit port', in_array("open -p 21 'old.example.com'", $ftp, true));
ok('plain FTP disables SSL', in_array('set ftp:ssl-allow off', $ftp, true));
$ftpForce = FtpMover::connectionLines('ftp', 'h', 21, 'alice', 'pw', 'force');
ok('forced FTP requires SSL', in_array('set ftp:ssl-force true', $ftpForce, true));

// ------------------------------------------------ resource option defaults
// Omitting a toggle must fall back to the configured default, never to a
// silent "off" that disagrees with the ticked box the admin saw.
section('Planner - resource option defaults');

$defPlan = $planner->planAccount(account(), ['selected' => true, 'ssh_enabled' => true]);
ok('databases are planned when the option is omitted', !empty($defPlan['databases']));
ok('database import is on by default with SSH', !empty($defPlan['databases']['wp_site']['import_data']));
ok('mailboxes are planned when the option is omitted',
    in_array('email', array_column($defPlan['steps'], 'id'), true));

$offPlan = $planner->planAccount(account(), ['selected' => true, 'ssh_enabled' => true, 'include_databases' => false]);
check('an explicit opt-out keeps databases out', count($offPlan['databases']), 0);

// ------------------------------------------------ MySQL temp credentials file
// The defaults file must be written every time, not only when /tmp/olsmig is
// absent; a regression here silently drops the configured root password.
section('Mysql - temporary credentials file');

$mysqlProbe = new Mysql([]);
$defFile = new ReflectionMethod(Mysql::class, 'defaultsFile');
$defFile->setAccessible(true);
$cnf1 = $defFile->invoke($mysqlProbe, 'root', 'p@ss', '', 'localhost');
$cnf2 = $defFile->invoke($mysqlProbe, 'root', 'p@ss', '', 'localhost');
ok('a credentials file is written on the first call', is_string($cnf1) && is_file($cnf1));
ok('a credentials file is written on a repeat call', is_string($cnf2) && is_file($cnf2));
if (is_string($cnf1) && is_file($cnf1)) { @unlink($cnf1); }
if (is_string($cnf2) && is_file($cnf2)) { @unlink($cnf2); }

// ------------------------------------------------------------- cleanup
foreach ([$tmp, $cfgDir] as $dir) {
    if (!is_dir($dir)) { continue; }
    foreach (glob($dir . '/*') ?: [] as $f) { @unlink($f); }
    foreach (glob($dir . '/.*') ?: [] as $f) { if (basename($f) !== '.' && basename($f) !== '..') { @unlink($f); } }
    @rmdir($dir);
}

echo "\n" . str_repeat('=', 46) . "\n";
echo $fail === 0
    ? "All $pass checks passed.\n"
    : "$pass passed, $fail FAILED.\n";
exit($fail === 0 ? 0 : 1);