<?php
/**
 * bootstrap - load everything, define shared runtime paths.
 */

declare(strict_types=1);

define('MIG_VERSION', '1.4.3');
define('MIG_DIR', __DIR__);
define('MIG_ROOT', dirname(__DIR__));

// Errors go to the migration log, never into the browser output.
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require_once __DIR__ . '/Util.php';
require_once __DIR__ . '/Log.php';
require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Http.php';
require_once __DIR__ . '/Auth.php';
require_once __DIR__ . '/Source/SourcePanel.php';
require_once __DIR__ . '/Source/DirectAdmin.php';
require_once __DIR__ . '/Source/CpanelWhm.php';
require_once __DIR__ . '/Source/CpanelFiles.php';
require_once __DIR__ . '/Source/Plesk.php';
require_once __DIR__ . '/Transfer/Ssh.php';
require_once __DIR__ . '/Transfer/Mysql.php';
require_once __DIR__ . '/Transfer/FileMover.php';
require_once __DIR__ . '/Transfer/FtpMover.php';
require_once __DIR__ . '/Transfer/DbMover.php';
require_once __DIR__ . '/Destination/OlsApi.php';
require_once __DIR__ . '/Planner.php';
require_once __DIR__ . '/Engine.php';

/**
 * Cache-busting token for the UI assets.
 *
 * The version string alone is not enough: it only changes when someone
 * remembers to bump it, and a stale app.js keeps showing the old interface.
 * The token therefore folds in each asset's mtime, so editing app.js or app.css
 * always changes the URL the browser is asked to fetch.
 */
function mig_asset_version(): string
{
    $parts = [MIG_VERSION];
    foreach (['ui/app.js', 'ui/app.css'] as $rel) {
        $path = MIG_ROOT . '/' . $rel;
        if (is_file($path)) {
            $parts[] = (string)@filemtime($path);
        }
    }
    return substr(hash('crc32b', implode('-', $parts)), 0, 8);
}

define('MIG_DATA_DIR', MIG_ROOT . '/data');
define('MIG_WORK_DIR', MIG_DATA_DIR . '/work');

/** Ensure the private data directories exist and are not web readable. */
function mig_prepare_dirs(): void
{
    foreach ([MIG_DATA_DIR, MIG_WORK_DIR] as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        @chmod($dir, 0700);
    }
    // Defence in depth: even if the web server serves this directory, nothing
    // inside it should be reachable.
    $guard = MIG_DATA_DIR . '/.htaccess';
    if (!is_file($guard)) {
        @file_put_contents($guard, "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    }
    $guard2 = MIG_WORK_DIR . '/.htaccess';
    if (!is_file($guard2)) {
        @file_put_contents($guard2, "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    }
    // index.html keeps the directory from being listed by servers that ignore
    // .htaccess, and stops a stray download of a dump in progress.
    foreach ([MIG_DATA_DIR, MIG_WORK_DIR] as $dir) {
        $idx = $dir . '/index.html';
        if (!is_file($idx)) {
            @file_put_contents($idx, "<!doctype html><title>403</title>\n");
        }
    }
}

mig_prepare_dirs();

/** Fatal error handler that keeps the UI responsive with a JSON error. */
set_exception_handler(static function (Throwable $e): void {
    Log::error('runtime', get_class($e) . ': ' . $e->getMessage());
    if (strpos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json') !== false || Util::isApiCall()) {
        Util::fail($e->getMessage(), 500);
    }
    echo '<div style="font:14px system-ui;padding:24px;color:#b91c1c">'
        . '<strong>Error:</strong> ' . Util::h($e->getMessage()) . '</div>';
    exit;
});