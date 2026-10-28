<?php
/**
 * Config - persistent settings store.
 *
 * Secrets (panel passwords, API tokens, SSH keys) are encrypted at rest with
 * AES-256-CBC using a key stored in a 0600 key file next to the config.
 */

declare(strict_types=1);

class Config
{
    /**
     * Sentinel the UI receives instead of a stored secret. Sending it back
     * means "keep whatever is already stored".
     */
    public const MASK = '__set__';

    /** Keys whose values are encrypted on disk. */
    private const SECRET_KEYS = [
        'source.password',
        'source.token',
        'ols.password',
        'ols.token',
        'ssh.password',
        'ssh.key_passphrase',
        'mysql.root_password',
    ];

    private string $dir;
    private string $file;
    private string $keyFile;
    private array $data;

    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, '/');
        $this->file = $this->dir . '/config.json';
        $this->keyFile = $this->dir . '/.key';
        $this->data = $this->defaults();
        $this->load();
    }

    private function defaults(): array
    {
        return [
            'source' => [
                'panel' => 'directadmin',      // directadmin | cpanel
                'host' => '',
                'port' => 2222,                // 2222 = DirectAdmin, 2087 = WHM
                'tls' => true,
                'verify_tls' => true,           // verify source panel certificates
                'username' => 'admin',
                'password' => '',
                'token' => '',                 // cPanel: WHM API token or root password
                'reseller' => '',              // limit the scan to one reseller's users
                // Direct (no-SSH) access. FTP/SFTP moves files, a direct MySQL
                // connection dumps databases, both with per-account credentials.
                'ftp_protocol' => 'ftp',       // ftp | sftp
                'ftp_port' => 21,              // FTP 21, SFTP 22 (or a custom port)
                'ftp_tls' => 'auto',           // auto | force | off (FTP only)
                // Optional login used for FTP/SFTP when it differs from the
                // account name (e.g. an email SFTP login). {user}/{domain} are
                // replaced with the source account and its main domain.
                'ftp_login' => '',
                'db_host' => '',               // '' = same host as the panel
                'db_port' => 3306,
            ],
            'ssh' => [
                'enabled' => false,
                'host' => '',
                'port' => 22,
                'username' => 'root',
                'auth' => 'key',               // key | password
                'key_path' => '',
                'key_passphrase' => '',
                'password' => '',
                'strict_host_key' => false,
            ],
            'ols' => [
                // Leave host empty to reuse the credentials forwarded by the panel.
                'host' => '',
                'port' => null,
                'username' => '',
                'password' => '',
                'token' => '',
                'schema' => 'http',
            ],
            'transfer' => [
                'home_root' => '/home',
                'user_home' => '/home/%s',
                // Home directory on the source server. Defaults to the same
                // layout as the destination, which is right for DirectAdmin and
                // cPanel installs that both live under /home.
                'source_user_home' => '/home/%s',
                'mail_dirs' => ['mail', 'Maildir'],
                'exclude' => [
                    '.cache', 'logs', 'tmp', 'backups',
                    'public_html/logs', 'public_html/old',
                ],
                'bandwidth_limit' => 0,   // 0 = unlimited; KB/s
                'transfer_timeout' => 0,  // 0 = no limit
                'delete_after' => false,
            ],
            'defaults' => [
                'php_version' => '8.2',
                'new_package_naming' => 'DA {source_package}',
                'password_length' => 14,
                'generate_databases' => true,
                'import_database_data' => true,
                'create_email_accounts' => true,
                'issue_ssl' => false,
            ],
            'mysql' => [
                // Local MySQL root access on the OLSpanel server.
                'auto_detect' => true,
                'socket' => '',
                'host' => 'localhost',
                'username' => 'root',
                'root_password' => '',
            ],
            'updates' => [
                // Manifest the "Plugin update" tab checks. It must be HTTPS.
                'manifest_url' => 'https://dev3.vgs1st.com/account_migrator-version.json',
            ],
            'capabilities' => [],   // probe results cache
            'installed_at' => null,
        ];
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
        }
        @chmod($this->dir, 0700);
    }

    private function key(): string
    {
        $this->ensureDir();
        if (is_file($this->keyFile)) {
            $raw = (string)@file_get_contents($this->keyFile);
            $bin = @hex2bin(trim($raw));
            if ($bin !== false && strlen($bin) === 32) {
                return $bin;
            }
        }
        $key = random_bytes(32);
        if (@file_put_contents($this->keyFile, bin2hex($key)) === false) {
            throw new RuntimeException('Cannot write the encryption key to ' . $this->keyFile . '.');
        }
        @chmod($this->keyFile, 0600);
        return $key;
    }

    private function load(): void
    {
        if (!is_file($this->file)) {
            return;
        }
        $raw = @file_get_contents($this->file);
        if ($raw === false || $raw === '') {
            return;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return;
        }
        $this->data = $this->merge($this->defaults(), $decoded);

        // Secrets live encrypted on disk but are held in clear text in memory
        // so every reader (adapters, transfers) just calls get().
        foreach (self::SECRET_KEYS as $path) {
            $val = $this->get($path);
            if (is_string($val) && $val !== '') {
                $this->set($path, $this->decrypt($val));
            }
        }
    }

    private function merge(array $base, array $override): array
    {
        foreach ($override as $k => $v) {
            if (is_array($v) && isset($base[$k]) && is_array($base[$k]) && !self::isList($v)) {
                $base[$k] = $this->merge($base[$k], $v);
            } else {
                $base[$k] = $v;
            }
        }
        return $base;
    }

    private static function isList(array $a): bool
    {
        return $a === [] || array_keys($a) === range(0, count($a) - 1);
    }

    private function encrypt(string $plain): string
    {
        $key = $this->key();
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($plain, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            return '';
        }
        return 'enc:' . base64_encode($iv . $cipher);
    }

    private function decrypt(string $stored): string
    {
        if (strpos($stored, 'enc:') !== 0) {
            return $stored;
        }
        $raw = base64_decode(substr($stored, 4), true);
        if ($raw === false || strlen($raw) <= 16) {
            return '';
        }
        $iv = substr($raw, 0, 16);
        $cipher = substr($raw, 16);
        $plain = openssl_decrypt($cipher, 'aes-256-cbc', $this->key(), OPENSSL_RAW_DATA, $iv);
        // Files written by older builds put a '|' between the IV and the
        // cipher text. Skip it so those configs keep working.
        if ($plain === false && isset($cipher[0]) && $cipher[0] === '|') {
            $plain = openssl_decrypt(substr($cipher, 1), 'aes-256-cbc', $this->key(), OPENSSL_RAW_DATA, $iv);
        }
        return $plain === false ? '' : $plain;
    }

    /** Dot-path getter: get('source.host'). */
    public function get(string $path, $default = null)
    {
        $node = $this->data;
        foreach (explode('.', $path) as $seg) {
            if (!is_array($node) || !array_key_exists($seg, $node)) {
                return $default;
            }
            $node = $node[$seg];
        }
        return $node;
    }

    public function set(string $path, $value): void
    {
        // A masked secret coming back from the UI means "leave it alone".
        if ($value === self::MASK && in_array($path, self::SECRET_KEYS, true)) {
            return;
        }

        $segs = explode('.', $path);
        $node = &$this->data;
        foreach ($segs as $i => $seg) {
            if ($i === count($segs) - 1) {
                $node[$seg] = $value;
                return;
            }
            if (!isset($node[$seg]) || !is_array($node[$seg])) {
                $node[$seg] = [];
            }
            $node = &$node[$seg];
        }
    }

    public function all(): array
    {
        return $this->data;
    }

    /**
     * Everything, including decrypted secrets. Internal use only - never hand
     * this to forUi()'s callers or write it anywhere but save().
     */
    public function resolved(): array
    {
        return $this->data;
    }

    /** Public settings for the UI: secrets are masked, never echoed back. */
    public function forUi(): array
    {
        $out = $this->data;
        foreach (self::SECRET_KEYS as $path) {
            $segs = explode('.', $path);
            $node = &$out;
            $last = array_pop($segs);
            foreach ($segs as $seg) {
                if (!isset($node[$seg]) || !is_array($node[$seg])) {
                    continue 2;
                }
                $node = &$node[$seg];
            }
            $has = isset($node[$last]) && is_string($node[$last]) && $node[$last] !== '';
            $node[$last] = $has ? self::MASK : '';
            unset($node);
        }
        return $out;
    }

    public function isSecretSet(string $path): bool
    {
        $v = $this->get($path);
        return is_string($v) && $v !== '' && $v !== self::MASK;
    }

    /**
     * Persist. Secrets are re-encrypted from clear text on the way out, so the
     * file on disk never holds anything readable.
     */
    public function save(): void
    {
        $this->ensureDir();
        if ($this->get('installed_at') === null) {
            $this->set('installed_at', gmdate('c'));
        }

        $out = $this->data;
        foreach (self::SECRET_KEYS as $path) {
            $val = $this->get($path);
            if (!is_string($val) || $val === '' || $val === self::MASK) {
                continue;
            }
            $enc = $this->encrypt($val);
            if ($enc === '') {
                throw new RuntimeException('Could not encrypt the value of ' . $path . '.');
            }
            $segs = explode('.', $path);
            $node = &$out;
            foreach ($segs as $seg) {
                $node = &$node[$seg];
            }
            $node = $enc;
            unset($node);
        }

        $json = json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('Could not encode the settings.');
        }
        $tmp = $this->file . '.tmp';
        if (@file_put_contents($tmp, $json) === false) {
            throw new RuntimeException('Could not write ' . $this->file . '.');
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $this->file)) {
            @unlink($tmp);
            throw new RuntimeException('Could not replace ' . $this->file . '.');
        }
        @chmod($this->file, 0600);
    }
}