<?php
/**
 * Util - shared helpers.
 *
 * OLSpanel Account Migrator
 */

declare(strict_types=1);

class Util
{
    /** JSON response + exit. */
    public static function json(array $payload, int $status = 200): void
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store');
        }
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function ok(array $data = []): void
    {
        self::json(['ok' => true] + $data);
    }

    public static function fail(string $message, int $status = 400, array $extra = []): void
    {
        self::json(['ok' => false, 'error' => $message] + $extra, $status);
    }

    public static function h(?string $s): string
    {
        return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** Session + CSRF token for state-changing requests. */
    public static function csrfToken(): string
    {
        if (empty($_SESSION['_csrf'])) {
            $_SESSION['_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['_csrf'];
    }

    /**
     * The decoded request body, so a token posted as JSON can be found.
     * Set once by the entry point.
     */
    private static array $requestBody = [];

    public static function setRequestBody(array $body): void
    {
        self::$requestBody = $body;
    }

    public static function requestBody(): array
    {
        return self::$requestBody;
    }

    /** Returns true when the presented token matches the session token. */
    public static function csrfValid(): bool
    {
        $sent = (string)($_POST['_csrf']
            ?? self::$requestBody['_csrf']
            ?? $_SERVER['HTTP_X_CSRF_TOKEN']
            ?? '');
        $have = (string)($_SESSION['_csrf'] ?? '');
        return $have !== '' && $sent !== '' && hash_equals($have, $sent);
    }

    public static function requireCsrf(): void
    {
        if (!self::csrfValid()) {
            self::fail('Invalid or expired CSRF token. Reload the page.', 419);
        }
    }

    /**
     * Cryptographically strong password.
     * Always includes one character from each required class.
     */
    public static function genPassword(int $length = 14): string
    {
        $sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789', '!@#$%^&*-_=+?'];
        $all = implode('', $sets);
        $out = '';
        foreach ($sets as $set) {
            $out .= $set[random_int(0, strlen($set) - 1)];
        }
        for ($i = strlen($out); $i < $length; $i++) {
            $out .= $all[random_int(0, strlen($all) - 1)];
        }
        return str_shuffle($out);
    }

    /**
     * Normalise a disk/bandwidth value to megabytes.
     * Returns null for "unlimited".
     */
    public static function toMb($value): ?int
    {
        if ($value === null || $value === '' ) {
            return null;
        }
        if (is_bool($value)) {
            return $value ? null : 0;
        }
        if (is_int($value) || is_float($value)) {
            return $value <= 0 ? null : (int) round($value);
        }

        $str = strtolower(trim((string)$value));
        if ($str === '' || $str === 'unlimited' || $str === 'unlimited ' || $str === '-1') {
            return null;
        }
        $str = str_replace([' ', ','], '', $str);
        if (!preg_match('/^(-?[0-9]*\.?[0-9]+)([kmgtp]?)(i?b?)$/', $str, $m)) {
            return null;
        }
        $num = (float) $m[1];
        $mult = ['' => 1, 'k' => 1 / 1024, 'm' => 1, 'g' => 1024, 't' => 1048576, 'p' => 1073741824];
        if ($num <= 0) {
            return null;
        }
        return (int) round($num * $mult[$m[2]]);
    }

    public static function humanMb(?int $mb): string
    {
        if ($mb === null) {
            return 'unlimited';
        }
        if ($mb >= 1048576) {
            return rtrim(rtrim(number_format($mb / 1048576, 2), '0'), '.') . ' TB';
        }
        if ($mb >= 1024) {
            return rtrim(rtrim(number_format($mb / 1024, 2), '0'), '.') . ' GB';
        }
        return $mb . ' MB';
    }

    /** "unlimited" / 0 / null => 0 which OLSpanel treats as unlimited. */
    public static function limitValue($value): int
    {
        if ($value === null || $value === '' || $value === 'unlimited') {
            return 0;
        }
        $v = (int) $value;
        return $v < 0 ? 0 : $v;
    }

    public static function validUsername(string $u): bool
    {
        return (bool) preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/', $u);
    }

    public static function validDomain(string $d): bool
    {
        $d = trim($d);
        if ($d === '' || strlen($d) > 253) {
            return false;
        }
        return (bool) preg_match('/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/', $d);
    }

    public static function validHost(string $h): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/', $h);
    }

    public static function validEmail(string $e): bool
    {
        $e = trim($e);
        if (strlen($e) > 254) {
            return false;
        }
        return (bool) preg_match('/^[A-Za-z0-9._%+-]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/', $e);
    }

    /**
     * MySQL schema / user name.
     *
     * $allowDot covers schema names, where a prefix separator is normal; plain
     * MySQL user names cannot contain a dot.
     */
    public static function validIdentifier(string $s, bool $allowDot = false): bool
    {
        $max = 64;
        if (strlen($s) === 0 || strlen($s) > $max) {
            return false;
        }
        $pattern = $allowDot
            ? '/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/'
            : '/^[A-Za-z0-9_]+$/';
        return (bool) preg_match($pattern, $s);
    }

    /** Pick a free username based on a desired name. */
    public static function suggestUsername(string $desired, array $taken): string
    {
        $taken = array_map('strtolower', $taken);
        if (!in_array(strtolower($desired), $taken, true)) {
            return $desired;
        }
        $base = substr($desired, 0, 24);
        for ($i = 2; $i < 1000; $i++) {
            $candidate = $base . $i;
            if (self::validUsername($candidate) && !in_array(strtolower($candidate), $taken, true)) {
                return $candidate;
            }
        }
        return $base . random_int(100, 999);
    }

    public static function normaliseUrl(string $host, int $port, bool $tls = true, string $path = ''): string
    {
        $host = trim($host);
        if ($host === '' || preg_match('/[\s\/?#@]/', $host)) {
            throw new InvalidArgumentException('Invalid source host.');
        }
        $scheme = $tls ? 'https' : 'http';
        $url = $scheme . '://' . $host . ':' . $port;
        return rtrim($url, '/') . ($path !== '' ? '/' . ltrim($path, '/') : '');
    }

    /** Trim a string list. */
    public static function listOf(array $rows, string $key): array
    {
        $out = [];
        foreach ($rows as $row) {
            if (!empty($row[$key])) {
                $out[] = (string) $row[$key];
            }
        }
        return array_values(array_unique($out));
    }

    /** Build a query string skipping null/empty values. */
    public static function qs(array $params): string
    {
        $clean = [];
        foreach ($params as $k => $v) {
            if ($v === null || $v === '') {
                continue;
            }
            $clean[$k] = $v;
        }
        return http_build_query($clean, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Parse the bulk "no SSH" credential paste.
     *
     * One account per line, colon separated:
     *   source_user:ftp_password:db_user:db_password
     * Trailing fields may be omitted (a files-only account needs just the first
     * two). Blank lines and lines starting with # are ignored. Only the first
     * three colons are treated as separators, so a database password may itself
     * contain colons.
     *
     * @return array<string,array{ftp_password:string,db_user:string,db_password:string}>
     */
    public static function parseCredentialLines(string $text): array
    {
        $out = [];
        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            if (trim($line) === '' || ltrim($line)[0] === '#') {
                continue;
            }
            $parts = explode(':', $line, 4);
            $user = trim($parts[0]);
            if (!self::validUsername($user)) {
                continue;
            }
            $out[$user] = [
                'ftp_password' => (string)($parts[1] ?? ''),
                'db_user' => trim((string)($parts[2] ?? '')),
                'db_password' => (string)($parts[3] ?? ''),
            ];
        }
        return $out;
    }

    /**
     * Parse a raw crontab into individual jobs.
 *
 * OLSpanel's cronjob_add endpoint takes the five time fields and a command
 * separately, so the crontab has to be split before it can be replayed.
 * Shortcuts (@daily, ...) are expanded; anything that genuinely cannot be
 * expressed that way is reported instead of silently dropped.
 *
     * @param string[] $lines raw crontab lines
     * @return array{jobs:array[],unsupported:string[]}
     */
    public static function parseCrontab(array $lines): array
    {
        $shortcuts = [
            '@yearly' => ['0', '0', '1', '1', '*'],
            '@annually' => ['0', '0', '1', '1', '*'],
            '@monthly' => ['0', '0', '1', '*', '*'],
            '@weekly' => ['0', '0', '*', '*', '0'],
            '@daily' => ['0', '0', '*', '*', '*'],
            '@midnight' => ['0', '0', '*', '*', '*'],
            '@hourly' => ['0', '*', '*', '*', '*'],
        ];

        $jobs = [];
        $unsupported = [];

        foreach ($lines as $line) {
            $line = trim((string)$line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            // Environment assignments such as SHELL=/bin/bash or PATH=...
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*\s*=/', $line)) {
                continue;
            }

            $fields = null;
            $lower = strtolower($line);
            if ($lower[0] === '@') {
                $token = strtok($line, " \t");
                $key = strtolower((string)$token);
                if (!isset($shortcuts[$key])) {
                    // @reboot and friends have no equivalent in this API.
                    $unsupported[] = $line;
                    continue;
                }
                $rest = trim(substr($line, strlen((string)$token)));
                if ($rest === '') {
                    $unsupported[] = $line;
                    continue;
                }
                $fields = array_merge($shortcuts[$key], [$rest]);
            } else {
                $fields = preg_split('/\s+/', $line, 6) ?: [];
            }

            if (count($fields) !== 6) {
                $unsupported[] = $line;
                continue;
            }

            // Each time field must be a valid crontab expression.
            $valid = true;
            for ($i = 0; $i < 5; $i++) {
                if (!preg_match('/^[\d\*,\/\-]+$/', (string)$fields[$i])) {
                    $valid = false;
                    break;
                }
            }
            if (!$valid || trim((string)$fields[5]) === '') {
                $unsupported[] = $line;
                continue;
            }

            $jobs[] = [
                'minute' => (string)$fields[0],
                'hour' => (string)$fields[1],
                'day' => (string)$fields[2],
                'month' => (string)$fields[3],
                'weekday' => (string)$fields[4],
                'command' => trim((string)$fields[5]),
            ];
        }

        return ['jobs' => $jobs, 'unsupported' => $unsupported];
    }

    /** True when the current request is one of the JSON API endpoints. */
    public static function isApiCall(): bool
    {
        return isset($_GET['action'])
            || isset($_POST['action'])
            || isset(self::$requestBody['action']);
    }

    /**
     * Normalise a reseller allocation/limit payload.
     *
     * disk and bandwidth use null for unlimited (as OLSpanel does); the
     * counters use 0 for unlimited. This is the shape the rest of the reseller
     * migration (packages, capping) expects.
     */
    public static function normaliseAllocation(array $in): array
    {
        return [
            'disk_mb' => array_key_exists('disk_mb', $in) ? self::toMb($in['disk_mb']) : null,
            'bandwidth_mb' => array_key_exists('bandwidth_mb', $in) ? self::toMb($in['bandwidth_mb']) : null,
            'domains' => self::limitValue($in['domains'] ?? 0),
            'subdomains' => self::limitValue($in['subdomains'] ?? 0),
            'emails' => self::limitValue($in['emails'] ?? 0),
            'databases' => self::limitValue($in['databases'] ?? 0),
            'ftp' => self::limitValue($in['ftp'] ?? 0),
        ];
    }

    /**
     * Cap a plan's limits by the reseller's allocation.
     *
     * A null/0 allocation value means unlimited, so the plan keeps its request.
     * Otherwise the plan is capped - the same rule the Reseller Manager plugin
     * applies to plans a reseller creates from its portal.
     */
    public static function capLimits(array $want, array $alloc): array
    {
        $out = [];
        foreach (['disk_mb', 'bandwidth_mb', 'domains', 'subdomains', 'emails', 'databases', 'ftp'] as $field) {
            $a = $alloc[$field] ?? null;
            $w = $want[$field] ?? null;
            if ($a === null || (float)$a === 0.0) {
                $out[$field] = $w;
                continue;
            }
            if ($w === null || (float)$w === 0.0) {
                $out[$field] = $a;
                continue;
            }
            $out[$field] = min((int)$w, (int)$a);
        }
        return $out;
    }
}