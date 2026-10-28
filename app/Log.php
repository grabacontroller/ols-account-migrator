<?php
/**
 * Log - append-only migration log with levels.
 */

declare(strict_types=1);

class Log
{
    public const DEBUG = 10;
    public const INFO = 20;
    public const WARN = 30;
    public const ERROR = 40;

    private static string $file = '';
    private static string $jobId = '';
    private static array $buffer = [];

    public static function init(string $dir, string $jobId = ''): void
    {
        self::$file = rtrim($dir, '/') . '/migrate.log';
        self::$jobId = $jobId;
        self::$buffer = [];
    }

    public static function setJob(string $jobId): void
    {
        self::$jobId = $jobId;
    }

    public static function write(int $level, string $channel, string $message): void
    {
        $line = sprintf(
            "[%s] %s %-8s %s\n",
            gmdate('Y-m-d H:i:s\Z'),
            $level >= self::ERROR ? 'ERROR' : ($level >= self::WARN ? 'WARN ' : ($level >= self::INFO ? 'INFO  ' : 'DEBUG ')),
            $channel,
            $message
        );
        self::$buffer[] = $line;
        if (self::$file !== '' && is_dir(dirname(self::$file))) {
            @file_put_contents(self::$file, $line, FILE_APPEND | LOCK_EX);
        }
    }

    public static function debug(string $channel, string $m): void { self::write(self::DEBUG, $channel, $m); }
    public static function info(string $channel, string $m): void { self::write(self::INFO, $channel, $m); }
    public static function warn(string $channel, string $m): void { self::write(self::WARN, $channel, $m); }
    public static function error(string $channel, string $m): void { self::write(self::ERROR, $channel, $m); }

    public static function tail(int $lines = 200): string
    {
        if (self::$file === '' || !is_file(self::$file)) {
            return implode('', self::$buffer);
        }
        $raw = @file(self::$file, FILE_IGNORE_NEW_LINES) ?: [];
        return implode("\n", array_slice($raw, -$lines));
    }

    /** Everything logged in this request - handy for returning context to the UI. */
    public static function buffer(): string
    {
        return implode('', self::$buffer);
    }

    public static function clear(): void
    {
        if (self::$file !== '' && is_file(self::$file)) {
            @file_put_contents(self::$file, '');
        }
        self::$buffer = [];
    }
}