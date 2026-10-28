<?php
/**
 * SourcePanel - contract every source control panel adapter fulfils.
 *
 * An adapter's only job is to answer: "what is on the source server?".
 * Everything else (package mapping, transfers, reporting) is panel agnostic.
 */

declare(strict_types=1);

abstract class SourcePanel
{
    protected array $cfg;

    public function __construct(array $sourceConfig)
    {
        $this->cfg = $sourceConfig;
    }

    /** Panel base URL, e.g. https://host:2222 */
    protected function base(int $defaultPort = 2222): string
    {
        return Util::normaliseUrl(
            (string)$this->cfg['host'],
            (int)($this->cfg['port'] ?? $defaultPort),
            !empty($this->cfg['tls'])
        );
    }

    /** Short name shown in the UI: "DirectAdmin", "cPanel / WHM". */
    abstract public function label(): string;

    /** Human readable list of what this adapter can inventory. */
    abstract public function capabilities(): array;

    /** Verify credentials. Returns ['ok'=>bool,'message'=>string,'extra'=>array]. */
    abstract public function test(): array;

    /**
     * Reseller names on the source panel.
     *
     * Only panels with a reseller concept implement this; the default is an
     * empty list so cPanel/WHM and future adapters are unaffected.
     *
     * @return string[]
     */
    public function listResellers(): array
    {
        return [];
    }

    /**
     * @param string $reseller limit the list to one reseller's accounts; ''
     *                         means every account the credentials can see.
     * @return string[] usernames of all migratable accounts
     */
    abstract public function listAccounts(string $reseller = ''): array;

    /**
     * The reseller's own account and the accounts beneath it.
     *
     * Used to recreate a reseller on OLSpanel (through the Reseller Manager
     * plugin) after its customers have been migrated. Panels without a reseller
     * concept return null.
     *
     * @return array|null {username, domain, email, package, limits, reseller:
     *                    {name, login, email, allocation, users}}
     */
    public function fetchReseller(string $name): ?array
    {
        return null;
    }

    /**
     * Full inventory for one account.
     *
     * @return array{
     *   username:string, domain:string, email:string, package:string,
     *   suspended:bool, limits:array, usage:array,
     *   domains:string[], subdomains:string[], emails:string[], databases:string[],
     *   notes:string[]
     * }
     */
    abstract public function fetchAccount(string $username): array;

    /** Package definitions on the source server (name => limits). */
    abstract public function listPackages(): array;

    protected function baseLimits(): array
    {
        return [
            'disk_mb' => null,
            'bandwidth_mb' => null,
            'domains' => 0,
            'subdomains' => 0,
            'emails' => 0,
            'databases' => 0,
            'ftp' => 0,
        ];
    }

    protected function baseUsage(): array
    {
        return [
            'disk_mb' => 0,
            'domains' => 0,
            'emails' => 0,
            'databases' => 0,
            'ftp' => 0,
        ];
    }

    protected function blankAccount(string $username): array
    {
        return [
            'username' => $username,
            'domain' => '',
            'email' => '',
            'package' => 'custom',
            'suspended' => false,
            'limits' => $this->baseLimits(),
            'usage' => $this->baseUsage(),
            'domains' => [],
            'subdomains' => [],
            'emails' => [],
            'databases' => [],
            'notes' => [],
        ];
    }
}