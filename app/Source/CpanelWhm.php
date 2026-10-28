<?php
/**
 * CpanelWhm - source adapter for cPanel servers, driven through WHM API 1.
 *
 * WHM API 1 is the only cPanel interface that lets an administrator read every
 * account's limits and usage in one place, so it is used for the account
 * inventory. WHM's json-api requires the basic-auth username to be prefixed
 * with "whm " (e.g. "whm root:<token>").
 */

declare(strict_types=1);

class CpanelWhm extends SourcePanel
{
    /** WHM json-api calls need api.version=1. */
    private function api(string $function, array $params = []): array
    {
        $user = 'whm ' . (string)($this->cfg['username'] ?? 'root');
        $secret = (string)(($this->cfg['token'] ?? '') ?: ($this->cfg['password'] ?? ''));
        if ($secret === '') {
            return ['ok' => false, 'data' => null, 'status' => 0, 'body' => '', 'error' => 'No WHM API token configured.'];
        }

        $http = new Http($this->base(2087), [], !empty($this->cfg['verify_tls']), 90, [$user, $secret]);
        $params['api.version'] = 1;
        $res = $http->request('json-api/' . $function, 'GET', $params);

        if ($res['error'] !== '') {
            return ['ok' => false, 'data' => null, 'status' => 0, 'body' => '', 'error' => $res['error']];
        }

        $json = $res['json'];
        $meta = is_array($json) ? ($json['metadata'] ?? []) : [];
        $ok = $res['status'] === 200
            && is_array($json)
            && isset($meta['result'])
            && (int)$meta['result'] === 1
            && (string)($meta['reason'] ?? '') === 'OK';

        return [
            'ok' => $ok,
            'data' => $ok ? ($json['data'] ?? null) : null,
            'status' => $res['status'],
            'body' => $res['body'],
            'error' => $ok ? '' : trim((string)($meta['reason'] ?? ('HTTP ' . $res['status']))),
        ];
    }

    public function label(): string
    {
        return 'cPanel / WHM';
    }

    public function capabilities(): array
    {
        return [
            'limits' => 'Full (via WHM accountsummary)',
            'usage' => 'Full (via WHM accountsummary)',
            'domains' => 'Main domain + aliases via API; full list over SSH',
            'mailboxes' => 'Over SSH (cPanel userdomains files)',
            'databases' => 'Over SSH (MySQL grants)',
            'subdomains' => 'Over SSH (cPanel account config)',
            'cron' => 'Not migrated',
        ];
    }

    public function test(): array
    {
        $res = $this->api('version');
        if (!$res['ok']) {
            $hint = '';
            if (stripos($res['error'], 'access denied') !== false || stripos($res['error'], 'not authorized') !== false) {
                $hint = ' Create an API token in WHM -> API Tokens (or use the root password).';
            }
            return [
                'ok' => false,
                'message' => trim($res['error'] . ($res['error'] !== '' ? '' : $res['body'])) . $hint,
            ];
        }
        $version = is_array($res['data']) ? (string)($res['data']['version'] ?? '') : '';
        $accounts = $this->api('listaccts');
        $count = $accounts['ok'] && is_array($accounts['data']) ? count($accounts['data']) : 0;

        return [
            'ok' => true,
            'message' => sprintf(
                'Connected to WHM at %s:%s%s. %d account(s) found.',
                $this->cfg['host'],
                $this->cfg['port'] ?? 2087,
                $version !== '' ? ' (WHM ' . $version . ')' : '',
                $count
            ),
            'accounts' => $count,
        ];
    }

    public function listAccounts(string $reseller = ''): array
    {
        $res = $this->api('listaccts');
        if (!$res['ok'] || !is_array($res['data'])) {
            return [];
        }
        $wantedReseller = trim($reseller);
        if ($wantedReseller === '') {
            $wantedReseller = trim((string)($this->cfg['reseller'] ?? ''));
        }

        $names = [];
        foreach ($res['data'] as $acct) {
            $user = is_array($acct) ? (string)($acct['user'] ?? '') : '';
            if ($user === '' || !Util::validUsername($user)) {
                continue;
            }
            if ($wantedReseller !== '') {
                $owner = strtolower(is_array($acct) ? (string)($acct['owner'] ?? '') : '');
                if ($owner !== strtolower($wantedReseller) && strtolower($user) !== strtolower($wantedReseller)) {
                    continue;
                }
            }
            $names[] = $user;
        }
        return array_values(array_unique($names));
    }

    public function fetchAccount(string $username): array
    {
        $acct = $this->blankAccount($username);

        $sum = $this->api('accountsummary', ['user' => $username]);
        $d = ($sum['ok'] && is_array($sum['data'])) ? $sum['data'] : [];
        if (!$d) {
            $acct['notes'][] = 'accountsummary unavailable: ' . trim((string)$sum['error']);
        }

        $acct['package'] = (string)($d['plan'] ?? 'custom');
        $acct['domain'] = (string)($d['domain'] ?? '');
        $acct['email'] = (string)($d['email'] ?? '');
        $acct['suspended'] = in_array(strtoupper((string)($d['suspended'] ?? 0)), ['1', 'SUSPENDED'], true);

        // accountsummary's email/mysql/ftp/vhosts/subdomains fields are the
        // account's *limits*, not what it currently uses.
        $acct['limits'] = [
            'disk_mb' => Util::toMb($d['disk_limit'] ?? null),
            'bandwidth_mb' => Util::toMb($d['bandwidth_limit'] ?? null),
            'domains' => Util::limitValue($d['vhosts'] ?? 0),
            'subdomains' => Util::limitValue($d['subdomains'] ?? 0),
            'emails' => Util::limitValue($d['email'] ?? 0),
            'databases' => Util::limitValue($d['mysql'] ?? 0),
            'ftp' => Util::limitValue($d['ftp'] ?? 0),
        ];

        $acct['usage'] = [
            'disk_mb' => (int) round((float)($d['disk_usage'] ?? 0)),
            'domains' => 0,
            'emails' => 0,
            'databases' => 0,
            'ftp' => 0,
        ];

        // getacct adds the contact e-mail, the alias list and the suspension
        // state; accountsummary leaves some of those blank.
        $getacct = $this->api('getacct', ['user' => $username]);
        $g = ($getacct['ok'] && is_array($getacct['data'])) ? $getacct['data'] : [];
        if ($g) {
            $acct['suspended'] = in_array(strtoupper((string)($g['suspended'] ?? 0)), ['1', 'SUSPENDED'], true);
            $acct['email'] = $acct['email'] !== '' ? $acct['email'] : (string)($g['contact_email'] ?? '');
            if ($acct['domain'] === '') {
                $acct['domain'] = (string)($g['domain'] ?? '');
            }
            $acct['usage']['disk_mb'] = (int) round((float)($g['disk_usage'] ?? $acct['usage']['disk_mb']));
        }

        // Domains: WHM exposes the main domain plus a comma separated alias list.
        if ($acct['domain'] !== '') {
            $acct['domains'][] = strtolower($acct['domain']);
        }
        foreach (preg_split('/[\s,]+/', (string)($g['aliases'] ?? '')) as $a) {
            $a = strtolower(trim($a));
            if (Util::validDomain($a)) {
                $acct['domains'][] = $a;
            }
        }
        $acct['domains'] = array_values(array_unique($acct['domains']));

        // Everything below the domain level is enumerated rather than guessed:
        // CpanelFiles::merge() raises these counts from the real files, and
        // DbMover discovers the databases from the source's own grants.
        $acct['usage']['domains'] = count($acct['domains']);
        $acct['notes'][] = 'WHM reports limits only for mailboxes, databases and FTP accounts; '
            . 'the real inventory is read from the source host over SSH.';

        if ($acct['domain'] === '') {
            $acct['domain'] = $username . '.example.com';
            $acct['notes'][] = 'No domain reported by WHM - review the substituted domain before running.';
        }
        if ($acct['email'] === '' && $acct['domain'] !== '') {
            $acct['email'] = 'admin@' . $acct['domain'];
        }

        return $acct;
    }

    public function listPackages(): array
    {
        $res = $this->api('listpkgs');
        if (!$res['ok'] || !is_array($res['data'])) {
            return [];
        }
        $packages = [];
        foreach ($res['data'] as $p) {
            $name = is_array($p) ? (string)($p['name'] ?? '') : '';
            if ($name === '') {
                continue;
            }
            $packages[$name] = [
                'name' => $name,
                'limits' => [
                    'disk_mb' => Util::toMb(is_array($p) ? ($p['disk_quota'] ?? null) : null),
                    'bandwidth_mb' => Util::toMb(is_array($p) ? ($p['bandwidth'] ?? null) : null),
                    'domains' => Util::limitValue(is_array($p) ? ($p['max_vhosts'] ?? 0) : 0),
                    'subdomains' => Util::limitValue(is_array($p) ? ($p['max_subdoms'] ?? 0) : 0),
                    'emails' => Util::limitValue(is_array($p) ? ($p['max_mailacct'] ?? 0) : 0),
                    'databases' => Util::limitValue(is_array($p) ? ($p['max_db'] ?? 0) : 0),
                    'ftp' => Util::limitValue(is_array($p) ? ($p['maxftp'] ?? 0) : 0),
                ],
            ];
        }
        return $packages;
    }
}