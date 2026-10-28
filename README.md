# OLSpanel Account Migrator

A 3rd-party plugin for [OLSpanel](https://olspanel.com) that moves hosting
accounts from a **DirectAdmin**, **cPanel/WHM** or **Plesk** server onto an
OLSpanel server: accounts, packages, domains, files, mail, mailboxes, cron jobs
and database contents. When the destination runs the **Reseller Manager**
plugin, a migrated DirectAdmin (or Plesk) reseller can be recreated on OLSpanel
with its customers attached underneath it.

Migration is **copy-only**. Nothing is deleted, moved or modified on the source
server, so a migration can be repeated or rolled back by pointing DNS back.

---

## Requirements

### On the OLSpanel server

| Requirement | Why |
|---|---|
| PHP 7.4+ with `openssl`, `curl` or `allow_url_fopen` | API calls and the encrypted config |
| OLSpanel running as the host panel | the plugin is installed through it |
| `root` privileges for the plugin process | `chown` on transferred files, local MySQL access |
| `rsync` and `ssh` (and `scp`) | file and mail transfer over SSH |
| `lftp` | file and mail transfer over FTP when SSH is not used |
| `mysqldump` and `mysql` client | database dumps and imports (works over SSH or a direct connection) |
| `sshpass` | only if you authenticate to the source over SSH with a password |

The plugin **must** run as `root` (see `user=root` in the `.conf`). A non-root
process cannot fix file ownership or import databases, and both failures are
reported in the preflight check rather than silently ignored.

### On the source server

- A DirectAdmin admin login, a WHM API token / root password, or a Plesk API
  key (or Plesk administrator credentials; REST is exposed on port 8443).
- **Root SSH access**, for the full migration:
  - cPanel exposes every mailbox, alias and cron job only in local files
    (`/var/cpanel/...`), which the plugin reads over SSH.
  - Database discovery and `mysqldump` run on the source host.
- Without SSH the plugin still creates accounts, packages, domains and
  databases through the panel APIs, but file, mail and database *contents* are
  skipped, and the affected steps are marked **blocked** rather than done.

---

## Installation

Build or use the release zip, then install it from an OLSpanel root shell:

```sh
install_cp_plugin https://your-panel-host/path/plugin_account_migrator.zip
```

or upload the same zip through the OLSpanel admin interface. The zip's root
holds `plugin_account_migrator.conf` and `plugin_icon.png`, which is what the
panel looks for.

### One-line install (bundle)

`build-bundle.sh` produces `account_migrator_bundle.zip`, a self-contained
installer. On the OLSpanel server:

```sh
curl -fsSL https://<host>/account_migrator_bundle.zip -o /tmp/am.zip \
  && unzip -oq /tmp/am.zip -d /tmp/am \
  && bash /tmp/am/account_migrator/install.sh
```

The installer refreshes the plugin, creates `etc/_<admin>` (when given
`ADMIN_PASSWORD='...'`) so the panel can forward an admin token, primes a master
passphrase into `data/config.json`, and writes `/usr/local/bin/account_migrator`.
See `INSTALL.md` in the bundle for details.

The plugin then appears under **3rd-party plugins** in the admin panel. It
registers as `service=admin_panel` and forwards `%username%` / `%usertoken%`
as `HTTP_AUTOLOGINUSER` / `HTTP_AUTOLOGINTOKEN`; those credentials are
re-verified against the OLSpanel API on every request, and non-administrators
are refused. No separate login exists for the migrator.

### Updating the plugin

The **Plugin update** tab fetches an HTTPS version manifest
(`https://dev3.vgs1st.com/account_migrator-version.json` by default), compares it
with the installed version, and can download and run the newer bundle's
installer. The bundle is verified against its published SHA-256 before it is
run, and the installer is idempotent, so settings are preserved. The manifest
URL can be changed under **Settings**.

### Building the zip

```sh
cd ols-account-migrator
zip -r ../plugin_account_migrator.zip . \
    -x 'data/*' 'tests/*' '.git/*' '*.md'
```

`data/` (config, encryption key, job logs) and `tests/` are excluded: the first
must not ship, the second is not needed on the server.

---

## Usage

1. **Settings** – source panel host, port and credentials; OLSpanel API
   credentials (leave the host empty to reuse the ones the panel forwards);
   SSH access to the source; local MySQL; and the home directory layout.
   *Test source*, *Test SSH* and *Test OLSpanel* verify each one.

   Leave **OLSpanel host** empty to use the panel's own session. The plugin
   verifies the forwarded admin token with a read-only
   `admin_api/packages_list/` call before acting. If you need to run the
   migrator against a *different* OLSpanel install, set the host and either a
   `username`/`password` pair or a `master_key` (the admin's `sha256` token).

2. **Preflight** – checks local tools, SSH reachability and privileges, the
   OLSpanel API, MySQL access, free disk space and the home directory. It also
   states honestly which optional APIs this OLSpanel build exposes.
3. **Scan** – lists the accounts on the source server. On DirectAdmin and Plesk,
   choose a reseller to scan only the accounts that reseller owns; picking *All
   accounts* scans the whole server. The reseller's users arrive ticked, so a
   whole reseller can be inventoried, planned and migrated in one run. Tick
   **Recreate the reseller in OLSpanel** to also migrate the reseller's own
   account and attach its customers underneath it (see *Resellers* below). On
   cPanel the reseller filter lives in Settings.

4. **Inventory** – per account: domains and subdomains, mailboxes and aliases,
   databases, cron entries, usage and limits. For cPanel this reads the local
   `/var/cpanel` metadata over SSH, which is why the inventory is far more
   complete than the WHM API alone.

5. **Plan** – per account you choose the target username, package (or let the
   planner pick the smallest that fits), and which resources to include. Blocked
   and warning items are spelled out before anything runs.

6. **Run** – steps execute in order and each is idempotent, so a re-run after a
   failure resumes rather than duplicating:

   `package` → `account` → `domains` → `files` → `mail` → `fixperms` →
   `databases` → `email` → `ftp` → `cron` → `suspend` → `ssl` → `verify`

   File and mail transfers run as detached `rsync` jobs; the wrapper shell
   records the exit status, so a job that vanished without reporting is
   reported as a **failure**, never as success. Database dumps run on the
   source and are verified with `gzip -t` before being loaded.

   **Without SSH.** File and database *contents* can also be migrated using the
   account's own credentials, so a source server that exposes no SSH (or one
   you would rather not give root on) still moves completely:

   - **Files** are mirrored with `lftp` over **FTP/FTPS or SFTP** (chosen under
     Settings → *Transfer protocol*) using the account's own login. FTP is
     chrooted to the account home by DirectAdmin/cPanel; SFTP logs into the
     account's SSH home. The login defaults to the account name — set a
     *FTP/SFTP login override* (with optional `{user}`/`{domain}` placeholders)
     when a host uses a different login, such as an email-shaped SFTP user. The
     password is written to a `0600` script that is deleted as soon as the job
     exits.
   - **Databases** are dumped by connecting straight to the source MySQL from
     the OLSpanel server with the account's own database user, then loaded into
     the new schema. A plain MySQL user is shown only the schemas it owns, which
     is exactly what should come across.
   - Paste the per-account credentials in the **Select accounts** step, one line
     each: `source_user:ftp_password:db_user:db_password`. Trailing fields may be
     omitted and `#` starts a comment. When SSH is enabled it takes precedence;
     otherwise this block is used.

7. **Report** – issues per account, the generated passwords, and a per-account
   cutover checklist (DNS A records, testing, and any application config that
   hardcodes the old server IP or `/home/USER` paths).

---

## How packages are chosen

The planner picks the smallest OLSpanel package that satisfies the source
account's disk, bandwidth, domain, subdomain, email, database and FTP counts.
An unlimited plan only wins when the account genuinely exceeds every finite
package. If nothing fits, a package is created from the source limits, named
`DA {source_package}` by default, and the plan says so.

Domain counts above the target package's limit are **capped and reported**
rather than silently truncated.

---

## Plesk support

Plesk is read through its REST API v2 (`https://host:8443/api/v2`), with an API
key (recommended) or the administrator credentials. A Plesk **subscription** is
treated as one migratable account, keyed by a sanitised form of its primary
domain; its domains, mailboxes and databases are read where the REST API exposes
them, and anything it does not is discovered over SSH at transfer time (files
live under `/var/www/vhosts/<domain>`, mail under `/var/qmail/mailnames/`).
Because a Plesk account keeps the same layout as `/var/www/vhosts`, set the
source home template in Settings to `/var/www/vhosts/%s` for Plesk.

REST is not uniform across Plesk builds, so every collection read is best
effort: a collection that cannot be read is reported in the account notes rather
than failing the scan.

---

## Resellers

When the OLSpanel destination runs the **Reseller Manager** plugin - which adds
a real reseller role on top of OLSpanel - the migrator can recreate a whole
source reseller rather than leaving its customers as loose accounts:

1. In **Select accounts**, pick the source reseller and tick **Recreate the
   reseller in OLSpanel**. The reseller's own account is added to the selection
   and migrated like any other account (files, mail, databases).
2. The customers are migrated as usual, each with its own package.
3. When the run finishes, the migrator promotes the reseller through the Reseller
   Manager so it owns an **allocation package** (mirroring the source reseller's
   limits), then moves every customer onto a reseller-owned plan capped by that
   allocation. The reseller can then sign in to the Reseller Portal and manage
   its customers.

The Reseller Manager's panel extension (`admin_api_resellers/`) is detected
automatically; if it is not installed, the checkbox has no effect and the
customers are migrated as ordinary accounts. Preflight reports whether it is
present.

---

## Secrets

Passwords, API tokens, the SSH password and the SSH key passphrase are
encrypted at rest with AES-256-CBC under a random 32-byte key in
`data/.key` (mode `0600`). `data/config.json` is also `0600` and additionally
guarded by `.htaccess` and `index.html`.

The browser never receives a stored secret. It gets the literal `__set__`
marker, and sending that marker back means "keep what is already stored" — so
re-saving a settings form cannot blank a password.

---

## Known limitations

These are real and are surfaced in the UI rather than papered over:

- **Email and FTP account creation** depend on APIs that not every OLSpanel
  build exposes. They are probed at runtime; when missing, the step is marked
  **blocked** and lists exactly which mailboxes or FTP accounts to create by
  hand. The mail *data* is still copied.
- **No-SSH transfers** need the account's own FTP/SFTP and database passwords,
  which panels keep hashed. Supply them in the Select accounts step. A source
  MySQL that only listens on localhost cannot be reached directly and needs SSH.
  SFTP also needs the source to expose SSH (on the configured port) for that
  account; the login may differ from the account name (see the override).
- **Cron** replays entries that map onto the documented
  `api/cronjob_add/` fields. `@reboot` and other entries with no equivalent are
  listed for manual recreation instead of being dropped.
- **Names over 16 characters** are shortened deterministically for MySQL users,
  with a short digest of the original name appended so two long names cannot
  collide.
- **Directory listing / app caches** are excluded from transfers by default;
  adjust the exclude list in Settings.
- Nothing here converts mail formats. If the source and destination use
  different mail storage (for example Maildir vs. a panel-specific layout),
  verify one mailbox before migrating many.

---

## Tests

The suite is offline: no control panel, no network, no root required.

```sh
php tests/run.php
```

It covers size normalisation, package matching and capping, username/domain
validators, password generation, the encrypted-config round trip, rsync command
building (including hostile account names), SSH key-passphrase handling,
crontab parsing, plan validation, the cPanel metadata merge, Plesk response
parsing, reseller allocation capping, the auth gate and CSRF handling.
