# OLSpanel Account Migrator - installation

This bundle installs the Account Migrator plugin on an OLSpanel server and
prepares the two things the panel needs before the tool will open: a working
admin auto-login file (`etc/_<admin>`) and/or a master passphrase.

## One-line install over SSH

On the OLSpanel server (`dev3.vgs1st.com`):

```bash
curl -fsSL https://<host>/account_migrator_bundle.zip -o /tmp/am.zip \
  && unzip -oq /tmp/am.zip -d /tmp/am \
  && bash /tmp/am/account_migrator/install.sh
```

Replace `<host>` with wherever the bundle is published. If you also want the
installer to set a known admin password (writes `etc/_admin`, so the tool opens
straight from the menu), add it:

```bash
ADMIN_PASSWORD='your-panel-admin-password' bash /tmp/am/account_migrator/install.sh
```

When run from an unpacked bundle the whole command reduces to:

```bash
sudo bash install.sh
```

The installer is idempotent: re-running it refreshes the plugin without losing
your settings.

## What the installer does

1. Installs or refreshes the plugin through the panel's own
   `install_cp_plugin`, falling back to a file copy if that command is absent.
   The plugin appears under **Admin -> 3rd-party -> Account Migrator**.
2. Creates `etc/_<admin>` so the panel can forward a valid admin token to the
   tool. Needs `ADMIN_PASSWORD`; without it the step is skipped.
3. Writes a master passphrase into `data/config.json` (sha256) and saves the
   plaintext to `~/.migrator_master_key`. This is the fallback when the panel
   cannot forward a token.
4. Writes `/usr/local/bin/account_migrator`, a small menu entry point that
   prints the admin URL and the master-key location.

## Verifying

```bash
account_migrator            # prints the URL and the master key
cat ~/.migrator_master_key  # the master passphrase, if one was generated
```

Then open **Admin -> 3rd-party -> Account Migrator**, or the direct URL. If the
page still says *Administrator authentication required*:

- Open it from the admin menu rather than a bookmark, **or**
- Paste the master key from `~/.migrator_master_key` into the box on the page.

## The two authentication modes

- **Panel session (preferred).** The panel signs the admin in and forwards
  `%username%` / `%usertoken%` as request headers. The tool re-verifies them
  against the panel API on every request. This needs `etc/_<admin>`, which the
  installer creates when given `ADMIN_PASSWORD`, or when you change the admin
  password once in the panel UI.
- **Master passphrase (fallback).** A passphrase whose sha256 is stored in
  `data/config.json` under `master_key`. Accepted whenever it is presented and
  correct; used exactly when the panel cannot forward a token.

## Configuration

After installing, open the tool and use the **Settings** tab:

- **Source panel** - host, port and credentials for the DirectAdmin or
  cPanel/WHM server you are migrating from.
- **Source server SSH** - optional; enables rsync file transfer and database
  dumps that need no per-account passwords.
- **Files & databases without SSH** - optional; FTP port/encryption and the
  source MySQL host/port. Per-account passwords are pasted in the **Select
  accounts** step as `source_user:ftp_password:db_user:db_password`.
- **OLSpanel destination** - leave the host blank to reuse this panel's own
  admin session.
- **Plugin updates** - the manifest URL checked by the **Plugin update** tab.
  That tab downloads and installs a newer published bundle over HTTPS after
  verifying its checksum; settings are preserved.

## Uninstalling

```bash
rm -rf /usr/local/olspanel/mypanel/3rdparty/account_migrator
rm -f  /usr/local/olspanel/mypanel/plugin/account_migrator.conf
rm -f  /usr/local/olspanel/mypanel/media/icon/account_migrator.png
rm -f  /usr/local/bin/account_migrator
```

`data/` holds the encrypted settings and job logs; remove it only if you are
sure you no longer need the configuration.

## Files in this bundle

```
account_migrator/                 installable plugin (one folder, as the panel expects)
  install.sh                      the one-line installer
  INSTALL.md                      this document
  plugin_account_migrator.conf    plugin registration
  plugin_icon.png                 menu icon
  index.php                       entry point
  app/                            PHP: sources, planner, engine, transfers
  ui/                             the web interface (app.js, app.css)
  README.md                       full feature documentation
```
