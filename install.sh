#!/bin/bash
#
# OLSpanel Account Migrator - one-line installer.
#
# Normally run for you by the bootstrap one-liner:
#
#   curl -fsSL https://raw.vgs1st.com/account_migrator_bundle.zip | ... (see INSTALL.md)
#
# It can also be run directly from an unpacked bundle:
#
#   sudo bash install.sh
#
# What it does
#   1. Installs/refreshes the plugin through the panel's own installer.
#   2. Ensures the panel can forward a working admin token to the tool by
#      creating etc/_<admin> when it is missing and no master key is set.
#   3. Primes data/config.json with a master passphrase (printed once).
#   4. Writes /usr/local/bin/account_migrator, a menu-friendly entry point.
#
# It is idempotent: re-running it refreshes the plugin without losing settings.

set -euo pipefail

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
PLUGIN_NAME="account_migrator"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
  red "Run this as root (sudo bash install.sh)."
  exit 1
fi

# --- locate the panel ------------------------------------------------------
HOME_FILE="/etc/olspanel/base_dir"
PY_FILE="/etc/olspanel/PYTHON_PATH"
PROJECT_DIR=""
PYTHON=""
[ -f "$HOME_FILE" ] && PROJECT_DIR="$(cat "$HOME_FILE")"
[ -f "$PY_FILE" ] && PYTHON="$(cat "$PY_FILE")"
[ -z "$PROJECT_DIR" ] && [ -d /usr/local/olspanel/mypanel ] && PROJECT_DIR=/usr/local/olspanel/mypanel
[ -z "$PROJECT_DIR" ] && [ -d /usr/local/lsws/Example/html/mypanel ] && PROJECT_DIR=/usr/local/lsws/Example/html/mypanel
[ -z "$PYTHON" ] && [ -x /root/venv/bin/python3 ] && PYTHON=/root/venv/bin/python3

if [ -z "$PROJECT_DIR" ] || [ ! -d "$PROJECT_DIR" ]; then
  red "Could not find the OLSpanel project directory."
  exit 1
fi
if [ -z "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
  red "Could not find the panel's Python interpreter (/etc/olspanel/PYTHON_PATH)."
  exit 1
fi

grn "Panel:  $PROJECT_DIR"
grn "Python: $PYTHON"

# --- install / refresh the plugin -----------------------------------------
# install_cp_plugin wants a .zip/.tar whose root holds exactly one folder. The
# bundle is unpacked, so rebuild that archive from the payload and install it.
WORK="$(mktemp -d)"
mkdir -p "$WORK/$PLUGIN_NAME"
for item in app ui index.php plugin_${PLUGIN_NAME}.conf plugin_icon.png panel_repair.py; do
  [ -e "$SCRIPT_DIR/$item" ] && cp -R "$SCRIPT_DIR/$item" "$WORK/$PLUGIN_NAME/"
done
rm -rf "$WORK/$PLUGIN_NAME/plugin"
ARCHIVE="$WORK/${PLUGIN_NAME}.zip"
if command -v zip >/dev/null 2>&1; then
  ( cd "$WORK" && zip -rq "$ARCHIVE" "$PLUGIN_NAME" )
else
  ( cd "$WORK" && tar czf "${ARCHIVE%.zip}.tar.gz" "$PLUGIN_NAME" )
  ARCHIVE="${ARCHIVE%.zip}.tar.gz"
fi

if command -v install_cp_plugin >/dev/null 2>&1; then
  ylw "Installing the plugin through the panel installer..."
  install_cp_plugin "$ARCHIVE" || {
    red "install_cp_plugin failed; falling back to copying files."
    install_cp_plugin "$SCRIPT_DIR" || true
  }
else
  ylw "install_cp_plugin not found; installing the plugin by copying files..."
  TARGET="$PROJECT_DIR/3rdparty/$PLUGIN_NAME"
  mkdir -p "$TARGET" "$PROJECT_DIR/plugin" "$PROJECT_DIR/media/icon"
  for item in app ui index.php panel_repair.py; do
    [ -e "$SCRIPT_DIR/$item" ] && cp -R "$SCRIPT_DIR/$item" "$TARGET/"
  done
  cp "$SCRIPT_DIR/plugin_${PLUGIN_NAME}.conf" "$PROJECT_DIR/plugin/${PLUGIN_NAME}.conf"
  [ -f "$SCRIPT_DIR/plugin_icon.png" ] && cp "$SCRIPT_DIR/plugin_icon.png" "$PROJECT_DIR/media/icon/${PLUGIN_NAME}.png"
fi
rm -rf "$WORK"

# --- install the shared panel repair helper --------------------------------
# OLSpanel updates replace the panel's Python files and revert the session
# patches both plugins need. Install the idempotent repair helper and schedule
# it so a later panel update cannot silently break auto-login again.
if [ -f "$SCRIPT_DIR/panel_repair.py" ]; then
  install -m 755 "$SCRIPT_DIR/panel_repair.py" /usr/local/bin/olspanel-plugin-repair
  /usr/local/bin/olspanel-plugin-repair --install-cron || true
  /usr/local/bin/olspanel-plugin-repair || true
fi

DATA_DIR="$PROJECT_DIR/3rdparty/$PLUGIN_NAME/data"
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

# --- make an admin auto-login token available ------------------------------
# The panel forwards %usertoken% from etc/_<admin>. Without that file the tool
# refuses to open from the menu unless a master passphrase is configured.
ETC_DIR="$PROJECT_DIR/etc"
ADMIN_FILE="$ETC_DIR/_$ADMIN_USER"

MASTER_KEY=""
if [ -f "$DATA_DIR/config.json" ]; then
  MASTER_KEY="$(grep -o '"master_key"[^,}]*' "$DATA_DIR/config.json" | grep -o '"[a-f0-9]\{64\}"' | tr -d '"' || true)"
fi

if [ ! -f "$ADMIN_FILE" ]; then
  if [ -n "$ADMIN_PASSWORD" ]; then
    ylw "Creating $ADMIN_FILE for admin '$ADMIN_USER'..."
    PW="$ADMIN_PASSWORD" ADMIN_USER="$ADMIN_USER" "$PYTHON" - "$PROJECT_DIR" <<'PY'
import os, sys, base64, random, string, secrets
project = sys.argv[1]
sys.path.insert(0, project)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'user_management.settings')
try:
    import django
    django.setup()
    from django.contrib.auth.models import User
    u = User.objects.get(username=os.environ['ADMIN_USER'])
    pw = os.environ['PW'] or secrets.token_urlsafe(18)
    u.set_password(pw)
    u.save()
except Exception as e:
    pw = os.environ['PW']
    sys.stderr.write(f" (password not changed in the panel DB: {e})\n")
enc = ''.join(random.choices(string.ascii_lowercase, k=5)) + base64.b64encode(pw.encode()).decode()
path = os.path.join(project, 'etc', '_' + os.environ['ADMIN_USER'])
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w') as f:
    f.write(enc)
print(f"NEW_ADMIN_PASSWORD={pw}")
PY
  elif [ -z "$MASTER_KEY" ]; then
    red "Neither $ADMIN_FILE nor a master passphrase exists."
    red "Re-run with the admin password, e.g.:  ADMIN_PASSWORD='your-admin-password' bash install.sh"
    red "The install continues, but the tool will ask for a master passphrase until one of the two exists."
  fi
fi

# --- prime the config with a master passphrase -----------------------------
if [ -f "$DATA_DIR/config.json" ]; then
  if [ -z "$MASTER_KEY" ]; then
    if command -v openssl >/dev/null 2>&1; then
      PASSPHRASE="$(openssl rand -base64 24)"
    else
      PASSPHRASE="$("$PYTHON" -c 'import secrets;print(secrets.token_urlsafe(24))')"
    fi
    HASH="$("$PYTHON" -c 'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$PASSPHRASE")"
    "$PYTHON" - "$DATA_DIR/config.json" "$HASH" <<'PY'
import json, sys
path, h = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
cfg['master_key'] = h
with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
PY
    echo "$PASSPHRASE" > "$HOME/.migrator_master_key"
    chmod 600 "$HOME/.migrator_master_key"
    grn "Master passphrase generated and saved to $HOME/.migrator_master_key"
  else
    grn "A master passphrase is already configured."
  fi
fi

# --- menu entry point ------------------------------------------------------
cat > /usr/local/bin/account_migrator <<EOF
#!/bin/bash
echo "Account Migrator:"
echo "  Admin menu : Admin -> 3rd-party -> Account Migrator"
echo "  Direct URL : https://\$(hostname -f 2>/dev/null || echo SERVER):8058/3rdparty/$PLUGIN_NAME/index.php"
echo "  Master key : \${HOME:-/root}/.migrator_master_key"
echo "  Repair     : /usr/local/bin/olspanel-plugin-repair"
echo
echo "If the page says 'Administrator authentication required', open it from the"
echo "admin menu, or enter the master key in the box on the page."
EOF
chmod +x /usr/local/bin/account_migrator

grn "Done."
echo
echo "Next:"
echo "  1. Open the admin menu: Admin -> 3rd-party -> Account Migrator"
echo "     (direct: https://\$(hostname -f 2>/dev/null):8058/3rdparty/$PLUGIN_NAME/index.php)"
echo "  2. In Settings, set the source panel + (optionally) SSH or the without-SSH FTP/DB options."
echo "  3. Run Preflight, then Scan."
