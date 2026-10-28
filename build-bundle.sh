#!/bin/sh
# Build the one-line installer bundle.
#
#   ./build-bundle.sh   -> ../account_migrator_bundle.zip
#
# The bundle is a self-contained installer: on the target OLSpanel server the
# operator runs a single curl|bash line, which downloads this archive and calls
# install.sh. install.sh then
#   * installs/refreshes the plugin through the panel's own install_cp_plugin,
#   * writes an etc/_<admin> auto-login file so the panel can forward a working
#     admin token to the tool (otherwise opening it from the menu is refused),
#   * primes data/config.json with the master passphrase, and
#   * writes an account_migrator installer command to /usr/local/bin.
#
# Layout: install_cp_plugin needs EXACTLY ONE folder in the archive root, so the
# plugin payload is bundled in account_migrator/. The bundle holds:
#   account_migrator/            the installable plugin (conf + icon + code)
#   account_migrator/install.sh  what the bootstrap one-liner runs
#   account_migrator/INSTALL.md  operator documentation

set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
NAME=account_migrator_bundle
FOLDER=account_migrator
OUT=${1:-"$DIR/../$NAME.zip"}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

cd "$DIR"

echo "Linting PHP..."
for f in $(find . -name '*.php' -not -path './data/*'); do
    php -l "$f" >/dev/null || { echo "Syntax error in $f" >&2; exit 1; }
done
if [ -f "$DIR/ui/app.js" ]; then
    node --check "$DIR/ui/app.js"
fi

echo "Running the offline test suite..."
php "$DIR/tests/run.php" | tail -n 2

echo "Staging $FOLDER/..."
mkdir -p "$STAGE/$FOLDER"
for item in app ui index.php plugin_account_migrator.conf plugin_icon.png panel_repair.py install.sh INSTALL.md; do
    cp -R "$DIR/$item" "$STAGE/$FOLDER/"
done
rm -rf "$STAGE/$FOLDER/plugin"

# Nothing sensitive may ship.
if find "$STAGE" -name 'config.json' -o -name '.key' -o -name 'migrate.log' | grep -q .; then
    echo "Refusing to build: a config or key file made it into the archive" >&2
    exit 1
fi

rm -f "$OUT"
(cd "$STAGE" && zip -r -q "$OUT" "$FOLDER" -x '*/.DS_Store')

echo
echo "Built $OUT"
unzip -l "$OUT"
