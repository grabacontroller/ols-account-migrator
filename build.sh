#!/bin/sh
# Build the installable plugin zip.
#
#   ./build.sh            -> ../plugin_account_migrator.zip
#
# Layout: install_cp_plugin requires EXACTLY ONE folder in the archive root, and
# that folder's name becomes the plugin name, so the payload lives in
# account_migrator/. plugin_account_migrator.conf and plugin_icon.png sit at
# the top of it, which is where the installer looks for them. It then places
# the code in 3rdparty/account_migrator/, the conf in plugin/ and the icon in
# media/icon/.
#
# data/ (config, encryption key, job logs) and tests/ are excluded: the first
# must not ship, the second is not needed on the server.

set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
NAME=plugin_account_migrator
FOLDER=account_migrator
OUT=${1:-"$DIR/../$NAME.zip"}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

cd "$DIR"

# Lint before shipping: a syntax error in the plugin is a failed install.
echo "Linting PHP..."
for f in $(find . -name '*.php' -not -path './data/*'); do
    php -l "$f" >/dev/null || { echo "Syntax error in $f" >&2; exit 1; }
done

if [ -f "$DIR/ui/app.js" ]; then
    echo "Checking ui/app.js..."
    node --check "$DIR/ui/app.js"
fi

echo "Running the offline test suite..."
php "$DIR/tests/run.php" | tail -n 2

echo "Staging $FOLDER/..."
mkdir -p "$STAGE/$FOLDER"
for item in app ui index.php plugin_account_migrator.conf plugin_icon.png panel_repair.py; do
    cp -R "$DIR/$item" "$STAGE/$FOLDER/"
done

# The link JSON is optional: the .conf alone registers the plugin. Keeping it
# out avoids the plugin appearing twice in the admin list.
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
