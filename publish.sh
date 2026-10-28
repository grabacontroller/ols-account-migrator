#!/bin/sh
# Build and publish the Account Migrator plugin and installer bundle.
#
#   ./publish.sh [destination]
#
# The default destination is the download host's public directory. Artifacts:
#
#   plugin_account_migrator.zip    installable plugin (panel installer)
#   account_migrator_bundle.zip    one-line SSH installer bundle
#   account_migrator-version.json  version manifest the self-updater reads
#   INSTALL.md                     operator documentation (served as-is)
#
# Re-running is safe: the manifest's sha256 is regenerated from the bundle that
# is actually published, so the two can never drift.
#
# When the GitHub CLI is installed and authenticated, the same artifacts are
# also attached to a GitHub release tagged v<version> in this repository, so
# the latest build is always downloadable from the releases page. Set
# GITHUB_RELEASE=0 to publish only to the download host.

set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
DEST=${1:-/home/dev3/public_html}
OWNER=${OWNER:-dev3:dev3}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
RELEASE_URL=

VERSION=$(sed -n "s/.*MIG_VERSION', '\([0-9][^']*\)'.*/\1/p" "$DIR/app/bootstrap.php" | head -n1)
[ -n "$VERSION" ] || { echo "Could not read MIG_VERSION from app/bootstrap.php" >&2; exit 1; }

echo "Building v$VERSION ..."
bash "$DIR/build.sh" "$STAGE/plugin_account_migrator.zip" >/dev/null
bash "$DIR/build-bundle.sh" "$STAGE/account_migrator_bundle.zip" >/dev/null

SHA=$(sha256sum "$STAGE/account_migrator_bundle.zip" | awk '{print $1}')
UPDATED=$(date -u +%Y-%m-%d)
cat > "$STAGE/account_migrator-version.json" <<EOF
{
  "name": "account_migrator",
  "version": "$VERSION",
  "updated": "$UPDATED",
  "bundle": "account_migrator_bundle.zip",
  "sha256": "$SHA",
  "notes": "Account Migrator v$VERSION"
}
EOF

if [ ! -d "$DEST" ]; then
  echo "Destination '$DEST' does not exist; skipping the download-host copy." >&2
else
  UG=$(id -u 2>/dev/null || echo 0)
  if [ "$UG" -eq 0 ]; then
    install -m 644 -o "${OWNER%:*}" -g "${OWNER#*:}" "$STAGE/plugin_account_migrator.zip" "$DEST/plugin_account_migrator.zip"
    install -m 644 -o "${OWNER%:*}" -g "${OWNER#*:}" "$STAGE/account_migrator_bundle.zip" "$DEST/account_migrator_bundle.zip"
    install -m 644 -o "${OWNER%:*}" -g "${OWNER#*:}" "$STAGE/account_migrator-version.json" "$DEST/account_migrator-version.json"
    install -m 644 -o "${OWNER%:*}" -g "${OWNER#*:}" "$DIR/INSTALL.md" "$DEST/INSTALL.md"
  else
    install -m 644 "$STAGE/plugin_account_migrator.zip" "$DEST/plugin_account_migrator.zip"
    install -m 644 "$STAGE/account_migrator_bundle.zip" "$DEST/account_migrator_bundle.zip"
    install -m 644 "$STAGE/account_migrator-version.json" "$DEST/account_migrator-version.json"
    install -m 644 "$DIR/INSTALL.md" "$DEST/INSTALL.md"
  fi

  echo "Copied v$VERSION to $DEST"
fi

# --- GitHub release -------------------------------------------------------
if [ "${GITHUB_RELEASE:-1}" = 1 ]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "GitHub release skipped: gh is not installed." >&2
  elif ! gh auth status >/dev/null 2>&1; then
    echo "GitHub release skipped: gh is not authenticated (run 'gh auth login')." >&2
  else
    REPO=${REPO:-$(git -C "$DIR" remote get-url origin 2>/dev/null \
      | sed -n 's#.*github\.com[:/]\(.*\)\.git$#\1#p')}
    [ -n "$REPO" ] || REPO=grabacontroller/ols-account-migrator
    TAG="v$VERSION"
    NOTES="Account Migrator v$VERSION

Installer bundle: account_migrator_bundle.zip (sha256 $SHA)
Version manifest: account_migrator-version.json
Operator documentation: INSTALL.md"

    if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
      gh release upload "$TAG" \
        "$STAGE/plugin_account_migrator.zip" \
        "$STAGE/account_migrator_bundle.zip" \
        "$STAGE/account_migrator-version.json" \
        "$DIR/INSTALL.md" \
        --repo "$REPO" --clobber >/dev/null
      gh release edit "$TAG" --repo "$REPO" \
        --title "Account Migrator v$VERSION" --notes "$NOTES" >/dev/null
    else
      gh release create "$TAG" \
        "$STAGE/plugin_account_migrator.zip" \
        "$STAGE/account_migrator_bundle.zip" \
        "$STAGE/account_migrator-version.json" \
        "$DIR/INSTALL.md" \
        --repo "$REPO" --title "Account Migrator v$VERSION" --notes "$NOTES" >/dev/null
    fi

    RELEASE_URL=$(gh release view "$TAG" --repo "$REPO" --json url -q .url)
    echo "Released $TAG on GitHub: $RELEASE_URL"
  fi
fi

echo
echo "Published v$VERSION"
echo "  bundle sha256: $SHA"
if [ -n "$RELEASE_URL" ]; then
  echo "  release:       $RELEASE_URL"
fi
