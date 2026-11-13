#!/bin/bash
# Installs nandi on a Mac. Written for a Jamf Pro policy script, and works
# from any MDM or by hand with sudo.
#
#   Jamf parameter 4: version to install, e.g. v0.2.0 (default: latest)
#   Jamf parameter 5: policy packs to install, comma separated
#                     (default: coding-agent,payments)
#   Jamf parameter 6: "no-agents" to skip the per-user launch agents
#
# What it does:
#   - downloads the release for this Mac's architecture from GitHub and
#     checks its SHA-256
#   - installs /usr/local/bin/nandi
#   - writes the policy packs to /Library/Application Support/nandi/policies
#   - installs launch agents that run `nandi run` and `nandi discover --report`
#     for every user, and starts them for the user logged in now
#
# Managed settings (mode, policies, report target) come from the
# configuration profile (nandi.mobileconfig or the Jamf custom settings
# plist), deployed separately.

set -euo pipefail

VERSION="${4:-latest}"
PACKS="${5:-coding-agent,payments}"
AGENTS="${6:-}"
REPO="dmdhrumilmistry/nandi"
PREFIX="/usr/local/bin"
SUPPORT="/Library/Application Support/nandi"
AGENT_DIR="/Library/LaunchAgents"
LABELS=(io.github.dmdhrumilmistry.nandi.run io.github.dmdhrumilmistry.nandi.discover)

log() { echo "nandi install: $*"; }

[ "$(id -u)" -eq 0 ] || { log "run as root"; exit 1; }

case "$(uname -m)" in
  arm64) TARGET="aarch64-apple-darwin" ;;
  x86_64) TARGET="x86_64-apple-darwin" ;;
  *) log "unsupported architecture $(uname -m)"; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || { log "could not find the latest release"; exit 1; }
fi
NAME="nandi-$VERSION-$TARGET"
URL="https://github.com/$REPO/releases/download/$VERSION/$NAME.tar.gz"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
log "downloading $NAME"
curl -fsSL -o "$TMP/$NAME.tar.gz" "$URL"
curl -fsSL -o "$TMP/$NAME.tar.gz.sha256" "$URL.sha256"
(cd "$TMP" && shasum -a 256 -c "$NAME.tar.gz.sha256") || { log "checksum mismatch"; exit 1; }
tar xzf "$TMP/$NAME.tar.gz" -C "$TMP"

mkdir -p "$PREFIX"
install -m 0755 -o root -g wheel "$TMP/$NAME/nandi" "$PREFIX/nandi"
"$PREFIX/nandi" version

# Policy packs, readable by everyone, writable by root only.
mkdir -p "$SUPPORT/policies"
IFS=',' read -r -a pack_list <<< "$PACKS"
for p in "${pack_list[@]}"; do
  p=$(echo "$p" | tr -d ' ')
  [ -n "$p" ] || continue
  "$PREFIX/nandi" policy pack "$p" > "$SUPPORT/policies/$p.yaml"
  log "policy pack $p"
done
chown -R root:wheel "$SUPPORT"
chmod -R go-w "$SUPPORT"

[ "$AGENTS" = "no-agents" ] && { log "done (no launch agents)"; exit 0; }

# The launch agents ship in the release archive (checked above).
for label in "${LABELS[@]}"; do
  src="$TMP/$NAME/deploy/mdm/macos/$label.plist"
  plutil -lint "$src" >/dev/null
  install -m 0644 -o root -g wheel "$src" "$AGENT_DIR/$label.plist"
done

# Start them for the user at the console now; everyone else gets them at
# their next login.
CONSOLE_USER=$(stat -f %Su /dev/console)
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ] && [ "$CONSOLE_USER" != "loginwindow" ]; then
  UID_=$(id -u "$CONSOLE_USER")
  for label in "${LABELS[@]}"; do
    launchctl bootout "gui/$UID_/$label" 2>/dev/null || true
    launchctl bootstrap "gui/$UID_" "$AGENT_DIR/$label.plist"
  done
  log "started for $CONSOLE_USER"
fi
log "installed $VERSION"
