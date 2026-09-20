#!/bin/zsh
# Build HomeAuditWiFi.app and install it to ~/Applications.
#
# Built from source on the machine that runs it, ad-hoc signed, no downloads.
# Rebuilding changes the signature, and macOS may then ask for the Location
# Services permission again — that is expected, not a fault.
set -euo pipefail
HERE="${0:A:h}"
APP="${1:-$HOME/Applications/HomeAuditWiFi.app}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/HomeAuditWiFi.app/Contents/MacOS"
cp "$HERE/Info.plist" "$STAGE/HomeAuditWiFi.app/Contents/Info.plist"
xcrun swiftc -O -o "$STAGE/HomeAuditWiFi.app/Contents/MacOS/HomeAuditWiFi" "$HERE/main.swift"
codesign --force --sign - "$STAGE/HomeAuditWiFi.app"

mkdir -p "${APP:h}"
rm -rf "$APP"
cp -R "$STAGE/HomeAuditWiFi.app" "$APP"
echo "Installed $APP"
echo "Grant the permission once with:  open -W \"$APP\" --args --prompt"
