#!/bin/zsh
# Build HomeAuditRunner.app and install it to ~/Applications.
#
# Built from source on the machine that runs it, ad-hoc signed, no downloads.
# Rebuilding changes the signature, and macOS may then ask for the Local Network
# permission again — that is expected, not a fault.
set -euo pipefail
HERE="${0:A:h}"
APP="${1:-$HOME/Applications/HomeAuditRunner.app}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/HomeAuditRunner.app/Contents/MacOS"
cp "$HERE/Info.plist" "$STAGE/HomeAuditRunner.app/Contents/Info.plist"
xcrun swiftc -O -o "$STAGE/HomeAuditRunner.app/Contents/MacOS/HomeAuditRunner" "$HERE/main.swift"
codesign --force --sign - --identifier com.rstuklis.homeaudit.runner "$STAGE/HomeAuditRunner.app"

mkdir -p "${APP:h}"
rm -rf "$APP"
cp -R "$STAGE/HomeAuditRunner.app" "$APP"
echo "Installed $APP"
