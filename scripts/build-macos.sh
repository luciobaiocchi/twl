#!/bin/sh
set -eu

identity=${TWL_CODESIGN_IDENTITY:--}
team_id=${TWL_TEAM_ID:-}
if [ -z "$team_id" ]; then
    echo "TWL_TEAM_ID is required for the protected Keychain access group" >&2
    exit 1
fi
if command -v cargo >/dev/null 2>&1; then
    cargo_path=$(command -v cargo)
elif [ -x "$HOME/.cargo/bin/cargo" ]; then
    cargo_path="$HOME/.cargo/bin/cargo"
else
    echo "cargo was not found" >&2
    exit 1
fi

"$cargo_path" build --release --locked
entitlements=$(mktemp "${TMPDIR:-/tmp}/twl-entitlements.XXXXXX")
trap 'rm -f "$entitlements"' EXIT HUP INT TERM
sed "s/__TEAM_ID__/$team_id/g" config/macos.entitlements >"$entitlements"
codesign --force --sign "$identity" --options runtime \
    --entitlements "$entitlements" target/release/twl
codesign --verify --strict target/release/twl
codesign -d --entitlements - target/release/twl >/dev/null
target/release/twl doctor
