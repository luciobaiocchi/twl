#!/bin/sh
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
repository_dir=$(CDPATH= cd "$script_dir/.." && pwd)

if command -v cargo >/dev/null 2>&1; then
    cargo_path=$(command -v cargo)
else
    echo "cargo was not found" >&2
    exit 1
fi

cd "$repository_dir"
"$cargo_path" build --release --locked
version=$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)

TWL_BINARY="$repository_dir/target/release/twl" \
TWL_APP_BUNDLE="$repository_dir/target/release/TowelCLI.app" \
TWL_VERSION="$version" \
    "$script_dir/package-macos-app.sh"

doctor_output=$(mktemp "${TMPDIR:-/tmp}/twl-doctor.XXXXXX")
trap 'rm -f "$doctor_output"' EXIT HUP INT TERM
"$repository_dir/target/release/TowelCLI.app/Contents/MacOS/twl" doctor \
    | tee "$doctor_output"
if ! grep -q "protected macOS project sessions: available" "$doctor_output"; then
    echo "signed app bundle cannot open the protected Keychain store" >&2
    exit 1
fi
