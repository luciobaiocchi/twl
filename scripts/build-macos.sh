#!/bin/sh
set -eu

identity=${TWL_CODESIGN_IDENTITY:--}
if command -v cargo >/dev/null 2>&1; then
    cargo_path=$(command -v cargo)
elif [ -x "$HOME/.cargo/bin/cargo" ]; then
    cargo_path="$HOME/.cargo/bin/cargo"
else
    echo "cargo was not found" >&2
    exit 1
fi

"$cargo_path" build --release --locked
codesign --force --sign "$identity" --options runtime target/release/twl
codesign --verify --strict target/release/twl
target/release/twl doctor
