#!/bin/sh
set -eu

if command -v cargo >/dev/null 2>&1; then
    cargo_path=$(command -v cargo)
elif [ -x "$HOME/.cargo/bin/cargo" ]; then
    cargo_path="$HOME/.cargo/bin/cargo"
else
    echo "cargo was not found" >&2
    exit 1
fi

# A musl target produces a static binary that runs on any distribution. Fall
# back to the host target so the script still works without musl installed.
target=${TWL_TARGET:-}
if [ -z "$target" ]; then
    default_target=$(uname -m)-unknown-linux-musl
    if command -v rustup >/dev/null 2>&1 &&
        rustup target list --installed 2>/dev/null |
        grep -qx "$default_target"; then
        target=$default_target
    else
        echo "musl target unavailable; building for the host target" >&2
        echo "install it with: rustup target add $default_target" >&2
    fi
fi

if [ -n "$target" ]; then
    "$cargo_path" build --release --locked --target "$target"
    binary=target/$target/release/twl
else
    "$cargo_path" build --release --locked
    binary=target/release/twl
fi

case "$target" in
    *-musl)
        # A musl build that still carries an interpreter is not portable, which
        # defeats the point of selecting the target at all.
        if command -v file >/dev/null 2>&1; then
            if file -b "$binary" | grep -q "dynamically linked"; then
                echo "$binary is dynamically linked; expected a static musl build" >&2
                exit 1
            fi
        elif command -v ldd >/dev/null 2>&1; then
            if ldd "$binary" 2>&1 | grep -qv "not a dynamic executable"; then
                echo "$binary is dynamically linked; expected a static musl build" >&2
                exit 1
            fi
        fi
        ;;
esac

"$binary" doctor
echo "built $binary"
