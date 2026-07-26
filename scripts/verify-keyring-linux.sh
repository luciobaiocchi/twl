#!/bin/bash
# Demonstrates the property Linux support rests on:
#
#   the keyring authorizes by USER, not by application, so on its own it
#   doesn't stop the agent. The barrier is set by the mount namespace, which
#   removes the bus socket from it.
#
# The exact same command runs both outside and inside capshell.
#
# Requires: bubblewrap, libsecret-tools, gnome-keyring, dbus-x11.
# Uses a throwaway keyring: it doesn't touch yours.
set -u
cd "$(dirname "$0")/.."

BIN=./target/debug/capshell
[ -x "$BIN" ] || { echo "build first: cargo build"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export XDG_RUNTIME_DIR="$TMP/run"
export XDG_DATA_HOME="$TMP/data"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"
chmod 700 "$XDG_RUNTIME_DIR"

cat > "$TMP/capshell.yaml" <<'YAML'
secrets:
  - name: CAPSHELL_CANARY
    connector: openai
    upstream: http://127.0.0.1:1
YAML

dbus-run-session -- bash -c '
  eval "$(echo -n passphrase | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)"
  export GNOME_KEYRING_CONTROL

  echo "sk-CANARY-MUST-NOT-LEAK" | '"$BIN"' secret set CAPSHELL_CANARY >/dev/null

  echo "--- outside capshell ---"
  secret-tool lookup service capshell account CAPSHELL_CANARY 2>&1 | head -1

  echo "--- inside capshell, same command ---"
  '"$BIN"' run --config '"$TMP"'/capshell.yaml -- \
    sh -c "secret-tool lookup service capshell account CAPSHELL_CANARY 2>&1 | head -1"
' 2>&1 | grep -vE "dbus-daemon\[|Gtk-WARNING|gcr-prompter|discover_other_daemon|^$"

echo
echo "Expected: the value reads outside, the bus is unreachable inside."
