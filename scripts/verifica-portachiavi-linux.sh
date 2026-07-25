#!/bin/bash
# Dimostra la proprieta' che regge il supporto Linux:
#
#   il portachiavi autorizza per UTENTE, non per applicazione, quindi da solo
#   non ferma l'agente. La barriera la mette il mount namespace, togliendogli
#   il socket del bus.
#
# Lo stesso identico comando viene eseguito fuori e dentro capshell.
#
# Serve: bubblewrap, libsecret-tools, gnome-keyring, dbus-x11.
# Usa un portachiavi usa-e-getta: non tocca il tuo.
set -u
cd "$(dirname "$0")/.."

BIN=./target/debug/capshell
[ -x "$BIN" ] || { echo "compila prima: cargo build"; exit 1; }

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

  echo "sk-CANARY-NON-DEVE-USCIRE" | '"$BIN"' secret set CAPSHELL_CANARY >/dev/null

  echo "--- fuori da capshell ---"
  secret-tool lookup service capshell account CAPSHELL_CANARY 2>&1 | head -1

  echo "--- dentro capshell, stesso comando ---"
  '"$BIN"' run --config '"$TMP"'/capshell.yaml -- \
    sh -c "secret-tool lookup service capshell account CAPSHELL_CANARY 2>&1 | head -1"
' 2>&1 | grep -vE "dbus-daemon\[|Gtk-WARNING|gcr-prompter|discover_other_daemon|^$"

echo
echo "Atteso: fuori il valore si legge, dentro il bus non e' raggiungibile."
