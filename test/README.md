# TWL + Gemini test

`project/real-project/` contains only `app.py` and the agent `README.md`.

## Install release

```bash
release_dir="$(mktemp -d)" && cd "$release_dir"
curl -fLO https://github.com/luciobaiocchi/twl/releases/download/v0.1.0-alpha.1/SHA256SUMS
curl -fLO https://github.com/luciobaiocchi/twl/releases/download/v0.1.0-alpha.1/twl-0.1.0-alpha.1-x86_64-unknown-linux-musl.tar.gz
sha256sum --ignore-missing --check SHA256SUMS
tar -xzf twl-0.1.0-alpha.1-x86_64-unknown-linux-musl.tar.gz
mkdir -p ~/.local/bin
install -m 0755 twl-0.1.0-alpha.1-x86_64-unknown-linux-musl/twl ~/.local/bin/twl
export PATH="$HOME/.local/bin:$PATH"
```

## Local canary

```bash
cd "$(git rev-parse --show-toplevel)"
twl demo --config examples/towel.yaml -- bash -lc '
  export GEMINI_API_KEY="$APP_API_KEY" GEMINI_BASE_URL="$APP_BASE_URL"
  python3 test/project/real-project/app.py
'
```

## Live route

```bash
twl project add google-ai-demo
```

Use route `gemini`, base URL
`https://generativelanguage.googleapis.com/v1beta/openai`, API-key variable
`GEMINI_API_KEY`, base-URL variable `GEMINI_BASE_URL`, and paste the key into
the hidden prompt.

```bash
cd "$(git rev-parse --show-toplevel)/test/project/real-project"
export GEMINI_MODEL=gemini-2.5-flash
twl run --project google-ai-demo -- codex
```

Tell Codex: `Read README.md and follow it.`

OpenHands uses the same command shape:

```bash
twl run --project google-ai-demo -- \
  openhands --headless --file README.md
```

Use a restricted key. Do not reuse it as the agent's own model-provider key.
