# Mithril (`mtl`)

Mithril is a small local credential broker for tools and coding agents. The
child process receives service-shaped fake keys and local API base URLs. `mtl`
keeps real keys in its parent process and adds them only when forwarding an
approved request to the destination selected by trusted session input.

> Experimental security software: it has not been independently audited. Use
> test or tightly limited credentials while evaluating it.

## Security model

A real session has three controls:

1. The child environment contains a fake key, never the Keychain value.
2. Workspace YAML can select a connector but cannot supply a credential or
   destination. Built-in provider destinations are compiled in; an ephemeral
   application destination must be supplied directly to the parent at startup.
3. On macOS, every Keychain read follows native LocalAuthentication. Touch ID,
   Apple Watch, or the account password must authorize each new real session,
   while the Keychain item's ACL blocks silent reads by other binaries.

An agent **can execute `mtl`**. Trying to forbid that for another process of the
same user is not a useful security boundary. Instead, a nested invocation hits
the same native Keychain gate and cannot silently open a session. Reject any
Mithril authorization prompt you did not initiate.

Stored-key mode currently fails closed outside macOS. Ephemeral application
credentials work on macOS and Linux: macOS requires the hardened build, while
Linux disables same-user process inspection before reading the credential.
`mtl demo` is portable and never reads a real credential.

Mithril is not a process or filesystem sandbox. An authorized child can use the
allowed provider APIs, consume quota, change project files, and attempt to
debug same-user processes. Use a container or separate OS user when that threat
is in scope. Only variables for selected connectors and Mithril parent inputs
are scrubbed; other ambient secrets and sockets remain the caller's
responsibility. The response scanner blocks accidental plain/base64 credential
reflection, but it is defense in depth—not protection from a malicious
provider, which necessarily receives the key. Responses are buffered up to 16
MiB, so real-time streaming is not supported yet. At most 16 requests are
forwarded concurrently; excess requests fail locally with `503` instead of
being queued.

## How the agent knows which endpoint to call

The agent's provider SDK already chooses the method and path. Mithril only
changes the SDK's base URL:

```text
OpenAI SDK: GET /models
OPENAI_BASE_URL=http://127.0.0.1:<port>/<session>/openai/v1
Result:      GET /<session>/openai/v1/models
```

The proxy removes the session and connector prefix, checks the exact compiled
method/path pair, and forwards it to `https://api.openai.com/v1/models`. It
ignores any client `Authorization`, `Host`, or forwarding headers and installs
the real authentication itself. Unknown connectors and unapproved endpoints
never reach a provider.

Current connector policy:

| Connector | Child variables | Allowed provider endpoints |
|---|---|---|
| `openai` | `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_API_BASE` | `GET /v1/models`; `POST /v1/responses`; `POST /v1/chat/completions`; `POST /v1/embeddings` |
| `anthropic` | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_URL` | `GET /v1/models`; `POST /v1/messages` |
| `application` | `APP_API_KEY`, `APP_BASE_URL` | General `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` paths at one parent-selected destination; bearer authentication |

The built-in provider connectors remain exact allowlists. The application
connector deliberately grants broader API authority because its purpose is to
run a project against its service; it still cannot change destination or read
the credential. Use a narrowly scoped application key.

## Build and try it safely

```bash
cargo build --locked
./target/debug/mtl doctor       # demo works; real mode reports missing hardening

# Built-in fake provider, generated canary key, no Keychain or API charge.
./target/debug/mtl demo --config examples/mithril.yaml -- \
  sh -c 'curl -s "$OPENAI_BASE_URL/models"'
```

The last command prints JSON showing `/v1/models` and a redacted canary
authorization header. You can also start an interactive demo shell:

```bash
./target/debug/mtl demo --config examples/mithril.yaml -- sh
```

Inside it, `OPENAI_API_KEY` is fake and `OPENAI_BASE_URL` points to the
session-scoped local proxy. A client that ignores the base-URL variable will not
work through Mithril; `mtl` warns when no approved request reached its proxy.

## Run an application through Codex or OpenHands

The `application` connector protects a credential used by the project that an
agent runs. It does not replace or hide the agent's own login credential.

For a canary-only check that needs no service or credential, run:

```bash
./target/debug/mtl demo --config examples/application.yaml -- \
  python3 examples/application_client.py
```

Start the disposable local service in one terminal:

```bash
MTL_TEST_APPLICATION_KEY=third-party-test-key \
  python3 examples/application_upstream.py
```

On macOS, first build the hardened binary with `scripts/build-macos.sh`. Then
start Codex in another terminal; `mtl` prompts for `APP_API_KEY` without using
the child's standard input:

```bash
./target/release/mtl run \
  --config examples/application.yaml \
  --upstream application=http://127.0.0.1:8765 \
  -- codex
```

Enter `third-party-test-key`, then ask Codex to run:

```bash
python3 examples/application_client.py
```

The app succeeds, but Codex and the app see only an `mtl-app-...` placeholder
in `APP_API_KEY` and a session-local `APP_BASE_URL`. The mock service confirms
that only the broker sent the real test key. Replace `codex` with `openhands` or
another agent to exercise the same inheritance flow.

For noninteractive launchers, provide the secret on a dedicated descriptor.
The descriptor is read, marked close-on-exec, and closed before the agent starts:

```bash
./target/release/mtl run \
  --config examples/application.yaml \
  --upstream application=http://127.0.0.1:8765 \
  --secret-fd application=3 \
  3<<<'third-party-test-key' \
  -- codex
```

The literal above is only a disposable test value. For a real secret, connect
FD 3 to a secret-producing process instead of placing the value in shell
history. `MTL_APPLICATION_API_KEY` and `MTL_APPLICATION_UPSTREAM` are also
accepted as parent inputs, but the CLI warns that environment values can leak
through shell history, logs, or process metadata.

## Configure and run a real session on macOS

Real credentials require a hardened binary so an agent cannot inject code
before the authorization check. Build and ad-hoc sign one for local use:

```bash
scripts/build-macos.sh
```

For distribution, set `MTL_CODESIGN_IDENTITY` to a stable signing identity.
The binary rejects real-key operations if hardened runtime, library validation,
or signature validity is missing, or if debugging is enabled.

Workspace configuration selects connectors and an optional per-session request
count. It cannot name a secret or destination:

```yaml
connectors:
  - openai

budget:
  max_requests: 5
```

Store a credential, then launch the client:

```bash
./target/release/mtl secret set openai
./target/release/mtl run --config examples/mithril.yaml -- your-command
```

`secret set` never updates an existing item, because doing so could inherit a
weak ACL from an item created by another process. Rotate explicitly with
`mtl secret delete openai`, followed by `mtl secret set openai`.

The budget is enforced before forwarding, including under concurrency. It is a
request-count guard, not a token or billing limit.

To verify the nested-agent defense manually, launch an interactive shell with
`mtl run`, approve the expected prompt, then invoke another `mtl run` inside
that shell. The nested process must cause a new native prompt; reject it and the
nested session must fail.

For one-time migration from a simple `KEY=value` file:

```bash
./target/release/mtl secret import .env --config examples/mithril.yaml
```

Run migration before starting an untrusted agent. All configured credentials
must be present, and their Keychain items must not already exist. After the
Keychain writes succeed, the file is atomically replaced with fake values; no
plaintext `.bak` is created.

## Test locally

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

The tests cover child environment scrubbing, dedicated-descriptor closure, the
Python application flow, destination validation, immutable built-in connector
policy, session tokens, hostile headers and paths, redirect handling, response
reflection, exact endpoint allowlists, concurrent budgets, and the canary-only
CLI demo. Keychain tests are deliberately manual because they require native
user interaction and modify persistent user state.

### Opt-in live OpenAI smoke test

After storing a real key, run one small Responses API request through the
hardened proxy:

```bash
scripts/test-openai-live.sh
```

This test requires native authorization, consumes API quota, and is never run
in CI. It succeeds only when the model returns `MITHRIL_OK`. An
`insufficient_quota` response exits with status 2: it confirms that Mithril
reached OpenAI with an authenticated request, but not that model generation
succeeded. Override the defaults with `MTL_TEST_MODEL`, `MTL_BIN`, or
`MTL_CONFIG`.
