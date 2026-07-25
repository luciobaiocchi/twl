# Mithril (`mtl`)

Mithril is a small local credential broker for tools and coding agents. The
child process receives provider-shaped fake keys and local API base URLs. `mtl`
keeps the real keys in its parent process and adds them only when forwarding an
approved request to a fixed provider.

> Experimental security software: it has not been independently audited. Use
> test or tightly limited credentials while evaluating it.

## Security model

A real session has three controls:

1. The child environment contains a fake key, never the Keychain value.
2. Provider destinations, authentication headers, and allowed endpoints are
   compiled into `mtl`; workspace YAML cannot replace them.
3. On macOS, every Keychain read follows native LocalAuthentication. Touch ID,
   Apple Watch, or the account password must authorize each new real session,
   while the Keychain item's ACL blocks silent reads by other binaries.

An agent **can execute `mtl`**. Trying to forbid that for another process of the
same user is not a useful security boundary. Instead, a nested invocation hits
the same native Keychain gate and cannot silently open a session. Reject any
Mithril authorization prompt you did not initiate.

Real-key mode currently fails closed outside macOS. `mtl demo` is portable and
never reads a real credential.

Mithril is not a process or filesystem sandbox. An authorized child can use the
allowed provider APIs, consume quota, change project files, and attempt to
debug same-user processes. Use a container or separate OS user when that threat
is in scope. Only the credential variables in the connector table are scrubbed;
other ambient secrets and sockets remain the caller's responsibility. The
response scanner blocks accidental plain/base64 credential reflection, but it
is defense in depth—not protection from a malicious provider, which necessarily
receives the key. Responses are buffered up to 16 MiB, so real-time streaming
is not supported yet.

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

If an SDK needs another endpoint, add that exact route to the connector table,
test it, and rebuild. It is intentionally not configurable from the workspace.

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

## Configure and run a real session on macOS

Real credentials require a hardened binary so an agent cannot inject code
before the authorization check. Build and ad-hoc sign one for local use:

```bash
scripts/build-macos.sh
```

For distribution, set `MTL_CODESIGN_IDENTITY` to a stable signing identity.
The binary rejects real-key operations if hardened runtime, library validation,
or signature validity is missing, or if debugging is enabled.

Workspace configuration selects compiled connectors and an optional per-session
request count. It cannot name a secret or destination:

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

The tests cover child environment scrubbing, immutable connector policy,
session tokens, hostile headers and paths, redirect handling, response
reflection, exact endpoint allowlists, concurrent budgets, and the canary-only
CLI demo. Keychain tests are deliberately manual because they require native
user interaction and modify persistent user state.
