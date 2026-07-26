# Mithril (`mtl`)

Mithril keeps a project application's API key out of a coding agent's process.
The application receives a fake `APP_API_KEY` and a session-local
`APP_BASE_URL`; the separate Mithril parent adds the real key only while
forwarding requests to one upstream chosen at startup.

Mithril does **not** hide the agent's own Codex, OpenHands, or model-provider
credential. It is not a persistent secret store.

> Experimental security software: it has not been independently audited. Use
> disposable or tightly limited credentials while evaluating it.

## Current contract

The intentionally small first version supports one project credential:

- `Authorization: Bearer <secret>` authentication;
- an HTTPS upstream, with HTTP allowed only for loopback testing;
- ordinary `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` application paths;
- an optional per-session request-count budget.

The upstream and real credential are trusted parent inputs. Project YAML can
only set the request budget, so an agent that edits the repository cannot
redirect the real key.

Mithril prevents direct credential disclosure; it does not prevent the agent
from using the local proxy to exercise the credential's API authority. Use a
narrowly scoped, development-only key and a budget. It is also not a process or
filesystem sandbox: other ambient secrets, sockets, and files remain the
caller's responsibility.

The proxy binds only to loopback, requires an unguessable session path, ignores
client authentication and forwarding headers, never follows redirects, caps
bodies at 16 MiB, and blocks accidental plaintext or base64 reflection of the
real key. Responses are buffered, so streaming is not supported yet. At most
16 requests are forwarded concurrently; excess requests fail with `503`.

## Build and test

```bash
cargo build --locked
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

On macOS, real-key mode requires a hardened binary:

```bash
scripts/build-macos.sh
```

For distribution, set `MTL_CODESIGN_IDENTITY` to a stable signing identity.
On Linux, Mithril disables same-user process inspection before reading the
credential. `mtl doctor` reports whether the current binary can open a real
session.

## Safe local demo

The demo uses a generated canary and a generated local service:

```bash
./target/debug/mtl demo --config examples/mithril.yaml -- \
  python3 examples/application_client.py
```

The application succeeds while seeing only the fake key and local URL.

## Run a project through an agent

Start the disposable example service in one terminal:

```bash
MTL_TEST_APPLICATION_KEY=third-party-test-key \
  python3 examples/application_upstream.py
```

Then start the agent through the hardened release binary:

```bash
./target/release/mtl run \
  --config examples/mithril.yaml \
  --upstream http://127.0.0.1:8765 \
  -- codex
```

Mithril reads `APP_API_KEY` through a hidden terminal prompt before launching
Codex. Ask the agent to run:

```bash
python3 examples/application_client.py
```

The app receives a successful response, but both Codex and the app can see only
an `mtl-app-...` placeholder. The real test key exists only in the parent and
in the outbound request received by the fixed service.

Applications opt in by reading:

```text
APP_API_KEY   fake value suitable for the application's key field
APP_BASE_URL  local session URL used instead of the real service URL
```

## Noninteractive secret input

A dedicated file descriptor keeps the secret separate from the child's
terminal input. `mtl` reads it, marks it close-on-exec, and closes it before
launching the agent:

```bash
./target/release/mtl run \
  --upstream http://127.0.0.1:8765 \
  --secret-fd 3 \
  3< <(printf %s 'disposable-test-key') \
  -- codex
```

The literal is only for local testing. In production, connect FD 3 directly to
a trusted secret-producing process. The descriptor number is explicit because
the parent launcher owns descriptor allocation; `mtl` cannot safely guess
which inherited descriptor contains the secret.

For simple deployment environments, `MTL_APPLICATION_API_KEY` and
`MTL_APPLICATION_UPSTREAM` are also accepted as parent inputs. Mithril removes
them from the child environment and installs the fake application variables,
but warns that parent environment values may be exposed by shell history,
logs, crash reports, or process inspection before Mithril hardens itself.

## Configuration

Configuration is optional. A project file contains only low-authority session
limits:

```yaml
budget:
  max_requests: 5
```

The credential and destination never belong in this file. Omit `--config` for
an unlimited session.
