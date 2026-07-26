# Towel (`twl`)

Towel keeps a project application's API key out of a coding agent's process.
The application receives a fake `APP_API_KEY` and a session-local
`APP_BASE_URL`; the separate Towel parent adds the real key only while
forwarding requests to one upstream chosen at startup.

Towel does **not** hide the agent's own Codex, OpenHands, or model-provider
credential. It is not a persistent secret store.

[Website](https://luciobaiocchi.github.io/twl/) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) ·
[Apache-2.0 license](LICENSE)

The name is a concise nod to Douglas Adams's famously indispensable towel:
lightweight, unassuming, and useful in more situations than expected. Keep it
beside the agent, put the dangerous credential behind it, and don't panic.
Towel is an independent project and is not affiliated with Douglas Adams's
estate or publishers.

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

Towel prevents direct credential disclosure; it does not prevent the agent
from using the local proxy to exercise the credential's API authority. Use a
narrowly scoped, development-only key and a budget. It is also not a process or
filesystem sandbox: other ambient secrets, sockets, and files remain the
caller's responsibility.

The proxy binds only to loopback, requires an unguessable session path, ignores
client authentication and forwarding headers, never follows redirects, caps
bodies at 16 MiB, and blocks accidental plaintext or base64 reflection of the
real key. Responses are buffered, so streaming is not supported yet. At most
16 requests are forwarded concurrently; excess requests fail with `503`.

## Installation and release status

Towel has not published its first public package yet. Until then, build it
from source using the instructions below.

The planned primary installation method is a Homebrew tap backed by prebuilt
GitHub Release artifacts:

```bash
brew install luciobaiocchi/tap/twl
```

That command will become available with the first public release. The tap will
select the appropriate macOS or Linux artifact and verify its checksum. macOS
artifacts must be Developer ID-signed, hardened, and notarized; an ordinary
`cargo install` binary cannot open a real macOS session.

Cargo installation may be offered later as a Linux-oriented source-install
option under the `twl` package name. It should not be advertised as the macOS
installation path because locally compiled binaries lack the required
distribution signature.

Prebuilt packages will not require Rust or Python. Python is used only by the
example application and tests.

### Runtime requirements

- The project application must use `APP_API_KEY` and `APP_BASE_URL`, or provide
  a small adapter that maps them to its own configuration.
- The current protocol supports one static Bearer credential and one HTTPS
  upstream per session. HTTP is accepted only for loopback development.
- The host must allow a loopback listener and outbound HTTPS connections.
- On macOS, real sessions require the signed and hardened release binary.
- On Linux, run the agent as an unprivileged user without `CAP_SYS_PTRACE`.
  Running the agent as container root weakens the process boundary.
- In containers, `twl`, the agent, and the project application must share a
  network namespace so they can use the same loopback interface.

### Before the first public tag

The release still requires making the repository public, verifying the first
CI and dependency-audit runs, producing checksummed multi-architecture
artifacts, macOS Developer ID signing and notarization, a Homebrew tap, and
installation tests on clean machines. The intended first version is an
explicitly experimental `v0.1.0-alpha.1`, not a stable security guarantee.

## Build and test

```bash
cargo build --locked
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

Building from source requires Rust 1.82 or newer and a native build toolchain
(Xcode Command Line Tools on macOS, or a C compiler and linker on Linux).

On macOS, real-key mode requires a hardened binary:

```bash
scripts/build-macos.sh
```

For distribution, set `TWL_CODESIGN_IDENTITY` to a stable signing identity.
On Linux, Towel disables same-user process inspection before reading the
credential. `twl doctor` reports whether the current binary can open a real
session.

## Safe local demo

The demo uses a generated canary and a generated local service:

```bash
./target/debug/twl demo --config examples/towel.yaml -- \
  python3 examples/application_client.py
```

The application succeeds while seeing only the fake key and local URL.

## Run a project through an agent

Start the disposable example service in one terminal:

```bash
TWL_TEST_APPLICATION_KEY=third-party-test-key \
  python3 examples/application_upstream.py
```

Then start the agent through the hardened release binary:

```bash
./target/release/twl run \
  --config examples/towel.yaml \
  --upstream http://127.0.0.1:8765 \
  -- codex
```

Towel reads `APP_API_KEY` through a hidden terminal prompt before launching
Codex. Ask the agent to run:

```bash
python3 examples/application_client.py
```

The app receives a successful response, but both Codex and the app can see only
a `twl-app-...` placeholder. The real test key exists only in the parent and
in the outbound request received by the fixed service.

Applications opt in by reading:

```text
APP_API_KEY   fake value suitable for the application's key field
APP_BASE_URL  local session URL used instead of the real service URL
```

## Noninteractive secret input

A dedicated file descriptor keeps the secret separate from the child's
terminal input. `twl` reads it, marks it close-on-exec, and closes it before
launching the agent:

```bash
./target/release/twl run \
  --upstream http://127.0.0.1:8765 \
  --secret-fd 3 \
  3< <(printf %s 'disposable-test-key') \
  -- codex
```

The literal is only for local testing. In production, connect FD 3 directly to
a trusted secret-producing process. The descriptor number is explicit because
the parent launcher owns descriptor allocation; `twl` cannot safely guess
which inherited descriptor contains the secret.

For simple deployment environments, `TWL_APPLICATION_API_KEY` and
`TWL_APPLICATION_UPSTREAM` are also accepted as parent inputs. Towel removes
them from the child environment and installs the fake application variables,
but warns that parent environment values may be exposed by shell history,
logs, crash reports, or process inspection before Towel hardens itself.

## Configuration

Configuration is optional. A project file contains only low-authority session
limits:

```yaml
budget:
  max_requests: 5
```

The credential and destination never belong in this file. Omit `--config` for
an unlimited session.
