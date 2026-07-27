# Towel (`twl`)

Towel is a lightweight, portable HTTP secrets broker for AI coding agents. It
keeps reusable provider credentials in a trusted process and injects them only
into requests that match encrypted, destination-bound policies.

The agent and its applications receive fake credentials, loopback broker URLs,
and a short-lived session token. They can exercise the API authority explicitly
granted to that session, but Towel never gives them a reusable provider key.

[Website](https://luciobaiocchi.github.io/twl/) ·
[Security policy](SECURITY.md) · [Deployments](deploy/README.md) ·
[Contributing](CONTRIBUTING.md) · [Apache-2.0 license](LICENSE)

> Experimental security software: Towel has not been independently audited.
> Use narrowly scoped, disposable development credentials while evaluating it.

## Why a separate broker process?

An out-of-process broker is a stronger secret-isolation boundary than
in-process Python inside OpenHands. The reusable credentials live outside the
agent's memory and privilege boundary; the trusted codebase is smaller; the
broker is independent of the agent language and runtime; and the same core can
be reused on a laptop, in Docker, and in Kubernetes. Compromise of OpenHands or
one of its dependencies therefore does not automatically disclose the real
credential.

That boundary is operationally more demanding: it adds IPC, lifecycle, and
deployment work. Towel accepts that cost where secret isolation matters. It
does not pretend that an in-process helper and a separately isolated broker
offer the same protection.

## Security model

```text
trusted user / control plane
        │ encrypted vault + explicit allow-route set
        ▼
  Towel process ── HTTPS + real Bearer key ──► fixed upstream A
        │       └─ HTTPS + real Bearer key ──► fixed upstream B
        │
        └─ loopback URLs + fake keys + expiring token
                                │
                                ▼
                         agent + application
```

The encrypted vault contains both credential values and every policy field
that controls where and how they may be used. Towel uses Argon2id for password
derivation and XChaCha20-Poly1305 for authenticated encryption. Changing a
destination, credential reference, injection policy, method, path, budget,
size limit, concurrency limit, or expiry invalidates authentication of the
vault.

The vault file is the primary portable storage mechanism on macOS, Linux, and
containers. Towel does not depend on OS-specific keyring behavior; a keyring
may later be offered only as an optional way to store or unlock the vault key.

Each route defines:

- a unique route ID;
- an exact scheme, hostname, and port (HTTPS, except loopback tests);
- a credential reference and `Authorization: Bearer` injection policy;
- allowed `GET`, `POST`, `PUT`, `PATCH`, and/or `DELETE` methods;
- optional normalized path prefixes;
- request-count, request-size, response-size, concurrency, and expiry limits.

At runtime Towel denies by default, binds a random 256-bit session token to the
selected route set, binds natively to loopback, never accepts a destination
from the client, never follows redirects, strips client authentication and
forwarding headers, and injects a credential only at its configured location.
Responses are buffered, size-limited, stripped to a safe content type, and
blocked if they contain plaintext or standard/URL-safe base64 forms of any
session credential.

The real credentials are never placed by Towel in the agent environment,
filesystem, process memory, command line, or inherited file descriptors. This
claim depends on preserving the process/container boundary described below: an
agent with host root, a shared PID namespace, `CAP_SYS_PTRACE`, the vault
password, or equivalent access can defeat it.

## Supported scope

The first version supports ordinary non-streaming HTTP requests and static
Bearer authentication. HTTPS is required for real upstreams; HTTP is accepted
only for loopback testing.

Towel is the lightweight data-plane broker. It is not an enterprise identity
or multi-tenant credential platform. Systems such as OpenHands may later
provide identity, tenant authorization, credential lifecycle, rotation,
revocation, auditing, and short-lived grants through the `GrantProvider`
interface.

Explicit non-goals for this version include:

- generic TCP, database, SSH, or other non-HTTP protocols;
- arbitrary authentication templates, API-key headers, AWS SigV4, or request
  signing;
- streaming responses;
- applications that fundamentally require a raw local secret;
- judging shell commands as a security boundary;
- stopping an authorized agent from using the API authority it was granted;
- hiding the agent's own Codex/OpenHands model login unless that provider is
  separately integrated as an application route.

## Build and test

Towel requires Rust 1.82 or newer until prebuilt packages are published.

```bash
cargo build --locked
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

On macOS, operations that read real credentials (vault sealing and real
sessions) require a signed hardened-runtime binary:

```bash
scripts/build-macos.sh
```

Set `TWL_CODESIGN_IDENTITY` for a distributable build. On Linux, Towel disables
same-user process inspection before opening the vault. `twl doctor` reports
whether the current binary can open a protected session.

## Safe canary demo

The demo creates a generated credential and local upstream, then launches an
ordinary application through the same grant and route-map implementation:

```bash
./target/debug/twl demo --config examples/towel.yaml -- \
  python3 examples/application_client.py
```

No vault or real credential is used.

## Create an encrypted vault

Copy [the trusted-route template](examples/trusted-routes.yaml.example) to a
trusted location outside the repository, replace its placeholder credential
and origin, then seal it:

```bash
./target/release/twl vault seal \
  --input /secure/towel/trusted-routes.yaml \
  --output /secure/towel/towel.vault
```

Towel prompts twice for a new password, refuses to overwrite an existing
vault, and creates the encrypted file with mode `0600` on Unix. The plaintext
source is not removed automatically. A trusted secret-producing process may
instead pipe YAML with `--input -` so no plaintext route document is stored.

For noninteractive native automation, connect a trusted producer directly to
a dedicated descriptor:

```bash
./target/release/twl vault seal \
  --input - --output /secure/towel/towel.vault \
  --password-fd 3 3</secure/towel/unlock-password
```

The descriptor is marked close-on-exec, consumed, and closed. Container secret
mounts can use `--password-file`; that file must be mounted only in the Towel
container, never in the agent container.

## Launch an agent natively

The trusted launcher chooses the maximum route authority explicitly. A project
configuration can select only a subset of this list and can only reduce limits:

```bash
./target/release/twl run \
  --vault /secure/towel/towel.vault \
  --allow-route application \
  --config examples/towel.yaml \
  -- codex
```

For a one-route session, Towel preserves the simple application contract:

```text
APP_API_KEY   unique fake value
APP_BASE_URL  http://127.0.0.1:<port>/<session-token>/<route-id>
```

Every session also receives `TWL_BROKER_URL`, `TWL_SESSION_TOKEN`, and one pair
per route. Route IDs are uppercased and hyphens become underscores:

```text
TWL_ROUTE_APPLICATION_URL
TWL_ROUTE_APPLICATION_CREDENTIAL
```

The application sends its ordinary request to the local URL. Client-provided
authentication is discarded; Towel adds the real Bearer credential only after
the token, route, method, path, expiry, size, budget, and concurrency checks
pass.

## Low-authority repository configuration

Repository-controlled YAML may contain route references and reductions only:

```yaml
routes:
  - application
limits:
  max_requests: 5
  max_request_bytes: 1048576
  max_response_bytes: 2097152
  max_concurrent_requests: 2
  session_expiry_seconds: 300
```

It cannot contain credentials, origins, credential references, or
authentication policy. A route reference not present in the trusted
`--allow-route` set fails closed.

## Docker and Kubernetes

`twl serve` creates the same isolated session without launching a child and
writes an agent-visible JSON manifest containing only local URLs, fake
credentials, and the expiring capability token. It never writes provider
credentials or upstream destinations to that shared file.

See [deploy/README.md](deploy/README.md) for Docker Compose and Kubernetes
sidecar templates. The essential rules are separate PID and filesystem
boundaries, no provider-vault or unlock mount in the agent, an unprivileged
agent with all capabilities dropped (including `CAP_SYS_PTRACE`), a shared
network namespace only where loopback requires it, and one Towel session per
agent runtime or conversation.

## Release status

The planned first public build is an experimental `v0.1.0-alpha.1`. The
intended installation path is a checksummed Homebrew release:

```bash
brew install luciobaiocchi/tap/twl
```

That command is not available until the first release. macOS artifacts must be
Developer ID-signed, hardened, and notarized; ordinary `cargo install` builds
cannot open protected macOS sessions.

The name is a concise nod to Douglas Adams's famously indispensable towel:
lightweight, unassuming, and useful in more situations than expected. Towel is
an independent project and is not affiliated with Douglas Adams's estate or
publishers.
