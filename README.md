# Towel (`twl`)

**Give agents capabilities, not credentials.**

Towel lets AI agents use authenticated services while keeping the reusable
credentials in a separate trusted process.

```text
Agent / Harness
      │
      │  github-read
      ▼
    Towel  🔐 GitHub token stays here
      │
      │  GET /repos/my-org/my-repo/...
      ▼
  GitHub API
```

The agent can use `github-read`. It cannot read or copy the GitHub token.

[Website](https://luciobaiocchi.github.io/twl/) ·
[Releases](https://github.com/luciobaiocchi/twl/releases) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) ·
[Apache-2.0 license](LICENSE)

> Experimental security software: it has not been independently audited. Use
> disposable or tightly scoped development credentials while evaluating it.

## Why would I use this?

Your agent needs to call an authenticated service. Normally that means putting
a reusable secret inside the agent process — in `environ`, in every child
process it spawns, one `echo $API_KEY` away from the transcript and one `curl`
away from anywhere on the internet. It stays valid long after you close the
terminal.

The agent never wanted the key. It wanted the *effect* of the key: a request
that arrives at the service and is accepted. Towel lends the effect and keeps
the key.

- **A private GitHub repository.** The agent gets `github-read`, scoped to
  `GET` under `/repos/my-org/`. Your personal access token never enters the
  agent process, so it cannot be copied into a commit, a log, or a paste.
- **An internal company API.** The destination is fixed in a protected project
  record, not in a repository file, so a prompt injection cannot redirect
  authenticated requests to an attacker's host.
- **A paid SaaS API.** The agent can spend the quota you granted it for the
  length of the session, and nothing more — it never holds a key that keeps
  working tomorrow.

## Try it in 30 seconds

No account, no credential, no install: the demo generates a canary credential
and a local service, then runs a real application against them.

```bash
git clone https://github.com/luciobaiocchi/twl
cd twl
cargo build --locked

./target/debug/twl demo \
  --config examples/towel.yaml \
  -- python3 examples/application_client.py
```

Or download the latest release and check that it works. **macOS:**

```bash
TAG=$(gh release list --repo luciobaiocchi/twl --limit 1 \
  --json tagName --jq '.[0].tagName')

case "$(uname -m)" in
  arm64)  TARGET="aarch64-apple-darwin" ;;
  x86_64) TARGET="x86_64-apple-darwin" ;;
esac

gh release download "$TAG" --repo luciobaiocchi/twl \
  --pattern "twl-${TAG#v}-${TARGET}.zip"
unzip -q "twl-${TAG#v}-${TARGET}.zip"

"./twl-${TAG#v}-${TARGET}/TowelCLI.app/Contents/MacOS/twl" doctor
```

**Linux:**

```bash
TAG=$(gh release list --repo luciobaiocchi/twl --limit 1 \
  --json tagName --jq '.[0].tagName')

case "$(uname -m)" in
  aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
  x86_64)        TARGET="x86_64-unknown-linux-musl" ;;
esac

gh release download "$TAG" --repo luciobaiocchi/twl \
  --pattern "twl-${TAG#v}-${TARGET}.tar.gz"
tar xzf "twl-${TAG#v}-${TARGET}.tar.gz"

"./twl-${TAG#v}-${TARGET}/twl" doctor
```

`doctor` reports whether this build can open protected project storage on your
platform. macOS archives contain a signed `TowelCLI.app`; keep the bundle
together and invoke `TowelCLI.app/Contents/MacOS/twl`.

## How it works

Towel supports two ways of lending a credential's effect. Both use the same
trusted routes, protected storage, and credential-injection core.

### Agent-native capabilities

A Harness invokes named capabilities such as `github-read` over a private
stdio channel. Each capability references exactly one trusted route and
narrows it with explicit HTTP methods, normalized path prefixes, and a maximum
response size. The agent names a capability; it never names a host.

```text
twl capability add --project <name>
twl capability list --project <name>
twl capability show --project <name> <capability>
twl capability delete --project <name> <capability>
twl capability serve --project <name> --stdio
```

`serve` is a private, versioned NDJSON service intended for trusted Harness
adapters. It exposes discovery and invocation results, never route
credentials, credential fingerprints, or arbitrary destination selection.
Towel validates the capability name, HTTP method, normalized path, query,
headers, and body bounds before resolving the trusted route or executing an
upstream request.

Try the contract with no protected storage and no real credential:

```bash
twl capability demo --stdio
```

### Existing applications

For software that already reads an API key from the environment, Towel starts a
small HTTP broker on loopback, hands the child a random fake key and a
`127.0.0.1` URL, and substitutes the real credential on the way out.

```bash
twl project add my-app
twl run --project my-app -- codex
```

The child receives, for every application-bound route, only a random fake value
in the route's API-key variable and a route-specific loopback broker URL in its
base-URL variable. Real credentials and real upstream destinations are not
placed in child environment variables, arguments, plaintext files, logs, or
inherited file descriptors.

Capability-only routes are never mounted in the application loopback broker, so
an application session cannot reach a credential meant for agent capabilities.

## First integration: DeepSeek Harness

The [DeepSeek Harness adapter](integrations/deepseek-harness/README.md)
registers a `twl_request` tool, owns exactly one Towel child process through
Harness lifecycle effects, and contains no credential-resolution logic. The
model sees capability names and sanitized results; the adapter never sees a
credential.

```jsonc
{
  "capability": "github-read",
  "method": "GET",
  "path": "/repos/my-org/my-repo/pulls"
}
```

The adapter owns the child pipes, and normal agent-launched subprocesses are
not given those descriptors. Closing stdin, unloading the adapter, or
SIGINT/SIGTERM ends the session and drops its in-memory route credentials. The
reproducible mock-provider run is recorded in the
[V1 capability validation report](docs/v1-capability-validation.md).

## What Towel guarantees

- The reusable credential is not placed in the agent process, its environment,
  its arguments, its files, or its inherited descriptors.
- The destination comes from the protected project record. Repository files
  cannot create a route, widen a capability, or redirect where authentication
  is placed.
- Capability policy — method, normalized path prefix, response bound — is
  enforced in Towel before any upstream request.
- Client `Authorization` headers, arbitrary origins, redirects, and ambient
  proxy settings are rejected.
- Direct plaintext and common-Base64 credential reflection in a response is
  blocked.

## What Towel does not guarantee

Towel keeps the reusable credential out of the agent. **It does not make the
authority behind that credential harmless: anything the granted capability can
legitimately access is still available to the agent.** During a session the
agent can read data the capability allows, create resources the capability
allows, and spend quota. Towel is not a sandbox and is not trying to be.

It also does not protect the agent's own model login, unrelated ambient
secrets, or anything reachable outside its routes; it cannot stop an authorized
upstream that transforms, reflects, or otherwise exposes a credential; and
responses are buffered, so streaming is not supported.

## Installation

Prebuilt archives for macOS (Apple Silicon and Intel) and Linux (x86-64 and
ARM64) are published on the
[releases page](https://github.com/luciobaiocchi/twl/releases). Linux binaries
are statically linked against musl and run on any glibc or musl distribution.

Release archives carry a build-provenance attestation. Check it before you
trust a security tool you downloaded:

```bash
gh attestation verify twl-<version>-<target>.tar.gz --repo luciobaiocchi/twl
sha256sum --check --ignore-missing SHA256SUMS
```

macOS ZIP archives contain a Developer ID-signed, provisioned, notarized, and
stapled `TowelCLI.app`, so `spctl` and Gatekeeper accept it directly.

## Security architecture

### Projects and routes

A project is the unit of authorization. On macOS, one versioned Data Protection
Keychain record contains the project. On Linux, one password-encrypted age
vault contains every project and its revision. A project has one or more named
routes; every route contains:

- an exact HTTPS base URL, optionally including a base path;
- one static Bearer API key;
- an optional application binding: the API-key and base-URL environment
  variables expected by an application.

A route can have an application binding, agent capabilities, or both.
Capability policy lives in the same protected project record as the credential.
Stored format v2 adds this model, while v1 project records are migrated in
memory and remain readable without being silently rewritten.

```text
twl project add <name>
twl project list
twl project show <name>
twl project edit <name>
twl project delete <name>
```

`add` and `edit` prompt for each route and hide API-key input. `show` displays
route names, destinations, optional application bindings, and capability
policy, but never secret values or secret-derived fingerprints. Project, route,
and capability names are identifiers, not paths.

The commands and project format are the same on macOS and Linux. macOS uses the
application-scoped Keychain backend. Linux uses
`$XDG_DATA_HOME/twl/projects.age`, falling back to
`~/.local/share/twl/projects.age`.

### Broker protections

The application broker binds only to loopback and uses an unguessable session
prefix. It accepts ordinary `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`
requests. It ignores client authentication, `Host`, proxy, and forwarding
headers; never follows redirects; rejects malformed paths; disables ambient
proxy settings; caps request and response bodies at 16 MiB; limits concurrency
to 16 requests; and blocks direct plaintext or common-Base64 credential
reflection.

The same upstream executor handles application and capability requests, so
credential injection, header filtering, redirect denial, ambient-proxy
disabling, request/response bounds, and reflection checks do not diverge.
Upstreams must use HTTPS. Loopback HTTP exists only for automated tests and
generated canary demos.

### Session lifetime

Starting `twl run --project NAME -- COMMAND` performs one authorization for the
entire project session: LocalAuthentication on macOS or one vault-password
prompt on Linux. Touch ID is used when available; macOS authorization times out
after 120 seconds.

Authorization is per session, not per request. During the session the agent can
exercise all API authority granted by the project's credentials. Use narrowly
scoped, development-only keys and end the child process to end the session.

### Linux encrypted vault

The Linux backend uses the standard age passphrase format; Towel does not
implement cryptography itself. The password is read directly from `/dev/tty`
once per protected command or run session, and is confirmed when the first
vault is created. It is never accepted through an argument or environment
variable. Use a strong, unique password: it cannot be recovered, and a copied
vault can be subjected to offline password guessing. Authenticated encryption
detects modification, but cannot prevent deletion or rollback to an older valid
vault; keep an appropriate backup.

The vault directory is mode `0700`; vault and lock files are mode `0600`. Towel
rejects symlinks, non-regular files, unexpected ownership, unsafe file modes,
hard links, and oversized ciphertext or plaintext. Updates take an exclusive
lock and use a same-directory temporary file, `fsync`, and atomic rename.
Passwords, decoded vault records, and broker route credentials use zeroizing
memory where their lifetimes end.

Before reading a password or decrypting the vault, Towel disables Linux process
dumpability. For `twl run`, it drops the password, decrypted vault, and open
vault descriptors before starting the child. If `bwrap` is available, Towel
also masks the vault directory and gives the child a separate PID namespace and
private `/proc`. The rest of the host filesystem, Git, SSH/GPG, Docker socket,
and network remain available. Towel accepts only a root-owned, non-writable
system installation at `/usr/bin/bwrap` or `/usr/local/bin/bwrap`; it does not
trust an agent-controlled `PATH`.

Inside an existing container, the same CLI requires an interactive TTY, a
persistent mount for the vault directory, and a shared network namespace
between Towel and its child so loopback broker URLs work. Towel does not create
or manage that container.

### Protected macOS build

Real Keychain sessions require a Developer ID-signed app bundle with an
embedded provisioning profile, hardened runtime, debugging disabled, and
Towel's code-signing-scoped Keychain access group. At startup Towel verifies
its code-signing status flags, Team ID, application identifier, and
access-group entitlements. An ordinary `cargo build` binary intentionally fails
closed.

```bash
export TWL_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export TWL_TEAM_ID=TEAMID
export TWL_PROVISIONING_PROFILE=/path/to/TowelCLI.provisionprofile
scripts/build-macos.sh
```

The script validates the profile's team, app identifier, Keychain access group,
expiry, distribution settings, and exact signing certificate before packaging
`target/release/TowelCLI.app`. It then runs
`TowelCLI.app/Contents/MacOS/twl doctor` and fails unless protected project
sessions are available. Ad-hoc signing is not supported because it cannot
authorize this restricted entitlement.

### Linux build

Linux needs no signing. The vault protects itself with a password, so an
ordinary release build is a real deployment:

```bash
scripts/build-linux.sh
```

The script builds against musl when that target is installed, checks that the
binary really is static, and runs `twl doctor` against it. Set `TWL_TARGET` to
override the target triple. `bwrap` (bubblewrap) is an optional runtime
dependency; nothing else is required.

## Development

Towel requires Rust 1.82 or newer:

```bash
cargo +1.82.0 fmt --all -- --check
cargo +1.82.0 test --all-targets --locked
cargo +1.82.0 clippy --all-targets --all-features --locked -- -D warnings
cargo +1.82.0 build --release --locked
```

The DeepSeek adapter is checked separately with Node 22 or newer. Its exact
tested Harness API version is documented in the integration README.

```bash
cd integrations/deepseek-harness
npm ci --ignore-scripts
npm run check
```

Security reviews, adversarial tests, and focused integrations are especially
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Explicit non-goals

This version does not provide Linux Secret Service integration, custom
cryptography, Docker or OCI image management, a dedicated Linux user, network
isolation, configurable sandbox policies, a daemon or control plane,
provider-specific profiles, repository-controlled destinations, arbitrary
authentication templates, or transparent TLS interception. The agent's own
Codex/OpenHands/model login and ambient files, sockets, and unrelated secrets
are outside Towel's boundary. V1 capabilities cover only credential-backed HTTP
requests; filesystem, shell/process, Git, generic secret retrieval, approval
flows, profiles, skill manifests, OAuth minting, delegation, and remote or
multi-user grants are intentionally not implemented.
