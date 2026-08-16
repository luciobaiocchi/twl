# Towel (`twl`)

Towel keeps destination-bound API keys out of coding-agent processes. It can
lend the credential's effect through either an application-compatible loopback
broker or a named, method/path-constrained agent capability. Both interfaces
use the same trusted routes, protected storage, and credential-injection core.

```bash
twl project add my-app
twl run --project my-app -- codex
```

[Website](https://luciobaiocchi.github.io/twl/) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) ·
[Apache-2.0 license](LICENSE)

> Experimental security software: it has not been independently audited. Use
> disposable or tightly scoped development credentials while evaluating it.

## Why this exists

You want to run a coding agent on your machine. It needs to call some API, so
you do what everybody does: you put the key in the environment and launch it.

Now look at what you just did. The key is in `environ`. It is in every child
process the agent spawns. It is one `echo $API_KEY` away from the transcript,
one `curl` away from anywhere on the internet, and it stays valid long after
you close the terminal. You did not grant the agent *use* of your API. You
handed over the credential, and a credential does not expire when your patience
does.

Here is the thing though: the agent never wanted the key. It wanted the
*effect* of the key — a request that arrives at the API and is accepted. That
is a much smaller thing to give away, and it turns out you can give it away
without giving anything up.

So Towel keeps the key and lends out the effect. For existing applications, it
starts a small HTTP broker on loopback, hands the child a random fake key and a
`127.0.0.1` URL, and substitutes the real credential on the way out. For an
agent-native operation, a Harness adapter invokes a named capability over a
private stdio channel instead. In both cases the destination comes from the
trusted route and the credential stays in Towel.

I would rather be clear about the limits than oversell this. While the session
is running, the agent can reach the API through the broker, so it can spend
your quota and touch your data. Towel does not sandbox it and is not trying to.
What it takes away is the credential itself: nothing the agent can read, log,
print, or copy out is worth anything once the session ends. That is a narrower
promise than "your agent is contained", and it is the one I can actually keep.

## Projects and routes

A project is the unit of authorization. On macOS, one versioned Data Protection
Keychain record contains the project. On Linux, one password-encrypted age
vault contains every project and its revision. A project has one or more named
routes; every route contains:

- an exact HTTPS base URL, optionally including a base path;
- one static Bearer API key;
- an optional application binding: the API-key and base-URL environment
  variables expected by an application.

A route can have an application binding, agent capabilities, or both. An agent
capability stores a name and description, references exactly one route, and
narrows it with explicit HTTP methods, normalized path prefixes, and a maximum
response size. Capability policy lives in the same protected project record as
the credential; repository files cannot create or widen it. Stored format v2
adds this model, while v1 project records are migrated in memory and remain
readable without being silently rewritten.

Create and maintain projects with the interactive CLI:

```text
twl project add <name>
twl project list
twl project show <name>
twl project edit <name>
twl project delete <name>
```

`add` and `edit` prompt for each route and hide API-key input. `show` displays
route names, destinations, optional application bindings, and capability
policy, but never secret values or secret-derived fingerprints. Project,
route, and capability names are identifiers, not paths.

Manage v1 HTTP capabilities through the protected project service:

```text
twl capability add --project <name>
twl capability list --project <name>
twl capability show --project <name> <capability>
twl capability delete --project <name> <capability>
twl capability serve --project <name> --stdio
```

`serve` is a private, versioned NDJSON service intended for trusted Harness
adapters. It exposes discovery and invocation results, never route credentials,
credential fingerprints, or arbitrary destination selection. The generated
canary service exercises the same contract without protected storage or a real
credential:

```bash
twl capability demo --stdio
```

The first adapter is the out-of-tree
[DeepSeek Harness integration](integrations/deepseek-harness/README.md). It
registers `twl_request`, owns one Towel child process through Harness lifecycle
effects, and contains no credential-resolution logic. The reproducible mock
provider run is recorded in the
[V1 capability validation report](docs/v1-capability-validation.md).

The commands and project format are the same on macOS and Linux. macOS uses the
application-scoped Keychain backend. Linux uses `$XDG_DATA_HOME/twl/projects.age`,
falling back to `~/.local/share/twl/projects.age`.

## Linux encrypted vault

The Linux backend uses the standard age passphrase format; Towel does not
implement cryptography itself. The password is read directly from `/dev/tty`
once per protected command or run session, and is confirmed when the first
vault is created. It is never accepted through an argument or environment
variable. Use a strong, unique password: it cannot be recovered, and a copied
vault can be subjected to offline password guessing. Authenticated encryption
detects modification, but cannot prevent deletion or rollback to an older
valid vault; keep an appropriate backup.

The vault directory is mode `0700`; vault and lock files are mode `0600`.
Towel rejects symlinks, non-regular files, unexpected ownership, unsafe file
modes, hard links, and oversized ciphertext or plaintext. Updates take an
exclusive lock and use a same-directory temporary file, `fsync`, and atomic
rename. Passwords, decoded vault records, and broker route credentials use
zeroizing memory where their lifetimes end.

Before reading a password or decrypting the vault, Towel disables Linux process
dumpability. For `twl run`, it drops the password, decrypted vault, and open
vault descriptors before starting the child. If `bwrap` is available, Towel
also masks the vault directory and gives the child a separate PID namespace and
private `/proc`. The rest of the host filesystem, Git, SSH/GPG, Docker socket,
and network remain available. Towel accepts only a root-owned, non-writable
system installation at `/usr/bin/bwrap` or `/usr/local/bin/bwrap`; it does not
trust an agent-controlled `PATH`. If that profile is not used, the age-encrypted
vault remains protected by its password.

Inside an existing container, the same CLI requires an interactive TTY, a
persistent mount for the vault directory, and a shared network namespace
between Towel and its child so loopback broker URLs work. Towel does not create
or manage that container.

## Application session contract

Starting `twl run --project NAME -- COMMAND` performs one authorization for the
entire project session: LocalAuthentication on macOS or one vault-password
prompt on Linux. Touch ID is used when available; macOS can fall back to the
configured device-owner authentication. macOS authorization times out after
120 seconds.

The child receives, for every application-bound route, only:

- a random fake value in the route's application-facing API-key variable; and
- a route-specific loopback broker URL in its base-URL variable.

Real credentials and real upstream destinations are not placed in child
environment variables, arguments, plaintext files, logs, or inherited file
descriptors.
They remain in the trusted Towel process and are bound together by the project
record. The broker selects the upstream from the authenticated route path and
injects only that route's key as `Authorization: Bearer`.

Authorization is per session, not per request. During the session the agent can
exercise all API authority granted by the project's credentials through the
broker, including consuming quota or mutating data allowed by those keys.
Towel does not directly place a reusable credential in the child contract. Use
narrowly scoped, development-only keys and end the child process to end the
session.

Capability-only routes are not mounted in the application loopback broker. A
native capability session instead starts
`twl capability serve --project NAME --stdio`; its adapter owns the child
pipes, and normal agent-launched subprocesses are not given those descriptors.
Towel validates the capability name, HTTP method, normalized path, query,
headers, and body bounds before resolving the trusted route or executing an
upstream request. Closing stdin, unloading the adapter, or SIGINT/SIGTERM ends
the session and drops its in-memory route credentials.

## Broker protections

The application broker binds only to loopback and uses an unguessable session prefix. It
accepts ordinary `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` requests. It
ignores client authentication, `Host`, proxy, and forwarding headers; never
follows redirects; rejects malformed paths; disables ambient proxy settings;
caps request and response bodies at 16 MiB; limits concurrency to 16 requests;
and blocks direct plaintext or common-Base64 credential reflection. It does not
protect against an authorized upstream that transforms, reflects, or otherwise
exposes a credential. Responses remain buffered, so streaming is not supported.

The same upstream executor handles application and capability requests, so
credential injection, header filtering, redirect denial, ambient-proxy
disabling, request/response bounds, and reflection checks do not diverge.
Upstreams must use HTTPS. Loopback HTTP exists only for automated tests and
generated canary demos.

## Protected macOS build

Real Keychain sessions require a Developer ID-signed app-like bundle with an
embedded provisioning profile, hardened runtime, library validation, runtime
enforcement, debugging disabled, and Towel's code-signing-scoped Keychain
access group. At startup Towel verifies its Team ID, application identifier,
and access-group entitlements. An ordinary `cargo build` binary intentionally
fails closed.

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

## Linux build

Linux needs no signing. The vault protects itself with a password, so an
ordinary release build is a real deployment:

```bash
scripts/build-linux.sh
```

The script builds against musl when that target is installed, so the result is
a static binary that runs on any glibc or musl distribution, then checks that
the binary really is static and runs `twl doctor` against it. Set
`TWL_TARGET` to override the target triple.

`bwrap` (bubblewrap) is an optional runtime dependency. When it is present
Towel additionally masks the vault directory and gives the child a private PID
namespace; when it is absent Towel says so and the encrypted vault is unchanged.
Nothing else is required at runtime.

## Verifying a release

Release archives carry a build-provenance attestation. Check it before you
trust a downloaded binary:

```bash
gh attestation verify twl-<version>-<target>.tar.gz --repo luciobaiocchi/twl
sha256sum --check --ignore-missing SHA256SUMS
```

macOS ZIP archives contain a Developer ID-signed, provisioned, notarized, and
stapled `TowelCLI.app`, so `spctl` and Gatekeeper accept it directly. Preserve
the bundle and invoke its command at `TowelCLI.app/Contents/MacOS/twl`.

## Build and test

Towel requires Rust 1.82 or newer:

```bash
cargo +1.82.0 fmt --all -- --check
cargo +1.82.0 test --all-targets --locked
cargo +1.82.0 clippy --all-targets --all-features --locked -- -D warnings
cargo +1.82.0 build --release --locked
```

The canary-only demo does not read stored credentials and works on supported
development hosts:

```bash
./target/debug/twl demo --config examples/towel.yaml -- \
  python3 examples/application_client.py
```

The DeepSeek adapter is checked separately with Node 22 or newer. Its exact
tested Harness API version is documented in the integration README.

```bash
cd integrations/deepseek-harness
npm ci --ignore-scripts
npm run check
```

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
