# Towel (`twl`)

Towel keeps destination-bound application API keys out of coding-agent
processes. The macOS-only v0.1 stores a set of routes under one named project,
then opens that project for a child command after one native authorization.

```bash
twl project add my-app
twl run --project my-app -- codex
```

[Website](https://luciobaiocchi.github.io/twl/) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) ·
[Apache-2.0 license](LICENSE)

> Experimental security software: it has not been independently audited. Use
> disposable or tightly scoped development credentials while evaluating it.

## Projects and routes

A project is the unit of authorization. One versioned, application-scoped
macOS Data Protection Keychain record contains all of its trusted destinations
and credentials. A project has one or more named routes; every route contains:

- an exact HTTPS base URL, optionally including a base path;
- one static Bearer API key;
- the API-key environment variable expected by the application;
- the base-URL environment variable expected by the application.

Create and maintain projects with the interactive CLI:

```text
twl project add <name>
twl project list
twl project show <name>
twl project edit <name>
twl project delete <name>
```

`add` and `edit` prompt for each route and hide API-key input. `show` displays
route names, destinations, and environment variable names, but never secret
values or secret-derived fingerprints. Project and route names are identifiers,
not paths.

Real project operations require macOS. Towel does not create a portable vault,
password-encrypted file, Linux credential backend, daemon, or control plane.

## Session contract

Starting `twl run --project NAME -- COMMAND` performs one macOS
LocalAuthentication approval for the entire project session. Touch ID is used
when available; macOS can fall back to the configured device-owner
authentication. Authorization times out after 120 seconds.

The child receives, for every route, only:

- a random fake value in the route's application-facing API-key variable; and
- a route-specific loopback broker URL in its base-URL variable.

Real credentials and real upstream destinations are not placed in child
environment variables, arguments, files, logs, or inherited file descriptors.
They remain in the trusted Towel process and are bound together by the project
record. The broker selects the upstream from the authenticated route path and
injects only that route's key as `Authorization: Bearer`.

Authorization is per session, not per request. During the session the agent can
exercise all API authority granted by the project's credentials through the
broker, including consuming quota or mutating data allowed by those keys.
Towel does not directly place a reusable credential in the child contract. Use
narrowly scoped, development-only keys and end the child process to end the
session.

## Broker protections

The broker binds only to loopback and uses an unguessable session prefix. It
accepts ordinary `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` requests. It
ignores client authentication, `Host`, proxy, and forwarding headers; never
follows redirects; rejects malformed paths; disables ambient proxy settings;
caps request and response bodies at 16 MiB; limits concurrency to 16 requests;
and blocks direct plaintext or common-Base64 credential reflection. It does not
protect against an authorized upstream that transforms, reflects, or otherwise
exposes a credential. Responses remain buffered, so streaming is not supported.

Upstreams must use HTTPS. Loopback HTTP exists only for automated tests and the
generated canary demo.

## Protected macOS build

Real Keychain sessions require a signed binary with hardened runtime, library
validation, runtime enforcement, debugging disabled, and Towel's
code-signing-scoped Keychain access group. At startup Towel verifies its Team
ID, application identifier, and access-group entitlements. An ordinary `cargo
build` binary intentionally fails closed.

```bash
scripts/build-macos.sh
```

Set `TWL_CODESIGN_IDENTITY` to a stable signing identity and `TWL_TEAM_ID` to
its Apple Team ID for a real deployment. The script uses ad-hoc signing when
the identity is unset; that mode is for local build checks, not real credential
deployment. `twl doctor` reports whether the current binary satisfies the
hardened-runtime checks.

## Build and test

Towel requires Rust 1.82 or newer:

```bash
cargo +1.82.0 fmt --all -- --check
cargo +1.82.0 test --all-targets --locked
cargo +1.82.0 clippy --all-targets --all-features --locked -- -D warnings
cargo +1.82.0 build --release --locked
```

The canary-only demo does not read Keychain credentials and works on supported
development hosts:

```bash
./target/debug/twl demo --config examples/towel.yaml -- \
  python3 examples/application_client.py
```

## Explicit non-goals

This version does not provide a custom encrypted vault, Argon2/password-based
storage, Linux credentials, Docker or Kubernetes integration, a daemon or
control plane, provider-specific profiles, repository-controlled destinations,
arbitrary authentication templates, transparent TLS interception, release
packaging, or Homebrew distribution. The agent's own Codex/OpenHands/model
login and ambient files, sockets, and unrelated secrets are outside Towel's
boundary.
