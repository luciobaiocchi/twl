# Security policy

Towel is experimental security software and has not been independently
audited. Use disposable or narrowly scoped development credentials while
evaluating it.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting flow under the repository
Security tab. Do not disclose exploit details in a public issue, pull request,
discussion, or chat transcript.

Include the affected commit or version, operating system or deployment model,
threat assumptions, reproduction steps, impact, and any suggested mitigation.
The maintainers will acknowledge the report, investigate it, and coordinate
disclosure according to severity.

## Supported versions

Before the first tagged release, only the latest commit on `main` is supported.
After release, security fixes target the newest `0.x` line; older experimental
versions may require upgrading rather than receiving backports.

## Primary guarantee

Towel keeps reusable provider credentials outside the untrusted agent runtime
and injects them only into HTTP requests matching trusted,
destination-bound policies. Credential values and those policies are stored
together in an Argon2id/XChaCha20-Poly1305 encrypted vault, so an agent cannot
change the endpoint associated with a key by editing repository configuration
or the vault ciphertext.

The trusted launcher explicitly authorizes a route set for one short-lived
session. The agent receives only fake credentials, loopback route URLs, and a
random capability token. This token permits use of the configured API authority
until route budgets or expiry stop it; it cannot be exchanged for the reusable
provider credential.

## Enforced broker rules

- Deny unknown tokens, routes, methods, and paths by default.
- Derive upstream destinations only from authenticated route policy.
- Require HTTPS, except for loopback-only tests.
- Strip client authentication, host overrides, proxy, and forwarding headers.
- Inject only the supported `Authorization: Bearer` form.
- Never follow redirects or return redirect locations.
- Enforce per-route request count, body sizes, concurrency, and expiry.
- Buffer non-streaming responses and block plaintext and standard/URL-safe
  base64 reflection of any credential in the session.
- Bind natively to loopback and never inspect shell commands as a security
  decision.

## Operating assumptions

- Native Towel is the trusted parent. On macOS it must be signed with hardened
  runtime; on Linux it disables same-user process inspection before opening the
  vault.
- A containerized agent has a separate PID and root filesystem namespace from
  Towel, runs unprivileged, cannot escalate, and has no `CAP_SYS_PTRACE`.
- The encrypted vault, unlock password, trusted grants, and control-plane inputs
  are never mounted into the agent container or workspace.
- Only the paired agent can read its session manifest. The token in that file is
  sensitive short-lived authority even though it is not a provider credential.
- The host kernel, container runtime, Towel binary, trusted user/control plane,
  DNS/TLS roots, and intended upstream are trusted.

Host root, a shared PID namespace, ptrace-equivalent access, a compromised
Towel process, or access to both vault and password is outside the guarantee.

## Deliberate limitations

Towel does not prevent an authorized agent from using the permitted API
authority. It is not a process or filesystem sandbox, a generic TCP proxy, a
universal local-secret solution, an enterprise identity/multi-tenant platform,
or protection against a malicious intended upstream that necessarily receives
its own credential.

The first version supports static Bearer HTTP authentication and buffered
responses only. Arbitrary authentication templates, API-key headers, AWS
SigV4, token refresh, request-signing protocols, streaming responses, database
passwords, SSH keys, and local cryptographic keys are outside its supported
boundary.
