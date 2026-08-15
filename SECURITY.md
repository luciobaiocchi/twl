# Security policy

Towel is experimental security software and has not been independently
audited. Use disposable or narrowly scoped development credentials while
evaluating it.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting flow under the repository
Security tab. Do not disclose exploit details in a public issue, pull request,
discussion, or chat transcript.

Include the affected commit or version, operating system, threat assumptions,
reproduction steps, impact, and any suggested mitigation. The maintainers will
acknowledge the report, investigate it, and coordinate disclosure according to
its severity.

## Supported versions

Before the first tagged release, only the latest commit on `main` is supported.
After release, security fixes will target the newest `0.x` release line; older
experimental versions may require upgrading rather than receiving backports.

## Security boundary

Towel is designed to keep a named project's static Bearer credentials out of a
coding agent's process while lending their effects through two interfaces:

- application access uses fake credentials and route-specific loopback URLs;
- agent-native access uses named HTTP capabilities over a private, versioned
  stdio service owned by a trusted Harness adapter.

Both interfaces use one broker core and trusted route store. macOS stores each
project in the Data Protection Keychain. Linux stores all projects in a
password-encrypted age vault. Towel is not:

- a process, filesystem, or container sandbox;
- a portable or general secret store;
- protection for the agent's own model-provider login;
- protection against a malicious upstream, which necessarily receives the
  credential;
- protection against an authorized upstream that transforms, reflects, or
  otherwise exposes a credential;
- a restriction on use of API authority already granted for the session.

V1 agent capabilities are not filesystem, shell, Git, process, approval,
delegation, OAuth, or general secret capabilities.

One platform authorization opens the complete project session. The child
receives only per-application-route fake keys and loopback URLs. Capability-only
routes are excluded from that application broker. On macOS, each real
credential and exact HTTPS destination remain together in one
application-scoped Data Protection Keychain record. macOS limits records to
Towel's signed Keychain access group, and Towel verifies the effective signing
entitlements before opening the repository.

On Linux, the age vault protects persistent credentials when an agent can read
or copy the filesystem but does not know the vault password. Towel reads that
password from `/dev/tty`, disables process dumpability before loading secrets,
and drops the password and full decrypted vault before launching the child.
Copying the ciphertext enables offline password guessing, and authenticated
encryption detects modification but not deletion or rollback to an older valid
vault.

For agent-native access, capability policy is persisted beside its route in the
protected record. The request cannot carry a host or origin. Towel resolves the
capability by exact name, checks the method and normalized path prefix, rejects
malformed queries and client `Authorization`, applies body/response bounds, and
only then resolves and invokes the fixed route. Policy denial occurs before an
upstream request. The response contains a sanitized status, canonical content
type, and bounded body, with no upstream authentication headers.

The DeepSeek Harness adapter starts one
`twl capability serve --project NAME --stdio` child with explicit Node pipes.
It receives capability descriptors and sanitized results, not a real
credential, protected project payload, vault password, or credential
fingerprint. Its Cordis lifecycle effect closes stdin, rejects pending calls,
waits for exit, and escalates termination on unload or HMR. Normal
agent-launched subprocesses are not intentionally given those pipe descriptors;
Node creates the dedicated stdio pipes non-inheritable for unrelated spawned
children. If the Harness process itself is compromised, its live pipe can still
exercise every capability granted to that session.

The stdio peer is treated as untrusted: request lines and bodies are bounded,
the first frame must negotiate protocol v1, malformed frames fail without raw
body logging, unknown operations fail closed, and stdout carries protocol
frames only. EOF, adapter disposal, SIGINT, and SIGTERM end the service. Towel
zeroizes route credentials when the final broker owner drops; abrupt operating
system termination also destroys the process address space.

Bubblewrap, when installed, is only an additional filesystem-masking and
PID/`/proc` isolation layer. It deliberately does not isolate the network or
the rest of the filesystem and does not block Docker access. Its absence does
not weaken age encryption of the vault.

The Linux build uses age with its already-empty default feature set. Age 0.11's
localization dependencies are unconditional, so disabling default features
does not remove that transitive graph. Those dependencies are locked and
covered by the repository's RustSec check, but remain part of the trusted
process's supply-chain surface.

An agent that can use a privileged host Docker daemon, `sudo`, `ptrace`, or
another route to full host control may attack the running broker or Towel
process. Host-level compromise, same-user denial of service, and destructive
replacement of the encrypted vault are outside Towel's security boundary. See
the README for the complete operating assumptions and known limitations.
