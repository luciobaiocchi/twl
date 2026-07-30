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
coding agent's process while allowing applications launched by that agent to
use a destination-bound local broker. macOS stores each project in the Data
Protection Keychain. Linux stores all projects in a password-encrypted age
vault. It is not:

- a process, filesystem, or container sandbox;
- a portable or general secret store;
- protection for the agent's own model-provider login;
- protection against a malicious upstream, which necessarily receives the
  credential;
- protection against an authorized upstream that transforms, reflects, or
  otherwise exposes a credential;
- a restriction on use of API authority already granted for the session.

One platform authorization opens the complete project session. The child
receives only per-route fake keys and loopback URLs. On macOS, each real
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

Bubblewrap, when installed, is only an additional filesystem-masking and
PID/`/proc` isolation layer. It deliberately does not isolate the network or
the rest of the filesystem and does not block Docker access.

An agent that can use a privileged host Docker daemon, `sudo`, `ptrace`, or
another route to full host control may attack the running broker or Towel
process. Host-level compromise, same-user denial of service, and destructive
replacement of the encrypted vault are outside Towel's security boundary. See
the README for the complete operating assumptions and known limitations.
