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
use a destination-bound local broker. Real credentials are currently macOS
only. It is not:

- a process, filesystem, or container sandbox;
- a portable or general secret store;
- protection for the agent's own model-provider login;
- protection against a malicious upstream, which necessarily receives the
  credential;
- protection against an authorized upstream that transforms, reflects, or
  otherwise exposes a credential;
- a restriction on use of API authority already granted for the session.

One LocalAuthentication approval opens the complete project session. The child
receives only per-route fake keys and loopback URLs; each real credential and
exact HTTPS destination remain together in one trusted Keychain record. See the
README for the complete operating assumptions and known limitations.
