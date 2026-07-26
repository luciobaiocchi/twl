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

Towel is designed to keep one project HTTP credential out of a coding agent's
process while allowing an application launched by that agent to use a local
broker. It is not:

- a process, filesystem, or container sandbox;
- a general secret store;
- protection for the agent's own model-provider login;
- protection against a malicious upstream, which necessarily receives the
  credential;
- protection against a Linux child running as root or with `CAP_SYS_PTRACE`.

The current version supports one static Bearer credential and one fixed HTTPS
upstream per session. See the README for the complete operating assumptions
and known limitations.
