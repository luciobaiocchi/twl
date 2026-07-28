# Contributing to Towel

Thank you for helping make project-secret handling safer for coding agents.
Towel is intentionally small: prefer a narrow, auditable change over a broad
framework.

## Before starting

- Use GitHub Discussions or a feature issue for product-design questions.
- Search existing issues before opening a new one.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md) and do not open a
  public issue containing exploit details.
- Keep changes within Towel's scope: project HTTP credentials, not the agent's
  own login, general secret storage, or a full process sandbox.

## Local setup

Install Rust 1.82 or newer and a native build toolchain, then run:

```bash
cargo build --locked
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
```

The Python example uses only the standard library. On macOS, set
`TWL_TEAM_ID=<team-id>` and use `scripts/build-macos.sh` before manually
testing a real credential; ordinary Cargo binaries intentionally fail closed.

## Security invariants

Changes must preserve these properties:

- Real credentials and destinations never appear in child arguments,
  environment variables, workspace configuration, files, logs, inherited
  descriptors, or error messages.
- Every credential is bound to the exact upstream stored in its trusted
  Keychain project record.
- Client authentication, host, and forwarding headers cannot override policy.
- Redirects never carry credentials to another destination.
- One native authorization opens one complete project session.
- Invalid requests fail before consuming the session request budget.

Add a regression test for every security-relevant behavior change. Use only
disposable canaries in tests and documentation.

## Pull requests

- Keep each pull request focused and explain its security impact.
- Write code, comments, commits, and documentation in English.
- Run formatting, tests, and Clippy before requesting review.
- Update the README and changelog when behavior or the CLI changes.
- Do not mix generated formatting changes with unrelated logic.

Unless explicitly stated otherwise, contributions submitted for inclusion are
licensed under the Apache License, Version 2.0, as described in Section 5 of
the license.
