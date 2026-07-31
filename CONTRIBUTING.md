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
On Linux, use disposable vault credentials and set `XDG_DATA_HOME` to a
dedicated test directory for manual backend testing.

## Security invariants

Changes must preserve these properties:

- Real credentials and destinations never appear in child arguments,
  environment variables, workspace configuration, files, logs, inherited
  descriptors, or error messages.
- Every credential is bound to the exact upstream stored in its trusted
  platform project repository.
- Linux vault operations preserve age compatibility, strict ownership and file
  modes, size limits, locking, atomic replacement, and zeroizing secret
  lifetimes.
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

## Cutting a release

Releases are driven by the tag, not by merging. The tag is the release
identity, so `verify-version` refuses to build when it disagrees with the
version in `Cargo.toml`.

Before tagging, bump `version` in `Cargo.toml`, refresh `Cargo.lock`, and move
the `Unreleased` changelog heading to the new version.

Pushing the tag is the whole ceremony:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

macOS is opt-in. Signing and notarization need credentials and an entitlement
configuration that has to be verified on a real Developer ID build, so the
macOS job only runs when the `MACOS_RELEASE` repository variable is set to
`true`. Until then a tag produces a Linux-only prerelease and passes; nothing
has to be worked around, and the run reports which platforms it chose.
[docs/macos-release.md](docs/macos-release.md) is the setup path, starting with
a local check that needs no credentials.

The **Release** workflow can also be started by hand from the Actions tab, with
two inputs:

- `platforms` — `all`, or `linux-only` to skip macOS for one run even when
  `MACOS_RELEASE` is set.
- `publish` — off by default. Leave it off for a dry run that builds, packages,
  and runs every artifact check without creating a release. Turn it on only
  when the run is started from an existing tag; a release cannot point at a
  branch.

Use a dry run from a branch to exercise the packaging steps before spending a
tag on them.

Unless explicitly stated otherwise, contributions submitted for inclusion are
licensed under the Apache License, Version 2.0, as described in Section 5 of
the license.
