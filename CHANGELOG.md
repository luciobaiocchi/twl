# Changelog

All notable changes to Towel will be documented here. The project uses
[Semantic Versioning](https://semver.org/) after its first public tag.

## Unreleased

## 0.1.0-dev.0 - 2026-08-15

### Added

- V1 agent-native, credential-backed HTTP capabilities with explicit method,
  normalized path-prefix, and response-size policy.
- Versioned, bounded stdio capability discovery/invocation service and a
  generated canary demo that needs no real credential or protected store.
- Interactive capability add/list/show/delete commands and capability-only
  routes without application environment bindings.
- DeepSeek Harness `twl_request` adapter with effect-owned process lifecycle,
  bounded result rendering, and protocol/lifecycle tests.

### Changed

- Project storage format is now v2; v1 records remain readable through an
  in-memory, secret-preserving migration and are written as v2 only when saved.
- Application loopback proxying and agent capability invocation now share one
  broker executor for credential injection, redirect policy, ambient-proxy
  disabling, body bounds, header filtering, and reflection checks.
- macOS release artifacts now preserve Towel inside a provisioned, Developer
  ID-signed app-like bundle and staple the notarization ticket before packaging.

## 0.1.0-alpha.1 - 2026-08-01

First public prerelease. Linux artifacts only: macOS builds stay disabled
until the Developer ID signing and entitlement path is verified on hardware,
as described in `docs/macos-release.md`.

### Added

- macOS Keychain-backed named projects with multiple destination-bound Bearer
  routes and one LocalAuthentication approval per project session.
- Linux password-encrypted age vault with locked atomic updates, per-command
  `/dev/tty` authorization, dump protection, and optional Bubblewrap masking.
- Per-route fake API keys and route-specific loopback broker URLs.
- Fixed-destination Bearer proxy with reflection and request-security checks.
- macOS hardened-runtime and library-validation enforcement.
- Dependency-free Python application and upstream compatibility example.

### Changed

- Renamed the project and command from Mithril/`mtl` to Towel/`twl` before the
  first public release.
