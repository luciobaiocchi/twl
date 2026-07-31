# Changelog

All notable changes to Towel will be documented here. The project uses
[Semantic Versioning](https://semver.org/) after its first public tag.

## Unreleased

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
