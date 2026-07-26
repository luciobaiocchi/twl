# Changelog

All notable changes to Towel will be documented here. The project uses
[Semantic Versioning](https://semver.org/) after its first public tag.

## Unreleased

### Added

- Parent-only project credential handling through hidden input, a dedicated
  file descriptor, or a warned environment fallback.
- Session-local fake `APP_API_KEY` and `APP_BASE_URL` values.
- Fixed-destination Bearer proxy with request budgets and reflection checks.
- macOS hardened-runtime and Linux process-inspection defenses.
- Dependency-free Python application and upstream compatibility example.

### Changed

- Renamed the project and command from Mithril/`mtl` to Towel/`twl` before the
  first public release.
