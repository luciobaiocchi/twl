# Changelog

All notable changes to Towel will be documented here. The project uses
[Semantic Versioning](https://semver.org/) after its first public tag.

## Unreleased

### Added

- Portable encrypted vaults using Argon2id and XChaCha20-Poly1305 for both
  credential values and destination-bound route policies.
- Multi-upstream route maps with explicit credential references, Bearer
  injection, method/path allowlists, budgets, body limits, concurrency caps,
  and expiry.
- Random route-set-bound session tokens, per-route fake credentials and local
  URLs, plus one-route `APP_API_KEY` / `APP_BASE_URL` compatibility.
- Native parent launch and detached `serve` mode with an atomic agent-visible
  session manifest.
- Docker Compose and Kubernetes native-sidecar deployment templates with
  non-root execution and capability dropping.
- A `GrantProvider` interface for future trusted control-plane-issued grants.
- Plaintext and standard/URL-safe base64 reflection checks across every
  credential in a session.
- macOS hardened-runtime and Linux process-inspection defenses.
- Dependency-free Python application and upstream compatibility example.

### Changed

- Replaced raw credential/upstream startup inputs with encrypted vault unlock
  through a hidden prompt, dedicated file descriptor, or Towel-only container
  password file.
- Restricted repository YAML to route references and limit reductions inside a
  trusted `--allow-route` set.
- Renamed the project and command from Mithril/`mtl` to Towel/`twl` before the
  first public release.
