# Releasing Towel

The first intended public version is `v0.1.0-alpha.1`. Do not present an alpha
as an audited or stable security guarantee.

## One-time prerequisites

- Resolve and document the final product-name check.
- Make the repository public and enable private vulnerability reporting.
- Enable GitHub Pages with GitHub Actions as its source.
- Create `luciobaiocchi/homebrew-tap` for the `twl` formula.
- Obtain an Apple Developer ID Application certificate and notarization
  credentials, plus a Developer ID provisioning profile for `dev.towel.twl`
  that authorizes the Towel Keychain access group. Ad-hoc signatures cannot
  authorize the restricted entitlement.
- Configure a protected `release` environment, require maintainer review, and
  add these secrets:
  - `APPLE_CERTIFICATE_P12_BASE64`
  - `APPLE_CERTIFICATE_PASSWORD`
  - `APPLE_SIGNING_IDENTITY`
  - `APPLE_TEAM_ID`
  - `APPLE_PROVISIONING_PROFILE_BASE64`
  - `APPLE_API_KEY_P8_BASE64`
  - `APPLE_API_KEY_ID`
  - `APPLE_API_ISSUER_ID`

## Release checklist

1. Confirm CI and the dependency audit pass on `main`.
2. Run the full test suite and the Python canary flow on clean Linux and macOS
   machines.
3. Update `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and the README version.
4. Push the signed version tag. The release workflow builds Linux x86-64 and
   ARM64 plus macOS Apple Silicon and Intel artifacts from the tagged commit.
5. Build the macOS executable inside `TowelCLI.app`, embed its Developer ID
   provisioning profile, sign the bundle with hardened runtime and a secure
   timestamp, notarize it, staple the ticket, and verify it on a clean Mac.
6. Generate SHA-256 checksums for every artifact.
7. Create an annotated, signed tag and a GitHub prerelease with generated notes.
8. Verify downloaded artifacts before updating the Homebrew tap.
9. Test `brew install luciobaiocchi/tap/twl` and `brew upgrade twl` on clean
   machines.
10. Publish only after the installed binary passes `twl doctor`.

Publishing to crates.io is optional and should not be advertised as the macOS
installation path: Cargo-built macOS binaries do not carry the distribution
signature required by real sessions.
