# Enabling macOS releases

macOS is opt-in. Until the `MACOS_RELEASE` repository variable is set to
`true`, tagging builds and publishes Linux alone. This document is the path to
a provisioned, Developer ID-signed, notarized macOS artifact.

## 0. What you need

- An Apple Developer Program membership. Developer ID certificates are not
  available on a free account.
- A Mac. Signing and notarization both require Apple tooling; neither can be
  done from Linux or from CI without the certificate.
- Xcode Command Line Tools: `xcode-select --install`.
- An explicit macOS App ID for `dev.towel.twl` with the Keychain access group
  `TEAMID.dev.towel.project`, plus a Developer ID provisioning profile for it.

## 1. Team ID and signing certificate

Find your Team ID at <https://developer.apple.com/account> under Membership.
It is ten alphanumeric characters.

Create a **Developer ID Application** certificate — not "Apple Development",
not "Apple Distribution". Xcode does this under Settings → Accounts → Manage
Certificates → `+`. Then confirm the Mac can see it:

```bash
security find-identity -v -p codesigning
```

The line you want reads `Developer ID Application: Your Name (TEAMID)`. Keep
that full string; it is the signing identity.

Create a Developer ID provisioning profile for the explicit bundle identifier
`dev.towel.twl` in the developer portal. Download the resulting
`.provisionprofile` file. Towel validates that it is unexpired and authorizes
the expected team, application identifier, and Keychain access group. After
signing, it also verifies that the profile contains the exact leaf certificate
selected by `codesign`.

## 2. Build and test the provisioned app locally

Towel verifies its own entitlements at startup: the Team ID, the application
identifier, and the `keychain-access-groups` entry must all be present and
consistent, or it refuses to open the Keychain.

A real CI run confirmed that a correctly signed bare executable is killed by
macOS as soon as it starts with the restricted Keychain entitlement. Apple
requires a provisioning profile, and macOS expects that profile at
`TowelCLI.app/Contents/embedded.provisionprofile`. Towel therefore follows
Apple's [app-like bundle layout for command-line
programs](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement).

```bash
export TWL_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export TWL_TEAM_ID=TEAMID
export TWL_PROVISIONING_PROFILE=/path/to/TowelCLI.provisionprofile
scripts/build-macos.sh
```

The script creates this bundle, embeds and validates the profile, signs the
bundle with `config/macos.entitlements`, verifies the signature, prints the
applied entitlements, and runs `twl doctor`:

```text
target/release/TowelCLI.app/
└── Contents/
    ├── Info.plist
    ├── MacOS/
    │   └── twl
    └── embedded.provisionprofile
```

Read the last lines:

```
protected macOS project sessions: available
```

**That line is the whole test.** It means the hardened-runtime checks passed
*and* the access group resolved. Go to part 3.

Anything else means it did not work:

| Output | Meaning |
|---|---|
| `unavailable (trusted project store is unavailable)` | Entitlements did not take effect — see 2.1 |
| `unavailable (this binary is not protected…)` | Signing or hardened runtime failed; re-check the identity |
| `TWL_TEAM_ID must contain…` | The variable is unset or malformed |
| `invalid Developer ID provisioning profile: …` | The profile is expired or does not authorize Towel's team, app ID, and access group |

Note that `twl doctor` exits `0` in every case, so read the text rather than
the exit status.

Then exercise it for real, which `doctor` does not do:

```bash
./target/release/TowelCLI.app/Contents/MacOS/twl project add scratch
./target/release/TowelCLI.app/Contents/MacOS/twl project list
./target/release/TowelCLI.app/Contents/MacOS/twl project delete scratch
```

Use a disposable credential. `add` prompting for Touch ID and `list` returning
the project is the proof that reading and writing both work.

### 2.1 If the access group does not resolve

Do not remove or weaken the entitlement checks. Inspect the embedded profile
and signed entitlements instead:

```bash
security cms -D -i \
  target/release/TowelCLI.app/Contents/embedded.provisionprofile
codesign -d --entitlements - target/release/TowelCLI.app
```

Both must contain `TEAMID.dev.towel.twl` under
`com.apple.application-identifier` and authorize
`TEAMID.dev.towel.project` under `keychain-access-groups`. Apple explains why a
[standalone executable cannot claim a restricted
entitlement](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles).

## 3. Prove the conformance suite against a real Keychain

The repository conformance suite has never run against `MacKeychainRepository`;
CI cannot run it because an unsigned binary fails closed. A signed local build
can. See issue #36 (A1) for the ignored test to add, then:

```bash
cargo test -- --ignored
```

This covers add-only creation, stale-revision conflict, concurrent replace, and
exact deletion. If `SecItemAdd` does not reject a duplicate, this is where it
shows up.

## 4. Notarization credentials

Notarization needs an App Store Connect API key, which is separate from the
signing certificate. At <https://appstoreconnect.apple.com/access/integrations/api>
create a key with the **Developer** role and download the `.p8` **once** — it
cannot be downloaded again.

You now have three values: the key file, its Key ID, and the Issuer ID shown
above the key list.

Verify them before putting them in CI:

```bash
xcrun notarytool history --key AuthKey_KEYID.p8 --key-id KEYID --issuer ISSUER_ID
```

An empty history is success. An authentication error means the values are wrong.

## 5. Repository configuration

Export the signing certificate with its private key from Keychain Access as a
`.p12`, giving it a password, then base64 the certificate, provisioning
profile, and notarization key:

```bash
base64 -i certificate.p12 | pbcopy
base64 -i TowelCLI.provisionprofile | pbcopy
base64 -i AuthKey_KEYID.p8 | pbcopy
```

Create an Environment named `release` under Settings → Environments — the macOS
job is scoped to it and will not start without it. Add these secrets there:

| Secret | Value |
|---|---|
| `APPLE_CERTIFICATE_P12_BASE64` | base64 of the `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | password chosen during export |
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_TEAM_ID` | the ten-character Team ID |
| `APPLE_PROVISIONING_PROFILE_BASE64` | base64 of the Developer ID `.provisionprofile` |
| `APPLE_API_KEY_P8_BASE64` | base64 of the `.p8` |
| `APPLE_API_KEY_ID` | Key ID |
| `APPLE_API_ISSUER_ID` | Issuer ID |

The profile and `APPLE_TEAM_ID` are checked before signing. Missing, expired,
debug-enabled, or mismatched values fail the job rather than producing a bundle
that macOS kills or that cannot open its own Keychain.

## 6. First macOS run

Do not add a tag on the first run. Set this repository variable first so the
macOS jobs are included:

```text
MACOS_RELEASE = true
```

If the `release` environment restricts deployment branches, allow the patch
branch before testing it. Then use **Actions → Release → Run workflow**, select
that branch, choose `platforms: all`, and leave `tag` empty.

An empty tag makes this a dry run: it builds both Linux packages, creates and
signs both macOS app bundles, asserts on `doctor`, notarizes and staples them,
and publishes nothing. Notarization can take several minutes. When all four
jobs are green, a matching tag can publish both platforms.

## 7. Recovering a bad release

The workflow publishes prereleases, so a broken macOS artifact is not
advertised as stable. To withdraw one:

```bash
gh release delete vX.Y.Z --yes
git push --delete origin vX.Y.Z
```

Then unset `MACOS_RELEASE` to return to Linux-only releases while you
investigate. Tags are cheap; a published binary that fails closed on every
command is not.
