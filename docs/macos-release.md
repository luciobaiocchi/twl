# Enabling macOS releases

macOS is opt-in. Until the `MACOS_RELEASE` repository variable is set to
`true`, tagging builds and publishes Linux alone. This document is the path
from there to a signed, notarized macOS artifact.

Work through it in order. Part 2 answers the only genuinely open question, and
it costs nothing — do not buy notarization credentials or touch repository
settings before it passes.

## 0. What you need

- An Apple Developer Program membership. Developer ID certificates are not
  available on a free account.
- A Mac. Signing and notarization both require Apple tooling; neither can be
  done from Linux or from CI without the certificate.
- Xcode Command Line Tools: `xcode-select --install`.

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

## 2. The local test that decides everything

Towel verifies its own entitlements at startup: the Team ID, the application
identifier, and the `keychain-access-groups` entry must all be present and
consistent, or it refuses to open the Keychain. Whether those entitlements
take effect on a Developer ID binary — as opposed to an App Store one — has
not been confirmed on real hardware. This is the check that confirms it.

```bash
export TWL_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export TWL_TEAM_ID=TEAMID
scripts/build-macos.sh
```

The script builds, signs with `config/macos.entitlements`, verifies the
signature, prints the applied entitlements, and runs `twl doctor`. Read the
last lines:

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
| `TWL_TEAM_ID is required` | The variable is unset |

Note that `twl doctor` exits `0` in every case, so read the text rather than
the exit status.

Then exercise it for real, which `doctor` does not do:

```bash
./target/release/twl project add scratch     # Touch ID should prompt
./target/release/twl project list
./target/release/twl project delete scratch
```

Use a disposable credential. `add` prompting for Touch ID and `list` returning
the project is the proof that reading and writing both work.

### 2.1 If the access group did not resolve

The likely cause is that `application-identifier` and `keychain-access-groups`
need a provisioning profile to be honoured outside the App Store. Options, in
the order worth trying:

1. Create a macOS Developer ID provisioning profile for the app ID
   `TEAMID.dev.towel.twl` in the developer portal, and embed it. For a
   command-line binary this means `--entitlements` plus an embedded profile
   rather than a bundle, which may require shipping Towel inside an `.app`.
2. Drop `application-identifier` from `config/macos.entitlements` and keep only
   `com.apple.developer.team-identifier` and `keychain-access-groups`, then
   relax the matching check in `effective_access_group()`. This weakens the
   startup check to team plus access group; decide whether that is acceptable
   before doing it.
3. Fall back to the default Keychain by dropping
   `kSecUseDataProtectionKeychain`. This gives up the guarantee that the store
   is not a mutable user-selected keychain, and is the option to avoid.

Whatever the outcome, record it in issue #36 (item A2) — it is the answer to a
question that is currently open.

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
`.p12`, giving it a password, then base64 both files:

```bash
base64 -i certificate.p12 | pbcopy
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
| `APPLE_API_KEY_P8_BASE64` | base64 of the `.p8` |
| `APPLE_API_KEY_ID` | Key ID |
| `APPLE_API_ISSUER_ID` | Issuer ID |

`APPLE_TEAM_ID` is checked before signing: empty or non-alphanumeric fails the
job rather than producing a binary that cannot open its own Keychain.

## 6. First macOS run

Do not enable macOS and tag in the same step. Dry-run it first:

**Actions → Release → Run workflow**, select your branch, `platforms: all`,
leave `publish` off.

This builds, signs, notarizes, and asserts on `doctor` without publishing.
Notarization can take several minutes. A failure here costs nothing.

When it is green, set the variable under Settings → Secrets and variables →
Actions → Variables:

```
MACOS_RELEASE = true
```

From then on a tag builds and publishes both platforms, and the release run
reports which platforms it selected.

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
