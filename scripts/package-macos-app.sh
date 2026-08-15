#!/bin/sh
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
repository_dir=$(CDPATH= cd "$script_dir/.." && pwd)

binary=${TWL_BINARY:-$repository_dir/target/release/twl}
bundle=${TWL_APP_BUNDLE:-$repository_dir/target/release/TowelCLI.app}
profile=${TWL_PROVISIONING_PROFILE:-}
identity=${TWL_CODESIGN_IDENTITY:-}
team_id=${TWL_TEAM_ID:-}
version=${TWL_VERSION:-}
bundle_identifier=dev.towel.twl
access_group_suffix=dev.towel.project

if [ ! -x "$binary" ]; then
    echo "TWL_BINARY must point to an executable twl binary" >&2
    exit 1
fi
if [ ! -f "$profile" ]; then
    echo "TWL_PROVISIONING_PROFILE must point to a Developer ID provisioning profile" >&2
    exit 1
fi
if [ -z "$identity" ]; then
    echo "TWL_CODESIGN_IDENTITY is required; ad-hoc signatures cannot authorize the access group" >&2
    exit 1
fi
case "$team_id" in
    "" | *[!A-Za-z0-9]*)
        echo "TWL_TEAM_ID must contain only ASCII letters and digits" >&2
        exit 1
        ;;
esac
case "$version" in
    "" | *[!0-9A-Za-z.+-]*)
        echo "TWL_VERSION is missing or contains unsupported characters" >&2
        exit 1
        ;;
esac

# Apple bundle versions are numeric even when the Cargo version is a prerelease.
bundle_version=${version%%-*}
if ! printf '%s\n' "$bundle_version" | grep -Eq '^[0-9]+(\.[0-9]+){0,2}$'; then
    echo "TWL_VERSION must start with a one-to-three-part numeric version" >&2
    exit 1
fi

bundle_parent=$(dirname "$bundle")
if [ "$(basename "$bundle")" != "TowelCLI.app" ]; then
    echo "TWL_APP_BUNDLE must end in TowelCLI.app" >&2
    exit 1
fi
if [ -L "$bundle" ] || { [ -e "$bundle" ] && [ ! -d "$bundle" ]; }; then
    echo "refusing to replace non-directory bundle path: $bundle" >&2
    exit 1
fi

mkdir -p "$bundle_parent"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/twl-macos-package.XXXXXX")
staging_dir=$(mktemp -d "$bundle_parent/.twl-macos-package.XXXXXX")
staged_bundle="$staging_dir/TowelCLI.app"
cleanup() {
    rm -rf "$work_dir" "$staging_dir"
}
trap cleanup EXIT HUP INT TERM

profile_plist="$work_dir/profile.plist"
entitlements="$work_dir/twl.entitlements"
security cms -D -i "$profile" >"$profile_plist"

python3 - "$profile_plist" "$team_id" "$bundle_identifier" "$access_group_suffix" <<'PY'
import datetime
import plistlib
import sys

profile_path, team_id, bundle_identifier, access_group_suffix = sys.argv[1:]
with open(profile_path, "rb") as source:
    profile = plistlib.load(source)

def fail(message):
    raise SystemExit(f"invalid Developer ID provisioning profile: {message}")

expiration = profile.get("ExpirationDate")
if not isinstance(expiration, datetime.datetime):
    fail("ExpirationDate is missing")
if expiration.tzinfo is None:
    expiration = expiration.replace(tzinfo=datetime.timezone.utc)
if expiration <= datetime.datetime.now(datetime.timezone.utc):
    fail("the profile has expired")

profile_teams = profile.get("TeamIdentifier", [])
if isinstance(profile_teams, str):
    profile_teams = [profile_teams]
if team_id not in profile_teams:
    fail(f"TeamIdentifier does not contain {team_id}")
if profile.get("ProvisionsAllDevices") is not True:
    fail("ProvisionsAllDevices is not enabled; expected a Developer ID profile")

entitlements = profile.get("Entitlements")
if not isinstance(entitlements, dict):
    fail("Entitlements are missing")

expected_application = f"{team_id}.{bundle_identifier}"
application = entitlements.get("com.apple.application-identifier")
if application != expected_application:
    fail(
        "com.apple.application-identifier must be "
        f"{expected_application}, got {application!r}"
    )

entitlement_team = entitlements.get("com.apple.developer.team-identifier")
if entitlement_team != team_id:
    fail(
        "com.apple.developer.team-identifier must be "
        f"{team_id}, got {entitlement_team!r}"
    )

expected_group = f"{team_id}.{access_group_suffix}"
groups = entitlements.get("keychain-access-groups", [])
if not isinstance(groups, list):
    fail("keychain-access-groups must be an array")

def authorizes(group):
    if not isinstance(group, str):
        return False
    if group == expected_group:
        return True
    return group.endswith("*") and expected_group.startswith(group[:-1])

if not any(authorizes(group) for group in groups):
    fail(f"keychain-access-groups does not authorize {expected_group}")
if entitlements.get("get-task-allow") is True or entitlements.get(
    "com.apple.security.get-task-allow"
) is True:
    fail("get-task-allow must be disabled for a distribution build")

print(
    "validated provisioning profile "
    f"{profile.get('Name', profile.get('UUID', '<unnamed>'))!r}"
)
PY

sed "s/__TEAM_ID__/$team_id/g" \
    "$repository_dir/config/macos.entitlements" >"$entitlements"

mkdir -p "$staged_bundle/Contents/MacOS"
sed "s/__BUNDLE_VERSION__/$bundle_version/g" \
    "$repository_dir/config/macos.Info.plist" >"$staged_bundle/Contents/Info.plist"
cp "$binary" "$staged_bundle/Contents/MacOS/twl"
chmod 755 "$staged_bundle/Contents/MacOS/twl"
cp "$profile" "$staged_bundle/Contents/embedded.provisionprofile"

plutil -lint "$staged_bundle/Contents/Info.plist" "$entitlements"
codesign --force --options runtime --timestamp \
    --entitlements "$entitlements" \
    --sign "$identity" "$staged_bundle"
codesign --verify --deep --strict --verbose=2 "$staged_bundle"
codesign -d --entitlements - "$staged_bundle"

if [ -d "$bundle" ]; then
    rm -rf "$bundle"
fi
mv "$staged_bundle" "$bundle"
echo "created signed app bundle: $bundle"
