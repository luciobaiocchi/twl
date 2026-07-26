use rand::distributions::Alphanumeric;
use rand::Rng;

const SERVICE: &str = "capshell";

/// The mock has to match the provider's shape: several SDKs validate prefix
/// and length before calling, and a generic placeholder produces confusing
/// errors instead of a request that reaches the proxy.
pub fn mock(prefix: &str) -> String {
    let tail: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect();
    format!("{prefix}capshell{tail}")
}

// macOS and Windows: go through the library, not the command line. On macOS
// this is mandatory, because the Keychain ACL is tied to the signature of the
// binary asking: invoking `/usr/bin/security` would attach the guarantee to
// that binary instead, and any process could get it.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn get(name: &str) -> Result<String, String> {
    keyring::Entry::new(SERVICE, name)
        .and_then(|e| e.get_password())
        .map_err(|e| format!("keyring, {name}: {e}"))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn set(name: &str, value: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, name)
        .and_then(|e| e.set_password(value))
        .map_err(|e| format!("keyring, {name}: {e}"))
}

// Linux: shell out to `secret-tool`, the same keyring seen from the command
// line. The equivalent Rust library costs 79 crates to speak D-Bus and would
// not buy any extra guarantee: the Secret Service authorizes per user, not
// per application, so the barrier against the agent is set by `sandbox`'s
// mount namespace regardless. The keyring is left with a single job here —
// keeping the value encrypted at rest — and the CLI is enough for that.
#[cfg(target_os = "linux")]
pub fn get(name: &str) -> Result<String, String> {
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "service", SERVICE, "account", name])
        .output()
        .map_err(|_| secret_tool_missing())?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(format!("{name} is not in the keyring{}", no_session()));
    }
    let mut value =
        String::from_utf8(out.stdout).map_err(|_| "value is not valid text".to_string())?;
    if value.ends_with('\n') {
        value.pop();
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
pub fn set(name: &str, value: &str) -> Result<(), String> {
    use std::io::Write;

    let mut child = std::process::Command::new("secret-tool")
        .args(["store", "--label", &format!("capshell: {name}")])
        .args(["service", SERVICE, "account", name])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| secret_tool_missing())?;

    // The value goes through a pipe, never argv: `ps` must not be able to see it.
    child
        .stdin
        .take()
        .expect("stdin requested")
        .write_all(value.as_bytes())
        .map_err(|e| e.to_string())?;

    match child.wait().map_err(|e| e.to_string())? {
        s if s.success() => Ok(()),
        s => Err(format!("secret-tool store: {s}{}", no_session())),
    }
}

#[cfg(target_os = "linux")]
fn secret_tool_missing() -> String {
    "secret-tool not found: `apt install libsecret-tools`, or use --env".into()
}

/// The keyring lives on the D-Bus session bus, which only exists with an open
/// desktop session. Over SSH, in a container, or in CI there isn't one, and
/// the CLI's own error doesn't tell the user what to do about it.
#[cfg(target_os = "linux")]
fn no_session() -> &'static str {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        "\n  (no D-Bus session: over SSH, in a container, or in CI use --env)"
    } else {
        ""
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn get(_name: &str) -> Result<String, String> {
    let _ = SERVICE;
    Err("no keyring on this platform: use --env".into())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn set(_name: &str, _value: &str) -> Result<(), String> {
    Err("no keyring on this platform".into())
}

/// Minimal .env file parser: `KEY=value`, `#` comments, optional quotes.
pub fn parse_env_file(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("export ").unwrap_or(l).split_once('='))
        .map(|(k, v)| {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            (k.trim().to_string(), v.to_string())
        })
        .collect()
}

/// Replaces the declared values in the .env text with their placeholders.
/// The file stops holding secrets and can even go into git.
pub fn rewrite_env_file(raw: &str, replacements: &[(String, String)]) -> String {
    raw.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            match body.split_once('=') {
                Some((k, _)) => match replacements.iter().find(|(n, _)| n == k.trim()) {
                    Some((_, placeholder)) => {
                        let indent = &line[..line.len() - trimmed.len()];
                        let kw = if trimmed.starts_with("export ") {
                            "export "
                        } else {
                            ""
                        };
                        format!("{indent}{kw}{}={placeholder}", k.trim())
                    }
                    None => line.to_string(),
                },
                None => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
