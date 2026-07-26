use rand::distributions::Alphanumeric;
use rand::Rng;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
const SERVICE: &str = "mithril";

#[cfg(target_os = "macos")]
type AuthenticationContext = objc2::rc::Retained<objc2_local_authentication::LAContext>;

fn random_tail(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Provider-shaped placeholder visible to the child process.
pub fn mock(prefix: &str) -> String {
    format!("{prefix}mtl{}", random_tail(40))
}

/// A recognizable fake credential used only by `mtl demo`.
pub fn demo(prefix: &str) -> String {
    format!("{prefix}MTL-DEMO-CANARY-{}", random_tail(24))
}

#[cfg(target_os = "macos")]
pub fn process_preflight() -> Result<(), String> {
    use std::ffi::c_void;

    const CS_OPS_STATUS: u32 = 0;
    const CS_VALID: u32 = 0x0000_0001;
    const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
    const CS_FORCED_LV: u32 = 0x0000_0010;
    const CS_HARD: u32 = 0x0000_0100;
    const CS_KILL: u32 = 0x0000_0200;
    const CS_ENFORCEMENT: u32 = 0x0000_1000;
    const CS_REQUIRE_LV: u32 = 0x0000_2000;
    const CS_RUNTIME: u32 = 0x0001_0000;
    const CS_DEBUGGED: u32 = 0x1000_0000;

    unsafe extern "C" {
        fn csops(pid: i32, ops: u32, address: *mut c_void, size: usize) -> i32;
    }

    let mut flags = 0u32;
    let status = unsafe {
        csops(
            std::process::id() as i32,
            CS_OPS_STATUS,
            (&mut flags as *mut u32).cast(),
            std::mem::size_of_val(&flags),
        )
    };
    if status != 0 {
        return Err(format!(
            "reading hardened-runtime state: {}",
            std::io::Error::last_os_error()
        ));
    }

    let required = CS_VALID | CS_HARD | CS_KILL | CS_ENFORCEMENT | CS_RUNTIME;
    let library_validation = flags & (CS_FORCED_LV | CS_REQUIRE_LV) != 0;
    if flags & required != required
        || !library_validation
        || flags & (CS_GET_TASK_ALLOW | CS_DEBUGGED) != 0
    {
        return Err(format!(
            "this binary is not protected for real credentials (code-signing flags {flags:#010x}); build it with `scripts/build-macos.sh`"
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn authentication_context() -> Result<AuthenticationContext, String> {
    use objc2_local_authentication::{LAContext, LAPolicy};

    process_preflight()?;
    let context = unsafe { LAContext::new() };
    unsafe { context.setTouchIDAuthenticationAllowableReuseDuration(0.0) };
    unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
        .map_err(|error| format!("local authentication is unavailable: {error}"))?;
    Ok(context)
}

#[cfg(target_os = "linux")]
pub fn process_preflight() -> Result<(), String> {
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "disabling same-user process inspection: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_preflight() -> Result<(), String> {
    Err("runtime credentials currently require macOS or Linux process hardening".into())
}

#[cfg(target_os = "macos")]
pub fn preflight() -> Result<(), String> {
    use security_framework::os::macos::keychain::SecKeychain;

    authentication_context()?;
    SecKeychain::default()
        .map(|_| ())
        .map_err(|error| format!("opening the login Keychain: {error}"))
}

#[cfg(target_os = "macos")]
fn authorize(reason: &str) -> Result<(), String> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::LAPolicy;

    let context = authentication_context()?;

    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        } else if let Some(error) = unsafe { error.as_ref() } {
            Err(format!(
                "local authentication failed: {}",
                error.localizedDescription()
            ))
        } else {
            Err("local authentication failed".into())
        };
        let _ = sender.send(result);
    });
    let reason = NSString::from_str(reason);
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason,
            &reply,
        );
    }
    match receiver.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            unsafe { context.invalidate() };
            Err("local authentication timed out after 120 seconds".into())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("local authentication ended without a result".into())
        }
    }
}

/// A nested `mtl` can execute this code, but it cannot silently satisfy the
/// native LocalAuthentication prompt that precedes every Keychain read.
#[cfg(target_os = "macos")]
pub fn get(connector: &str) -> Result<String, String> {
    use security_framework::os::macos::keychain::SecKeychain;

    authorize(&format!("start a Mithril session for {connector}"))?;
    let keychain =
        SecKeychain::default().map_err(|error| format!("opening the login Keychain: {error}"))?;
    let (bytes, _) = keychain
        .find_generic_password(SERVICE, connector)
        .map_err(|error| format!("Keychain read for {connector}: {error}"))?;
    String::from_utf8(bytes.to_owned())
        .map_err(|_| format!("Keychain value for {connector} is not UTF-8"))
}

/// Add-only storage avoids updating an item that another process pre-created
/// with a weak ACL. Rotation is deliberately `delete`, then `set`.
#[cfg(target_os = "macos")]
pub fn set(connector: &str, value: &str) -> Result<(), String> {
    use security_framework::os::macos::keychain::SecKeychain;

    const ITEM_NOT_FOUND: i32 = -25300;

    authorize(&format!("store a Mithril credential for {connector}"))?;
    let keychain =
        SecKeychain::default().map_err(|error| format!("opening the login Keychain: {error}"))?;
    match keychain.find_generic_password(SERVICE, connector) {
        Ok(_) => Err(format!(
            "a Keychain item for {connector} already exists; use `mtl secret delete {connector}` before replacing it"
        )),
        Err(error) if error.code() == ITEM_NOT_FOUND => keychain
            .add_generic_password(SERVICE, connector, value.as_bytes())
            .map_err(|error| format!("Keychain write for {connector}: {error}")),
        Err(error) => Err(format!("checking the Keychain for {connector}: {error}")),
    }
}

#[cfg(target_os = "macos")]
pub fn delete(connector: &str) -> Result<(), String> {
    authorize(&format!("delete the Mithril credential for {connector}"))?;
    security_framework::passwords::delete_generic_password(SERVICE, connector)
        .map_err(|error| format!("Keychain deletion for {connector}: {error}"))
}

#[cfg(not(target_os = "macos"))]
pub fn get(_connector: &str) -> Result<String, String> {
    Err(
        "real-key sessions currently require macOS user presence; use `mtl demo` on this platform"
            .into(),
    )
}

#[cfg(not(target_os = "macos"))]
pub fn set(_connector: &str, _value: &str) -> Result<(), String> {
    Err("secure keyring import is currently available only on macOS".into())
}

#[cfg(not(target_os = "macos"))]
pub fn delete(_connector: &str) -> Result<(), String> {
    Err("secure keyring deletion is currently available only on macOS".into())
}

#[cfg(not(target_os = "macos"))]
pub fn preflight() -> Result<(), String> {
    Err("native user-presence Keychain sessions are currently available only on macOS".into())
}

/// Minimal `.env` parser for one-time migration.
pub fn parse_env_file(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.strip_prefix("export ").unwrap_or(line).split_once('='))
        .map(|(key, value)| {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .or_else(|| {
                    value
                        .strip_prefix('\'')
                        .and_then(|value| value.strip_suffix('\''))
                })
                .unwrap_or(value);
            (key.trim().to_string(), value.to_string())
        })
        .collect()
}

pub fn rewrite_env_file(raw: &str, replacements: &[(String, String)]) -> String {
    let mut rewritten = raw
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            match body.split_once('=') {
                Some((key, _)) => replacements
                    .iter()
                    .find(|(name, _)| name == key.trim())
                    .map(|(_, placeholder)| {
                        let indent = &line[..line.len() - trimmed.len()];
                        let export = if trimmed.starts_with("export ") {
                            "export "
                        } else {
                            ""
                        };
                        format!("{indent}{export}{}={placeholder}", key.trim())
                    })
                    .unwrap_or_else(|| line.to_string()),
                None => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if raw.ends_with('\n') {
        rewritten.push('\n');
    }
    rewritten
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    Ok(parent.join(format!(".{name}.mtl-tmp-{}", random_tail(12))))
}

/// Replace a migration file without a plaintext backup. On failure the
/// original remains untouched and the temporary file is removed.
pub fn atomic_rewrite(path: &Path, contents: &str) -> Result<(), String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let temporary = temporary_path(path)?;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("{}: {error}", temporary.display()))?;
        file.set_permissions(metadata.permissions())
            .map_err(|error| format!("{}: {error}", temporary.display()))?;
        file.write_all(contents.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("{}: {error}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::File::open(parent).and_then(|directory| directory.sync_all());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
