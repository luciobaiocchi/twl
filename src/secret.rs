use rand::distributions::Alphanumeric;
use rand::Rng;
#[cfg(any(target_os = "macos", test))]
use std::sync::mpsc::{Receiver, RecvTimeoutError};
#[cfg(any(target_os = "macos", test))]
use std::time::Duration;

#[cfg(target_os = "macos")]
type AuthenticationContext = objc2::rc::Retained<objc2_local_authentication::LAContext>;

fn random_tail(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Placeholder visible to the agent and its child processes.
pub fn mock() -> String {
    format!("twl-app-{}", random_tail(40))
}

/// A recognizable fake credential used only by `twl demo`.
pub fn demo() -> String {
    format!("twl-demo-canary-{}", random_tail(24))
}

#[cfg(any(target_os = "macos", test))]
fn wait_for_authorization(
    receiver: Receiver<Result<(), String>>,
    timeout: Duration,
    invalidate: impl FnOnce(),
) -> Result<(), String> {
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            invalidate();
            Err(format!(
                "local authentication timed out after {} seconds",
                timeout.as_secs()
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            Err("local authentication ended without a result".into())
        }
    }
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

#[cfg(target_os = "macos")]
pub fn authorize(reason: &str) -> Result<(), String> {
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
    wait_for_authorization(receiver, Duration::from_secs(120), || unsafe {
        context.invalidate()
    })
}

#[cfg(not(target_os = "macos"))]
pub fn authorize(_reason: &str) -> Result<(), String> {
    Err("project credentials are currently available only on macOS".into())
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

#[cfg(target_os = "linux")]
pub fn process_preflight() -> Result<(), String> {
    Err("real project credentials are currently available only on macOS".into())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_preflight() -> Result<(), String> {
    Err("real project credentials are currently available only on macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn authorization_cancellation_is_returned() {
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(Err("local authentication failed: canceled".into()))
            .unwrap();
        let error = wait_for_authorization(receiver, Duration::from_secs(1), || {}).unwrap_err();
        assert!(error.contains("canceled"));
    }

    #[test]
    fn authorization_timeout_invalidates_context() {
        let (_sender, receiver) = std::sync::mpsc::channel();
        let invalidated = Arc::new(AtomicBool::new(false));
        let marker = invalidated.clone();
        let error = wait_for_authorization(receiver, Duration::from_millis(1), move || {
            marker.store(true, Ordering::SeqCst);
        })
        .unwrap_err();
        assert!(error.contains("timed out"));
        assert!(invalidated.load(Ordering::SeqCst));
    }
}
