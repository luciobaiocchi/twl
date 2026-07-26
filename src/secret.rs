use rand::distributions::Alphanumeric;
use rand::Rng;

fn random_tail(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Placeholder visible to the agent and its child processes.
pub fn mock() -> String {
    format!("mtl-app-{}", random_tail(40))
}

/// A recognizable fake credential used only by `mtl demo`.
pub fn demo() -> String {
    format!("mtl-demo-canary-{}", random_tail(24))
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
