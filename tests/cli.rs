use std::process::Command;

#[test]
fn run_rejects_env_files_before_touching_the_keyring() {
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .args(["run", "--env", "secrets.env", "--", "unused"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option: --env"));
}

#[test]
fn doctor_reports_the_platform_security_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .arg("doctor")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("secure keyring sessions"));
}

#[cfg(target_os = "macos")]
#[test]
fn ordinary_cargo_binary_fails_closed_for_real_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "run",
            "--config",
            "examples/mithril.yaml",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not protected for real credentials"));
}

#[test]
fn demo_uses_sdk_compatible_local_base_url_without_keyring() {
    if std::env::var_os("MTL_TEST_DEMO_CHILD").is_some() {
        return;
    }
    let current_test = std::env::current_exe().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("MTL_TEST_DEMO_CHILD", "1")
        .args(["demo", "--config", "examples/mithril.yaml", "--"])
        .arg(current_test)
        .args(["--exact", "demo_child_request", "--nocapture"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"path\":\"/v1/models\""));
}

#[test]
fn demo_child_request() {
    if std::env::var_os("MTL_TEST_DEMO_CHILD").is_none() {
        return;
    }
    let key = std::env::var("OPENAI_API_KEY").unwrap();
    let base = std::env::var("OPENAI_BASE_URL").unwrap();
    assert!(key.starts_with("sk-mtl"));
    assert!(base.ends_with("/openai/v1"));
    let response = ureq::get(&format!("{base}/models"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    println!("{response}");
}
