use std::process::Command;

#[test]
fn run_rejects_env_files() {
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("protected project sessions"));
    assert!(stdout.contains("canary-only demo"));
}

#[test]
fn persistent_secret_commands_are_not_part_of_the_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .args(["secret", "set", "application"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

#[cfg(target_os = "linux")]
#[test]
fn environment_secret_prints_the_weaker_input_warning() {
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .env("MTL_APPLICATION_API_KEY", "disposable-test-key")
        .args([
            "run",
            "--upstream",
            "http://127.0.0.1:1",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("weaker input"));
    assert!(stderr.contains("prefer --secret-fd FD"));
}

#[cfg(target_os = "macos")]
#[test]
fn ordinary_cargo_binary_fails_closed_for_real_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_mtl"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("MTL_APPLICATION_API_KEY", "disposable-test-key")
        .args([
            "run",
            "--upstream",
            "http://127.0.0.1:1",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not protected for real credentials"));
}

#[test]
fn demo_uses_the_generic_application_contract() {
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
    let key = std::env::var("APP_API_KEY").unwrap();
    let base = std::env::var("APP_BASE_URL").unwrap();
    assert!(key.starts_with("mtl-app-"));
    assert!(base.starts_with("http://127.0.0.1:"));
    let response = ureq::get(&format!("{base}/v1/models"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    println!("{response}");
}
