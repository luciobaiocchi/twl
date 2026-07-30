use std::process::Command;

#[test]
fn run_rejects_env_files() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args(["run", "--env", "secrets.env", "--", "unused"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option: --env"));
}

#[test]
fn doctor_reports_the_platform_security_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .arg("doctor")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    #[cfg(target_os = "macos")]
    assert!(stdout.contains("protected macOS project sessions"));
    #[cfg(target_os = "linux")]
    assert!(stdout.contains("encrypted Linux project sessions"));
    assert!(stdout.contains("canary-only demo"));
}

#[test]
fn persistent_secret_commands_are_not_part_of_the_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args(["secret", "set", "application"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

#[test]
fn invalid_project_commands_fail_before_platform_checks() {
    for args in [
        vec!["project", "unknown"],
        vec!["project", "show", "../not-an-identifier"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_twl"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("usage:") || stderr.contains("identifier"));
        assert!(!stderr.contains("only on macOS"));
        assert!(!stderr.contains("not protected for real credentials"));
    }
}

#[test]
fn run_requires_a_named_project_and_rejects_legacy_inputs() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args([
            "run",
            "--upstream",
            "https://service.example",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown option: --upstream"));
}

#[cfg(target_os = "macos")]
#[test]
fn ordinary_cargo_binary_fails_closed_for_real_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("TWL_APPLICATION_API_KEY", "disposable-test-key")
        .args(["run", "--project", "test-project", "--", "/usr/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not protected for real credentials"));
}

#[test]
fn demo_uses_the_generic_application_contract() {
    if std::env::var_os("TWL_TEST_DEMO_CHILD").is_some() {
        return;
    }
    let current_test = std::env::current_exe().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("TWL_TEST_DEMO_CHILD", "1")
        .args(["demo", "--config", "examples/towel.yaml", "--"])
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
    if std::env::var_os("TWL_TEST_DEMO_CHILD").is_none() {
        return;
    }
    let key = std::env::var("APP_API_KEY").unwrap();
    let base = std::env::var("APP_BASE_URL").unwrap();
    assert!(key.starts_with("twl-app-"));
    assert!(base.starts_with("http://127.0.0.1:"));
    let response = ureq::get(&format!("{base}/v1/models"))
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    println!("{response}");
}
