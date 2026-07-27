use std::process::Command;

#[test]
fn run_rejects_legacy_raw_secret_and_destination_flags() {
    for option in ["--env", "--upstream", "--secret-fd"] {
        let output = Command::new(env!("CARGO_BIN_EXE_twl"))
            .args(["run", option, "value", "--", "unused"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("unknown option: {option}")),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn native_run_rejects_agent_readable_password_files() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args([
            "run",
            "--vault",
            "towel.vault",
            "--allow-route",
            "application",
            "--password-file",
            "/tmp/password",
            "--",
            "unused",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("isolated serve mode"));
}

#[test]
fn doctor_reports_the_platform_security_and_vault_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .arg("doctor")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("protected broker sessions"));
    assert!(stdout.contains("Argon2id + XChaCha20-Poly1305"));
    assert!(stdout.contains("canary-only demo"));
}

#[test]
fn generic_persistent_secret_commands_are_not_part_of_the_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args(["secret", "set", "application"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
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

#[cfg(target_os = "linux")]
#[test]
fn vault_seal_cli_writes_a_loadable_encrypted_file() {
    let directory = temporary_directory("seal");
    let trusted = directory.join("trusted.yaml");
    let encrypted = directory.join("towel.vault");
    std::fs::write(&trusted, trusted_yaml()).unwrap();

    let output = command_with_password(&[
        "vault",
        "seal",
        "--input",
        trusted.to_str().unwrap(),
        "--output",
        encrypted.to_str().unwrap(),
        "--password-fd",
        "3",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = twl::vault::load(&encrypted, TEST_PASSWORD).unwrap();
    assert!(payload.routes.contains_key("application"));
    assert!(
        !String::from_utf8_lossy(&std::fs::read(&encrypted).unwrap()).contains("cli-real-test-key")
    );

    std::fs::remove_file(trusted).unwrap();
    std::fs::remove_file(encrypted).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn native_run_opens_the_vault_before_launching_the_agent() {
    let directory = temporary_directory("run");
    let encrypted = directory.join("towel.vault");
    let payload = twl::policy::VaultPayload::parse_trusted_yaml(&trusted_yaml()).unwrap();
    let encoded = twl::vault::seal(&payload, TEST_PASSWORD).unwrap();
    twl::vault::write_new(&encrypted, &encoded).unwrap();

    let output = command_with_password(&[
        "run",
        "--vault",
        encrypted.to_str().unwrap(),
        "--allow-route",
        "application",
        "--password-fd",
        "3",
        "--",
        "/usr/bin/true",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("1 route(s)"));

    std::fs::remove_file(encrypted).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn ordinary_cargo_binary_fails_closed_before_opening_a_real_vault() {
    let output = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args([
            "run",
            "--vault",
            "does-not-matter.vault",
            "--allow-route",
            "application",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not protected for real credentials"));
}

#[cfg(target_os = "linux")]
const TEST_PASSWORD: &str = "correct horse battery staple";

#[cfg(target_os = "linux")]
fn command_with_password(arguments: &[&str]) -> std::process::Output {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;

    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(TEST_PASSWORD.as_bytes()).unwrap();
    drop(writer);
    let source = reader.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_twl"));
    command.args(arguments);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.output().unwrap()
}

#[cfg(target_os = "linux")]
fn temporary_directory(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "twl-cli-{label}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[cfg(target_os = "linux")]
fn trusted_yaml() -> String {
    "version: 1\ncredentials:\n  application-key: cli-real-test-key\nroutes:\n  application:\n    origin:\n      scheme: https\n      hostname: service.example\n      port: 443\n    credential: application-key\n    authentication:\n      location: header\n      name: Authorization\n      format: bearer\n    allowed_methods: [GET, POST, PUT, PATCH, DELETE]\n    request_count_budget: 5\n    max_request_bytes: 1048576\n    max_response_bytes: 1048576\n    max_concurrent_requests: 4\n    session_expiry_seconds: 300\n"
        .into()
}
