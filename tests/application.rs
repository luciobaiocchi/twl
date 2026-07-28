#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use common::upstream;
use std::process::Command;
use twl::proxy::{self, Route};
use twl::{child_command, secret};

const REAL_KEY: &str = "third-party-real-test-key";

#[test]
fn python_app_uses_the_service_without_receiving_the_real_key() {
    if std::env::var_os("TWL_TEST_APPLICATION_PARENT").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env("TWL_TEST_APPLICATION_PARENT", "1")
            .env("TWL_APPLICATION_API_KEY", REAL_KEY)
            .env("TWL_APPLICATION_UPSTREAM", "http://attacker.invalid")
            .args([
                "--exact",
                "python_app_uses_the_service_without_receiving_the_real_key",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let (upstream, log) = upstream();
    let handle = proxy::spawn(
        vec![Route {
            name: "application".into(),
            upstream,
            key: REAL_KEY.into(),
        }],
        None,
    )
    .unwrap();
    let overrides = vec![
        ("APP_API_KEY".into(), secret::mock()),
        (
            "APP_BASE_URL".into(),
            format!(
                "http://127.0.0.1:{}/{}/application",
                handle.port, handle.token
            ),
        ),
    ];
    let app = format!(
        "{}/examples/application_client.py",
        env!("CARGO_MANIFEST_DIR")
    );

    let output = child_command("python3", &[app], &overrides)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"app\": \"ok\""));
    assert!(!stdout.contains(REAL_KEY));

    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "/v1/models");
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {REAL_KEY}"))
    );
    drop(handle);
}
