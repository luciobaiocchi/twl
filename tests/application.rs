#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use common::upstream;
use mithril::{child_command, prepare_session, SessionMaterial};
use std::process::Command;

const REAL_KEY: &str = "third-party-real-test-key";

#[test]
fn python_app_uses_the_service_without_receiving_the_real_key() {
    if std::env::var_os("MTL_TEST_APPLICATION_PARENT").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env("MTL_TEST_APPLICATION_PARENT", "1")
            .env("MTL_APPLICATION_API_KEY", REAL_KEY)
            .env("MTL_APPLICATION_UPSTREAM", "http://attacker.invalid")
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
    let prepared = prepare_session(SessionMaterial {
        key: REAL_KEY.to_string(),
        upstream,
    })
    .unwrap();
    let (handle, overrides) = prepared.start(None).unwrap();
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
