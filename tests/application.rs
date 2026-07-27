mod common;

use common::{grant, granted_route, upstream};
use twl::{child_command, prepare_grant};

const REAL_KEY: &str = "third-party-real-test-key";

#[test]
fn python_app_uses_the_service_without_receiving_the_real_key() {
    let (upstream, log) = upstream();
    let prepared = prepare_grant(grant(vec![granted_route(
        "application",
        &upstream,
        REAL_KEY,
    )]))
    .unwrap();
    let (handle, manifest) = prepared.start().unwrap();
    let app = format!(
        "{}/examples/application_client.py",
        env!("CARGO_MANIFEST_DIR")
    );

    let output = child_command("python3", &[app], &manifest.environment())
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
