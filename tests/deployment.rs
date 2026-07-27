use std::collections::BTreeMap;
use std::process::Command;
use twl::{runtime, RouteAccess, SessionManifest};

#[test]
fn container_entrypoint_installs_only_session_scoped_environment() {
    let directory = std::env::temp_dir().join(format!(
        "twl-entrypoint-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("session.json");
    let token = "test-session-token";
    let broker = "http://127.0.0.1:41234";
    let mut routes = BTreeMap::new();
    routes.insert(
        "provider-api".into(),
        RouteAccess {
            url: format!("{broker}/{token}/provider-api"),
            credential: "twl-app-fake-container-credential".into(),
        },
    );
    let manifest = SessionManifest {
        version: 1,
        broker_url: broker.into(),
        session_token: token.into(),
        routes,
    };
    runtime::write_session_manifest(&path, &manifest).unwrap();

    let assertion = "import os; assert os.environ['TWL_SESSION_TOKEN'] == 'test-session-token'; assert os.environ['TWL_ROUTE_PROVIDER_API_URL'].endswith('/provider-api'); assert os.environ['APP_API_KEY'].startswith('twl-app-'); print('entrypoint-ok')";
    let output = Command::new("python3")
        .arg(format!(
            "{}/deploy/session-entrypoint.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg(&path)
        .args(["python3", "-c", assertion])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "entrypoint-ok"
    );

    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
