mod common;

use common::{grant, granted_route, upstream};
use twl::{prepare_grant, runtime};

const REAL_KEY: &str = "manifest-real-provider-key";

#[test]
fn session_manifest_file_contains_only_agent_visible_authority() {
    let (upstream, _log) = upstream();
    let prepared = prepare_grant(grant(vec![granted_route(
        "application",
        &upstream,
        REAL_KEY,
    )]))
    .unwrap();
    let (_handle, manifest) = prepared.start().unwrap();
    let directory = std::env::temp_dir().join(format!(
        "twl-manifest-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("session.json");
    std::fs::write(&path, b"stale manifest").unwrap();

    runtime::write_session_manifest(&path, &manifest).unwrap();
    let encoded = std::fs::read_to_string(&path).unwrap();
    let decoded: twl::SessionManifest = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, manifest);
    assert!(!encoded.contains(REAL_KEY));
    assert!(!encoded.contains(&upstream));
    assert!(encoded.contains("twl-app-"));
    assert!(encoded.contains(&manifest.session_token));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
