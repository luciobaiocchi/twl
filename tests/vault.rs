mod common;

use common::granted_route;
use std::collections::BTreeMap;
use twl::policy::{VaultPayload, VAULT_PAYLOAD_VERSION};
use twl::vault;

const REAL_KEY: &str = "vault-real-provider-key-0123456789";
const PASSWORD: &str = "correct horse battery staple";

#[test]
fn vault_round_trip_hides_credentials_and_destination_policies() {
    let payload = payload();
    let encoded = vault::seal(&payload, PASSWORD).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();

    for protected in [REAL_KEY, "api.example.test", "provider-api", "/v1"] {
        assert!(!text.contains(protected), "vault exposed {protected}");
    }

    let opened = vault::open(&encoded, PASSWORD).unwrap();
    assert_eq!(opened, payload);
}

#[test]
fn wrong_password_and_header_or_ciphertext_tampering_share_a_generic_error() {
    let encoded = vault::seal(&payload(), PASSWORD).unwrap();
    assert_eq!(
        vault::open(&encoded, "wrong password").unwrap_err(),
        "vault could not be opened"
    );

    let mut header: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    header["kdf"]["memory_kib"] = serde_json::json!(32_768);
    assert_eq!(
        vault::open(&serde_json::to_vec(&header).unwrap(), PASSWORD).unwrap_err(),
        "vault could not be opened"
    );

    let mut ciphertext: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let data = ciphertext["cipher"]["data"].as_str().unwrap();
    let replacement = if data.ends_with('A') { 'B' } else { 'A' };
    ciphertext["cipher"]["data"] =
        serde_json::Value::String(format!("{}{replacement}", &data[..data.len() - 1]));
    assert_eq!(
        vault::open(&serde_json::to_vec(&ciphertext).unwrap(), PASSWORD).unwrap_err(),
        "vault could not be opened"
    );
}

#[test]
fn new_vault_file_is_owner_only_and_never_overwritten() {
    let directory = std::env::temp_dir().join(format!(
        "twl-vault-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("towel.vault");
    let encoded = vault::seal(&payload(), PASSWORD).unwrap();

    vault::write_new(&path, &encoded).unwrap();
    assert_eq!(vault::load(&path, PASSWORD).unwrap(), payload());
    assert!(vault::write_new(&path, b"replacement").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), encoded);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn trusted_route_yaml_rejects_missing_credentials_and_unsafe_policy() {
    let missing = trusted_yaml("missing", "GET", "/v1");
    assert!(VaultPayload::parse_trusted_yaml(&missing).is_err());

    let method = trusted_yaml("provider", "OPTIONS", "/v1");
    assert!(VaultPayload::parse_trusted_yaml(&method).is_err());

    let path = trusted_yaml("provider", "GET", "/v1/%2e%2e/admin");
    assert!(VaultPayload::parse_trusted_yaml(&path).is_err());

    let arbitrary_auth =
        trusted_yaml("provider", "GET", "/v1").replace("format: bearer", "format: template");
    assert!(VaultPayload::parse_trusted_yaml(&arbitrary_auth).is_err());
}

fn payload() -> VaultPayload {
    let mut route = granted_route("provider-api", "https://api.example.test:443", REAL_KEY);
    route.policy.path_prefixes = Some(vec!["/v1".into()]);
    route.policy.request_count_budget = 12;
    route.policy.max_request_bytes = 4_096;
    route.policy.max_response_bytes = 8_192;
    route.policy.max_concurrent_requests = 3;
    route.policy.session_expiry_seconds = 300;

    let mut credentials = BTreeMap::new();
    credentials.insert(route.policy.credential.clone(), route.credential);
    let mut routes = BTreeMap::new();
    routes.insert(route.id, route.policy);
    VaultPayload {
        version: VAULT_PAYLOAD_VERSION,
        credentials,
        routes,
    }
}

fn trusted_yaml(credential: &str, method: &str, prefix: &str) -> String {
    format!(
        "version: 1\ncredentials:\n  provider: provider-secret-value\nroutes:\n  provider-api:\n    origin:\n      scheme: https\n      hostname: api.example.test\n      port: 443\n    credential: {credential}\n    authentication:\n      location: header\n      name: Authorization\n      format: bearer\n    allowed_methods: [{method}]\n    path_prefixes: [{prefix}]\n    request_count_budget: 5\n    max_request_bytes: 1024\n    max_response_bytes: 2048\n    max_concurrent_requests: 2\n    session_expiry_seconds: 60\n"
    )
}
