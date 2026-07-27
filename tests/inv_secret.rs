mod common;

use common::{grant, granted_route, upstream};
use std::collections::BTreeMap;
use twl::config::{
    Config, BROKER_URL_ENV, CHILD_BASE_URL_ENV, CHILD_SECRET_ENV, SESSION_TOKEN_ENV,
};
use twl::grant::{GrantProvider, GrantRequest};
use twl::policy::{OriginPolicy, SecretValue, VaultPayload, VAULT_PAYLOAD_VERSION};
use twl::{child_command, prepare_grant};

const ALPHA_KEY: &str = "alpha-real-key-0123456789";
const BETA_KEY: &str = "beta-real-key-9876543210";

fn value<'a>(variables: &'a [(String, String)], name: &str) -> &'a str {
    variables
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .unwrap_or_default()
}

#[test]
fn child_receives_only_local_urls_fake_credentials_and_session_token() {
    let (alpha_upstream, _alpha_log) = upstream();
    let (beta_upstream, _beta_log) = upstream();
    let prepared = prepare_grant(grant(vec![
        granted_route("alpha", &alpha_upstream, ALPHA_KEY),
        granted_route("beta", &beta_upstream, BETA_KEY),
    ]))
    .unwrap();
    let (_handle, manifest) = prepared.start().unwrap();
    let variables = manifest.environment();

    assert!(value(&variables, BROKER_URL_ENV).starts_with("http://127.0.0.1:"));
    assert_eq!(value(&variables, SESSION_TOKEN_ENV), manifest.session_token);
    assert!(value(&variables, "TWL_ROUTE_ALPHA_URL").contains(&manifest.session_token));
    assert!(value(&variables, "TWL_ROUTE_BETA_URL").contains(&manifest.session_token));
    assert!(value(&variables, "TWL_ROUTE_ALPHA_CREDENTIAL").starts_with("twl-app-"));
    assert!(value(&variables, "TWL_ROUTE_BETA_CREDENTIAL").starts_with("twl-app-"));
    assert_ne!(
        value(&variables, "TWL_ROUTE_ALPHA_CREDENTIAL"),
        value(&variables, "TWL_ROUTE_BETA_CREDENTIAL")
    );
    assert!(variables
        .iter()
        .all(|(_, value)| value != ALPHA_KEY && value != BETA_KEY));
    assert!(value(&variables, CHILD_SECRET_ENV).is_empty());
    assert!(value(&variables, CHILD_BASE_URL_ENV).is_empty());

    let encoded = serde_json::to_string(&manifest).unwrap();
    for forbidden in [ALPHA_KEY, BETA_KEY, &alpha_upstream, &beta_upstream] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn one_route_keeps_the_generic_application_compatibility_contract() {
    let (upstream, _log) = upstream();
    let prepared = prepare_grant(grant(vec![granted_route(
        "application",
        &upstream,
        ALPHA_KEY,
    )]))
    .unwrap();
    let (_handle, manifest) = prepared.start().unwrap();
    let variables = manifest.environment();

    assert!(value(&variables, CHILD_SECRET_ENV).starts_with("twl-app-"));
    assert_eq!(
        value(&variables, CHILD_BASE_URL_ENV),
        manifest.routes["application"].url
    );
}

#[test]
fn child_command_removes_parent_inputs_and_installs_only_fakes() {
    let (upstream, _log) = upstream();
    let prepared = prepare_grant(grant(vec![granted_route(
        "application",
        &upstream,
        ALPHA_KEY,
    )]))
    .unwrap();
    let (_handle, manifest) = prepared.start().unwrap();
    let command = child_command("unused", &[], &manifest.environment());
    let configured: Vec<_> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect();

    for name in [
        "TWL_VAULT_PASSWORD",
        "TWL_APPLICATION_API_KEY",
        "TWL_APPLICATION_UPSTREAM",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        assert!(configured
            .iter()
            .any(|(key, value)| key == name && value.is_none()));
    }
    assert!(configured.iter().any(|(key, value)| {
        key == CHILD_SECRET_ENV
            && value
                .as_deref()
                .is_some_and(|value| value.starts_with("twl-app-"))
    }));
    assert!(configured.iter().all(|(_, value)| {
        value
            .as_deref()
            .is_none_or(|value| !value.contains(ALPHA_KEY))
    }));
}

#[test]
fn repository_config_can_only_narrow_trusted_routes_and_limits() {
    let config = Config::parse(
        "routes:\n  - alpha\nlimits:\n  max_requests: 5\n  max_request_bytes: 1024\n  max_response_bytes: 2048\n  max_concurrent_requests: 2\n  session_expiry_seconds: 60\n",
    )
    .unwrap();
    let authorized = vec!["alpha".into(), "beta".into()];
    let request = config.grant_request(&authorized).unwrap();
    assert_eq!(request.route_ids, ["alpha"]);

    let payload = test_payload();
    let grant = payload.issue_grant(&request).unwrap();
    assert_eq!(grant.routes.len(), 1);
    let policy = &grant.routes[0].policy;
    assert_eq!(policy.request_count_budget, 5);
    assert_eq!(policy.max_request_bytes, 1024);
    assert_eq!(policy.max_response_bytes, 2048);
    assert_eq!(policy.max_concurrent_requests, 2);
    assert_eq!(policy.session_expiry_seconds, 60);

    let hostile = Config::parse("routes: [beta]\n").unwrap();
    let error = hostile.grant_request(&["alpha".into()]).unwrap_err();
    assert!(error.contains("not in the trusted allow-route set"));
}

#[test]
fn repository_config_rejects_high_authority_fields() {
    for invalid in [
        "upstream: https://evil.example\n",
        "credentials:\n  key: stolen\n",
        "authentication:\n  format: template\n",
        "budget:\n  max_requests: 5\n",
        "limits:\n  max_request_bytes: 0\n",
        "routes: [alpha, alpha]\n",
    ] {
        assert!(Config::parse(invalid).is_err(), "accepted: {invalid}");
    }
}

#[test]
fn upstream_origins_require_an_exact_port_and_https_except_loopback() {
    for valid in [
        OriginPolicy {
            scheme: "https".into(),
            hostname: "service.example".into(),
            port: 443,
        },
        OriginPolicy {
            scheme: "http".into(),
            hostname: "127.0.0.1".into(),
            port: 8080,
        },
        OriginPolicy {
            scheme: "http".into(),
            hostname: "::1".into(),
            port: 8080,
        },
        OriginPolicy {
            scheme: "http".into(),
            hostname: "localhost".into(),
            port: 8080,
        },
    ] {
        assert!(valid.base_url().is_ok(), "rejected: {valid:?}");
    }
    for invalid in [
        OriginPolicy {
            scheme: "http".into(),
            hostname: "service.example".into(),
            port: 80,
        },
        OriginPolicy {
            scheme: "file".into(),
            hostname: "localhost".into(),
            port: 1,
        },
        OriginPolicy {
            scheme: "https".into(),
            hostname: "user@service.example".into(),
            port: 443,
        },
        OriginPolicy {
            scheme: "https".into(),
            hostname: "service.example/path".into(),
            port: 443,
        },
        OriginPolicy {
            scheme: "https".into(),
            hostname: "service.example".into(),
            port: 0,
        },
    ] {
        assert!(invalid.base_url().is_err(), "accepted: {invalid:?}");
    }
}

#[test]
fn credentials_and_environment_route_names_fail_closed() {
    assert!(SecretValue::new(String::new()).is_err());
    assert!(SecretValue::new("secret\nsecond-header".into()).is_err());

    let (upstream, _log) = upstream();
    let error = prepare_grant(grant(vec![
        granted_route("a-b", &upstream, ALPHA_KEY),
        granted_route("a_b", &upstream, BETA_KEY),
    ]))
    .err()
    .unwrap();
    assert!(error.contains("collide"));
    assert!(!error.contains(ALPHA_KEY));
    assert!(!error.contains(BETA_KEY));
}

fn test_payload() -> VaultPayload {
    let alpha = granted_route("alpha", "https://alpha.example:443", ALPHA_KEY);
    let beta = granted_route("beta", "https://beta.example:443", BETA_KEY);
    let mut credentials = BTreeMap::new();
    credentials.insert(alpha.policy.credential.clone(), alpha.credential);
    credentials.insert(beta.policy.credential.clone(), beta.credential);
    let mut routes = BTreeMap::new();
    routes.insert(alpha.id, alpha.policy);
    routes.insert(beta.id, beta.policy);
    VaultPayload {
        version: VAULT_PAYLOAD_VERSION,
        credentials,
        routes,
    }
}

#[test]
fn grant_provider_rejects_unknown_routes() {
    let payload = test_payload();
    let request = GrantRequest {
        route_ids: vec!["unknown".into()],
        limits: Default::default(),
    };
    assert!(payload.issue_grant(&request).is_err());
}
