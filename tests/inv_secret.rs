use twl::config::{
    validate_upstream, Config, CHILD_BASE_URL_ENV, CHILD_SECRET_ENV, PARENT_SECRET_ENV,
    PARENT_UPSTREAM_ENV,
};
use twl::{child_command, prepare_session, SessionMaterial};

const KEY: &str = "project-canary-real-key-0123456789";

fn prepared() -> twl::Prepared {
    prepare_session(SessionMaterial {
        key: KEY.to_string(),
        upstream: "https://service.example/api".into(),
    })
    .unwrap()
}

fn value<'a>(variables: &'a [(String, String)], name: &str) -> &'a str {
    variables
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .unwrap_or_default()
}

#[test]
fn child_receives_one_fake_project_key_and_local_url() {
    let variables = prepared().env_overrides(41234, "SESSIONTOKEN");

    assert!(value(&variables, CHILD_SECRET_ENV).starts_with("twl-app-"));
    assert_ne!(value(&variables, CHILD_SECRET_ENV), KEY);
    assert_eq!(
        value(&variables, CHILD_BASE_URL_ENV),
        "http://127.0.0.1:41234/SESSIONTOKEN"
    );
    assert!(variables.iter().all(|(_, value)| value != KEY));
}

#[test]
fn child_command_removes_parent_inputs_but_leaves_agent_credentials_alone() {
    let variables = prepared().env_overrides(41234, "TOKEN");
    let command = child_command("unused", &[], &variables);
    let configured: Vec<_> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect();

    assert!(configured.iter().any(|(key, value)| {
        key == CHILD_SECRET_ENV
            && value
                .as_deref()
                .is_some_and(|value| value.starts_with("twl-app-"))
    }));
    for name in [PARENT_SECRET_ENV, PARENT_UPSTREAM_ENV] {
        assert!(configured
            .iter()
            .any(|(key, value)| key == name && value.is_none()));
    }
    assert!(configured
        .iter()
        .any(|(key, value)| key == "DBUS_SESSION_BUS_ADDRESS" && value.is_none()));
    assert!(configured.iter().all(|(key, _)| key != "AGENT_LOGIN_TOKEN"));
}

#[test]
fn credentials_with_header_control_characters_are_rejected() {
    let error = prepare_session(SessionMaterial {
        key: "secret\nsecond-header".into(),
        upstream: "https://service.example".into(),
    })
    .err()
    .unwrap();

    assert!(error.contains("control characters"));
    assert!(!error.contains("second-header"));
}

#[test]
fn prepared_sessions_revalidate_the_trusted_destination() {
    let error = prepare_session(SessionMaterial {
        key: KEY.into(),
        upstream: "http://service.example".into(),
    })
    .err()
    .unwrap();

    assert!(error.contains("HTTPS"));
}

#[test]
fn project_config_contains_only_an_optional_request_budget() {
    let config = Config::parse("budget:\n  max_requests: 5\n").unwrap();
    assert_eq!(config.budget.unwrap().max_requests, 5);
    assert!(Config::parse("{}\n").unwrap().budget.is_none());

    for invalid in [
        "upstream: https://evil.example\n",
        "secrets:\n  - APP_API_KEY\n",
        "connectors: [legacy-provider]\n",
        "budget:\n  max_requests: 5\n  extra: true\n",
    ] {
        assert!(Config::parse(invalid).is_err(), "accepted: {invalid}");
    }
}

#[test]
fn upstreams_require_https_except_for_loopback_tests() {
    for valid in [
        "https://service.example",
        "https://service.example/prefix/",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://localhost:8080",
    ] {
        assert!(validate_upstream(valid).is_ok(), "rejected: {valid}");
    }
    for invalid in [
        "http://service.example",
        "file:///tmp/socket",
        "https://user:pass@service.example",
        "https://service.example/path?redirect=evil",
        "https://service.example/path#fragment",
        "not-a-url",
    ] {
        assert!(validate_upstream(invalid).is_err(), "accepted: {invalid}");
    }
}
