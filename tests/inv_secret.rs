use twl::config::{validate_upstream, Config};
use twl::project::{Project, ProjectRoute};
use twl::{child_command, prepare_project};

const BILLING_KEY: &str = "billing-canary-real-key-0123456789";
const SEARCH_KEY: &str = "search-canary-real-key-9876543210";

fn project() -> Project {
    Project::new(
        "my-app".into(),
        vec![
            ProjectRoute::new(
                "billing".into(),
                "https://billing.example.test/v1".into(),
                BILLING_KEY.into(),
                "BILLING_API_KEY".into(),
                "BILLING_BASE_URL".into(),
            )
            .unwrap(),
            ProjectRoute::new(
                "search".into(),
                "https://search.example.test/api".into(),
                SEARCH_KEY.into(),
                "SEARCH_API_KEY".into(),
                "SEARCH_BASE_URL".into(),
            )
            .unwrap(),
        ],
    )
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
fn child_receives_fake_keys_and_route_specific_loopback_urls() {
    let variables = prepare_project(project())
        .unwrap()
        .environment_overrides(41234, "SESSIONTOKEN");

    for name in ["BILLING_API_KEY", "SEARCH_API_KEY"] {
        assert!(value(&variables, name).starts_with("twl-app-"));
    }
    assert_eq!(
        value(&variables, "BILLING_BASE_URL"),
        "http://127.0.0.1:41234/SESSIONTOKEN/billing"
    );
    assert_eq!(
        value(&variables, "SEARCH_BASE_URL"),
        "http://127.0.0.1:41234/SESSIONTOKEN/search"
    );
    for (_, value) in &variables {
        assert!(!value.contains(BILLING_KEY));
        assert!(!value.contains(SEARCH_KEY));
        assert!(!value.contains("billing.example.test"));
        assert!(!value.contains("search.example.test"));
    }
}

#[test]
fn child_command_removes_legacy_parent_inputs_and_leaves_agent_login_alone() {
    let variables = prepare_project(project())
        .unwrap()
        .environment_overrides(41234, "TOKEN");
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

    for name in [
        "TWL_APPLICATION_API_KEY",
        "TWL_APPLICATION_UPSTREAM",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        assert!(configured
            .iter()
            .any(|(key, value)| key == name && value.is_none()));
    }
    assert!(configured.iter().all(|(key, _)| key != "AGENT_LOGIN_TOKEN"));
    assert!(configured.iter().all(|(_, value)| {
        value
            .as_deref()
            .is_none_or(|value| !value.contains(BILLING_KEY) && !value.contains(SEARCH_KEY))
    }));
}

#[test]
fn project_config_contains_only_an_optional_demo_request_budget() {
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
