use mithril::config::{connector, validate_runtime_upstream, Config, CredentialSource};
use mithril::{child_command, prepare, prepare_session, secret, SessionMaterial};

const KEY: &str = "sk-CANARY-REAL-KEY-0123456789";
const YAML: &str = "connectors:\n  - openai\n  - anthropic\n";

fn overrides() -> Vec<(String, String)> {
    let config = Config::parse(YAML).unwrap();
    prepare(&config, |_| Ok(KEY.to_string()))
        .unwrap()
        .env_overrides(41234, "SESSIONTOKEN")
}

fn value<'a>(variables: &'a [(String, String)], name: &str) -> &'a str {
    variables
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .unwrap_or_default()
}

#[test]
fn child_receives_provider_shaped_mocks_not_real_values() {
    let variables = overrides();
    assert!(value(&variables, "OPENAI_API_KEY").starts_with("sk-mtl"));
    assert!(value(&variables, "ANTHROPIC_API_KEY").starts_with("sk-ant-mtl"));
    assert!(variables.iter().all(|(_, value)| value != KEY));
}

#[test]
fn base_urls_include_session_token_and_sdk_specific_prefix() {
    let variables = overrides();
    for name in ["OPENAI_BASE_URL", "OPENAI_API_BASE"] {
        assert_eq!(
            value(&variables, name),
            "http://127.0.0.1:41234/SESSIONTOKEN/openai/v1"
        );
    }
    for name in ["ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"] {
        assert_eq!(
            value(&variables, name),
            "http://127.0.0.1:41234/SESSIONTOKEN/anthropic"
        );
    }
}

#[test]
fn child_command_replaces_selected_values_and_preserves_unrelated_ones() {
    let config = Config::parse("connectors: [openai]\n").unwrap();
    let variables = prepare(&config, |_| Ok(KEY.to_string()))
        .unwrap()
        .env_overrides(41234, "TOKEN");
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
        key == "OPENAI_API_KEY"
            && value
                .as_deref()
                .is_some_and(|value| value.starts_with("sk-mtl"))
    }));
    assert!(configured.iter().all(|(key, _)| key != "ANTHROPIC_API_KEY"));
    assert!(configured
        .iter()
        .any(|(key, value)| key == "DBUS_SESSION_BUS_ADDRESS" && value.is_none()));
    for name in ["MTL_APPLICATION_API_KEY", "MTL_APPLICATION_UPSTREAM"] {
        assert!(configured
            .iter()
            .any(|(key, value)| key == name && value.is_none()));
    }
}

#[test]
fn application_connector_does_not_replace_agent_provider_credentials() {
    let config = Config::parse("connectors: [application]\n").unwrap();
    let variables = prepare_session(&config, |_| {
        Ok(SessionMaterial {
            key: KEY.into(),
            upstream: "https://service.example".into(),
        })
    })
    .unwrap()
    .env_overrides(41234, "TOKEN");
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
        key == "APP_API_KEY"
            && value
                .as_deref()
                .is_some_and(|value| value.starts_with("mtl-app-mtl"))
    }));
    assert!(configured.iter().all(|(key, _)| key != "OPENAI_API_KEY"));
    assert!(configured.iter().all(|(key, _)| key != "OPENAI_BASE_URL"));
}

#[test]
fn runtime_application_exposes_only_a_fake_key_and_local_url() {
    let config = Config::parse("connectors: [application]\n").unwrap();
    let prepared = prepare_session(&config, |connector| {
        assert_eq!(connector.id, "application");
        Ok(SessionMaterial {
            key: KEY.to_string(),
            upstream: "https://service.example/api".into(),
        })
    })
    .unwrap();
    let variables = prepared.env_overrides(41234, "TOKEN");

    assert!(value(&variables, "APP_API_KEY").starts_with("mtl-app-mtl"));
    assert_ne!(value(&variables, "APP_API_KEY"), KEY);
    assert_eq!(
        value(&variables, "APP_BASE_URL"),
        "http://127.0.0.1:41234/TOKEN/application"
    );
}

#[test]
fn credentials_with_header_control_characters_are_rejected() {
    let config = Config::parse("connectors: [openai]\n").unwrap();
    let error = prepare(&config, |_| Ok("secret\nsecond-header".into()))
        .err()
        .unwrap();

    assert!(error.contains("control characters"));
    assert!(!error.contains("second-header"));
}

#[test]
fn workspace_config_cannot_define_secret_identity_or_upstream() {
    for invalid in [
        "connectors: [openai]\nupstream: http://evil.example\n",
        "secrets:\n  - name: OPENAI_API_KEY\n    connector: openai\n",
        "connectors: [openai, openai]\n",
        "connectors: [unknown]\n",
        "connectors: []\n",
    ] {
        assert!(Config::parse(invalid).is_err(), "accepted: {invalid}");
    }

    let openai = connector("openai").unwrap();
    assert_eq!(openai.secret_env, "OPENAI_API_KEY");
    assert_eq!(
        openai.credential_source,
        CredentialSource::Keychain {
            upstream: "https://api.openai.com"
        }
    );
}

#[test]
fn runtime_upstreams_require_https_except_for_loopback_tests() {
    for valid in [
        "https://service.example",
        "https://service.example/prefix/",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://localhost:8080",
    ] {
        assert!(
            validate_runtime_upstream(valid).is_ok(),
            "rejected: {valid}"
        );
    }
    for invalid in [
        "http://service.example",
        "file:///tmp/socket",
        "https://user:pass@service.example",
        "https://service.example/path?redirect=evil",
        "https://service.example/path#fragment",
        "not-a-url",
    ] {
        assert!(
            validate_runtime_upstream(invalid).is_err(),
            "accepted: {invalid}"
        );
    }
}

#[test]
fn env_migration_rewrites_only_compiled_connector_variables() {
    let raw = "# comment\nOPENAI_API_KEY=sk-real-123\nexport OTHER=\"stays\"\nPORT=8080\n";
    let parsed = secret::parse_env_file(raw);
    assert_eq!(
        parsed
            .iter()
            .find(|(key, _)| key == "OPENAI_API_KEY")
            .unwrap()
            .1,
        "sk-real-123"
    );

    let rewritten = secret::rewrite_env_file(
        raw,
        &[("OPENAI_API_KEY".into(), "sk-mtl-placeholder".into())],
    );
    assert!(!rewritten.contains("sk-real-123"));
    assert!(rewritten.contains("OPENAI_API_KEY=sk-mtl-placeholder"));
    assert!(rewritten.contains("export OTHER=\"stays\""));
    assert!(rewritten.ends_with('\n'));
}

#[cfg(not(target_os = "windows"))]
#[test]
fn atomic_migration_creates_no_plaintext_backup() {
    let directory = std::env::temp_dir().join(format!(
        "mithril-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("secrets.env");
    std::fs::write(&path, "OPENAI_API_KEY=real\n").unwrap();
    secret::atomic_rewrite(&path, "OPENAI_API_KEY=placeholder\n").unwrap();

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "OPENAI_API_KEY=placeholder\n"
    );
    assert!(!directory.join("secrets.env.bak").exists());
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("mtl-tmp")));

    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
