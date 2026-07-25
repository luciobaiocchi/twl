use mithril::config::{connector, Config};
use mithril::{child_command, prepare, secret};

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
fn child_command_removes_all_ambient_supported_credentials() {
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
    assert!(configured
        .iter()
        .any(|(key, value)| key == "ANTHROPIC_API_KEY" && value.is_none()));
    assert!(configured
        .iter()
        .any(|(key, value)| key == "DBUS_SESSION_BUS_ADDRESS" && value.is_none()));
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
    assert_eq!(openai.upstream, "https://api.openai.com");
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
