use capshell::config::Config;
use capshell::{child_command, prepare, secret};

const KEY: &str = "sk-CANARY-REAL-KEY-0123456789";

const YAML: &str = r#"
secrets:
  - name: OPENAI_API_KEY
    connector: openai
  - name: ANTHROPIC_API_KEY
    connector: anthropic
"#;

fn overrides() -> Vec<(String, String)> {
    let cfg = Config::parse(YAML).unwrap();
    prepare(&cfg, |_| Ok(KEY.to_string()))
        .unwrap()
        .env_overrides(41234, "TESTTOKEN")
}

fn value(vars: &[(String, String)], name: &str) -> String {
    vars.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

#[test]
fn the_agent_receives_a_mock_not_the_real_value() {
    let vars = overrides();

    let openai = value(&vars, "OPENAI_API_KEY");
    assert_ne!(openai, KEY);
    assert!(
        openai.starts_with("sk-"),
        "the mock must match the provider's shape: {openai}"
    );
    assert!(value(&vars, "ANTHROPIC_API_KEY").starts_with("sk-ant-"));
    assert!(vars.iter().all(|(_, v)| v != KEY));
}

#[test]
fn base_urls_point_at_the_proxy_under_every_alias() {
    let vars = overrides();

    for var in ["OPENAI_BASE_URL", "OPENAI_API_BASE"] {
        assert_eq!(
            value(&vars, var),
            "http://127.0.0.1:41234/TESTTOKEN/openai",
            "{var}"
        );
    }
    for var in ["ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"] {
        assert_eq!(
            value(&vars, var),
            "http://127.0.0.1:41234/TESTTOKEN/anthropic",
            "{var}"
        );
    }
}

#[test]
fn two_secrets_on_the_same_connector_fail() {
    let cfg = Config::parse(
        "secrets:\n  - name: A\n    connector: openai\n  - name: B\n    connector: openai\n",
    )
    .unwrap();
    assert!(prepare(&cfg, |_| Ok(KEY.to_string())).is_err());
}

#[test]
fn the_child_process_never_sees_the_canary() {
    // Worst case: the real key is already exported in the parent process.
    std::env::set_var("OPENAI_API_KEY", KEY);
    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus");

    let out = child_command("/bin/sh", &["-c".into(), "env".into()], &overrides())
        .output()
        .expect("sh");
    let env = String::from_utf8_lossy(&out.stdout);

    std::env::remove_var("OPENAI_API_KEY");
    std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");

    assert!(
        !env.contains(KEY),
        "the canary ended up in the child's environment"
    );
    assert!(env.contains("OPENAI_API_KEY=sk-"), "the mock must be there");
    assert!(
        !env.contains("DBUS_SESSION_BUS_ADDRESS"),
        "the channel to the keyring must be stripped"
    );
}

#[test]
fn the_env_file_gets_rewritten_with_placeholders() {
    let raw = "# comment\nOPENAI_API_KEY=sk-real-123\nexport OTHER=\"stays\"\nPORT=8080\n";
    let parsed = secret::parse_env_file(raw);

    assert_eq!(
        parsed
            .iter()
            .find(|(k, _)| k == "OPENAI_API_KEY")
            .unwrap()
            .1,
        "sk-real-123"
    );
    assert_eq!(
        parsed.iter().find(|(k, _)| k == "OTHER").unwrap().1,
        "stays"
    );

    let out = secret::rewrite_env_file(
        raw,
        &[("OPENAI_API_KEY".to_string(), "sk-capshellMOCK".to_string())],
    );
    assert!(!out.contains("sk-real-123"));
    assert!(out.contains("OPENAI_API_KEY=sk-capshellMOCK"));
    assert!(
        out.contains("export OTHER=\"stays\""),
        "the rest of the file is left untouched"
    );
    assert!(out.contains("# comment"));
}
