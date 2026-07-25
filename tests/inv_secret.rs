use capshell::config::Config;
use capshell::{child_command, prepare, secret};

const KEY: &str = "sk-CANARY-CHIAVE-VERA-0123456789";

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
        .env_overrides(41234)
}

fn value(vars: &[(String, String)], name: &str) -> String {
    vars.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

#[test]
fn l_agente_riceve_un_mock_non_il_valore_reale() {
    let vars = overrides();

    let openai = value(&vars, "OPENAI_API_KEY");
    assert_ne!(openai, KEY);
    assert!(
        openai.starts_with("sk-"),
        "il mock deve avere il formato del provider: {openai}"
    );
    assert!(value(&vars, "ANTHROPIC_API_KEY").starts_with("sk-ant-"));
    assert!(vars.iter().all(|(_, v)| v != KEY));
}

#[test]
fn i_base_url_puntano_al_proxy_con_tutti_gli_alias() {
    let vars = overrides();

    for var in ["OPENAI_BASE_URL", "OPENAI_API_BASE"] {
        assert_eq!(value(&vars, var), "http://127.0.0.1:41234/openai", "{var}");
    }
    for var in ["ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"] {
        assert_eq!(
            value(&vars, var),
            "http://127.0.0.1:41234/anthropic",
            "{var}"
        );
    }
}

#[test]
fn due_segreti_sullo_stesso_connector_falliscono() {
    let cfg = Config::parse(
        "secrets:\n  - name: A\n    connector: openai\n  - name: B\n    connector: openai\n",
    )
    .unwrap();
    assert!(prepare(&cfg, |_| Ok(KEY.to_string())).is_err());
}

#[test]
fn il_processo_figlio_non_vede_il_canary() {
    // Il caso peggiore: la chiave vera e' gia' esportata nel processo padre.
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
        "il canary e' finito nell'environment del figlio"
    );
    assert!(env.contains("OPENAI_API_KEY=sk-"), "il mock deve esserci");
    assert!(
        !env.contains("DBUS_SESSION_BUS_ADDRESS"),
        "il canale verso il portachiavi va tolto"
    );
}

#[test]
fn il_env_file_viene_riscritto_con_i_placeholder() {
    let raw = "# commento\nOPENAI_API_KEY=sk-vera-123\nexport OTHER=\"resta\"\nPORT=8080\n";
    let parsed = secret::parse_env_file(raw);

    assert_eq!(
        parsed
            .iter()
            .find(|(k, _)| k == "OPENAI_API_KEY")
            .unwrap()
            .1,
        "sk-vera-123"
    );
    assert_eq!(
        parsed.iter().find(|(k, _)| k == "OTHER").unwrap().1,
        "resta"
    );

    let out = secret::rewrite_env_file(
        raw,
        &[("OPENAI_API_KEY".to_string(), "sk-capshellMOCK".to_string())],
    );
    assert!(!out.contains("sk-vera-123"));
    assert!(out.contains("OPENAI_API_KEY=sk-capshellMOCK"));
    assert!(
        out.contains("export OTHER=\"resta\""),
        "il resto del file non si tocca"
    );
    assert!(out.contains("# commento"));
}
