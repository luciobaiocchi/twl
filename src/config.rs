use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub connectors: Vec<String>,
    #[serde(default)]
    pub budget: Option<Budget>,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub max_requests: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Auth {
    Bearer,
    XApiKey,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AllowedRoute {
    pub method: &'static str,
    pub path: &'static str,
}

pub struct Connector {
    pub id: &'static str,
    pub secret_env: &'static str,
    pub upstream: &'static str,
    pub auth: Auth,
    pub mock_prefix: &'static str,
    pub base_url_vars: &'static [&'static str],
    /// OpenAI clients append `responses` to a base URL that already ends in
    /// `/v1`; other clients have different conventions.
    pub client_base_suffix: &'static str,
    pub allowed: &'static [AllowedRoute],
}

const OPENAI_ROUTES: &[AllowedRoute] = &[
    AllowedRoute {
        method: "GET",
        path: "/v1/models",
    },
    AllowedRoute {
        method: "POST",
        path: "/v1/responses",
    },
    AllowedRoute {
        method: "POST",
        path: "/v1/chat/completions",
    },
    AllowedRoute {
        method: "POST",
        path: "/v1/embeddings",
    },
];

const ANTHROPIC_ROUTES: &[AllowedRoute] = &[
    AllowedRoute {
        method: "GET",
        path: "/v1/models",
    },
    AllowedRoute {
        method: "POST",
        path: "/v1/messages",
    },
];

pub static CONNECTORS: &[Connector] = &[
    Connector {
        id: "openai",
        secret_env: "OPENAI_API_KEY",
        upstream: "https://api.openai.com",
        auth: Auth::Bearer,
        mock_prefix: "sk-",
        base_url_vars: &["OPENAI_BASE_URL", "OPENAI_API_BASE"],
        client_base_suffix: "/v1",
        allowed: OPENAI_ROUTES,
    },
    Connector {
        id: "anthropic",
        secret_env: "ANTHROPIC_API_KEY",
        upstream: "https://api.anthropic.com",
        auth: Auth::XApiKey,
        mock_prefix: "sk-ant-",
        base_url_vars: &["ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"],
        client_base_suffix: "",
        allowed: ANTHROPIC_ROUTES,
    },
];

pub fn connector(name: &str) -> Option<&'static Connector> {
    CONNECTORS.iter().find(|connector| connector.id == name)
}

impl Config {
    pub fn parse(raw: &str) -> Result<Config, String> {
        let cfg: Config = serde_yaml::from_str(raw).map_err(|e| e.to_string())?;
        if cfg.connectors.is_empty() {
            return Err("at least one connector is required".into());
        }
        let mut seen = std::collections::HashSet::new();
        for name in &cfg.connectors {
            if connector(name).is_none() {
                return Err(format!("unknown connector: {name}"));
            }
            if !seen.insert(name) {
                return Err(format!("duplicate connector: {name}"));
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Config::parse(&raw).map_err(|e| format!("{path}: {e}"))
    }
}
