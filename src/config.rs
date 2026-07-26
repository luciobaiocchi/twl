use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub secrets: Vec<SecretDecl>,
    #[serde(default)]
    pub budget: Option<Budget>,
}

#[derive(Deserialize, Debug)]
pub struct SecretDecl {
    pub name: String,
    pub connector: String,
    /// Overrides the connector's hardwired upstream. Used to point at a fake
    /// provider during tests: it's declared by the human in the config file,
    /// and stays out of the agent's reach either way.
    #[serde(default)]
    pub upstream: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Copy)]
pub struct Budget {
    pub max_requests: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Auth {
    Bearer,
    XApiKey,
}

pub struct Connector {
    pub upstream: &'static str,
    pub auth: Auth,
    pub mock_prefix: &'static str,
    /// Every SDK looks at a different name for the base URL. Miss one and the
    /// client calls the real provider, gets a 401, and the user blames
    /// Capshell. All of them need to be set.
    pub base_url_vars: &'static [&'static str],
}

pub fn connector(name: &str) -> Option<Connector> {
    Some(match name {
        "openai" => Connector {
            upstream: "https://api.openai.com",
            auth: Auth::Bearer,
            mock_prefix: "sk-",
            base_url_vars: &["OPENAI_BASE_URL", "OPENAI_API_BASE"],
        },
        "anthropic" => Connector {
            upstream: "https://api.anthropic.com",
            auth: Auth::XApiKey,
            mock_prefix: "sk-ant-",
            base_url_vars: &["ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"],
        },
        _ => return None,
    })
}

impl Config {
    pub fn parse(raw: &str) -> Result<Config, String> {
        let cfg: Config = serde_yaml::from_str(raw).map_err(|e| e.to_string())?;
        for s in &cfg.secrets {
            if connector(&s.connector).is_none() {
                return Err(format!("unknown connector: {}", s.connector));
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Config::parse(&raw).map_err(|e| format!("{path}: {e}"))
    }
}
