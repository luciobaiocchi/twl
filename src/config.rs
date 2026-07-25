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
    /// Sovrascrive l'upstream cablato del connector. Serve per puntare a un
    /// finto provider durante i test: e' dichiarato dall'umano nel file di
    /// config, e resta comunque fuori dalla portata dell'agente.
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
    /// Ogni SDK guarda un nome diverso per il base URL. Se ne manca uno, il
    /// client chiama il provider vero, prende 401, e l'utente da' la colpa a
    /// Capshell. Vanno settati tutti.
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
                return Err(format!("connector sconosciuto: {}", s.connector));
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Config::parse(&raw).map_err(|e| format!("{path}: {e}"))
    }
}
