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
    path: AllowedPath,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum AllowedPath {
    Exact(&'static str),
    Any,
}

impl AllowedRoute {
    pub const fn exact(method: &'static str, path: &'static str) -> Self {
        Self {
            method,
            path: AllowedPath::Exact(path),
        }
    }

    pub const fn any(method: &'static str) -> Self {
        Self {
            method,
            path: AllowedPath::Any,
        }
    }

    pub fn matches_path(self, path: &str) -> bool {
        match self.path {
            AllowedPath::Exact(allowed) => allowed == path,
            AllowedPath::Any => true,
        }
    }

    pub fn allows(self, method: &str, path: &str) -> bool {
        self.method == method && self.matches_path(path)
    }
}

/// Defines where the trusted parent obtains a connector credential and fixes
/// whether its destination is built in or supplied for one session.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CredentialSource {
    Keychain {
        upstream: &'static str,
    },
    Runtime {
        parent_secret_env: &'static str,
        parent_upstream_env: &'static str,
    },
}

pub struct Connector {
    pub id: &'static str,
    pub secret_env: &'static str,
    pub credential_source: CredentialSource,
    pub auth: Auth,
    pub mock_prefix: &'static str,
    pub base_url_vars: &'static [&'static str],
    /// OpenAI clients append `responses` to a base URL that already ends in
    /// `/v1`; other clients have different conventions.
    pub client_base_suffix: &'static str,
    pub allowed: &'static [AllowedRoute],
}

const OPENAI_ROUTES: &[AllowedRoute] = &[
    AllowedRoute::exact("GET", "/v1/models"),
    AllowedRoute::exact("POST", "/v1/responses"),
    AllowedRoute::exact("POST", "/v1/chat/completions"),
    AllowedRoute::exact("POST", "/v1/embeddings"),
];

const ANTHROPIC_ROUTES: &[AllowedRoute] = &[
    AllowedRoute::exact("GET", "/v1/models"),
    AllowedRoute::exact("POST", "/v1/messages"),
];

const APPLICATION_ROUTES: &[AllowedRoute] = &[
    AllowedRoute::any("GET"),
    AllowedRoute::any("POST"),
    AllowedRoute::any("PUT"),
    AllowedRoute::any("PATCH"),
    AllowedRoute::any("DELETE"),
];

pub static CONNECTORS: &[Connector] = &[
    Connector {
        id: "openai",
        secret_env: "OPENAI_API_KEY",
        credential_source: CredentialSource::Keychain {
            upstream: "https://api.openai.com",
        },
        auth: Auth::Bearer,
        mock_prefix: "sk-",
        base_url_vars: &["OPENAI_BASE_URL", "OPENAI_API_BASE"],
        client_base_suffix: "/v1",
        allowed: OPENAI_ROUTES,
    },
    Connector {
        id: "anthropic",
        secret_env: "ANTHROPIC_API_KEY",
        credential_source: CredentialSource::Keychain {
            upstream: "https://api.anthropic.com",
        },
        auth: Auth::XApiKey,
        mock_prefix: "sk-ant-",
        base_url_vars: &["ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL"],
        client_base_suffix: "",
        allowed: ANTHROPIC_ROUTES,
    },
    Connector {
        id: "application",
        secret_env: "APP_API_KEY",
        credential_source: CredentialSource::Runtime {
            parent_secret_env: "MTL_APPLICATION_API_KEY",
            parent_upstream_env: "MTL_APPLICATION_UPSTREAM",
        },
        auth: Auth::Bearer,
        mock_prefix: "mtl-app-",
        base_url_vars: &["APP_BASE_URL"],
        client_base_suffix: "",
        allowed: APPLICATION_ROUTES,
    },
];

pub fn connector(name: &str) -> Option<&'static Connector> {
    CONNECTORS.iter().find(|connector| connector.id == name)
}

pub fn validate_runtime_upstream(value: &str) -> Result<String, String> {
    let parsed = url::Url::parse(value)
        .map_err(|_| "runtime upstream must be an absolute URL".to_string())?;
    if parsed.cannot_be_a_base() || parsed.host().is_none() {
        return Err("runtime upstream must include a host".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("runtime upstream must not contain user information".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("runtime upstream must not contain a query or fragment".into());
    }

    let loopback = match parsed.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err("runtime upstream must use HTTPS (HTTP is allowed only on loopback)".into());
    }

    Ok(parsed.as_str().trim_end_matches('/').to_string())
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
