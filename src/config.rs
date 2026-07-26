use serde::Deserialize;

pub const CHILD_SECRET_ENV: &str = "APP_API_KEY";
pub const CHILD_BASE_URL_ENV: &str = "APP_BASE_URL";
pub const PARENT_SECRET_ENV: &str = "TWL_APPLICATION_API_KEY";
pub const PARENT_UPSTREAM_ENV: &str = "TWL_APPLICATION_UPSTREAM";
pub const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub budget: Option<Budget>,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub max_requests: u64,
}

pub fn validate_upstream(value: &str) -> Result<String, String> {
    let parsed =
        url::Url::parse(value).map_err(|_| "upstream must be an absolute URL".to_string())?;
    if parsed.cannot_be_a_base() || parsed.host().is_none() {
        return Err("upstream must include a host".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("upstream must not contain user information".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("upstream must not contain a query or fragment".into());
    }

    let loopback = match parsed.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err("upstream must use HTTPS (HTTP is allowed only on loopback)".into());
    }

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

impl Config {
    pub fn parse(raw: &str) -> Result<Self, String> {
        serde_yaml_ng::from_str(raw).map_err(|error| error.to_string())
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        Self::parse(&raw).map_err(|error| format!("{path}: {error}"))
    }
}
