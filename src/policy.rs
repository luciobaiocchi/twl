use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use zeroize::Zeroize;

pub const VAULT_PAYLOAD_VERSION: u32 = 1;
pub const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
pub const ABSOLUTE_MAX_BODY_BYTES: u64 = 16 << 20;
pub const ABSOLUTE_MAX_ROUTE_CONCURRENCY: u16 = 16;
pub const ABSOLUTE_MAX_SESSION_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_ROUTES_PER_SESSION: usize = 64;

/// A credential value whose Debug output and destructor do not expose or retain
/// the plaintext longer than necessary.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: String) -> Result<Self, String> {
        validate_secret(&value)?;
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(<redacted>)")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginPolicy {
    pub scheme: String,
    pub hostname: String,
    pub port: u16,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticationLocation {
    Header,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticationFormat {
    Bearer,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationPolicy {
    pub location: AuthenticationLocation,
    pub name: String,
    pub format: AuthenticationFormat,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicy {
    pub origin: OriginPolicy,
    pub credential: String,
    pub authentication: AuthenticationPolicy,
    pub allowed_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefixes: Option<Vec<String>>,
    pub request_count_budget: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_concurrent_requests: u16,
    pub session_expiry_seconds: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultPayload {
    pub version: u32,
    pub credentials: BTreeMap<String, SecretValue>,
    pub routes: BTreeMap<String, RoutePolicy>,
}

impl fmt::Debug for VaultPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPayload")
            .field("version", &self.version)
            .field(
                "credential_ids",
                &self.credentials.keys().collect::<Vec<_>>(),
            )
            .field("route_ids", &self.routes.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl VaultPayload {
    pub fn parse_trusted_yaml(raw: &str) -> Result<Self, String> {
        let payload: Self = serde_yaml_ng::from_str(raw)
            .map_err(|error| format!("trusted route document is invalid: {error}"))?;
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != VAULT_PAYLOAD_VERSION {
            return Err(format!(
                "trusted route document version must be {VAULT_PAYLOAD_VERSION}"
            ));
        }
        if self.credentials.is_empty() {
            return Err("trusted route document must contain a credential".into());
        }
        if self.routes.is_empty() {
            return Err("trusted route document must contain a route".into());
        }
        if self.routes.len() > MAX_ROUTES_PER_SESSION {
            return Err(format!(
                "trusted route document exceeds {MAX_ROUTES_PER_SESSION} routes"
            ));
        }

        for (id, credential) in &self.credentials {
            validate_id(id, "credential")?;
            validate_secret(credential.expose())?;
        }
        for (id, route) in &self.routes {
            validate_id(id, "route")?;
            route.validate(id, &self.credentials)?;
        }
        Ok(())
    }
}

impl RoutePolicy {
    pub fn validate(
        &self,
        route_id: &str,
        credentials: &BTreeMap<String, SecretValue>,
    ) -> Result<(), String> {
        validate_id(route_id, "route")?;
        validate_id(&self.credential, "credential reference")?;
        if !credentials.contains_key(&self.credential) {
            return Err(format!("route {route_id} references an unknown credential"));
        }
        self.origin
            .base_url()
            .map_err(|error| format!("route {route_id} has an invalid upstream origin: {error}"))?;

        if !matches!(self.authentication.location, AuthenticationLocation::Header)
            || !matches!(self.authentication.format, AuthenticationFormat::Bearer)
            || !self
                .authentication
                .name
                .eq_ignore_ascii_case("authorization")
        {
            return Err(format!(
                "route {route_id} must inject Bearer authentication into the Authorization header"
            ));
        }

        if self.allowed_methods.is_empty() {
            return Err(format!("route {route_id} must allow at least one method"));
        }
        let mut methods = BTreeSet::new();
        for method in &self.allowed_methods {
            if !ALLOWED_METHODS.contains(&method.as_str()) {
                return Err(format!("route {route_id} contains an unsupported method"));
            }
            if !methods.insert(method) {
                return Err(format!("route {route_id} contains a duplicate method"));
            }
        }

        if let Some(prefixes) = &self.path_prefixes {
            if prefixes.is_empty() {
                return Err(format!(
                    "route {route_id} path_prefixes must be omitted or non-empty"
                ));
            }
            let mut unique = BTreeSet::new();
            for prefix in prefixes {
                validate_path(prefix).map_err(|message| {
                    format!("route {route_id} has an invalid path prefix: {message}")
                })?;
                if !unique.insert(prefix) {
                    return Err(format!("route {route_id} contains a duplicate path prefix"));
                }
            }
        }

        validate_limit(
            route_id,
            "max_request_bytes",
            self.max_request_bytes,
            ABSOLUTE_MAX_BODY_BYTES,
        )?;
        validate_limit(
            route_id,
            "max_response_bytes",
            self.max_response_bytes,
            ABSOLUTE_MAX_BODY_BYTES,
        )?;
        if self.max_concurrent_requests == 0
            || self.max_concurrent_requests > ABSOLUTE_MAX_ROUTE_CONCURRENCY
        {
            return Err(format!(
                "route {route_id} max_concurrent_requests must be between 1 and {ABSOLUTE_MAX_ROUTE_CONCURRENCY}"
            ));
        }
        if self.session_expiry_seconds == 0
            || self.session_expiry_seconds > ABSOLUTE_MAX_SESSION_SECONDS
        {
            return Err(format!(
                "route {route_id} session_expiry_seconds must be between 1 and {ABSOLUTE_MAX_SESSION_SECONDS}"
            ));
        }
        Ok(())
    }

    pub fn allows_path(&self, path: &str) -> bool {
        self.path_prefixes.as_ref().is_none_or(|prefixes| {
            prefixes.iter().any(|prefix| {
                prefix == "/"
                    || path == prefix
                    || (path.starts_with(prefix)
                        && (prefix.ends_with('/')
                            || path.as_bytes().get(prefix.len()) == Some(&b'/')))
            })
        })
    }
}

impl OriginPolicy {
    pub fn base_url(&self) -> Result<String, String> {
        if self.scheme != "https" && self.scheme != "http" {
            return Err("scheme must be HTTPS (or HTTP for loopback tests)".into());
        }
        if self.port == 0 {
            return Err("port must be between 1 and 65535".into());
        }
        if self.hostname.is_empty()
            || self.hostname.contains(['/', '@', '?', '#', '\\'])
            || self
                .hostname
                .bytes()
                .any(|byte| byte <= 0x20 || byte == 0x7f)
        {
            return Err("hostname is invalid".into());
        }

        let bracketed = self.hostname.starts_with('[') && self.hostname.ends_with(']');
        let displayed = if self.hostname.contains(':') && !bracketed {
            format!("[{}]", self.hostname)
        } else {
            self.hostname.clone()
        };
        let candidate = format!("{}://{}:{}/", self.scheme, displayed, self.port);
        let parsed = url::Url::parse(&candidate).map_err(|_| "hostname is invalid".to_string())?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host().is_none()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("origin must contain only scheme, hostname, and port".into());
        }

        let loopback = parsed.host().is_some_and(|host| match host {
            url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(address) => IpAddr::V4(address).is_loopback(),
            url::Host::Ipv6(address) => IpAddr::V6(address).is_loopback(),
        });
        if self.scheme == "http" && !loopback {
            return Err("HTTP is allowed only for loopback tests".into());
        }

        Ok(candidate.trim_end_matches('/').to_string())
    }
}

pub fn validate_id(value: &str, kind: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{kind} IDs must use 1-64 lowercase letters, digits, hyphens, or underscores"
        ))
    }
}

pub fn validate_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("path must be absolute and contain no control characters");
    }
    if path.contains(['\\', '%', '#', '?']) {
        return Err("encoded, query-bearing, or non-normalized paths are not allowed");
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.iter().enumerate().any(|(index, part)| {
        *part == "." || *part == ".." || (part.is_empty() && index != 0 && index + 1 != parts.len())
    }) {
        return Err("dot segments and repeated slashes are not allowed");
    }
    Ok(())
}

fn validate_secret(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("credential values must not be empty".into());
    }
    if value.len() > 64 * 1024 {
        return Err("credential values must not exceed 65536 bytes".into());
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("credential values must not contain control characters".into());
    }
    Ok(())
}

fn validate_limit(route: &str, name: &str, value: u64, maximum: u64) -> Result<(), String> {
    if value == 0 || value > maximum {
        Err(format!(
            "route {route} {name} must be between 1 and {maximum}"
        ))
    } else {
        Ok(())
    }
}
