use crate::grant::GrantRequest;
use crate::policy::{validate_id, MAX_ROUTES_PER_SESSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;

pub const CHILD_SECRET_ENV: &str = "APP_API_KEY";
pub const CHILD_BASE_URL_ENV: &str = "APP_BASE_URL";
pub const BROKER_URL_ENV: &str = "TWL_BROKER_URL";
pub const SESSION_TOKEN_ENV: &str = "TWL_SESSION_TOKEN";
pub const SESSION_FILE_ENV: &str = "TWL_SESSION_FILE";
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Repository-controlled configuration. Every field can only select a route
/// already authorized by the trusted launcher or reduce a trusted limit.
#[derive(Default, Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub limits: SessionLimits,
}

#[derive(Default, Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_request_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_requests: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_expiry_seconds: Option<u64>,
}

impl Config {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let config: Self = serde_yaml_ng::from_str(raw).map_err(|error| error.to_string())?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|error| format!("{path}: {error}"))?;
        let mut raw = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut raw)
            .map_err(|error| format!("{path}: {error}"))?;
        if raw.len() as u64 > MAX_CONFIG_BYTES {
            return Err(format!(
                "{path}: configuration exceeds {MAX_CONFIG_BYTES} bytes"
            ));
        }
        Self::parse(&raw).map_err(|error| format!("{path}: {error}"))
    }

    pub fn grant_request(&self, authorized_routes: &[String]) -> Result<GrantRequest, String> {
        if authorized_routes.is_empty() {
            return Err("at least one trusted --allow-route is required".into());
        }
        if authorized_routes.len() > MAX_ROUTES_PER_SESSION {
            return Err(format!(
                "a session may authorize at most {MAX_ROUTES_PER_SESSION} routes"
            ));
        }

        let mut authorized = BTreeSet::new();
        for route in authorized_routes {
            validate_id(route, "route")?;
            if !authorized.insert(route.clone()) {
                return Err(format!(
                    "trusted route {route} was authorized more than once"
                ));
            }
        }

        let selected = self.routes.as_deref().unwrap_or(authorized_routes).to_vec();
        if selected.is_empty() {
            return Err("repository route selection must not be empty".into());
        }
        let mut unique = BTreeSet::new();
        for route in &selected {
            validate_id(route, "route")?;
            if !unique.insert(route.clone()) {
                return Err(format!(
                    "repository route {route} was selected more than once"
                ));
            }
            if !authorized.contains(route) {
                return Err(format!(
                    "repository route {route} is not in the trusted allow-route set"
                ));
            }
        }

        Ok(GrantRequest {
            route_ids: selected,
            limits: self.limits.clone(),
        })
    }

    fn validate(&self) -> Result<(), String> {
        if let Some(routes) = &self.routes {
            if routes.len() > MAX_ROUTES_PER_SESSION {
                return Err(format!(
                    "configuration may select at most {MAX_ROUTES_PER_SESSION} routes"
                ));
            }
            let mut unique = BTreeSet::new();
            for route in routes {
                validate_id(route, "route")?;
                if !unique.insert(route) {
                    return Err(format!("route {route} is listed more than once"));
                }
            }
        }
        self.limits.validate()
    }
}

impl SessionLimits {
    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
            ("session_expiry_seconds", self.session_expiry_seconds),
        ] {
            if value == Some(0) {
                return Err(format!("{name} must be greater than zero"));
            }
        }
        if self.max_concurrent_requests == Some(0) {
            return Err("max_concurrent_requests must be greater than zero".into());
        }
        Ok(())
    }
}
