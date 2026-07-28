use crate::config::validate_upstream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

mod repository;

#[cfg(target_os = "macos")]
mod macos;

pub use repository::{
    Action, AuthorizationError, ProjectRepository, ProjectService, ProjectServiceError, Revision,
    SessionAuthorizer, StoreError, StoredProject,
};

#[cfg(target_os = "macos")]
pub use macos::{open_project_service, MacProjectService};

const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    InvalidIdentifier,
    InvalidEnvironment,
    InvalidBaseUrl,
    InvalidBearer,
    UnsupportedVersion,
    EmptyRoutes,
    DuplicateRoute,
    DuplicateEnvironment,
    MalformedPayload,
    Serialization,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "name must be a 1-64 character identifier",
            Self::InvalidEnvironment => "invalid or reserved environment variable name",
            Self::InvalidBaseUrl => "base URL must be canonical HTTPS without control characters",
            Self::InvalidBearer => "API key is not a valid Bearer value",
            Self::UnsupportedVersion => "unsupported project format version",
            Self::EmptyRoutes => "a project must contain at least one route",
            Self::DuplicateRoute => "duplicate route name",
            Self::DuplicateEnvironment => "duplicate environment variable name",
            Self::MalformedPayload => "malformed Keychain project payload",
            Self::Serialization => "serializing project failed",
        })
    }
}

impl std::error::Error for ModelError {}

/// A validated, versioned collection of destination-bound credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    version: u32,
    name: String,
    routes: Vec<ProjectRoute>,
}

/// A validated route containing a real secret; `Debug` always redacts the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoute {
    name: String,
    base_url: String,
    api_key: String,
    api_key_env: String,
    base_url_env: String,
}

pub fn validate_identifier(value: &str, _kind: &str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'-'))
    {
        return Err(ModelError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<(), ModelError> {
    let mut bytes = value.bytes();
    if value.len() > 128
        || bytes
            .next()
            .is_none_or(|byte| !(byte.is_ascii_alphabetic() || byte == b'_'))
        || bytes.any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        || value == "PATH"
        || value == "DBUS_SESSION_BUS_ADDRESS"
        || value.starts_with("TWL_")
        || value.starts_with("DYLD_")
        || matches!(value, "LD_PRELOAD" | "LD_LIBRARY_PATH")
    {
        return Err(ModelError::InvalidEnvironment);
    }
    Ok(())
}

fn canonical_base_url(value: &str) -> Result<String, ModelError> {
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(ModelError::InvalidBaseUrl);
    }
    let canonical = validate_upstream(value).map_err(|_| ModelError::InvalidBaseUrl)?;
    if url::Url::parse(&canonical).is_ok_and(|parsed| parsed.scheme() == "https") {
        Ok(canonical)
    } else {
        Err(ModelError::InvalidBaseUrl)
    }
}

impl fmt::Debug for Project {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Project")
            .field("version", &self.version)
            .field("name", &self.name)
            .field("routes", &self.routes)
            .finish()
    }
}

impl fmt::Debug for ProjectRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectRoute")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("api_key_env", &self.api_key_env)
            .field("base_url_env", &self.base_url_env)
            .finish()
    }
}

impl Project {
    pub fn new(name: String, routes: Vec<ProjectRoute>) -> Result<Self, ModelError> {
        let project = Self {
            version: FORMAT_VERSION,
            name,
            routes,
        };
        project.validate()?;
        Ok(project)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn routes(&self) -> &[ProjectRoute] {
        &self.routes
    }

    pub fn into_routes(self) -> Vec<ProjectRoute> {
        self.routes
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version != FORMAT_VERSION {
            return Err(ModelError::UnsupportedVersion);
        }
        validate_identifier(&self.name, "project name")?;
        if self.routes.is_empty() {
            return Err(ModelError::EmptyRoutes);
        }
        let mut route_names = HashSet::new();
        let mut env_names = HashSet::new();
        for route in &self.routes {
            route.validate()?;
            if !route_names.insert(route.name()) {
                return Err(ModelError::DuplicateRoute);
            }
            for name in [route.api_key_env(), route.base_url_env()] {
                if !env_names.insert(name) {
                    return Err(ModelError::DuplicateEnvironment);
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        serde_yaml_ng::to_string(self)
            .map(String::into_bytes)
            .map_err(|_| ModelError::Serialization)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        let decoded = std::str::from_utf8(bytes)
            .ok()
            .and_then(|raw| serde_yaml_ng::from_str::<Self>(raw).ok())
            .filter(|project| project.validate().is_ok());
        decoded.ok_or(ModelError::MalformedPayload)
    }

    pub fn description(&self) -> String {
        let mut output = format!("Project: {}\nRoutes: {}\n", self.name, self.routes.len());
        for route in &self.routes {
            output.push_str(&format!(
                "  {}\n    Base URL: {}\n    API-key environment: {}\n    Base-URL environment: {}\n",
                route.name, route.base_url, route.api_key_env, route.base_url_env
            ));
        }
        output
    }
}

impl ProjectRoute {
    pub fn new(
        name: String,
        base_url: String,
        api_key: String,
        api_key_env: String,
        base_url_env: String,
    ) -> Result<Self, ModelError> {
        let route = Self {
            name,
            base_url: canonical_base_url(&base_url)?,
            api_key,
            api_key_env,
            base_url_env,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    pub fn api_key_env(&self) -> &str {
        &self.api_key_env
    }
    pub fn base_url_env(&self) -> &str {
        &self.base_url_env
    }

    pub fn into_parts(self) -> (String, String, String, String, String) {
        (
            self.name,
            self.base_url,
            self.api_key,
            self.api_key_env,
            self.base_url_env,
        )
    }

    fn validate(&self) -> Result<(), ModelError> {
        validate_identifier(&self.name, "route name")?;
        if canonical_base_url(&self.base_url)? != self.base_url {
            return Err(ModelError::InvalidBaseUrl);
        }
        let unpadded = self.api_key.trim_end_matches('=');
        if unpadded.is_empty()
            || !unpadded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        {
            return Err(ModelError::InvalidBearer);
        }
        validate_env_name(&self.api_key_env)?;
        validate_env_name(&self.base_url_env)?;
        if self.api_key_env == self.base_url_env {
            return Err(ModelError::DuplicateEnvironment);
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
pub struct UnsupportedAuthorizer;
#[cfg(not(target_os = "macos"))]
impl SessionAuthorizer for UnsupportedAuthorizer {
    fn authorize(&self, _action: Action<'_>) -> Result<(), AuthorizationError> {
        unreachable!()
    }
}
#[cfg(not(target_os = "macos"))]
pub struct UnsupportedRepository;
#[cfg(not(target_os = "macos"))]
impl ProjectRepository for UnsupportedRepository {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    fn get(&self, _name: &str) -> Result<StoredProject, StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    fn create(&self, _project: &Project) -> Result<(), StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    fn replace(&self, _expected: &Revision, _project: &Project) -> Result<(), StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
    fn delete(&self, _name: &str) -> Result<(), StoreError> {
        Err(StoreError::UnsupportedPlatform)
    }
}
#[cfg(not(target_os = "macos"))]
pub type MacProjectService = ProjectService<UnsupportedAuthorizer, UnsupportedRepository>;
#[cfg(not(target_os = "macos"))]
pub fn open_project_service() -> Result<MacProjectService, StoreError> {
    Err(StoreError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, key_env: &str, url_env: &str) -> ProjectRoute {
        ProjectRoute::new(
            name.into(),
            "https://api.example.test/v1".into(),
            format!("secret-{name}"),
            key_env.into(),
            url_env.into(),
        )
        .unwrap()
    }

    #[test]
    fn versioned_project_round_trips_with_multiple_routes() {
        let project = Project::new(
            "my-app".into(),
            vec![
                route("billing", "BILLING_KEY", "BILLING_URL"),
                route("search", "SEARCH_KEY", "SEARCH_URL"),
            ],
        )
        .unwrap();
        assert_eq!(
            Project::decode(&project.encode().unwrap()).unwrap(),
            project
        );
    }

    #[test]
    fn names_are_identifiers_not_paths() {
        for invalid in ["", ".", "../app", "/tmp/app", "two words", "_hidden"] {
            assert!(validate_identifier(invalid, "project name").is_err());
        }
        for valid in ["app", "my-app", "app2", "2-app"] {
            assert!(validate_identifier(valid, "project name").is_ok());
        }
    }

    #[test]
    fn duplicate_routes_and_environment_names_are_rejected() {
        assert_eq!(
            Project::new(
                "app".into(),
                vec![
                    route("api", "ONE_KEY", "ONE_URL"),
                    route("api", "TWO_KEY", "TWO_URL")
                ]
            )
            .unwrap_err(),
            ModelError::DuplicateRoute
        );
        assert_eq!(
            Project::new(
                "app".into(),
                vec![
                    route("one", "SHARED", "ONE_URL"),
                    route("two", "TWO_KEY", "SHARED")
                ]
            )
            .unwrap_err(),
            ModelError::DuplicateEnvironment
        );
    }

    #[test]
    fn unsafe_urls_and_keys_are_rejected_without_echoing_keys() {
        for url in ["http://not-loopback.example", "http://127.0.0.1:8080"] {
            assert!(ProjectRoute::new(
                "api".into(),
                url.into(),
                "key".into(),
                "API_KEY".into(),
                "API_URL".into()
            )
            .is_err());
        }
        for invalid in ["   ", "café", "has space", "token:colon", "key\tvalue"] {
            let error = ProjectRoute::new(
                "api".into(),
                "https://example.test".into(),
                invalid.into(),
                "API_KEY".into(),
                "API_URL".into(),
            )
            .unwrap_err();
            assert!(!error.to_string().contains(invalid));
        }
    }

    #[test]
    fn destinations_are_canonicalized_once_and_controls_are_rejected() {
        let route = ProjectRoute::new(
            "api".into(),
            "HTTPS://EXAMPLE.TEST:443/safe/%2e%2e/admin".into(),
            "key".into(),
            "API_KEY".into(),
            "API_URL".into(),
        )
        .unwrap();
        assert_eq!(route.base_url(), "https://example.test/admin");
        let unicode = ProjectRoute::new(
            "api".into(),
            "https://éxample.test/路径".into(),
            "key".into(),
            "API_KEY".into(),
            "API_URL".into(),
        )
        .unwrap();
        assert!(
            unicode.base_url().contains("xn--")
                && unicode.base_url().contains("%E8%B7%AF%E5%BE%84")
        );
        for control in ['\n', '\t', '\u{1b}'] {
            assert!(ProjectRoute::new(
                "api".into(),
                format!("https://example.test/{control}hidden"),
                "key".into(),
                "API_KEY".into(),
                "API_URL".into()
            )
            .is_err());
        }
        let noncanonical = b"version: 1\nname: app\nroutes:\n- name: api\n  base_url: HTTPS://EXAMPLE.TEST:443/path\n  api_key: valid-key\n  api_key_env: API_KEY\n  base_url_env: API_URL\n";
        assert_eq!(
            Project::decode(noncanonical),
            Err(ModelError::MalformedPayload)
        );
    }

    #[test]
    fn malformed_records_and_debug_are_secret_safe() {
        for payload in [
            b"not: [valid".as_slice(),
            b"version: 99\nname: app\nroutes: []\n".as_slice(),
            b"version: 1\nname: ../app\nroutes: []\n".as_slice(),
        ] {
            assert_eq!(Project::decode(payload), Err(ModelError::MalformedPayload));
        }
        let project = Project::new("app".into(), vec![route("api", "API_KEY", "API_URL")]).unwrap();
        assert!(!project.description().contains("secret-api"));
        assert!(!format!("{project:?}").contains("secret-api"));
    }

    #[test]
    fn execution_sensitive_environment_names_are_rejected() {
        for name in [
            "PATH",
            "TWL_APPLICATION_API_KEY",
            "DBUS_SESSION_BUS_ADDRESS",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ] {
            assert_eq!(
                ProjectRoute::new(
                    "api".into(),
                    "https://example.test".into(),
                    "key".into(),
                    name.into(),
                    "API_URL".into(),
                ),
                Err(ModelError::InvalidEnvironment)
            );
        }
    }
}
