use crate::config::validate_upstream;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod repository;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

pub use repository::{
    Action, AuthorizationError, ProjectRepository, ProjectService, ProjectServiceError, Revision,
    SessionAuthorizer, StoreError, StoredProject,
};

#[cfg(target_os = "macos")]
pub use macos::{open_project_service, MacProjectService};

#[cfg(target_os = "macos")]
pub type PlatformProjectService = MacProjectService;

#[cfg(target_os = "linux")]
pub use linux::{
    linux_project_child_command, open_project_service, LinuxAgeVaultRepository, LinuxProjectService,
};

#[cfg(target_os = "linux")]
pub type PlatformProjectService = LinuxProjectService;

const LEGACY_FORMAT_VERSION: u32 = 1;
const FORMAT_VERSION: u32 = 2;
pub const DEFAULT_CAPABILITY_RESPONSE_BYTES: u64 = 1 << 20;
pub const MAX_CAPABILITY_RESPONSE_BYTES: u64 = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    InvalidIdentifier,
    InvalidEnvironment,
    InvalidBaseUrl,
    InvalidBearer,
    InvalidDescription,
    EmptyMethods,
    InvalidMethod,
    EmptyPathPrefixes,
    InvalidPathPrefix,
    InvalidResponseLimit,
    UnsupportedVersion,
    EmptyRoutes,
    DuplicateRoute,
    DuplicateEnvironment,
    DuplicateCapability,
    MissingCapabilityRoute,
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
            Self::InvalidDescription => {
                "description must be at most 512 characters without control characters"
            }
            Self::EmptyMethods => "capability must allow at least one HTTP method",
            Self::InvalidMethod => "unsupported HTTP method",
            Self::EmptyPathPrefixes => "capability must allow at least one path prefix",
            Self::InvalidPathPrefix => "capability path prefix is not normalized origin-form",
            Self::InvalidResponseLimit => {
                "capability response limit is outside the supported range"
            }
            Self::UnsupportedVersion => "unsupported project format version",
            Self::EmptyRoutes => "a project must contain at least one route",
            Self::DuplicateRoute => "duplicate route name",
            Self::DuplicateEnvironment => "duplicate environment variable name",
            Self::DuplicateCapability => "duplicate capability name",
            Self::MissingCapabilityRoute => "capability references an unknown route",
            Self::MalformedPayload => "malformed stored project payload",
            Self::Serialization => "serializing project failed",
        })
    }
}

impl std::error::Error for ModelError {}

/// A validated, versioned collection of destination-bound credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Project {
    #[zeroize(skip)]
    version: u32,
    #[zeroize(skip)]
    name: String,
    routes: Vec<ProjectRoute>,
    #[zeroize(skip)]
    #[serde(default)]
    capabilities: Vec<AgentCapability>,
}

/// A validated route containing a real secret; `Debug` always redacts the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoute {
    #[zeroize(skip)]
    name: String,
    #[zeroize(skip)]
    base_url: String,
    api_key: String,
    #[zeroize(skip)]
    application: Option<ApplicationBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationBinding {
    #[zeroize(skip)]
    api_key_env: String,
    #[zeroize(skip)]
    base_url_env: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicy {
    methods: BTreeSet<HttpMethod>,
    path_prefixes: Vec<String>,
    max_response_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapability {
    name: String,
    description: String,
    route: String,
    #[serde(flatten)]
    policy: HttpPolicy,
}

pub fn validate_identifier(value: &str) -> Result<(), ModelError> {
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
            .field("capabilities", &self.capabilities)
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
            .field("application", &self.application)
            .finish()
    }
}

impl HttpMethod {
    pub const ALL: [Self; 5] = [Self::GET, Self::POST, Self::PUT, Self::PATCH, Self::DELETE];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::PATCH => "PATCH",
            Self::DELETE => "DELETE",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HttpMethod {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::GET),
            "POST" => Ok(Self::POST),
            "PUT" => Ok(Self::PUT),
            "PATCH" => Ok(Self::PATCH),
            "DELETE" => Ok(Self::DELETE),
            _ => Err(ModelError::InvalidMethod),
        }
    }
}

impl HttpPolicy {
    pub fn new(
        methods: impl IntoIterator<Item = HttpMethod>,
        path_prefixes: Vec<String>,
        max_response_bytes: u64,
    ) -> Result<Self, ModelError> {
        let policy = Self {
            methods: methods.into_iter().collect(),
            path_prefixes,
            max_response_bytes,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn methods(&self) -> &BTreeSet<HttpMethod> {
        &self.methods
    }

    pub fn path_prefixes(&self) -> &[String] {
        &self.path_prefixes
    }

    pub fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    pub fn allows_method(&self, method: HttpMethod) -> bool {
        self.methods.contains(&method)
    }

    pub fn allows_path(&self, path: &str) -> bool {
        self.path_prefixes.iter().any(|prefix| {
            if prefix.ends_with('/') {
                path.starts_with(prefix)
            } else {
                path == prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|remainder| remainder.starts_with('/'))
            }
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.methods.is_empty() {
            return Err(ModelError::EmptyMethods);
        }
        if self.path_prefixes.is_empty() {
            return Err(ModelError::EmptyPathPrefixes);
        }
        if self
            .path_prefixes
            .iter()
            .any(|prefix| !crate::http::origin_path_is_normalized(prefix))
        {
            return Err(ModelError::InvalidPathPrefix);
        }
        if !(1..=MAX_CAPABILITY_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err(ModelError::InvalidResponseLimit);
        }
        Ok(())
    }
}

impl AgentCapability {
    pub fn new(
        name: String,
        description: String,
        route: String,
        methods: impl IntoIterator<Item = HttpMethod>,
        path_prefixes: Vec<String>,
        max_response_bytes: u64,
    ) -> Result<Self, ModelError> {
        Self::with_policy(
            name,
            description,
            route,
            HttpPolicy::new(methods, path_prefixes, max_response_bytes)?,
        )
    }

    pub fn with_policy(
        name: String,
        description: String,
        route: String,
        policy: HttpPolicy,
    ) -> Result<Self, ModelError> {
        let capability = Self {
            name,
            description,
            route,
            policy,
        };
        capability.validate()?;
        Ok(capability)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn route(&self) -> &str {
        &self.route
    }

    pub fn policy(&self) -> &HttpPolicy {
        &self.policy
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_identifier(&self.name)?;
        validate_identifier(&self.route)?;
        if self.description.len() > 512
            || self
                .description
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ModelError::InvalidDescription);
        }
        self.policy.validate()
    }
}

impl ApplicationBinding {
    pub fn new(api_key_env: String, base_url_env: String) -> Result<Self, ModelError> {
        let binding = Self {
            api_key_env,
            base_url_env,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn api_key_env(&self) -> &str {
        &self.api_key_env
    }

    pub fn base_url_env(&self) -> &str {
        &self.base_url_env
    }

    pub fn into_parts(mut self) -> (String, String) {
        (
            std::mem::take(&mut self.api_key_env),
            std::mem::take(&mut self.base_url_env),
        )
    }

    fn validate(&self) -> Result<(), ModelError> {
        validate_env_name(&self.api_key_env)?;
        validate_env_name(&self.base_url_env)?;
        if self.api_key_env == self.base_url_env {
            return Err(ModelError::DuplicateEnvironment);
        }
        Ok(())
    }
}

impl Project {
    pub fn new(name: String, routes: Vec<ProjectRoute>) -> Result<Self, ModelError> {
        Self::with_capabilities(name, routes, Vec::new())
    }

    pub fn with_capabilities(
        name: String,
        routes: Vec<ProjectRoute>,
        capabilities: Vec<AgentCapability>,
    ) -> Result<Self, ModelError> {
        let project = Self {
            version: FORMAT_VERSION,
            name,
            routes,
            capabilities,
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

    pub fn capabilities(&self) -> &[AgentCapability] {
        &self.capabilities
    }

    pub fn into_parts(mut self) -> (String, Vec<ProjectRoute>, Vec<AgentCapability>) {
        (
            std::mem::take(&mut self.name),
            std::mem::take(&mut self.routes),
            std::mem::take(&mut self.capabilities),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version != FORMAT_VERSION {
            return Err(ModelError::UnsupportedVersion);
        }
        validate_identifier(&self.name)?;
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
            if let Some(application) = route.application() {
                for name in [application.api_key_env(), application.base_url_env()] {
                    if !env_names.insert(name) {
                        return Err(ModelError::DuplicateEnvironment);
                    }
                }
            }
        }
        let mut capability_names = HashSet::new();
        for capability in &self.capabilities {
            capability.validate()?;
            if !capability_names.insert(capability.name()) {
                return Err(ModelError::DuplicateCapability);
            }
            if !route_names.contains(capability.route()) {
                return Err(ModelError::MissingCapabilityRoute);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ModelError> {
        self.validate()?;
        serde_yaml_ng::to_string(self)
            .map(String::into_bytes)
            .map(Zeroizing::new)
            .map_err(|_| ModelError::Serialization)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        #[derive(Deserialize)]
        struct VersionProbe {
            version: u32,
        }
        #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
        #[serde(deny_unknown_fields)]
        struct LegacyProject {
            #[zeroize(skip)]
            version: u32,
            #[zeroize(skip)]
            name: String,
            routes: Vec<LegacyRoute>,
        }
        #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
        #[serde(deny_unknown_fields)]
        struct LegacyRoute {
            #[zeroize(skip)]
            name: String,
            #[zeroize(skip)]
            base_url: String,
            api_key: String,
            #[zeroize(skip)]
            api_key_env: String,
            #[zeroize(skip)]
            base_url_env: String,
        }

        let raw = std::str::from_utf8(bytes).map_err(|_| ModelError::MalformedPayload)?;
        let probe: VersionProbe =
            serde_yaml_ng::from_str(raw).map_err(|_| ModelError::MalformedPayload)?;
        if probe.version == FORMAT_VERSION {
            let project: Project =
                serde_yaml_ng::from_str(raw).map_err(|_| ModelError::MalformedPayload)?;
            project
                .validate()
                .map_err(|_| ModelError::MalformedPayload)?;
            return Ok(project);
        }
        if probe.version != LEGACY_FORMAT_VERSION {
            return Err(ModelError::MalformedPayload);
        }
        let mut wire: LegacyProject =
            serde_yaml_ng::from_str(raw).map_err(|_| ModelError::MalformedPayload)?;
        if wire.version != LEGACY_FORMAT_VERSION {
            return Err(ModelError::MalformedPayload);
        }
        let routes = std::mem::take(&mut wire.routes)
            .into_iter()
            .map(|mut route| {
                let original_url = Zeroizing::new(route.base_url.clone());
                let route = ProjectRoute::new(
                    std::mem::take(&mut route.name),
                    std::mem::take(&mut route.base_url),
                    std::mem::take(&mut route.api_key),
                    std::mem::take(&mut route.api_key_env),
                    std::mem::take(&mut route.base_url_env),
                )?;
                if route.base_url() != original_url.as_str() {
                    return Err(ModelError::InvalidBaseUrl);
                }
                Ok(route)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ModelError::MalformedPayload)?;
        Project::new(std::mem::take(&mut wire.name), routes)
            .map_err(|_| ModelError::MalformedPayload)
    }

    pub fn description(&self) -> String {
        let mut output = format!(
            "Project: {}\nRoutes: {}\nCapabilities: {}\n",
            self.name,
            self.routes.len(),
            self.capabilities.len()
        );
        for route in &self.routes {
            output.push_str(&format!(
                "  {}\n    Base URL: {}\n",
                route.name, route.base_url
            ));
            if let Some(application) = route.application() {
                output.push_str(&format!(
                    "    Application binding: yes\n    API-key environment: {}\n    Base-URL environment: {}\n",
                    application.api_key_env, application.base_url_env
                ));
            } else {
                output.push_str("    Application binding: no\n");
            }
        }
        for capability in &self.capabilities {
            let methods = capability
                .policy
                .methods
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!(
                "  {}\n    Description: {}\n    Route: {}\n    Methods: {}\n    Path prefixes: {}\n    Maximum response bytes: {}\n",
                capability.name,
                capability.description,
                capability.route,
                methods,
                capability.policy.path_prefixes.join(", "),
                capability.policy.max_response_bytes
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
        Self::with_application(
            name,
            base_url,
            api_key,
            Some(ApplicationBinding::new(api_key_env, base_url_env)?),
        )
    }

    pub fn agent_only(name: String, base_url: String, api_key: String) -> Result<Self, ModelError> {
        Self::with_application(name, base_url, api_key, None)
    }

    pub fn with_application(
        name: String,
        base_url: String,
        api_key: String,
        application: Option<ApplicationBinding>,
    ) -> Result<Self, ModelError> {
        let route = Self {
            name,
            base_url: canonical_base_url(&base_url)?,
            api_key,
            application,
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
    pub fn application(&self) -> Option<&ApplicationBinding> {
        self.application.as_ref()
    }

    pub fn into_parts(mut self) -> (String, String, String, Option<ApplicationBinding>) {
        (
            std::mem::take(&mut self.name),
            std::mem::take(&mut self.base_url),
            std::mem::take(&mut self.api_key),
            std::mem::take(&mut self.application),
        )
    }

    fn validate(&self) -> Result<(), ModelError> {
        validate_identifier(&self.name)?;
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
        if let Some(application) = &self.application {
            application.validate()?;
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub struct UnsupportedAuthorizer;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl SessionAuthorizer for UnsupportedAuthorizer {
    fn authorize(&self, _action: Action<'_>) -> Result<(), AuthorizationError> {
        unreachable!()
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub struct UnsupportedRepository;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub type PlatformProjectService = ProjectService<UnsupportedAuthorizer, UnsupportedRepository>;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn open_project_service() -> Result<PlatformProjectService, StoreError> {
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

    fn capability(name: &str, route: &str) -> AgentCapability {
        AgentCapability::new(
            name.into(),
            "Read repository data.".into(),
            route.into(),
            [HttpMethod::GET],
            vec!["/repos/".into()],
            DEFAULT_CAPABILITY_RESPONSE_BYTES,
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
    fn v1_project_migrates_in_memory_without_changing_secret_or_binding() {
        let fixture = b"version: 1\nname: legacy-app\nroutes:\n- name: github\n  base_url: https://api.github.com\n  api_key: exact-legacy-secret+/=\n  api_key_env: GITHUB_TOKEN\n  base_url_env: GITHUB_API_URL\n";
        let project = Project::decode(fixture).unwrap();

        assert_eq!(project.name(), "legacy-app");
        assert!(project.capabilities().is_empty());
        let route = &project.routes()[0];
        assert_eq!(route.name(), "github");
        assert_eq!(route.base_url(), "https://api.github.com");
        assert_eq!(route.application().unwrap().api_key_env(), "GITHUB_TOKEN");
        assert_eq!(
            route.application().unwrap().base_url_env(),
            "GITHUB_API_URL"
        );
        assert_eq!(route.clone().into_parts().2, "exact-legacy-secret+/=");

        let encoded = project.encode().unwrap();
        let encoded = std::str::from_utf8(&encoded).unwrap();
        assert!(encoded.starts_with("version: 2\n"));
        assert!(encoded.contains("application:"));
        assert!(encoded.contains("capabilities: []"));
    }

    #[test]
    fn v2_capability_only_project_round_trips() {
        let project = Project::with_capabilities(
            "agent-project".into(),
            vec![ProjectRoute::agent_only(
                "github".into(),
                "https://api.github.com".into(),
                "private-token".into(),
            )
            .unwrap()],
            vec![capability("github-read", "github")],
        )
        .unwrap();

        let decoded = Project::decode(&project.encode().unwrap()).unwrap();
        assert_eq!(decoded, project);
        assert!(decoded.routes()[0].application().is_none());
        assert!(!decoded.description().contains("private-token"));
        assert!(!format!("{decoded:?}").contains("private-token"));
    }

    #[test]
    fn capability_references_and_names_fail_closed() {
        let routes = vec![route("github", "GITHUB_KEY", "GITHUB_URL")];
        assert_eq!(
            Project::with_capabilities(
                "app".into(),
                routes.clone(),
                vec![
                    capability("github-read", "github"),
                    capability("github-read", "github")
                ]
            )
            .unwrap_err(),
            ModelError::DuplicateCapability
        );
        assert_eq!(
            Project::with_capabilities(
                "app".into(),
                routes,
                vec![capability("github-read", "missing")]
            )
            .unwrap_err(),
            ModelError::MissingCapabilityRoute
        );
    }

    #[test]
    fn capability_policy_rejects_empty_or_malformed_authority() {
        assert_eq!(
            HttpPolicy::new([], vec!["/repos/".into()], 1).unwrap_err(),
            ModelError::EmptyMethods
        );
        assert_eq!(
            HttpPolicy::new([HttpMethod::GET], Vec::new(), 1).unwrap_err(),
            ModelError::EmptyPathPrefixes
        );
        for invalid in [
            "repos/",
            "https://api.github.com/repos/",
            "/repos/../admin",
            "/repos/%2e%2e/admin",
            "/repos\\admin",
            "/repos/#fragment",
        ] {
            assert_eq!(
                HttpPolicy::new([HttpMethod::GET], vec![invalid.into()], 1).unwrap_err(),
                ModelError::InvalidPathPrefix,
                "accepted {invalid}"
            );
        }
        for invalid in [0, MAX_CAPABILITY_RESPONSE_BYTES + 1] {
            assert_eq!(
                HttpPolicy::new([HttpMethod::GET], vec!["/repos/".into()], invalid).unwrap_err(),
                ModelError::InvalidResponseLimit
            );
        }
    }

    #[test]
    fn path_prefix_matching_has_segment_boundaries() {
        let slash = HttpPolicy::new([HttpMethod::GET], vec!["/repos/".into()], 1).unwrap();
        assert!(slash.allows_path("/repos/a"));
        assert!(slash.allows_path("/repos/a/b"));
        assert!(!slash.allows_path("/repos"));
        assert!(!slash.allows_path("/repositories/a"));

        let exact = HttpPolicy::new([HttpMethod::GET], vec!["/user".into()], 1).unwrap();
        assert!(exact.allows_path("/user"));
        assert!(exact.allows_path("/user/repos"));
        assert!(!exact.allows_path("/users"));
    }

    #[test]
    fn zeroize_marks_only_the_route_credential_as_secret() {
        let mut route = route("billing", "BILLING_KEY", "BILLING_URL");
        let name = route.name.clone();
        let base_url = route.base_url.clone();
        let application = route.application.clone();

        route.zeroize();

        assert!(route.api_key.is_empty());
        assert_eq!(route.name, name);
        assert_eq!(route.base_url, base_url);
        assert_eq!(route.application, application);
    }

    #[test]
    fn names_are_identifiers_not_paths() {
        for invalid in ["", ".", "../app", "/tmp/app", "two words", "_hidden"] {
            assert!(validate_identifier(invalid).is_err());
        }
        for valid in ["app", "my-app", "app2", "2-app"] {
            assert!(validate_identifier(valid).is_ok());
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
            b"version: 1\nname: \"bad\\e[31m\"\nroutes: []\n".as_slice(),
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
