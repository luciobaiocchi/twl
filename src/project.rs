use crate::config::validate_upstream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    version: u32,
    pub name: String,
    pub routes: Vec<ProjectRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoute {
    pub name: String,
    pub base_url: String,
    pub api_key: String,
    pub api_key_env: String,
    pub base_url_env: String,
}

pub fn validate_identifier(value: &str, kind: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'-'))
    {
        return Err(format!(
            "{kind} must be 1-64 ASCII letters, digits, or hyphens and start with a letter or digit"
        ));
    }
    Ok(())
}

fn validate_env_name(value: &str, field: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if value.len() > 128
        || bytes
            .next()
            .is_none_or(|byte| !(byte.is_ascii_alphabetic() || byte == b'_'))
        || bytes.any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return Err(format!("{field} must be a valid environment variable name"));
    }
    Ok(())
}

impl Project {
    pub fn new(name: String, routes: Vec<ProjectRoute>) -> Result<Self, String> {
        let project = Self {
            version: FORMAT_VERSION,
            name,
            routes,
        };
        project.validate()?;
        Ok(project)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != FORMAT_VERSION {
            return Err(format!(
                "unsupported project format version: {}",
                self.version
            ));
        }
        validate_identifier(&self.name, "project name")?;
        if self.routes.is_empty() {
            return Err("a project must contain at least one route".into());
        }

        let mut route_names = HashSet::new();
        let mut env_names = HashSet::new();
        for route in &self.routes {
            validate_identifier(&route.name, "route name")?;
            if !route_names.insert(route.name.as_str()) {
                return Err(format!("duplicate route name: {}", route.name));
            }
            route.validate()?;
            for name in [&route.api_key_env, &route.base_url_env] {
                if !env_names.insert(name.as_str()) {
                    return Err(format!("duplicate environment variable name: {name}"));
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_yaml_ng::to_string(self)
            .map(String::into_bytes)
            .map_err(|_| "serializing project failed".into())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let raw = std::str::from_utf8(bytes).map_err(|_| "malformed Keychain project payload")?;
        let project: Self =
            serde_yaml_ng::from_str(raw).map_err(|_| "malformed Keychain project payload")?;
        project
            .validate()
            .map_err(|_| "malformed Keychain project payload")?;
        Ok(project)
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
    fn validate(&self) -> Result<(), String> {
        validate_upstream(&self.base_url)?;
        if url::Url::parse(&self.base_url).is_ok_and(|parsed| parsed.scheme() != "https") {
            return Err(format!("route {} base URL must use HTTPS", self.name));
        }
        if self.api_key.is_empty() {
            return Err(format!("route {} has an empty API key", self.name));
        }
        if self.api_key.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(format!(
                "route {} API key contains control characters",
                self.name
            ));
        }
        validate_env_name(&self.api_key_env, "API-key environment variable")?;
        validate_env_name(&self.base_url_env, "base-URL environment variable")?;
        if self.api_key_env == self.base_url_env {
            return Err(format!(
                "route {} uses the same environment variable twice",
                self.name
            ));
        }
        Ok(())
    }
}

pub trait ProjectStore {
    fn list(&self) -> Result<Vec<String>, String>;
    fn get(&self, name: &str) -> Result<Project, String>;
    fn create(&self, project: &Project) -> Result<(), String>;
    fn replace(&self, project: &Project) -> Result<(), String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

pub struct MacKeychainProjectStore;

impl MacKeychainProjectStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacKeychainProjectStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
mod mac_store {
    use super::*;
    use crate::secret;
    use security_framework::base::Error;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const SERVICE: &str = "dev.towel.project";
    const INDEX_ACCOUNT: &str = "__project_index_v1";
    const ITEM_NOT_FOUND: i32 = -25300;

    fn account(name: &str) -> String {
        format!("project-v1:{name}")
    }

    fn missing(error: &Error) -> bool {
        error.code() == ITEM_NOT_FOUND
    }

    fn read_index() -> Result<Vec<String>, String> {
        match get_generic_password(SERVICE, INDEX_ACCOUNT) {
            Ok(bytes) => {
                let raw = std::str::from_utf8(&bytes)
                    .map_err(|_| "malformed Keychain project index".to_string())?;
                let mut names = Vec::new();
                for name in raw.lines() {
                    validate_identifier(name, "project name")
                        .map_err(|_| "malformed Keychain project index".to_string())?;
                    if names.iter().any(|existing| existing == name) {
                        return Err("malformed Keychain project index".into());
                    }
                    names.push(name.to_string());
                }
                names.sort();
                Ok(names)
            }
            Err(error) if missing(&error) => Ok(Vec::new()),
            Err(error) => Err(format!("reading Keychain project index: {error}")),
        }
    }

    fn write_index(names: &[String]) -> Result<(), String> {
        let mut sorted = names.to_vec();
        sorted.sort();
        let payload = sorted.join("\n");
        set_generic_password(SERVICE, INDEX_ACCOUNT, payload.as_bytes())
            .map_err(|error| format!("writing Keychain project index: {error}"))
    }

    fn read_project(name: &str) -> Result<Project, String> {
        let bytes = get_generic_password(SERVICE, &account(name)).map_err(|error| {
            if missing(&error) {
                format!("project not found: {name}")
            } else {
                format!("reading project from Keychain: {error}")
            }
        })?;
        let project = Project::decode(&bytes)?;
        if project.name != name {
            return Err("malformed Keychain project payload".into());
        }
        Ok(project)
    }

    impl ProjectStore for MacKeychainProjectStore {
        fn list(&self) -> Result<Vec<String>, String> {
            secret::authorize("list Towel projects")?;
            read_index()
        }

        fn get(&self, name: &str) -> Result<Project, String> {
            validate_identifier(name, "project name")?;
            secret::authorize(&format!("access Towel project {name}"))?;
            read_project(name)
        }

        fn create(&self, project: &Project) -> Result<(), String> {
            project.validate()?;
            secret::authorize(&format!("store Towel project {}", project.name))?;
            let mut names = read_index()?;
            if names.iter().any(|name| name == &project.name) {
                return Err(format!("project already exists: {}", project.name));
            }
            let account = account(&project.name);
            match get_generic_password(SERVICE, &account) {
                Ok(_) => return Err(format!("project already exists: {}", project.name)),
                Err(error) if missing(&error) => {}
                Err(error) => return Err(format!("checking Keychain project: {error}")),
            }
            set_generic_password(SERVICE, &account, &project.encode()?)
                .map_err(|error| format!("writing project to Keychain: {error}"))?;
            names.push(project.name.clone());
            if let Err(error) = write_index(&names) {
                let _ = delete_generic_password(SERVICE, &account);
                return Err(error);
            }
            Ok(())
        }

        fn replace(&self, project: &Project) -> Result<(), String> {
            project.validate()?;
            secret::authorize(&format!("replace Towel project {}", project.name))?;
            let names = read_index()?;
            if !names.iter().any(|name| name == &project.name) {
                return Err(format!("project not found: {}", project.name));
            }
            // SecItemUpdate replaces the record data atomically when the item exists.
            set_generic_password(SERVICE, &account(&project.name), &project.encode()?)
                .map_err(|error| format!("replacing project in Keychain: {error}"))
        }

        fn delete(&self, name: &str) -> Result<(), String> {
            validate_identifier(name, "project name")?;
            secret::authorize(&format!("delete Towel project {name}"))?;
            let project = read_project(name)?;
            let mut names = read_index()?;
            if !names.iter().any(|existing| existing == name) {
                return Err(format!("project not found: {name}"));
            }
            delete_generic_password(SERVICE, &account(name))
                .map_err(|error| format!("deleting project from Keychain: {error}"))?;
            names.retain(|existing| existing != name);
            if let Err(error) = write_index(&names) {
                let _ = set_generic_password(SERVICE, &account(name), &project.encode()?);
                return Err(error);
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl ProjectStore for MacKeychainProjectStore {
    fn list(&self) -> Result<Vec<String>, String> {
        Err("project credentials are currently available only on macOS".into())
    }

    fn get(&self, name: &str) -> Result<Project, String> {
        validate_identifier(name, "project name")?;
        Err("project credentials are currently available only on macOS".into())
    }

    fn create(&self, project: &Project) -> Result<(), String> {
        project.validate()?;
        Err("project credentials are currently available only on macOS".into())
    }

    fn replace(&self, project: &Project) -> Result<(), String> {
        project.validate()?;
        Err("project credentials are currently available only on macOS".into())
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        validate_identifier(name, "project name")?;
        Err("project credentials are currently available only on macOS".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, key_env: &str, url_env: &str) -> ProjectRoute {
        ProjectRoute {
            name: name.into(),
            base_url: "https://api.example.test/v1".into(),
            api_key: format!("secret-{name}"),
            api_key_env: key_env.into(),
            base_url_env: url_env.into(),
        }
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
            assert!(
                validate_identifier(invalid, "project name").is_err(),
                "{invalid}"
            );
        }
        for valid in ["app", "my-app", "app2", "2-app"] {
            assert!(
                validate_identifier(valid, "project name").is_ok(),
                "{valid}"
            );
        }
    }

    #[test]
    fn duplicate_routes_and_environment_names_are_rejected() {
        let duplicate_route = Project::new(
            "app".into(),
            vec![
                route("api", "ONE_KEY", "ONE_URL"),
                route("api", "TWO_KEY", "TWO_URL"),
            ],
        );
        assert!(duplicate_route.unwrap_err().contains("duplicate route"));

        let duplicate_env = Project::new(
            "app".into(),
            vec![
                route("one", "SHARED", "ONE_URL"),
                route("two", "TWO_KEY", "SHARED"),
            ],
        );
        assert!(duplicate_env.unwrap_err().contains("duplicate environment"));
    }

    #[test]
    fn unsafe_urls_and_keys_are_rejected_without_echoing_keys() {
        let mut candidate = route("api", "API_KEY", "API_URL");
        candidate.base_url = "http://not-loopback.example".into();
        assert!(Project::new("app".into(), vec![candidate]).is_err());

        let mut candidate = route("api", "API_KEY", "API_URL");
        candidate.base_url = "http://127.0.0.1:8080".into();
        assert!(Project::new("app".into(), vec![candidate]).is_err());

        let secret = "do-not-print\nheader";
        let mut candidate = route("api", "API_KEY", "API_URL");
        candidate.api_key = secret.into();
        let error = Project::new("app".into(), vec![candidate]).unwrap_err();
        assert!(!error.contains(secret));
        assert!(!error.contains("do-not-print"));
    }

    #[test]
    fn malformed_and_unknown_versions_fail_generically() {
        for payload in [
            b"not: [valid".as_slice(),
            b"version: 99\nname: app\nroutes: []\n".as_slice(),
            b"version: 1\nname: ../app\nroutes: []\n".as_slice(),
        ] {
            assert_eq!(
                Project::decode(payload).unwrap_err(),
                "malformed Keychain project payload"
            );
        }
    }

    #[test]
    fn description_never_contains_secrets_or_fingerprints() {
        let project = Project::new("app".into(), vec![route("api", "API_KEY", "API_URL")]).unwrap();
        let shown = project.description();
        assert!(shown.contains("https://api.example.test/v1"));
        assert!(shown.contains("API_KEY"));
        assert!(!shown.contains("secret-api"));
        assert!(!shown.to_ascii_lowercase().contains("fingerprint"));
    }
}
