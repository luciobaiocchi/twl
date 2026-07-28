use crate::config::validate_upstream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    version: u32,
    pub name: String,
    pub routes: Vec<ProjectRoute>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    if value == "PATH"
        || value == "DBUS_SESSION_BUS_ADDRESS"
        || value.starts_with("TWL_")
        || value.starts_with("DYLD_")
        || matches!(value, "LD_PRELOAD" | "LD_LIBRARY_PATH")
    {
        return Err(format!(
            "{field} is reserved by Towel or the process runtime"
        ));
    }
    Ok(())
}

impl std::fmt::Debug for Project {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Project")
            .field("version", &self.version)
            .field("name", &self.name)
            .field("routes", &self.routes)
            .finish()
    }
}

impl std::fmt::Debug for ProjectRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    pub fn new(name: String, mut routes: Vec<ProjectRoute>) -> Result<Self, String> {
        for route in &mut routes {
            route.canonicalize()?;
        }
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
    fn canonicalize(&mut self) -> Result<(), String> {
        if self
            .base_url
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(format!(
                "route {} base URL contains control characters",
                self.name
            ));
        }
        let canonical = validate_upstream(&self.base_url)?;
        if url::Url::parse(&canonical).is_ok_and(|parsed| parsed.scheme() != "https") {
            return Err(format!("route {} base URL must use HTTPS", self.name));
        }
        self.base_url = canonical;
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self
            .base_url
            .bytes()
            .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(format!(
                "route {} base URL contains control characters",
                self.name
            ));
        }
        let canonical = validate_upstream(&self.base_url)?;
        if canonical != self.base_url {
            return Err(format!("route {} base URL is not canonical", self.name));
        }
        if url::Url::parse(&canonical).is_ok_and(|parsed| parsed.scheme() != "https") {
            return Err(format!("route {} base URL must use HTTPS", self.name));
        }
        let unpadded = self.api_key.trim_end_matches('=');
        if unpadded.is_empty()
            || !unpadded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        {
            return Err(format!(
                "route {} API key is not a valid Bearer value",
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
    use core_foundation::base::TCFType;
    use security_framework::base::Error;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework_sys::base::errSecSuccess;
    use security_framework_sys::keychain_item::SecKeychainItemDelete;

    const SERVICE: &str = "dev.towel.project";
    const ITEM_NOT_FOUND: i32 = -25300;

    fn account(name: &str) -> String {
        format!("project-v1:{name}")
    }

    fn missing(error: &Error) -> bool {
        error.code() == ITEM_NOT_FOUND
    }

    struct ScopedKeychainStore {
        keychain: SecKeychain,
    }

    impl ScopedKeychainStore {
        fn default() -> Result<Self, String> {
            SecKeychain::default()
                .map(|keychain| Self { keychain })
                .map_err(|error| format!("opening the default Keychain: {error}"))
        }

        fn list(&self) -> Result<Vec<String>, String> {
            let results = match ItemSearchOptions::new()
                .keychains(std::slice::from_ref(&self.keychain))
                .class(ItemClass::generic_password())
                .service(SERVICE)
                .load_attributes(true)
                .limit(Limit::All)
                .search()
            {
                Ok(results) => results,
                Err(error) if missing(&error) => return Ok(Vec::new()),
                Err(error) => return Err(format!("listing Keychain projects: {error}")),
            };
            let mut names = Vec::with_capacity(results.len());
            for result in results {
                let SearchResult::Dict(_) = result else {
                    return Err("malformed Keychain project record".into());
                };
                let attributes = result
                    .simplify_dict()
                    .ok_or("malformed Keychain project record")?;
                let name = attributes
                    .get("acct")
                    .and_then(|account| account.strip_prefix("project-v1:"))
                    .ok_or("malformed Keychain project record")?;
                validate_identifier(name, "project name")
                    .map_err(|_| "malformed Keychain project record".to_string())?;
                if names.iter().any(|existing| existing == name) {
                    return Err("duplicate Keychain project records".into());
                }
                names.push(name.to_string());
            }
            names.sort();
            Ok(names)
        }

        fn find(&self, name: &str) -> Result<(Project, SecKeychainItem), String> {
            let (bytes, item) = self
                .keychain
                .find_generic_password(SERVICE, &account(name))
                .map_err(|error| {
                    if missing(&error) {
                        format!("project not found: {name}")
                    } else {
                        format!("reading project from Keychain: {error}")
                    }
                })?;
            let project = Project::decode(bytes.as_ref())?;
            if project.name != name {
                return Err("malformed Keychain project payload".into());
            }
            Ok((project, item))
        }

        fn get(&self, name: &str) -> Result<Project, String> {
            self.find(name).map(|(project, _)| project)
        }

        fn create(&self, project: &Project) -> Result<(), String> {
            self.keychain
                .add_generic_password(SERVICE, &account(&project.name), &project.encode()?)
                .map_err(|error| {
                    if error.code() == -25299 {
                        format!("project already exists: {}", project.name)
                    } else {
                        format!("writing project to Keychain: {error}")
                    }
                })
        }

        fn replace(&self, project: &Project) -> Result<(), String> {
            let (_, mut item) = self.find(&project.name)?;
            item.set_password(&project.encode()?)
                .map_err(|error| format!("replacing project in Keychain: {error}"))
        }

        fn delete(&self, name: &str) -> Result<(), String> {
            let (_, item) = self.find(name)?;
            let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
            if status == errSecSuccess {
                Ok(())
            } else {
                Err(format!(
                    "deleting project from Keychain: {}",
                    Error::from_code(status)
                ))
            }
        }
    }

    impl ProjectStore for MacKeychainProjectStore {
        fn list(&self) -> Result<Vec<String>, String> {
            secret::authorize("list Towel projects")?;
            ScopedKeychainStore::default()?.list()
        }

        fn get(&self, name: &str) -> Result<Project, String> {
            validate_identifier(name, "project name")?;
            secret::authorize(&format!("access Towel project {name}"))?;
            ScopedKeychainStore::default()?.get(name)
        }

        fn create(&self, project: &Project) -> Result<(), String> {
            project.validate()?;
            secret::authorize(&format!("store Towel project {}", project.name))?;
            ScopedKeychainStore::default()?.create(project)
        }

        fn replace(&self, project: &Project) -> Result<(), String> {
            project.validate()?;
            secret::authorize(&format!("replace Towel project {}", project.name))?;
            ScopedKeychainStore::default()?.replace(project)
        }

        fn delete(&self, name: &str) -> Result<(), String> {
            validate_identifier(name, "project name")?;
            secret::authorize(&format!("delete Towel project {name}"))?;
            ScopedKeychainStore::default()?.delete(name)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use security_framework::os::macos::keychain::CreateOptions;
        use std::path::PathBuf;

        fn project(name: &str, key: &str) -> Project {
            Project::new(
                name.into(),
                vec![ProjectRoute {
                    name: "api".into(),
                    base_url: "https://api.example.test/v1".into(),
                    api_key: key.into(),
                    api_key_env: "APP_API_KEY".into(),
                    base_url_env: "APP_BASE_URL".into(),
                }],
            )
            .unwrap()
        }

        fn test_store(label: &str) -> (PathBuf, ScopedKeychainStore) {
            let path = std::env::temp_dir().join(format!(
                "twl-{label}-{}-{}.keychain",
                std::process::id(),
                rand::random::<u64>()
            ));
            let keychain = CreateOptions::new()
                .password("test-password")
                .create(&path)
                .unwrap();
            (path, ScopedKeychainStore { keychain })
        }

        #[test]
        fn operations_never_touch_matching_items_in_another_keychain() {
            let (primary_path, primary) = test_store("primary");
            let (other_path, other) = test_store("other");
            let original = b"attacker-controlled";
            other
                .keychain
                .add_generic_password(SERVICE, &account("app"), original)
                .unwrap();

            primary.create(&project("app", "first-key")).unwrap();
            primary.replace(&project("app", "second-key")).unwrap();
            primary.delete("app").unwrap();

            let (other_value, _) = other
                .keychain
                .find_generic_password(SERVICE, &account("app"))
                .unwrap();
            assert_eq!(other_value.as_ref(), original);
            drop((primary, other));
            let _ = std::fs::remove_file(primary_path);
            let _ = std::fs::remove_file(other_path);
        }

        #[test]
        fn authoritative_records_survive_concurrent_creates_and_remain_manageable() {
            let (path, store) = test_store("concurrent");
            let keychain = store.keychain.clone();
            let first = std::thread::spawn(move || {
                ScopedKeychainStore { keychain }.create(&project("one", "first-key"))
            });
            let keychain = store.keychain.clone();
            let second = std::thread::spawn(move || {
                ScopedKeychainStore { keychain }.create(&project("two", "second-key"))
            });
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();

            assert_eq!(store.list().unwrap(), ["one", "two"]);
            store.replace(&project("one", "replacement-key")).unwrap();
            store.delete("one").unwrap();
            store.delete("two").unwrap();
            assert!(store.list().unwrap().is_empty());
            drop(store);
            let _ = std::fs::remove_file(path);
        }

        #[test]
        fn create_is_add_only_and_replace_never_creates() {
            let (path, store) = test_store("semantics");
            let candidate = project("app", "first-key");
            store.create(&candidate).unwrap();
            assert!(store
                .create(&candidate)
                .unwrap_err()
                .contains("already exists"));
            assert!(store
                .replace(&project("missing", "second-key"))
                .unwrap_err()
                .contains("not found"));
            store.delete("app").unwrap();
            drop(store);
            let _ = std::fs::remove_file(path);
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

        for invalid in ["   ", "café", "has space", "token:colon", "key\tvalue"] {
            let mut candidate = route("api", "API_KEY", "API_URL");
            candidate.api_key = invalid.into();
            let error = Project::new("app".into(), vec![candidate]).unwrap_err();
            assert!(!error.contains(invalid));
        }
    }

    #[test]
    fn destinations_are_canonicalized_once_and_controls_are_rejected() {
        let mut candidate = route("api", "API_KEY", "API_URL");
        candidate.base_url = "HTTPS://EXAMPLE.TEST:443/safe/%2e%2e/admin".into();
        let project = Project::new("app".into(), vec![candidate]).unwrap();
        assert_eq!(project.routes[0].base_url, "https://example.test/admin");
        assert!(project.description().contains("https://example.test/admin"));
        assert!(project
            .encode()
            .unwrap()
            .windows(26)
            .any(|part| part == b"https://example.test/admin"));

        let mut candidate = route("api", "API_KEY", "API_URL");
        candidate.base_url = "https://éxample.test/路径".into();
        let project = Project::new("app".into(), vec![candidate]).unwrap();
        assert!(project.routes[0].base_url.contains("xn--"));
        assert!(project.routes[0].base_url.contains("%E8%B7%AF%E5%BE%84"));

        for control in ['\n', '\t', '\u{1b}'] {
            let mut candidate = route("api", "API_KEY", "API_URL");
            candidate.base_url = format!("https://example.test/{control}hidden");
            assert!(Project::new("app".into(), vec![candidate]).is_err());
        }

        let noncanonical = b"version: 1\nname: app\nroutes:\n- name: api\n  base_url: HTTPS://EXAMPLE.TEST:443/path\n  api_key: valid-key\n  api_key_env: API_KEY\n  base_url_env: API_URL\n";
        assert_eq!(
            Project::decode(noncanonical).unwrap_err(),
            "malformed Keychain project payload"
        );
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
            assert!(Project::new("app".into(), vec![route("api", name, "API_URL")]).is_err());
        }
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
        assert!(!format!("{project:?}").contains("secret-api"));
    }
}
