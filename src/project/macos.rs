use super::{
    validate_identifier, Action, AuthorizationError, Project, ProjectRepository, ProjectService,
    Revision, SessionAuthorizer, StoreError, StoredProject,
};
use crate::secret;
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework::base::Error;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::kSecAttrAccount;
use security_framework_sys::keychain_item::SecKeychainItemDelete;
use std::collections::HashSet;
use std::sync::Mutex;

const SERVICE: &str = "dev.towel.project";
const ACCOUNT_PREFIX: &str = "project-v1:";
static KEYCHAIN_MUTATION: Mutex<()> = Mutex::new(());

fn account(name: &str) -> String {
    format!("{ACCOUNT_PREFIX}{name}")
}

fn platform(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Platform(format!("{context}: {error}"))
}

/// Repository pinned to one explicitly selected Keychain.
pub struct MacKeychainRepository {
    keychain: SecKeychain,
}

impl MacKeychainRepository {
    pub fn open_trusted_store() -> Result<Self, StoreError> {
        SecKeychain::default()
            .map(|keychain| Self { keychain })
            .map_err(|error| platform("opening the default Keychain", error))
    }

    fn find_item(&self, name: &str) -> Result<(Vec<u8>, SecKeychainItem), StoreError> {
        validate_identifier(name, "project name")?;
        self.keychain
            .find_generic_password(SERVICE, &account(name))
            .map(|(payload, item)| (payload.as_ref().to_vec(), item))
            .map_err(|error| {
                if error.code() == errSecItemNotFound {
                    StoreError::NotFound
                } else {
                    platform("reading project from Keychain", error)
                }
            })
    }
}

impl ProjectRepository for MacKeychainRepository {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        let results = match ItemSearchOptions::new()
            .keychains(std::slice::from_ref(&self.keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
        {
            Ok(results) => results,
            Err(error) if error.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(error) => return Err(platform("listing Keychain projects", error)),
        };

        let mut seen = HashSet::new();
        let mut names = Vec::with_capacity(results.len());
        for result in results {
            let SearchResult::Dict(attributes) = result else {
                return Err(StoreError::MalformedRecord);
            };
            let account_value = attributes
                .find(unsafe { kSecAttrAccount })
                .ok_or(StoreError::MalformedRecord)?;
            // SAFETY: Security Framework owns this live dictionary value and the account
            // attribute is a CFString for the lifetime of `attributes`.
            let account_value =
                unsafe { CFString::wrap_under_get_rule((*account_value).cast()) }.to_string();
            let name = account_value
                .strip_prefix(ACCOUNT_PREFIX)
                .ok_or(StoreError::MalformedRecord)?;
            validate_identifier(name, "project name").map_err(|_| StoreError::MalformedRecord)?;
            if !seen.insert(name.to_owned()) {
                return Err(StoreError::MalformedRecord);
            }
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    fn get(&self, name: &str) -> Result<StoredProject, StoreError> {
        let (payload, _) = self.find_item(name)?;
        let project = Project::decode(&payload).map_err(|_| StoreError::MalformedRecord)?;
        if project.name() != name {
            return Err(StoreError::MalformedRecord);
        }
        Ok(StoredProject::new(project, Revision::from_payload(payload)))
    }

    fn create(&self, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let _guard = KEYCHAIN_MUTATION
            .lock()
            .map_err(|_| StoreError::Platform("Keychain mutation lock failed".into()))?;
        self.keychain
            .add_generic_password(SERVICE, &account(project.name()), &project.encode()?)
            .map_err(|error| {
                if error.code() == errSecDuplicateItem {
                    StoreError::AlreadyExists
                } else {
                    platform("writing project to Keychain", error)
                }
            })
    }

    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let _guard = KEYCHAIN_MUTATION
            .lock()
            .map_err(|_| StoreError::Platform("Keychain mutation lock failed".into()))?;
        let (current, mut item) = self.find_item(project.name())?;
        if !expected.matches(&current) {
            return Err(StoreError::Conflict);
        }
        item.set_password(&project.encode()?)
            .map_err(|error| platform("replacing project in Keychain", error))
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        let _guard = KEYCHAIN_MUTATION
            .lock()
            .map_err(|_| StoreError::Platform("Keychain mutation lock failed".into()))?;
        let (_, item) = self.find_item(name)?;
        // SAFETY: `item` retains a live SecKeychainItem, its pointer is valid for this
        // call, and deletion does not transfer ownership of the retained reference.
        let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
        if status == errSecSuccess {
            Ok(())
        } else {
            Err(platform(
                "deleting project from Keychain",
                Error::from_code(status),
            ))
        }
    }
}

pub struct MacLocalAuthorizer;

impl SessionAuthorizer for MacLocalAuthorizer {
    fn authorize(&self, action: Action<'_>) -> Result<(), AuthorizationError> {
        let reason = match action {
            Action::List => "list Towel projects".to_owned(),
            Action::Read(name) => format!("access Towel project {name}"),
            Action::Create(name) => format!("store Towel project {name}"),
            Action::Replace(name) => format!("replace Towel project {name}"),
            Action::Delete(name) => format!("delete Towel project {name}"),
        };
        secret::authorize(&reason).map_err(AuthorizationError::platform)
    }
}

pub type MacProjectService = ProjectService<MacLocalAuthorizer, MacKeychainRepository>;

pub fn open_project_service() -> Result<MacProjectService, StoreError> {
    secret::process_preflight().map_err(StoreError::Platform)?;
    Ok(ProjectService::new(
        MacLocalAuthorizer,
        MacKeychainRepository::open_trusted_store()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::repository::exercise_repository;
    use crate::project::ProjectRoute;
    use security_framework::os::macos::keychain::CreateOptions;
    use std::path::PathBuf;

    fn project(name: &str, key: &str) -> Project {
        Project::new(
            name.into(),
            vec![ProjectRoute::new(
                "api".into(),
                "https://api.example.test/v1".into(),
                key.into(),
                "APP_API_KEY".into(),
                "APP_BASE_URL".into(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn test_store(label: &str) -> (PathBuf, MacKeychainRepository) {
        let path = std::env::temp_dir().join(format!(
            "twl-{label}-{}-{}.keychain",
            std::process::id(),
            rand::random::<u64>()
        ));
        let keychain = CreateOptions::new()
            .password("test-password")
            .create(&path)
            .unwrap();
        (path, MacKeychainRepository { keychain })
    }

    #[test]
    fn keychain_repository_conforms() {
        let (path, store) = test_store("conformance");
        exercise_repository(&store);
        drop(store);
        let _ = std::fs::remove_file(path);
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
        let stored = primary.get("app").unwrap();
        primary
            .replace(stored.revision(), &project("app", "second-key"))
            .unwrap();
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
}
