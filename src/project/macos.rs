use super::{
    validate_identifier, Action, AuthorizationError, Project, ProjectRepository, ProjectService,
    Revision, SessionAuthorizer, StoreError, StoredProject,
};
use crate::secret;
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex, CFArrayRef};
use core_foundation_sys::base::{CFEqual, CFRelease, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::string::CFStringRef;
use security_framework::base::Error;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::SecKeychainItem;
use security_framework_sys::base::{
    errSecDuplicateItem, errSecItemNotFound, errSecSuccess, SecAccessRef,
};
use security_framework_sys::item::kSecAttrAccount;
use security_framework_sys::keychain_item::SecKeychainItemDelete;
use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

const SERVICE: &str = "dev.towel.project";
const ACCOUNT_PREFIX: &str = "project-v1:";
static KEYCHAIN_MUTATION: Mutex<()> = Mutex::new(());

enum OpaqueSecAcl {}
type SecAclRef = *mut OpaqueSecAcl;
enum OpaqueSecTrustedApplication {}
type SecTrustedApplicationRef = *mut OpaqueSecTrustedApplication;

extern "C" {
    static kSecACLAuthorizationDecrypt: CFStringRef;
    fn SecKeychainItemCopyAccess(
        item: security_framework_sys::base::SecKeychainItemRef,
        access: *mut SecAccessRef,
    ) -> i32;
    fn SecAccessCopyACLList(access: SecAccessRef, acls: *mut CFArrayRef) -> i32;
    fn SecACLCopyAuthorizations(acl: SecAclRef, authorizations: *mut CFArrayRef) -> i32;
    fn SecACLCopyContents(
        acl: SecAclRef,
        applications: *mut CFArrayRef,
        description: *mut CFStringRef,
        prompt_selector: *mut std::ffi::c_void,
    ) -> i32;
    fn SecTrustedApplicationCopyData(
        application: SecTrustedApplicationRef,
        data: *mut CFDataRef,
    ) -> i32;
}

fn account(name: &str) -> String {
    format!("{ACCOUNT_PREFIX}{name}")
}

fn platform(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Platform(format!("{context}: {error}"))
}

fn user_home() -> Option<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let mut password: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: all output pointers refer to live writable storage for the call;
    // getpwuid_r writes at most `buffer.len()` bytes.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut password,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || password.pw_dir.is_null() {
        return None;
    }
    // SAFETY: a successful getpwuid_r returns a NUL-terminated pw_dir inside
    // the live buffer.
    let bytes = unsafe { CStr::from_ptr(password.pw_dir) }.to_bytes();
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

struct MutationLock {
    _file: File,
}

impl MutationLock {
    fn acquire(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| StoreError::UntrustedStore)?;
        let metadata = file.metadata().map_err(|_| StoreError::UntrustedStore)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(StoreError::UntrustedStore);
        }
        // SAFETY: the file descriptor is live and owned by `file`; flock does
        // not take ownership and remains held until the descriptor is closed.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(StoreError::Platform("locking project store failed".into()));
        }
        Ok(Self { _file: file })
    }
}

fn verify_item_acl(item: &SecKeychainItem, executable: &Path) -> Result<(), StoreError> {
    let mut access = ptr::null_mut();
    // SAFETY: `item` is retained and live; the successful Copy call returns an
    // owned access reference released below.
    if unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &mut access) }
        != errSecSuccess
        || access.is_null()
    {
        return Err(StoreError::UntrustedItem);
    }
    let trusted = verify_access_acls(access, executable);
    // SAFETY: access was returned at +1 by SecKeychainItemCopyAccess.
    unsafe { CFRelease(access.cast()) };
    if trusted {
        Ok(())
    } else {
        Err(StoreError::UntrustedItem)
    }
}

fn verify_access_acls(access: SecAccessRef, executable: &Path) -> bool {
    let mut acls = ptr::null();
    // SAFETY: access is live and the Copy call initializes an owned CFArray.
    if unsafe { SecAccessCopyACLList(access, &mut acls) } != errSecSuccess || acls.is_null() {
        return false;
    }
    let mut found_decrypt = false;
    let count = unsafe { CFArrayGetCount(acls) };
    for index in 0..count {
        let acl = unsafe { CFArrayGetValueAtIndex(acls, index) as SecAclRef };
        let mut authorizations = ptr::null();
        if acl.is_null()
            || unsafe { SecACLCopyAuthorizations(acl, &mut authorizations) } != errSecSuccess
            || authorizations.is_null()
        {
            unsafe { CFRelease(acls.cast()) };
            return false;
        }
        let decrypt = array_contains(
            authorizations,
            unsafe { kSecACLAuthorizationDecrypt }.cast(),
        );
        unsafe { CFRelease(authorizations.cast()) };
        if decrypt {
            found_decrypt = true;
            if !acl_allows_only_executable(acl, executable) {
                unsafe { CFRelease(acls.cast()) };
                return false;
            }
        }
    }
    unsafe { CFRelease(acls.cast()) };
    found_decrypt
}

fn array_contains(array: CFArrayRef, expected: CFTypeRef) -> bool {
    let count = unsafe { CFArrayGetCount(array) };
    (0..count)
        .any(|index| unsafe { CFEqual(CFArrayGetValueAtIndex(array, index).cast(), expected) != 0 })
}

fn acl_allows_only_executable(acl: SecAclRef, executable: &Path) -> bool {
    let mut applications = ptr::null();
    if unsafe { SecACLCopyContents(acl, &mut applications, ptr::null_mut(), ptr::null_mut()) }
        != errSecSuccess
        || applications.is_null()
    {
        return false;
    }
    let count = unsafe { CFArrayGetCount(applications) };
    let trusted = count > 0
        && (0..count).all(|index| {
            let application =
                unsafe { CFArrayGetValueAtIndex(applications, index) as SecTrustedApplicationRef };
            trusted_application_matches(application, executable)
        });
    unsafe { CFRelease(applications.cast()) };
    trusted
}

fn trusted_application_matches(application: SecTrustedApplicationRef, executable: &Path) -> bool {
    let mut data = ptr::null();
    if application.is_null()
        || unsafe { SecTrustedApplicationCopyData(application, &mut data) } != errSecSuccess
        || data.is_null()
    {
        return false;
    }
    let path = unsafe { CFData::wrap_under_create_rule(data) };
    let bytes = path.bytes().strip_suffix(&[0]).unwrap_or(path.bytes());
    if bytes.is_empty() {
        return true;
    }
    std::fs::canonicalize(Path::new(std::ffi::OsStr::from_bytes(bytes)))
        .is_ok_and(|candidate| candidate == executable)
}

/// Repository pinned to one explicitly selected Keychain.
pub struct MacKeychainRepository {
    keychain: SecKeychain,
    executable: PathBuf,
    lock_path: PathBuf,
}

impl MacKeychainRepository {
    pub fn open_login_store() -> Result<Self, StoreError> {
        let home = user_home().ok_or(StoreError::UntrustedStore)?;
        let keychain_path = home.join("Library/Keychains/login.keychain-db");
        let keychain = SecKeychain::open(&keychain_path).map_err(|_| StoreError::UntrustedStore)?;
        let executable = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| StoreError::UntrustedStore)?;
        Ok(Self {
            keychain,
            executable,
            lock_path: keychain_path.with_file_name(".twl-project.lock"),
        })
    }

    fn find_item(&self, name: &str) -> Result<(Vec<u8>, SecKeychainItem), StoreError> {
        let item = self.locate_item(name)?;
        verify_item_acl(&item, &self.executable)?;
        let (payload, _) = self
            .keychain
            .find_generic_password(SERVICE, &account(name))
            .map_err(|error| {
                if error.code() == errSecItemNotFound {
                    StoreError::NotFound
                } else {
                    platform("reading project from Keychain", error)
                }
            })?;
        Ok((payload.as_ref().to_vec(), item))
    }

    fn locate_item(&self, name: &str) -> Result<SecKeychainItem, StoreError> {
        validate_identifier(name)?;
        let results = ItemSearchOptions::new()
            .keychains(std::slice::from_ref(&self.keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(&account(name))
            .load_refs(true)
            .limit(Limit::Max(1))
            .search()
            .map_err(|error| {
                if error.code() == errSecItemNotFound {
                    StoreError::NotFound
                } else {
                    platform("locating project in Keychain", error)
                }
            })?;
        let Some(SearchResult::Ref(Reference::KeychainItem(item))) = results.into_iter().next()
        else {
            return Err(StoreError::MalformedRecord);
        };
        Ok(item)
    }

    fn mutation_lock(&self) -> Result<MutationLock, StoreError> {
        MutationLock::acquire(&self.lock_path)
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
                .find(unsafe { kSecAttrAccount.cast::<std::ffi::c_void>() })
                .ok_or(StoreError::MalformedRecord)?;
            // SAFETY: Security Framework owns this live dictionary value and the account
            // attribute is a CFString for the lifetime of `attributes`.
            let account_value =
                unsafe { CFString::wrap_under_get_rule((*account_value).cast()) }.to_string();
            let name = account_value
                .strip_prefix(ACCOUNT_PREFIX)
                .ok_or(StoreError::MalformedRecord)?;
            validate_identifier(name).map_err(|_| StoreError::MalformedRecord)?;
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
        let _process_guard = self.mutation_lock()?;
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
        let _process_guard = self.mutation_lock()?;
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
        let _process_guard = self.mutation_lock()?;
        let item = self.locate_item(name)?;
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
        MacKeychainRepository::open_login_store()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::repository::exercise_repository;
    use crate::project::ProjectRoute;
    use security_framework::os::macos::keychain::CreateOptions;
    use std::path::PathBuf;
    use std::process::Command;

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
        let store = store_for_path(&path, keychain);
        (path, store)
    }

    fn store_for_path(path: &Path, keychain: SecKeychain) -> MacKeychainRepository {
        MacKeychainRepository {
            keychain,
            executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            lock_path: path.with_extension("lock"),
        }
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

    #[test]
    fn malformed_keychain_item_fails_generically() {
        let (path, store) = test_store("malformed");
        store
            .keychain
            .add_generic_password(SERVICE, &account("app"), b"not: [valid")
            .unwrap();
        assert_eq!(store.get("app").unwrap_err(), StoreError::MalformedRecord);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn permissive_acl_item_is_rejected_before_replacement() {
        let (path, store) = test_store("permissive");
        let payload = project("app", "attacker-key").encode().unwrap();
        let account_value = account("app");
        let status = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-A",
                "-s",
                SERVICE,
                "-a",
                &account_value,
                "-w",
                std::str::from_utf8(&payload).unwrap(),
            ])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let expected = Revision::from_payload(payload);
        assert_eq!(
            store.replace(&expected, &project("app", "real-key")),
            Err(StoreError::UntrustedItem)
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[ignore]
    fn replacement_worker() {
        let Ok(path) = std::env::var("TWL_TEST_KEYCHAIN") else {
            return;
        };
        let result_path = std::env::var("TWL_TEST_RESULT").unwrap();
        let key = std::env::var("TWL_TEST_KEY").unwrap();
        let barrier = std::env::var("TWL_TEST_BARRIER").unwrap();
        while !Path::new(&barrier).exists() {
            std::thread::yield_now();
        }
        let keychain = SecKeychain::open(&path).unwrap();
        let store = store_for_path(Path::new(&path), keychain);
        let revision = Revision::from_payload(project("app", "original-key").encode().unwrap());
        let result = match store.replace(&revision, &project("app", &key)) {
            Ok(()) => "ok",
            Err(StoreError::Conflict) => "conflict",
            Err(error) => panic!("unexpected replacement error: {error}"),
        };
        std::fs::write(result_path, result).unwrap();
    }

    #[test]
    fn replacement_conflicts_are_serialized_between_processes() {
        let (path, store) = test_store("process-race");
        store.create(&project("app", "original-key")).unwrap();
        let barrier = path.with_extension("barrier");
        let first_result = path.with_extension("first-result");
        let second_result = path.with_extension("second-result");
        let worker = |key: &str, result: &Path| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "project::macos::tests::replacement_worker",
                    "--ignored",
                ])
                .env("TWL_TEST_KEYCHAIN", &path)
                .env("TWL_TEST_BARRIER", &barrier)
                .env("TWL_TEST_RESULT", result)
                .env("TWL_TEST_KEY", key)
                .spawn()
                .unwrap()
        };
        let mut first = worker("first-key", &first_result);
        let mut second = worker("second-key", &second_result);
        File::create(&barrier).unwrap();
        assert!(first.wait().unwrap().success());
        assert!(second.wait().unwrap().success());
        let mut outcomes = [
            std::fs::read_to_string(&first_result).unwrap(),
            std::fs::read_to_string(&second_result).unwrap(),
        ];
        outcomes.sort();
        assert_eq!(outcomes, ["conflict", "ok"]);
        store.delete("app").unwrap();
        drop(store);
        for target in [path, barrier, first_result, second_result] {
            let _ = std::fs::remove_file(target);
        }
    }

    struct DefaultKeychainGuard(String);

    impl Drop for DefaultKeychainGuard {
        fn drop(&mut self) {
            let _ = Command::new("/usr/bin/security")
                .args(["default-keychain", "-d", "user", "-s", &self.0])
                .status();
        }
    }

    #[test]
    fn changing_default_keychain_does_not_change_login_store() {
        let original = Command::new("/usr/bin/security")
            .args(["default-keychain", "-d", "user"])
            .output()
            .unwrap();
        assert!(original.status.success());
        let original = String::from_utf8(original.stdout)
            .unwrap()
            .trim()
            .trim_matches('"')
            .to_owned();
        let _guard = DefaultKeychainGuard(original);
        let (path, attacker) = test_store("default-substitution");
        attacker
            .keychain
            .add_generic_password(SERVICE, &account("substitution-test"), b"malformed")
            .unwrap();
        assert!(Command::new("/usr/bin/security")
            .args(["default-keychain", "-d", "user", "-s"])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        let login = MacKeychainRepository::open_login_store().unwrap();
        assert_eq!(
            login.get("substitution-test").unwrap_err(),
            StoreError::NotFound
        );
        drop((login, attacker));
        let _ = std::fs::remove_file(path);
    }
}
