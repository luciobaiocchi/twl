use super::{
    validate_identifier, Action, AuthorizationError, Project, ProjectRepository, ProjectService,
    Revision, SessionAuthorizer, StoreError, StoredProject,
};
use crate::secret;
use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{kCFAllocatorDefault, CFGetTypeID, CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;
use security_framework::base::Error;
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
    kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
    kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};
use std::collections::HashSet;
use std::ffi::c_void;
use std::ptr;

const SERVICE: &str = "dev.towel.project.v1";
const ACCOUNT_PREFIX: &str = "project-v1:";
const ACCESS_GROUP_SUFFIX: &str = "dev.towel.project";
const APPLICATION_IDENTIFIER: &str = "application-identifier";
const TEAM_IDENTIFIER: &str = "com.apple.developer.team-identifier";
const KEYCHAIN_ACCESS_GROUPS: &str = "keychain-access-groups";

type SecTaskRef = *const c_void;

extern "C" {
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    static kSecAttrGeneric: CFStringRef;
    static kSecUseDataProtectionKeychain: CFStringRef;
    fn SecTaskCreateFromSelf(allocator: *const c_void) -> SecTaskRef;
    fn SecTaskCopyValueForEntitlement(
        task: SecTaskRef,
        entitlement: CFStringRef,
        error: *mut CFErrorRef,
    ) -> CFTypeRef;
}

fn account(name: &str) -> String {
    format!("{ACCOUNT_PREFIX}{name}")
}

fn platform(context: &str, status: OSStatus) -> StoreError {
    StoreError::Platform(format!("{context}: {}", Error::from_code(status)))
}

fn add_pair(dict: &mut CFMutableDictionary, key: CFTypeRef, value: CFTypeRef) {
    dict.add(&key, &value);
}

fn base_query(access_group: &str) -> CFMutableDictionary {
    let mut query = CFMutableDictionary::new();
    let service = CFString::new(SERVICE);
    let group = CFString::new(access_group);
    unsafe {
        add_pair(
            &mut query,
            kSecClass.cast(),
            kSecClassGenericPassword.cast(),
        );
        add_pair(&mut query, kSecAttrService.cast(), service.as_CFTypeRef());
        add_pair(&mut query, kSecAttrAccessGroup.cast(), group.as_CFTypeRef());
        add_pair(
            &mut query,
            kSecAttrSynchronizable.cast(),
            CFBoolean::false_value().as_CFTypeRef(),
        );
        add_pair(
            &mut query,
            kSecUseDataProtectionKeychain.cast(),
            CFBoolean::true_value().as_CFTypeRef(),
        );
    }
    query
}

fn query_for(access_group: &str, name: &str) -> CFMutableDictionary {
    let mut query = base_query(access_group);
    let account = CFString::new(&account(name));
    unsafe { add_pair(&mut query, kSecAttrAccount.cast(), account.as_CFTypeRef()) };
    query
}

fn dictionary_value(dictionary: &CFDictionary, key: CFTypeRef) -> Result<CFTypeRef, StoreError> {
    dictionary
        .find(key.cast::<c_void>())
        .map(|value| *value as CFTypeRef)
        .ok_or(StoreError::MalformedRecord)
}

fn data_value(dictionary: &CFDictionary, key: CFTypeRef) -> Result<Vec<u8>, StoreError> {
    let value = dictionary_value(dictionary, key)?;
    if unsafe { CFGetTypeID(value) } != CFData::type_id() {
        return Err(StoreError::MalformedRecord);
    }
    // SAFETY: the dictionary owns this value and its checked runtime type is CFData.
    Ok(unsafe { CFData::wrap_under_get_rule(value.cast()) }
        .bytes()
        .to_vec())
}

fn string_value(dictionary: &CFDictionary, key: CFTypeRef) -> Result<String, StoreError> {
    let value = dictionary_value(dictionary, key)?;
    if unsafe { CFGetTypeID(value) } != CFString::type_id() {
        return Err(StoreError::MalformedRecord);
    }
    // SAFETY: the dictionary owns this value and its checked runtime type is CFString.
    Ok(unsafe { CFString::wrap_under_get_rule(value.cast()) }.to_string())
}

struct StoredRecord {
    payload: Vec<u8>,
    revision: Revision,
}

/// Data Protection Keychain repository scoped to Towel's signed access group.
pub struct MacKeychainRepository {
    access_group: String,
}

impl MacKeychainRepository {
    pub fn open_protected_store() -> Result<Self, StoreError> {
        Ok(Self {
            access_group: effective_access_group()?,
        })
    }

    fn get_record(&self, name: &str) -> Result<StoredRecord, StoreError> {
        validate_identifier(name)?;
        let mut query = query_for(&self.access_group, name);
        unsafe {
            add_pair(
                &mut query,
                kSecReturnData.cast(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            add_pair(
                &mut query,
                kSecReturnAttributes.cast(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
        }
        let mut result = ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if status == errSecItemNotFound {
            return Err(StoreError::NotFound);
        }
        if status != errSecSuccess {
            return Err(platform("reading protected project", status));
        }
        if result.is_null()
            || unsafe { CFGetTypeID(result) }
                != CFDictionary::<*const c_void, *const c_void>::type_id()
        {
            if !result.is_null() {
                unsafe { CFRelease(result) };
            }
            return Err(StoreError::MalformedRecord);
        }
        // SAFETY: SecItemCopyMatching returned a retained CFDictionary.
        let dictionary = unsafe { CFDictionary::wrap_under_create_rule(result.cast()) };
        let payload = data_value(&dictionary, unsafe { kSecValueData.cast() })?;
        let revision = data_value(&dictionary, unsafe { kSecAttrGeneric.cast() })?;
        if revision.len() != Revision::BYTES {
            return Err(StoreError::MalformedRecord);
        }
        Ok(StoredRecord {
            payload,
            revision: Revision::from_bytes(revision),
        })
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        let query = query_for(&self.access_group, name);
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), ptr::null_mut()) };
        match status {
            errSecSuccess => Ok(true),
            errSecItemNotFound => Ok(false),
            status => Err(platform("checking protected project", status)),
        }
    }
}

impl ProjectRepository for MacKeychainRepository {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut query = base_query(&self.access_group);
        unsafe {
            add_pair(
                &mut query,
                kSecReturnAttributes.cast(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            add_pair(&mut query, kSecMatchLimit.cast(), kSecMatchLimitAll.cast());
        }
        let mut result = ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if status == errSecItemNotFound {
            return Ok(Vec::new());
        }
        if status != errSecSuccess {
            return Err(platform("listing protected projects", status));
        }
        if result.is_null() || unsafe { CFGetTypeID(result) } != CFArray::<CFType>::type_id() {
            if !result.is_null() {
                unsafe { CFRelease(result) };
            }
            return Err(StoreError::MalformedRecord);
        }
        // SAFETY: SecItemCopyMatching returned a retained CFArray.
        let results: CFArray<CFType> =
            unsafe { CFArray::wrap_under_create_rule(result as CFArrayRef) };
        let mut seen = HashSet::new();
        let mut names = Vec::with_capacity(results.len() as usize);
        for value in results.iter() {
            if value.type_of() != CFDictionary::<*const c_void, *const c_void>::type_id() {
                return Err(StoreError::MalformedRecord);
            }
            // SAFETY: the array owns this value and its checked runtime type is CFDictionary.
            let dictionary =
                unsafe { CFDictionary::wrap_under_get_rule(value.as_CFTypeRef().cast()) };
            let account = string_value(&dictionary, unsafe { kSecAttrAccount.cast() })?;
            let name = account
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
        let record = self.get_record(name)?;
        let project = Project::decode(&record.payload).map_err(|_| StoreError::MalformedRecord)?;
        if project.name() != name {
            return Err(StoreError::MalformedRecord);
        }
        Ok(StoredProject::new(project, record.revision))
    }

    fn create(&self, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let encoded = project.encode()?;
        let payload = CFData::from_buffer(&encoded);
        let revision = Revision::random();
        let revision_data = CFData::from_buffer(revision.as_bytes());
        let mut attributes = query_for(&self.access_group, project.name());
        unsafe {
            add_pair(
                &mut attributes,
                kSecAttrAccessible.cast(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            );
            add_pair(
                &mut attributes,
                kSecValueData.cast(),
                payload.as_CFTypeRef(),
            );
            add_pair(
                &mut attributes,
                kSecAttrGeneric.cast(),
                revision_data.as_CFTypeRef(),
            );
        }
        let status = unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), ptr::null_mut()) };
        match status {
            errSecSuccess => Ok(()),
            errSecDuplicateItem => Err(StoreError::AlreadyExists),
            status => Err(platform("creating protected project", status)),
        }
    }

    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        if expected.as_bytes().len() != Revision::BYTES {
            return Err(StoreError::Conflict);
        }
        let expected_data = CFData::from_buffer(expected.as_bytes());
        let mut query = query_for(&self.access_group, project.name());
        unsafe {
            add_pair(
                &mut query,
                kSecAttrGeneric.cast(),
                expected_data.as_CFTypeRef(),
            );
        }
        let encoded = project.encode()?;
        let payload = CFData::from_buffer(&encoded);
        let revision = Revision::random();
        let revision_data = CFData::from_buffer(revision.as_bytes());
        let mut update = CFMutableDictionary::new();
        unsafe {
            add_pair(&mut update, kSecValueData.cast(), payload.as_CFTypeRef());
            add_pair(
                &mut update,
                kSecAttrGeneric.cast(),
                revision_data.as_CFTypeRef(),
            );
        }
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
        if status == errSecSuccess {
            return Ok(());
        }
        if status == errSecItemNotFound {
            return if self.exists(project.name())? {
                Err(StoreError::Conflict)
            } else {
                Err(StoreError::NotFound)
            };
        }
        Err(platform("replacing protected project", status))
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        validate_identifier(name)?;
        let query = query_for(&self.access_group, name);
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        match status {
            errSecSuccess => Ok(()),
            errSecItemNotFound => Err(StoreError::NotFound),
            status => Err(platform("deleting protected project", status)),
        }
    }
}

fn copy_entitlement(task: SecTaskRef, name: &str) -> Result<CFType, StoreError> {
    let name = CFString::new(name);
    let mut error = ptr::null_mut();
    let value =
        unsafe { SecTaskCopyValueForEntitlement(task, name.as_concrete_TypeRef(), &mut error) };
    if !error.is_null() {
        unsafe { CFRelease(error.cast()) };
    }
    if value.is_null() {
        return Err(StoreError::UntrustedStore);
    }
    // SAFETY: SecTaskCopyValueForEntitlement returned a retained CF object.
    Ok(unsafe { CFType::wrap_under_create_rule(value) })
}

fn entitlement_string(task: SecTaskRef, name: &str) -> Result<String, StoreError> {
    let value = copy_entitlement(task, name)?;
    if value.type_of() != CFString::type_id() {
        return Err(StoreError::UntrustedStore);
    }
    // SAFETY: value is retained for this scope and its checked runtime type is CFString.
    Ok(unsafe { CFString::wrap_under_get_rule(value.as_CFTypeRef().cast()) }.to_string())
}

fn effective_access_group() -> Result<String, StoreError> {
    let task = unsafe { SecTaskCreateFromSelf(kCFAllocatorDefault.cast()) };
    if task.is_null() {
        return Err(StoreError::UntrustedStore);
    }
    let result = (|| {
        let team = entitlement_string(task, TEAM_IDENTIFIER)?;
        let application = entitlement_string(task, APPLICATION_IDENTIFIER)?;
        if team.is_empty()
            || !team.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !application.starts_with(&format!("{team}."))
        {
            return Err(StoreError::UntrustedStore);
        }
        let expected = format!("{team}.{ACCESS_GROUP_SUFFIX}");
        let groups = copy_entitlement(task, KEYCHAIN_ACCESS_GROUPS)?;
        if groups.type_of() != CFArray::<CFType>::type_id() {
            return Err(StoreError::UntrustedStore);
        }
        // SAFETY: groups is retained for this scope and its checked runtime type is CFArray.
        let groups: CFArray<CFType> =
            unsafe { CFArray::wrap_under_get_rule(groups.as_CFTypeRef().cast()) };
        let present = groups.iter().any(|group| {
            group.type_of() == CFString::type_id()
                && unsafe { CFString::wrap_under_get_rule(group.as_CFTypeRef().cast()) }.to_string()
                    == expected
        });
        if !present {
            return Err(StoreError::UntrustedStore);
        }
        Ok(expected)
    })();
    unsafe { CFRelease(task.cast()) };
    result
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
        MacKeychainRepository::open_protected_store()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revisions_are_random_and_fixed_size() {
        let first = Revision::random();
        let second = Revision::random();
        assert_eq!(first.as_bytes().len(), Revision::BYTES);
        assert_ne!(first, second);
    }

    #[test]
    fn account_names_are_versioned() {
        assert_eq!(account("my-app"), "project-v1:my-app");
    }
}
