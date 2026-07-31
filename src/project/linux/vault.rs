use super::super::{
    validate_identifier, Project, ProjectRepository, Revision, StoreError, StoredProject,
};
use age::secrecy::SecretString;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const VAULT_FILE: &CStr = c"projects.age";
const LOCK_FILE: &CStr = c"projects.age.lock";
const VAULT_VERSION: u32 = 1;
// The count cap is independently reachable with small records; the aggregate plaintext cap
// intentionally prevents 256 maximum-sized projects from occupying one authorization session.
const MAX_PROJECTS: usize = 256;
const MAX_PROJECT_BYTES: usize = 256 << 10;
const MAX_ENCODED_PROJECT_BYTES: usize = ((MAX_PROJECT_BYTES + 2) / 3) * 4;
const MAX_PLAINTEXT_BYTES: u64 = 8 << 20;
// Standard age framing is much smaller; one MiB is a conservative bounded header allowance.
const MAX_AGE_OVERHEAD_BYTES: u64 = 1 << 20;
const MAX_CIPHERTEXT_BYTES: u64 = MAX_PLAINTEXT_BYTES + MAX_AGE_OVERHEAD_BYTES;

fn platform(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Platform(format!("{context}: {error}"))
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not modify memory.
    unsafe { libc::geteuid() }
}

#[derive(Clone, Copy)]
enum TrustScope {
    Store,
    Item,
}

impl TrustScope {
    fn error(self) -> StoreError {
        match self {
            Self::Store => StoreError::UntrustedStore,
            Self::Item => StoreError::UntrustedItem,
        }
    }
}

fn require_mode(file: &File, expected: u32, scope: TrustScope) -> Result<(), StoreError> {
    let actual = file
        .metadata()
        .map_err(|_| scope.error())?
        .permissions()
        .mode()
        & 0o777;
    if actual == expected {
        Ok(())
    } else {
        Err(scope.error())
    }
}

pub(super) fn vault_directory_path() -> Result<PathBuf, StoreError> {
    if let Some(value) = std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return Ok(path.join("twl"));
        }
    }

    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            StoreError::Platform("HOME does not identify an absolute directory".into())
        })?;
    Ok(home.join(".local/share/twl"))
}

/// Trusted directory descriptor used for all vault and lock I/O.
///
/// Entries are opened relative to this descriptor with symlink traversal disabled, then
/// revalidated by ownership, type, link count, and mode on the resulting descriptor.
pub(super) struct VaultDirectory {
    file: File,
}

impl VaultDirectory {
    pub(super) fn open(path: PathBuf) -> Result<Self, StoreError> {
        let parent = path.parent().ok_or(StoreError::UntrustedStore)?;
        fs::create_dir_all(parent).map_err(|error| platform("creating data directory", error))?;
        let created = match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(platform("creating project vault directory", error)),
        };

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| StoreError::UntrustedStore)?;
        let metadata = file.metadata().map_err(|_| StoreError::UntrustedStore)?;
        if !metadata.is_dir() || metadata.uid() != effective_uid() {
            return Err(StoreError::UntrustedStore);
        }
        if created {
            file.set_permissions(Permissions::from_mode(0o700))
                .map_err(|error| platform("securing project vault directory", error))?;
        }
        require_mode(&file, 0o700, TrustScope::Store)?;
        Ok(Self { file })
    }

    fn openat(&self, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
        // SAFETY: the directory descriptor and NUL-terminated name remain valid for the call;
        // a successful descriptor is immediately transferred into File ownership.
        let descriptor = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::mode_t,
            )
        };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    fn validate_file_identity(file: &File) -> Result<std::fs::Metadata, StoreError> {
        let metadata = file.metadata().map_err(|_| StoreError::UntrustedItem)?;
        if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.nlink() != 1 {
            return Err(StoreError::UntrustedItem);
        }
        Ok(metadata)
    }

    pub(super) fn lock(&self, exclusive: bool) -> Result<VaultLock, StoreError> {
        let (file, created) = match self.openat(
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
                self.openat(LOCK_FILE, libc::O_RDWR, 0)
                    .map_err(|_| StoreError::UntrustedItem)?,
                false,
            ),
            Err(_) => return Err(StoreError::UntrustedItem),
        };
        Self::validate_file_identity(&file)?;
        if created {
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|error| platform("securing project vault lock", error))?;
        }
        require_mode(&file, 0o600, TrustScope::Item)?;
        if exclusive {
            FileExt::lock_exclusive(&file)
        } else {
            FileExt::lock_shared(&file)
        }
        .map_err(|error| platform("locking project vault", error))?;
        Self::validate_file_identity(&file)?;
        Ok(VaultLock(file))
    }

    fn shared_lock(&self) -> Result<VaultLock, StoreError> {
        self.lock(false)
    }

    pub(super) fn vault_exists(&self) -> Result<bool, StoreError> {
        let _lock = self.shared_lock()?;
        self.open_vault().map(|vault| vault.is_some())
    }

    pub(super) fn open_vault(&self) -> Result<Option<(File, std::fs::Metadata)>, StoreError> {
        let file = match self.openat(VAULT_FILE, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::UntrustedItem),
        };
        let metadata = Self::validate_file_identity(&file)?;
        require_mode(&file, 0o600, TrustScope::Item)?;
        if metadata.len() > MAX_CIPHERTEXT_BYTES {
            return Err(StoreError::OversizedRecord);
        }
        Ok(Some((file, metadata)))
    }

    fn create_temp(&self, name: &CStr) -> Result<File, StoreError> {
        let file = self
            .openat(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
            .map_err(|error| platform("creating temporary project vault", error))?;
        Self::validate_file_identity(&file)?;
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|error| platform("securing temporary project vault", error))?;
        require_mode(&file, 0o600, TrustScope::Item)?;
        Ok(file)
    }

    fn rename_temp(&self, temporary: &CStr) -> Result<(), StoreError> {
        // SAFETY: both names are valid NUL-terminated strings and both descriptors refer to
        // the same open, trusted directory, making the rename atomic on its filesystem.
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                temporary.as_ptr(),
                self.file.as_raw_fd(),
                VAULT_FILE.as_ptr(),
            )
        };
        if result != 0 {
            return Err(platform(
                "replacing project vault",
                io::Error::last_os_error(),
            ));
        }
        self.file
            .sync_all()
            .map_err(|error| platform("syncing project vault directory", error))
    }

    fn unlink(&self, name: &CStr) {
        // SAFETY: name is a valid NUL-terminated basename relative to the trusted directory.
        unsafe {
            libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0);
        }
    }
}

/// Advisory lock on a stable inode shared by all cooperating TWL processes.
///
/// Reads hold this lock shared and mutations hold it exclusively. It is separate from the vault
/// inode because an atomic vault replacement changes that inode while the lock must remain stable.
pub(super) struct VaultLock(File);

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

#[derive(Default)]
pub(super) struct PasswordState {
    pub(super) password: Option<SecretString>,
    pub(super) operation_lock: Option<PendingLock>,
}

pub(super) struct PendingLock {
    pub(super) exclusive: bool,
    pub(super) lock: VaultLock,
}

#[derive(Clone, Default)]
pub(super) struct PasswordSession(Arc<Mutex<PasswordState>>);

impl PasswordSession {
    pub(super) fn lock(&self) -> Result<MutexGuard<'_, PasswordState>, StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Platform("vault password session is unavailable".into()))
    }

    fn password(&self) -> Result<SecretString, StoreError> {
        self.lock()?
            .password
            .as_ref()
            .cloned()
            .ok_or(StoreError::VaultUnlockFailed)
    }

    fn operation_lock(
        &self,
        directory: &VaultDirectory,
        exclusive: bool,
    ) -> Result<VaultLock, StoreError> {
        if let Some(pending) = self.lock()?.operation_lock.take() {
            if pending.exclusive == exclusive {
                return Ok(pending.lock);
            }
            return Err(StoreError::VaultUnlockFailed);
        }
        directory.lock(exclusive)
    }

    #[cfg(test)]
    fn with_password(password: &str) -> Self {
        Self(Arc::new(Mutex::new(PasswordState {
            password: Some(SecretString::from(password.to_owned())),
            operation_lock: None,
        })))
    }
}

/// Decoded in-memory representation of one encrypted vault entry.
struct VaultRecord {
    name: String,
    revision: Revision,
    payload: Zeroizing<Vec<u8>>,
}

/// Decoded version of the complete plaintext stored inside the age envelope.
#[derive(Default)]
struct Vault {
    records: Vec<VaultRecord>,
}

impl Vault {
    fn decode(plaintext: &[u8]) -> Result<Self, StoreError> {
        let wire: WireVault =
            serde_yaml_ng::from_slice(plaintext).map_err(|_| StoreError::MalformedRecord)?;
        if wire.version != VAULT_VERSION || wire.projects.len() > MAX_PROJECTS {
            return Err(StoreError::MalformedRecord);
        }

        let mut seen = HashSet::with_capacity(wire.projects.len());
        let mut records = Vec::with_capacity(wire.projects.len());
        for record in &wire.projects {
            validate_identifier(&record.name).map_err(|_| StoreError::MalformedRecord)?;
            let revision = STANDARD_NO_PAD
                .decode(record.revision.as_bytes())
                .map_err(|_| StoreError::MalformedRecord)?;
            if revision.len() != Revision::BYTES {
                return Err(StoreError::MalformedRecord);
            }
            if record.project.len() > MAX_ENCODED_PROJECT_BYTES {
                return Err(StoreError::OversizedRecord);
            }
            let payload = Zeroizing::new(
                STANDARD_NO_PAD
                    .decode(record.project.as_bytes())
                    .map_err(|_| StoreError::MalformedRecord)?,
            );
            if payload.len() > MAX_PROJECT_BYTES {
                return Err(StoreError::OversizedRecord);
            }
            let project = Project::decode(&payload).map_err(|_| StoreError::MalformedRecord)?;
            if project.name() != record.name || !seen.insert(record.name.clone()) {
                return Err(StoreError::MalformedRecord);
            }
            records.push(VaultRecord {
                name: record.name.clone(),
                revision: Revision::from_bytes(revision),
                payload,
            });
        }
        Ok(Self { records })
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if self.records.len() > MAX_PROJECTS {
            return Err(StoreError::OversizedRecord);
        }
        let wire = WireVault {
            version: VAULT_VERSION,
            projects: self
                .records
                .iter()
                .map(|record| WireRecord {
                    name: record.name.clone(),
                    revision: STANDARD_NO_PAD.encode(record.revision.as_bytes()),
                    project: STANDARD_NO_PAD.encode(&*record.payload),
                })
                .collect(),
        };
        let plaintext = Zeroizing::new(
            serde_yaml_ng::to_string(&wire)
                .map_err(|_| StoreError::MalformedRecord)?
                .into_bytes(),
        );
        if plaintext.len() as u64 > MAX_PLAINTEXT_BYTES {
            return Err(StoreError::OversizedRecord);
        }
        Ok(plaintext)
    }

    fn decoded_at(&self, index: usize) -> Result<Project, StoreError> {
        Project::decode(&self.records[index].payload).map_err(|_| StoreError::MalformedRecord)
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.records.iter().position(|record| record.name == name)
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
/// Versioned plaintext wire envelope serialized as YAML inside the encrypted age file.
struct WireVault {
    #[zeroize(skip)]
    version: u32,
    projects: Vec<WireRecord>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
/// YAML wire entry containing a name plus unpadded base64 revision and project payload.
struct WireRecord {
    #[zeroize(skip)]
    name: String,
    #[zeroize(skip)]
    revision: String,
    project: String,
}

/// Password-encrypted, age-compatible Linux project repository.
pub struct LinuxAgeVaultRepository {
    pub(super) directory: Arc<VaultDirectory>,
    pub(super) session: PasswordSession,
    pub(super) scrypt_work_factor_override: Option<u8>,
}

impl LinuxAgeVaultRepository {
    #[cfg(test)]
    fn open_for_test(path: PathBuf, password: &str) -> Result<Self, StoreError> {
        Ok(Self {
            directory: Arc::new(VaultDirectory::open(path)?),
            session: PasswordSession::with_password(password),
            scrypt_work_factor_override: Some(2),
        })
    }

    /// Reads and decrypts the vault while the caller keeps a shared or exclusive lock alive.
    fn read_locked(&self, _lock: &VaultLock) -> Result<Option<Vault>, StoreError> {
        let Some((mut file, metadata)) = self.directory.open_vault()? else {
            return Ok(None);
        };
        let mut ciphertext = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(MAX_CIPHERTEXT_BYTES + 1)
            .read_to_end(&mut ciphertext)
            .map_err(|error| platform("reading project vault", error))?;
        if ciphertext.len() as u64 > MAX_CIPHERTEXT_BYTES {
            return Err(StoreError::OversizedRecord);
        }

        let password = self.session.password()?;
        let decryptor = age::Decryptor::new_buffered(ciphertext.as_slice())
            .map_err(|_| StoreError::VaultUnlockFailed)?;
        if !decryptor.is_scrypt() {
            return Err(StoreError::VaultUnlockFailed);
        }
        let identity = age::scrypt::Identity::new(password);
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|_| StoreError::VaultUnlockFailed)?;
        let mut plaintext = Zeroizing::new(Vec::new());
        reader
            .by_ref()
            .take(MAX_PLAINTEXT_BYTES + 1)
            .read_to_end(&mut plaintext)
            .map_err(|_| StoreError::VaultUnlockFailed)?;
        if plaintext.len() as u64 > MAX_PLAINTEXT_BYTES {
            return Err(StoreError::OversizedRecord);
        }
        Vault::decode(&plaintext).map(Some)
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let password = self.session.password()?;
        let mut ciphertext = Vec::new();
        {
            let mut recipient = age::scrypt::Recipient::new(password);
            if let Some(work_factor) = self.scrypt_work_factor_override {
                recipient.set_work_factor(work_factor);
            }
            let encryptor =
                age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                    .map_err(|error| platform("initializing project vault encryption", error))?;
            let mut writer = encryptor
                .wrap_output(&mut ciphertext)
                .map_err(|error| platform("initializing project vault output", error))?;
            writer
                .write_all(plaintext)
                .map_err(|error| platform("encrypting project vault", error))?;
            writer
                .finish()
                .map_err(|error| platform("finishing project vault encryption", error))?;
        }
        if ciphertext.len() as u64 > MAX_CIPHERTEXT_BYTES {
            return Err(StoreError::OversizedRecord);
        }
        Ok(ciphertext)
    }

    /// Encrypts and atomically replaces the vault while the caller holds an exclusive lock.
    fn write_locked(&self, _lock: &VaultLock, vault: &Vault) -> Result<(), StoreError> {
        // Revalidate a current target immediately before replacing it. The stable lock file
        // coordinates all cooperating TWL processes while the vault inode changes atomically.
        self.directory.open_vault()?;
        let plaintext = vault.encode()?;
        let ciphertext = self.encrypt(&plaintext)?;
        let mut random = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let temporary_name = format!(".projects.age.tmp.{}", URL_SAFE_NO_PAD.encode(random));
        let temporary = CString::new(temporary_name).expect("base64 filename has no NUL");
        let result = (|| {
            let mut file = self.directory.create_temp(&temporary)?;
            file.write_all(&ciphertext)
                .map_err(|error| platform("writing temporary project vault", error))?;
            file.sync_all()
                .map_err(|error| platform("syncing temporary project vault", error))?;
            drop(file);
            self.directory.rename_temp(&temporary)
        })();
        if result.is_err() {
            self.directory.unlink(&temporary);
        }
        result
    }

    fn encode_project(project: &Project) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        project.validate()?;
        let payload = project.encode()?;
        if payload.len() > MAX_PROJECT_BYTES {
            return Err(StoreError::OversizedRecord);
        }
        Ok(payload)
    }
}

impl ProjectRepository for LinuxAgeVaultRepository {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        let lock = self.session.operation_lock(&self.directory, false)?;
        let Some(vault) = self.read_locked(&lock)? else {
            return Ok(Vec::new());
        };
        let mut names: Vec<_> = vault
            .records
            .iter()
            .map(|record| record.name.clone())
            .collect();
        names.sort();
        Ok(names)
    }

    fn get(&self, name: &str) -> Result<StoredProject, StoreError> {
        validate_identifier(name)?;
        let lock = self.session.operation_lock(&self.directory, false)?;
        let vault = self.read_locked(&lock)?.ok_or(StoreError::NotFound)?;
        let index = vault.find(name).ok_or(StoreError::NotFound)?;
        Ok(StoredProject::new(
            vault.decoded_at(index)?,
            vault.records[index].revision.clone(),
        ))
    }

    fn create(&self, project: &Project) -> Result<(), StoreError> {
        let payload = Self::encode_project(project)?;
        let lock = self.session.operation_lock(&self.directory, true)?;
        let mut vault = self.read_locked(&lock)?.unwrap_or_default();
        if vault.find(project.name()).is_some() {
            return Err(StoreError::AlreadyExists);
        }
        if vault.records.len() == MAX_PROJECTS {
            return Err(StoreError::OversizedRecord);
        }
        vault.records.push(VaultRecord {
            name: project.name().to_owned(),
            revision: Revision::random(),
            payload,
        });
        self.write_locked(&lock, &vault)
    }

    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError> {
        let payload = Self::encode_project(project)?;
        let lock = self.session.operation_lock(&self.directory, true)?;
        let mut vault = self.read_locked(&lock)?.ok_or(StoreError::NotFound)?;
        let index = vault.find(project.name()).ok_or(StoreError::NotFound)?;
        if &vault.records[index].revision != expected {
            return Err(StoreError::Conflict);
        }
        vault.records[index] = VaultRecord {
            name: project.name().to_owned(),
            revision: Revision::random(),
            payload,
        };
        self.write_locked(&lock, &vault)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        validate_identifier(name)?;
        let lock = self.session.operation_lock(&self.directory, true)?;
        let mut vault = self.read_locked(&lock)?.ok_or(StoreError::NotFound)?;
        let index = vault.find(name).ok_or(StoreError::NotFound)?;
        vault.records.remove(index);
        self.write_locked(&lock, &vault)
    }
}

#[cfg(test)]
mod tests {
    use super::super::LinuxVaultAuthorizer;
    use super::*;
    use crate::project::repository::exercise_repository;
    use crate::project::{Action, ProjectRoute, SessionAuthorizer};
    use std::os::unix::fs::symlink;
    use std::process::{Command, Output, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const LOCK_CHILD_DIRECTORY_ENV: &str = "TWL_TEST_LOCK_CHILD_DIRECTORY";
    const LOCK_CHILD_NAME_ENV: &str = "TWL_TEST_LOCK_CHILD_NAME";
    const LOCK_CHILD_READY_ENV: &str = "TWL_TEST_LOCK_CHILD_READY";
    const LOCK_CHILD_START_ENV: &str = "TWL_TEST_LOCK_CHILD_START";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut random);
            Self(std::env::temp_dir().join(format!(
                "twl-linux-test-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(random)
            )))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repository(directory: &TestDirectory, password: &str) -> LinuxAgeVaultRepository {
        LinuxAgeVaultRepository::open_for_test(directory.0.clone(), password).unwrap()
    }

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

    fn wire_record(name: &str) -> WireRecord {
        WireRecord {
            name: name.to_owned(),
            revision: STANDARD_NO_PAD.encode([7; Revision::BYTES]),
            project: STANDARD_NO_PAD.encode(&*project(name, "key").encode().unwrap()),
        }
    }

    fn wire_bytes(projects: Vec<WireRecord>) -> Vec<u8> {
        serde_yaml_ng::to_string(&WireVault {
            version: VAULT_VERSION,
            projects,
        })
        .unwrap()
        .into_bytes()
    }

    fn spawn_lock_child(
        directory: &TestDirectory,
        name: &str,
        ready: &std::path::Path,
        start: &std::path::Path,
    ) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .arg("separate_repository_process_lock_child")
            .arg("--nocapture")
            .env(LOCK_CHILD_DIRECTORY_ENV, &directory.0)
            .env(LOCK_CHILD_NAME_ENV, name)
            .env(LOCK_CHILD_READY_ENV, ready)
            .env(LOCK_CHILD_START_ENV, start)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn assert_child_success(name: &str, output: Output) {
        assert!(
            output.status.success(),
            "{name} child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn age_vault_repository_conforms() {
        let directory = TestDirectory::new();
        exercise_repository(&repository(&directory, "correct horse battery staple"));
        let vault = fs::metadata(directory.0.join("projects.age")).unwrap();
        let lock = fs::metadata(directory.0.join("projects.age.lock")).unwrap();
        let directory_metadata = fs::metadata(&directory.0).unwrap();
        assert_eq!(vault.permissions().mode() & 0o777, 0o600);
        assert_eq!(lock.permissions().mode() & 0o777, 0o600);
        assert_eq!(directory_metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn wrong_password_and_corrupted_ciphertext_are_indistinguishable() {
        let directory = TestDirectory::new();
        repository(&directory, "right-password")
            .create(&project("app", "real-key"))
            .unwrap();
        let wrong = repository(&directory, "wrong-password");
        let wrong_error = wrong.get("app").unwrap_err();

        let vault_path = directory.0.join("projects.age");
        let mut ciphertext = fs::read(&vault_path).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        fs::write(&vault_path, ciphertext).unwrap();
        fs::set_permissions(&vault_path, Permissions::from_mode(0o600)).unwrap();
        let corrupt_error = repository(&directory, "right-password")
            .get("app")
            .unwrap_err();

        assert_eq!(wrong_error, StoreError::VaultUnlockFailed);
        assert_eq!(corrupt_error, StoreError::VaultUnlockFailed);
        assert_eq!(wrong_error.to_string(), corrupt_error.to_string());
        assert!(!wrong_error.to_string().contains("right-password"));
        assert!(!wrong_error.to_string().contains("wrong-password"));
    }

    #[test]
    fn vault_is_an_age_scrypt_file_and_hides_plaintext() {
        let directory = TestDirectory::new();
        repository(&directory, "interoperable-password")
            .create(&project("app", "credential-not-in-ciphertext"))
            .unwrap();
        let ciphertext = fs::read(directory.0.join("projects.age")).unwrap();
        assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
        assert!(!ciphertext
            .windows(b"credential-not-in-ciphertext".len())
            .any(|window| window == b"credential-not-in-ciphertext"));

        let decryptor = age::Decryptor::new_buffered(ciphertext.as_slice()).unwrap();
        assert!(decryptor.is_scrypt());
        let identity =
            age::scrypt::Identity::new(SecretString::from("interoperable-password".to_owned()));
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plaintext = Zeroizing::new(Vec::new());
        reader.read_to_end(&mut plaintext).unwrap();
        let vault = Vault::decode(&plaintext).unwrap();
        let decoded = vault.decoded_at(0).unwrap();
        assert_eq!(
            decoded.routes()[0].clone().into_parts().2,
            "credential-not-in-ciphertext"
        );
    }

    #[test]
    fn production_scrypt_configuration_round_trips() {
        let directory = TestDirectory::new();
        let mut repository = repository(&directory, "production-password");
        repository.scrypt_work_factor_override = None;
        repository
            .create(&project("app", "production-path-key"))
            .unwrap();
        assert_eq!(
            repository.get("app").unwrap().project().routes()[0]
                .clone()
                .into_parts()
                .2,
            "production-path-key"
        );
    }

    #[test]
    fn malformed_vault_payloads_are_rejected() {
        let mut invalid_identifier = wire_record("app");
        invalid_identifier.name = "not valid".into();

        let mut malformed_revision = wire_record("app");
        malformed_revision.revision = "%".into();

        let mut short_revision = wire_record("app");
        short_revision.revision =
            STANDARD_NO_PAD.encode(vec![0_u8; Revision::BYTES.saturating_sub(1)]);

        let mut oversized_encoded_project = wire_record("app");
        oversized_encoded_project.project = "A".repeat(MAX_ENCODED_PROJECT_BYTES + 1);

        let oversized_payload = vec![0_u8; MAX_PROJECT_BYTES + 1];
        let oversized_payload_encoding = STANDARD_NO_PAD.encode(&oversized_payload);
        assert!(oversized_payload_encoding.len() <= MAX_ENCODED_PROJECT_BYTES);
        let mut oversized_decoded_project = wire_record("app");
        oversized_decoded_project.project = oversized_payload_encoding;

        let mut malformed_project_base64 = wire_record("app");
        malformed_project_base64.project = "%".into();

        let mut malformed_project = wire_record("app");
        malformed_project.project = STANDARD_NO_PAD.encode([0xff]);

        let mut mismatched_name = wire_record("payload-name");
        mismatched_name.name = "wire-name".into();

        let too_many_projects = (0..=MAX_PROJECTS)
            .map(|index| wire_record(&format!("project-{index}")))
            .collect();

        let cases = vec![
            (
                "unparseable yaml",
                b"projects: [".to_vec(),
                StoreError::MalformedRecord,
            ),
            (
                "unknown wire field",
                b"version: 1\nprojects: []\nextra: true\n".to_vec(),
                StoreError::MalformedRecord,
            ),
            (
                "wrong version",
                serde_yaml_ng::to_string(&WireVault {
                    version: VAULT_VERSION + 1,
                    projects: Vec::new(),
                })
                .unwrap()
                .into_bytes(),
                StoreError::MalformedRecord,
            ),
            (
                "too many projects",
                wire_bytes(too_many_projects),
                StoreError::MalformedRecord,
            ),
            (
                "invalid identifier",
                wire_bytes(vec![invalid_identifier]),
                StoreError::MalformedRecord,
            ),
            (
                "malformed revision base64",
                wire_bytes(vec![malformed_revision]),
                StoreError::MalformedRecord,
            ),
            (
                "wrong revision length",
                wire_bytes(vec![short_revision]),
                StoreError::MalformedRecord,
            ),
            (
                "oversized encoded project",
                wire_bytes(vec![oversized_encoded_project]),
                StoreError::OversizedRecord,
            ),
            (
                "malformed project base64",
                wire_bytes(vec![malformed_project_base64]),
                StoreError::MalformedRecord,
            ),
            (
                "oversized decoded project",
                wire_bytes(vec![oversized_decoded_project]),
                StoreError::OversizedRecord,
            ),
            (
                "malformed project payload",
                wire_bytes(vec![malformed_project]),
                StoreError::MalformedRecord,
            ),
            (
                "wire and project names differ",
                wire_bytes(vec![mismatched_name]),
                StoreError::MalformedRecord,
            ),
            (
                "duplicate project name",
                wire_bytes(vec![wire_record("duplicate"), wire_record("duplicate")]),
                StoreError::MalformedRecord,
            ),
        ];

        for (case, payload, expected) in cases {
            assert_eq!(Vault::decode(&payload).err(), Some(expected), "{case}");
        }
    }

    #[test]
    fn vault_symlinks_are_rejected() {
        let directory = TestDirectory::new();
        let repository = repository(&directory, "password");
        repository.create(&project("app", "key")).unwrap();
        let vault_path = directory.0.join("projects.age");
        fs::remove_file(&vault_path).unwrap();
        symlink("/dev/null", &vault_path).unwrap();
        assert_eq!(repository.list(), Err(StoreError::UntrustedItem));
    }

    #[test]
    fn unsafe_vault_modes_and_lock_symlinks_are_rejected() {
        let directory = TestDirectory::new();
        let repository = repository(&directory, "password");
        repository.create(&project("app", "key")).unwrap();
        let vault_path = directory.0.join("projects.age");
        fs::set_permissions(&vault_path, Permissions::from_mode(0o644)).unwrap();
        assert_eq!(repository.list(), Err(StoreError::UntrustedItem));

        fs::set_permissions(&vault_path, Permissions::from_mode(0o600)).unwrap();
        let lock_path = directory.0.join("projects.age.lock");
        fs::set_permissions(&lock_path, Permissions::from_mode(0o644)).unwrap();
        assert_eq!(repository.list(), Err(StoreError::UntrustedItem));

        fs::set_permissions(&lock_path, Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&lock_path).unwrap();
        symlink("/dev/null", &lock_path).unwrap();
        assert_eq!(repository.list(), Err(StoreError::UntrustedItem));
    }

    #[test]
    fn unsafe_existing_vault_directory_mode_is_rejected() {
        let directory = TestDirectory::new();
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            LinuxAgeVaultRepository::open_for_test(directory.0.clone(), "password")
                .err()
                .unwrap(),
            StoreError::UntrustedStore
        );
    }

    #[test]
    fn ciphertext_size_limit_is_enforced_before_decryption() {
        let directory = TestDirectory::new();
        let repository = repository(&directory, "password");
        let vault_path = directory.0.join("projects.age");
        let file = File::create(&vault_path).unwrap();
        file.set_len(MAX_CIPHERTEXT_BYTES + 1).unwrap();
        fs::set_permissions(&vault_path, Permissions::from_mode(0o600)).unwrap();
        assert_eq!(repository.list(), Err(StoreError::OversizedRecord));
    }

    #[test]
    fn separate_repository_process_lock_child() {
        let Some(directory) = std::env::var_os(LOCK_CHILD_DIRECTORY_ENV) else {
            return;
        };
        let name = std::env::var(LOCK_CHILD_NAME_ENV).unwrap();
        let ready = PathBuf::from(std::env::var_os(LOCK_CHILD_READY_ENV).unwrap());
        let start = PathBuf::from(std::env::var_os(LOCK_CHILD_START_ENV).unwrap());
        let repository =
            LinuxAgeVaultRepository::open_for_test(PathBuf::from(directory), "password").unwrap();
        fs::write(&ready, b"ready").unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !start.exists() {
            assert!(
                Instant::now() < deadline,
                "parent did not release the lock-test children"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        repository
            .create(&project(&name, &format!("{name}-key")))
            .unwrap();
    }

    #[test]
    fn separate_processes_share_the_lock() {
        let directory = TestDirectory::new();
        let parent = repository(&directory, "password");
        let first_ready = directory.0.join(".first-ready");
        let second_ready = directory.0.join(".second-ready");
        let start = directory.0.join(".start");
        let mut first = spawn_lock_child(&directory, "one", &first_ready, &start);
        let mut second = spawn_lock_child(&directory, "two", &second_ready, &start);

        let deadline = Instant::now() + Duration::from_secs(10);
        while !first_ready.exists() || !second_ready.exists() {
            if Instant::now() >= deadline {
                let _ = first.kill();
                let _ = second.kill();
                let first_output = first.wait_with_output().unwrap();
                let second_output = second.wait_with_output().unwrap();
                panic!(
                    "lock-test children did not become ready\nfirst stderr:\n{}\nsecond stderr:\n{}",
                    String::from_utf8_lossy(&first_output.stderr),
                    String::from_utf8_lossy(&second_output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        fs::write(&start, b"start").unwrap();
        assert_child_success("first", first.wait_with_output().unwrap());
        assert_child_success("second", second.wait_with_output().unwrap());
        assert_eq!(parent.list().unwrap(), ["one", "two"]);
    }

    #[test]
    fn authorizer_prompts_twice_only_for_first_creation_and_once_afterward() {
        let directory = TestDirectory::new();
        let session = PasswordSession::default();
        let vault_directory = Arc::new(VaultDirectory::open(directory.0.clone()).unwrap());
        let repository = LinuxAgeVaultRepository {
            directory: vault_directory.clone(),
            session: session.clone(),
            scrypt_work_factor_override: Some(2),
        };
        let prompts = Arc::new(AtomicUsize::new(0));
        let marker = prompts.clone();
        let authorizer = LinuxVaultAuthorizer {
            session,
            directory: vault_directory,
            prompt: Arc::new(move |_| {
                marker.fetch_add(1, Ordering::SeqCst);
                Ok(SecretString::from("password".to_owned()))
            }),
        };
        authorizer.authorize(Action::Create("app")).unwrap();
        authorizer.authorize(Action::Replace("app")).unwrap();
        assert_eq!(prompts.load(Ordering::SeqCst), 2);
        repository.create(&project("app", "key")).unwrap();

        let session = PasswordSession::default();
        let existing = LinuxAgeVaultRepository {
            directory: repository.directory.clone(),
            session: session.clone(),
            scrypt_work_factor_override: Some(2),
        };
        let prompts = Arc::new(AtomicUsize::new(0));
        let marker = prompts.clone();
        let authorizer = LinuxVaultAuthorizer {
            session,
            directory: existing.directory.clone(),
            prompt: Arc::new(move |_| {
                marker.fetch_add(1, Ordering::SeqCst);
                Ok(SecretString::from("password".to_owned()))
            }),
        };
        authorizer.authorize(Action::Read("app")).unwrap();
        authorizer.authorize(Action::Replace("app")).unwrap();
        assert_eq!(prompts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn authorizer_reprompts_if_vault_appears_before_operation_lock() {
        let directory = TestDirectory::new();
        let session = PasswordSession::default();
        let vault_directory = Arc::new(VaultDirectory::open(directory.0.clone()).unwrap());
        let target = LinuxAgeVaultRepository {
            directory: vault_directory.clone(),
            session: session.clone(),
            scrypt_work_factor_override: Some(2),
        };
        let competing = Arc::new(repository(&directory, "existing-password"));
        let prompts = Arc::new(AtomicUsize::new(0));
        let marker = prompts.clone();
        let authorizer = LinuxVaultAuthorizer {
            session,
            directory: vault_directory,
            prompt: Arc::new(move |label| {
                let prompt = marker.fetch_add(1, Ordering::SeqCst);
                if prompt == 0 {
                    assert_eq!(label, "Create Towel vault password: ");
                    competing
                        .create(&project("existing", "existing-key"))
                        .unwrap();
                    return Ok(SecretString::from("new-password".to_owned()));
                }
                if prompt == 1 {
                    assert_eq!(label, "Confirm Towel vault password: ");
                    return Ok(SecretString::from("new-password".to_owned()));
                }
                assert_eq!(label, "Towel vault password: ");
                Ok(SecretString::from("existing-password".to_owned()))
            }),
        };

        authorizer.authorize(Action::Create("second")).unwrap();
        target.create(&project("second", "second-key")).unwrap();

        assert_eq!(prompts.load(Ordering::SeqCst), 3);
        assert_eq!(
            repository(&directory, "existing-password").list().unwrap(),
            ["existing", "second"]
        );
    }

    #[test]
    fn missing_authorization_uses_generic_vault_error() {
        assert!(matches!(
            PasswordSession::default().password(),
            Err(StoreError::VaultUnlockFailed)
        ));
    }
}
