use super::{
    Action, AuthorizationError, Project, ProjectRepository, ProjectService, Revision,
    SessionAuthorizer, StoreError, StoredProject,
};
use age::secrecy::{ExposeSecret, SecretString};
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
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const VAULT_FILE: &CStr = c"projects.age";
const LOCK_FILE: &CStr = c"projects.age.lock";
const VAULT_VERSION: u32 = 1;
const REVISION_BYTES: usize = 32;
const MAX_PROJECTS: usize = 256;
const MAX_PROJECT_BYTES: usize = 256 << 10;
const MAX_PLAINTEXT_BYTES: u64 = 8 << 20;
const MAX_CIPHERTEXT_BYTES: u64 = 9 << 20;

fn platform(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Platform(format!("{context}: {error}"))
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not modify memory.
    unsafe { libc::geteuid() }
}

fn vault_directory_path() -> Result<PathBuf, StoreError> {
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

struct VaultDirectory {
    file: File,
}

impl VaultDirectory {
    fn open(path: PathBuf) -> Result<Self, StoreError> {
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
        } else if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(StoreError::UntrustedStore);
        }
        let metadata = file.metadata().map_err(|_| StoreError::UntrustedStore)?;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(StoreError::UntrustedStore);
        }
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

    fn lock(&self, exclusive: bool) -> Result<VaultLock, StoreError> {
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
        let metadata = Self::validate_file_identity(&file)?;
        if created {
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|error| platform("securing project vault lock", error))?;
        } else if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(StoreError::UntrustedItem);
        }
        if file
            .metadata()
            .map_err(|_| StoreError::UntrustedItem)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(StoreError::UntrustedItem);
        }
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

    fn exclusive_lock(&self) -> Result<VaultLock, StoreError> {
        self.lock(true)
    }

    fn open_vault(&self) -> Result<Option<(File, std::fs::Metadata)>, StoreError> {
        let file = match self.openat(VAULT_FILE, libc::O_RDONLY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::UntrustedItem),
        };
        let metadata = Self::validate_file_identity(&file)?;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(StoreError::UntrustedItem);
        }
        if metadata.len() > MAX_CIPHERTEXT_BYTES {
            return Err(StoreError::VaultUnlockFailed);
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
        if file
            .metadata()
            .map_err(|_| StoreError::UntrustedItem)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(StoreError::UntrustedItem);
        }
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

struct VaultLock(File);

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

#[derive(Clone, Default)]
struct PasswordSession(Arc<Mutex<Option<SecretString>>>);

impl PasswordSession {
    fn lock(&self) -> Result<MutexGuard<'_, Option<SecretString>>, StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::Platform("vault password session is unavailable".into()))
    }

    fn password(&self) -> Result<SecretString, StoreError> {
        self.lock()?
            .as_ref()
            .cloned()
            .ok_or_else(|| StoreError::Platform("vault password was not authorized".into()))
    }

    #[cfg(test)]
    fn with_password(password: &str) -> Self {
        Self(Arc::new(Mutex::new(Some(SecretString::from(
            password.to_owned(),
        )))))
    }
}

struct VaultRecord {
    name: String,
    revision: Revision,
    payload: Zeroizing<Vec<u8>>,
}

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
            super::validate_identifier(&record.name).map_err(|_| StoreError::MalformedRecord)?;
            let revision = STANDARD_NO_PAD
                .decode(record.revision.as_bytes())
                .map_err(|_| StoreError::MalformedRecord)?;
            if revision.len() != REVISION_BYTES
                || record.project.len() > MAX_PROJECT_BYTES.saturating_mul(2)
            {
                return Err(StoreError::MalformedRecord);
            }
            let payload = Zeroizing::new(
                STANDARD_NO_PAD
                    .decode(record.project.as_bytes())
                    .map_err(|_| StoreError::MalformedRecord)?,
            );
            if payload.len() > MAX_PROJECT_BYTES {
                return Err(StoreError::MalformedRecord);
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
            return Err(StoreError::MalformedRecord);
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
            return Err(StoreError::MalformedRecord);
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
struct WireVault {
    version: u32,
    projects: Vec<WireRecord>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    name: String,
    revision: String,
    project: String,
}

/// Password-encrypted, age-compatible Linux project repository.
pub struct LinuxAgeVaultRepository {
    directory: Arc<VaultDirectory>,
    session: PasswordSession,
}

impl LinuxAgeVaultRepository {
    fn open(session: PasswordSession) -> Result<Self, StoreError> {
        let directory = Arc::new(VaultDirectory::open(vault_directory_path()?)?);
        Ok(Self { directory, session })
    }

    #[cfg(test)]
    fn open_for_test(path: PathBuf, password: &str) -> Result<Self, StoreError> {
        Ok(Self {
            directory: Arc::new(VaultDirectory::open(path)?),
            session: PasswordSession::with_password(password),
        })
    }

    fn vault_exists(&self) -> Result<bool, StoreError> {
        let _lock = self.directory.shared_lock()?;
        self.directory.open_vault().map(|vault| vault.is_some())
    }

    fn read_locked(&self) -> Result<Option<Vault>, StoreError> {
        let Some((mut file, metadata)) = self.directory.open_vault()? else {
            return Ok(None);
        };
        let mut ciphertext = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(MAX_CIPHERTEXT_BYTES + 1)
            .read_to_end(&mut ciphertext)
            .map_err(|error| platform("reading project vault", error))?;
        if ciphertext.len() as u64 > MAX_CIPHERTEXT_BYTES {
            return Err(StoreError::VaultUnlockFailed);
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
            return Err(StoreError::VaultUnlockFailed);
        }
        Vault::decode(&plaintext).map(Some)
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let password = self.session.password()?;
        let mut ciphertext = Vec::new();
        {
            #[cfg(not(test))]
            let encryptor = age::Encryptor::with_user_passphrase(password);
            #[cfg(test)]
            let encryptor = {
                let mut recipient = age::scrypt::Recipient::new(password);
                recipient.set_work_factor(2);
                age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                    .map_err(|error| platform("initializing project vault encryption", error))?
            };
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
            return Err(StoreError::MalformedRecord);
        }
        Ok(ciphertext)
    }

    fn write_locked(&self, vault: &Vault) -> Result<(), StoreError> {
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

    fn random_revision() -> Revision {
        let mut bytes = vec![0_u8; REVISION_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Revision::from_bytes(bytes)
    }
}

impl ProjectRepository for LinuxAgeVaultRepository {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        let _lock = self.directory.shared_lock()?;
        let Some(vault) = self.read_locked()? else {
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
        super::validate_identifier(name)?;
        let _lock = self.directory.shared_lock()?;
        let vault = self.read_locked()?.ok_or(StoreError::NotFound)?;
        let index = vault.find(name).ok_or(StoreError::NotFound)?;
        Ok(StoredProject::new(
            vault.decoded_at(index)?,
            vault.records[index].revision.clone(),
        ))
    }

    fn create(&self, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let payload = Zeroizing::new(project.encode()?);
        if payload.len() > MAX_PROJECT_BYTES {
            return Err(StoreError::MalformedRecord);
        }
        let _lock = self.directory.exclusive_lock()?;
        let mut vault = self.read_locked()?.unwrap_or_default();
        if vault.find(project.name()).is_some() {
            return Err(StoreError::AlreadyExists);
        }
        if vault.records.len() == MAX_PROJECTS {
            return Err(StoreError::MalformedRecord);
        }
        vault.records.push(VaultRecord {
            name: project.name().to_owned(),
            revision: Self::random_revision(),
            payload,
        });
        self.write_locked(&vault)
    }

    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let payload = Zeroizing::new(project.encode()?);
        if payload.len() > MAX_PROJECT_BYTES {
            return Err(StoreError::MalformedRecord);
        }
        let _lock = self.directory.exclusive_lock()?;
        let mut vault = self.read_locked()?.ok_or(StoreError::NotFound)?;
        let index = vault.find(project.name()).ok_or(StoreError::NotFound)?;
        if &vault.records[index].revision != expected {
            return Err(StoreError::Conflict);
        }
        vault.records[index] = VaultRecord {
            name: project.name().to_owned(),
            revision: Self::random_revision(),
            payload,
        };
        self.write_locked(&vault)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        super::validate_identifier(name)?;
        let _lock = self.directory.exclusive_lock()?;
        let mut vault = self.read_locked()?.ok_or(StoreError::NotFound)?;
        let index = vault.find(name).ok_or(StoreError::NotFound)?;
        vault.records.remove(index);
        self.write_locked(&vault)
    }
}

type PasswordPrompt = Arc<dyn Fn(&str) -> Result<SecretString, String> + Send + Sync>;

/// Authorizes one Linux service session with one password read from `/dev/tty`.
pub struct LinuxVaultAuthorizer {
    repository: Arc<LinuxAgeVaultRepository>,
    prompt: PasswordPrompt,
}

impl SessionAuthorizer for LinuxVaultAuthorizer {
    fn authorize(&self, action: Action<'_>) -> Result<(), AuthorizationError> {
        let mut session = self
            .repository
            .session
            .lock()
            .map_err(|error| AuthorizationError::platform(error.to_string()))?;
        if session.is_some() {
            return Ok(());
        }

        let exists = self
            .repository
            .vault_exists()
            .map_err(|error| AuthorizationError::platform(error.to_string()))?;
        if !exists && !matches!(action, Action::Create(_)) {
            return Ok(());
        }

        let password = (self.prompt)(if exists {
            "Towel vault password: "
        } else {
            "Create Towel vault password: "
        })
        .map_err(AuthorizationError::platform)?;
        if password.expose_secret().is_empty() {
            return Err(AuthorizationError::platform(
                "vault password must not be empty".into(),
            ));
        }
        if !exists {
            let confirmation = (self.prompt)("Confirm Towel vault password: ")
                .map_err(AuthorizationError::platform)?;
            if password.expose_secret() != confirmation.expose_secret() {
                return Err(AuthorizationError::platform(
                    "vault passwords do not match".into(),
                ));
            }
        }
        *session = Some(password);
        Ok(())
    }
}

pub type LinuxProjectService = ProjectService<LinuxVaultAuthorizer, Arc<LinuxAgeVaultRepository>>;

impl ProjectRepository for Arc<LinuxAgeVaultRepository> {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        self.as_ref().list()
    }
    fn get(&self, name: &str) -> Result<StoredProject, StoreError> {
        self.as_ref().get(name)
    }
    fn create(&self, project: &Project) -> Result<(), StoreError> {
        self.as_ref().create(project)
    }
    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError> {
        self.as_ref().replace(expected, project)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.as_ref().delete(name)
    }
}

pub fn open_project_service() -> Result<LinuxProjectService, StoreError> {
    crate::secret::process_preflight().map_err(StoreError::Platform)?;
    let session = PasswordSession::default();
    let repository = Arc::new(LinuxAgeVaultRepository::open(session)?);
    let authorizer = LinuxVaultAuthorizer {
        repository: repository.clone(),
        prompt: Arc::new(|label| {
            rpassword::prompt_password(label)
                .map(SecretString::from)
                .map_err(|error| format!("reading vault password from /dev/tty: {error}"))
        }),
    };
    Ok(ProjectService::new(authorizer, repository))
}

fn find_bubblewrap() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("bwrap"))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

/// Builds the Linux child command, adding only vault masking and PID/proc isolation when
/// Bubblewrap is installed. Networking and the host filesystem otherwise remain shared.
pub fn linux_project_child_command(
    program: &str,
    args: &[String],
    overrides: &[(String, String)],
) -> Result<(Command, bool), String> {
    let (mut command, masked) = if let Some(bubblewrap) = find_bubblewrap() {
        let vault_directory = vault_directory_path().map_err(|error| error.to_string())?;
        (
            bubblewrap_command(&bubblewrap, &vault_directory, program, args, overrides),
            true,
        )
    } else {
        (crate::child_command(program, args, overrides), false)
    };
    seal_inherited_descriptors(&mut command)?;
    Ok((command, masked))
}

fn seal_inherited_descriptors(command: &mut Command) -> Result<(), String> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit points to writable storage for the duration of getrlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(format!(
            "reading descriptor limit: {}",
            io::Error::last_os_error()
        ));
    }
    let maximum = limit.rlim_cur.min(i32::MAX as libc::rlim_t) as i32;
    // SAFETY: the closure calls only async-signal-safe syscalls after fork. CLOEXEC preserves
    // Rust's exec-error pipe until a successful exec while ensuring no descriptor above stderr
    // reaches Bubblewrap or an unmasked child.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) == 0
            {
                return Ok(());
            }

            for descriptor in 3..maximum {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags < 0 {
                    if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                        continue;
                    }
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

fn bubblewrap_command(
    bubblewrap: &Path,
    vault_directory: &Path,
    program: &str,
    args: &[String],
    overrides: &[(String, String)],
) -> Command {
    let mut command = Command::new(bubblewrap);
    command
        .arg("--die-with-parent")
        .arg("--unshare-pid")
        .args(["--dev-bind", "/", "/"])
        .args(["--proc", "/proc"])
        .arg("--tmpfs")
        .arg(vault_directory)
        .arg("--")
        .arg(program)
        .args(args);
    for variable in crate::STRIP {
        command.env_remove(variable);
    }
    for (key, value) in overrides {
        command.env(key, value);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::repository::exercise_repository;
    use crate::project::ProjectRoute;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut random);
            Self(std::env::temp_dir().join(format!(
                "twl-linux-test-{}-{}",
                std::process::id(),
                STANDARD_NO_PAD.encode(random)
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
        assert_eq!(repository.list(), Err(StoreError::VaultUnlockFailed));
    }

    #[test]
    fn bubblewrap_profile_only_adds_vault_and_process_masking() {
        let command = bubblewrap_command(
            Path::new("/usr/bin/bwrap"),
            Path::new("/home/test/.local/share/twl"),
            "codex",
            &["--version".into()],
            &[("APP_API_KEY".into(), "twl-app-fake".into())],
        );
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            arguments,
            [
                "--die-with-parent",
                "--unshare-pid",
                "--dev-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--tmpfs",
                "/home/test/.local/share/twl",
                "--",
                "codex",
                "--version",
            ]
        );
        assert!(!arguments.iter().any(|argument| argument == "--unshare-net"));
    }

    #[test]
    fn child_does_not_inherit_open_descriptors() {
        let file = File::open("/dev/null").unwrap();
        let descriptor = file.as_raw_fd();
        // Deliberately make this descriptor inheritable so the launcher hardening is tested.
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) }, 0);
        let args = vec!["-c".into(), format!("test ! -e /proc/self/fd/{descriptor}")];
        let mut command = crate::child_command("/bin/sh", &args, &[]);
        seal_inherited_descriptors(&mut command).unwrap();
        assert!(command.status().unwrap().success());
    }

    #[test]
    fn separate_repository_instances_share_the_lock() {
        let directory = TestDirectory::new();
        let first = repository(&directory, "password");
        let second = repository(&directory, "password");
        std::thread::scope(|scope| {
            let one = scope.spawn(|| first.create(&project("one", "one-key")));
            let two = scope.spawn(|| second.create(&project("two", "two-key")));
            one.join().unwrap().unwrap();
            two.join().unwrap().unwrap();
        });
        assert_eq!(first.list().unwrap(), ["one", "two"]);
    }

    #[test]
    fn authorizer_prompts_twice_only_for_first_creation_and_once_afterward() {
        let directory = TestDirectory::new();
        let session = PasswordSession::default();
        let repository = Arc::new(LinuxAgeVaultRepository {
            directory: Arc::new(VaultDirectory::open(directory.0.clone()).unwrap()),
            session,
        });
        let prompts = Arc::new(AtomicUsize::new(0));
        let marker = prompts.clone();
        let authorizer = LinuxVaultAuthorizer {
            repository: repository.clone(),
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
        let existing = Arc::new(LinuxAgeVaultRepository {
            directory: repository.directory.clone(),
            session,
        });
        let prompts = Arc::new(AtomicUsize::new(0));
        let marker = prompts.clone();
        let authorizer = LinuxVaultAuthorizer {
            repository: existing,
            prompt: Arc::new(move |_| {
                marker.fetch_add(1, Ordering::SeqCst);
                Ok(SecretString::from("password".to_owned()))
            }),
        };
        authorizer.authorize(Action::Read("app")).unwrap();
        authorizer.authorize(Action::Replace("app")).unwrap();
        assert_eq!(prompts.load(Ordering::SeqCst), 1);
    }
}
