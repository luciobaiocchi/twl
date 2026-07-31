mod launcher;
mod vault;

use self::vault::{vault_directory_path, PasswordSession, PendingLock, VaultDirectory};
use super::{Action, AuthorizationError, ProjectService, SessionAuthorizer, StoreError};
use age::secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;

pub use launcher::linux_project_child_command;
pub use vault::LinuxAgeVaultRepository;

type PasswordPrompt = Arc<dyn Fn(&str) -> Result<SecretString, String> + Send + Sync>;

/// Authorizes one Linux service session with one password read from `/dev/tty`.
pub struct LinuxVaultAuthorizer {
    session: PasswordSession,
    directory: Arc<VaultDirectory>,
    prompt: PasswordPrompt,
}

impl SessionAuthorizer for LinuxVaultAuthorizer {
    fn authorize(&self, action: Action<'_>) -> Result<(), AuthorizationError> {
        if self
            .session
            .lock()
            .map_err(|error| AuthorizationError::platform(error.to_string()))?
            .password
            .is_some()
        {
            return Ok(());
        }

        loop {
            let exists = self
                .directory
                .vault_exists()
                .map_err(|error| AuthorizationError::platform(error.to_string()))?;
            let password = if !exists && !matches!(action, Action::Create(_)) {
                None
            } else {
                crate::secret::process_preflight().map_err(AuthorizationError::platform)?;
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
                Some(password)
            };

            let exclusive = matches!(
                action,
                Action::Create(_) | Action::Replace(_) | Action::Delete(_)
            );
            let operation_lock = self
                .directory
                .lock(exclusive)
                .map_err(|error| AuthorizationError::platform(error.to_string()))?;
            let still_exists = self
                .directory
                .open_vault()
                .map_err(|error| AuthorizationError::platform(error.to_string()))?
                .is_some();
            if still_exists != exists {
                continue;
            }

            let mut session = self
                .session
                .lock()
                .map_err(|error| AuthorizationError::platform(error.to_string()))?;
            if session.password.is_none() {
                session.password = password;
                session.operation_lock = Some(PendingLock {
                    exclusive,
                    lock: operation_lock,
                });
            }
            return Ok(());
        }
    }
}

pub type LinuxProjectService = ProjectService<LinuxVaultAuthorizer, LinuxAgeVaultRepository>;

pub fn open_project_service() -> Result<LinuxProjectService, StoreError> {
    let session = PasswordSession::default();
    let directory = Arc::new(VaultDirectory::open(vault_directory_path()?)?);
    let repository = LinuxAgeVaultRepository {
        directory: directory.clone(),
        session: session.clone(),
        scrypt_work_factor_override: None,
    };
    let authorizer = LinuxVaultAuthorizer {
        session,
        directory,
        prompt: Arc::new(|label| {
            rpassword::prompt_password(label)
                .map(SecretString::from)
                .map_err(|error| format!("reading vault password from /dev/tty: {error}"))
        }),
    };
    Ok(ProjectService::new(authorizer, repository))
}
