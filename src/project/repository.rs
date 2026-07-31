use super::{ModelError, Project};
#[cfg(test)]
use std::collections::HashMap;
use std::fmt;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque, secret-bearing record revision used to reject stale replacement.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Revision(Vec<u8>);

impl Revision {
    pub(crate) const BYTES: usize = 32;

    pub(crate) fn random() -> Self {
        use rand::RngCore;

        let mut bytes = vec![0_u8; Self::BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Revision(<redacted>)")
    }
}

/// A validated project together with the revision read from its repository.
#[derive(Debug)]
pub struct StoredProject {
    project: Project,
    revision: Revision,
}

impl StoredProject {
    #[allow(dead_code)]
    pub(crate) fn new(project: Project, revision: Revision) -> Self {
        Self { project, revision }
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn revision(&self) -> &Revision {
        &self.revision
    }

    pub fn into_parts(self) -> (Project, Revision) {
        (self.project, self.revision)
    }
}

/// Secret-safe repository failures shared by every platform backend.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    AlreadyExists,
    Conflict,
    MalformedRecord,
    OversizedRecord,
    VaultUnlockFailed,
    UntrustedStore,
    UntrustedItem,
    UnsupportedPlatform,
    InvalidProject(ModelError),
    Platform(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("project not found"),
            Self::AlreadyExists => formatter.write_str("project already exists"),
            Self::Conflict => formatter.write_str("project changed while it was being edited"),
            Self::MalformedRecord => formatter.write_str("malformed stored project record"),
            Self::OversizedRecord => {
                formatter.write_str("stored project data exceeds the supported size limit")
            }
            Self::VaultUnlockFailed => formatter
                .write_str("could not unlock the project vault: wrong password or damaged vault"),
            Self::UntrustedStore => formatter.write_str("trusted project store is unavailable"),
            Self::UntrustedItem => {
                formatter.write_str("project record has untrusted access control")
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("project credentials are unavailable on this platform")
            }
            Self::InvalidProject(error) => error.fmt(formatter),
            Self::Platform(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ModelError> for StoreError {
    fn from(error: ModelError) -> Self {
        Self::InvalidProject(error)
    }
}

/// Persistence contract for authoritative, versioned project records.
pub trait ProjectRepository: Send + Sync {
    fn list(&self) -> Result<Vec<String>, StoreError>;
    fn get(&self, name: &str) -> Result<StoredProject, StoreError>;
    fn create(&self, project: &Project) -> Result<(), StoreError>;
    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError>;
    fn delete(&self, name: &str) -> Result<(), StoreError>;
}

/// Human-presence action kept independent from persistence details.
#[derive(Debug, Clone, Copy)]
pub enum Action<'a> {
    List,
    Read(&'a str),
    Create(&'a str),
    Replace(&'a str),
    Delete(&'a str),
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizationError(String);

impl AuthorizationError {
    #[allow(dead_code)]
    pub(crate) fn platform(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AuthorizationError {}

pub trait SessionAuthorizer {
    fn authorize(&self, action: Action<'_>) -> Result<(), AuthorizationError>;
}

#[derive(Debug)]
pub enum ProjectServiceError {
    Authorization(AuthorizationError),
    Store(StoreError),
}

impl fmt::Display for ProjectServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProjectServiceError {}

/// Composes authorization policy with a backend-neutral repository.
pub struct ProjectService<A, R> {
    authorizer: A,
    repository: R,
}

impl<A, R> ProjectService<A, R>
where
    A: SessionAuthorizer,
    R: ProjectRepository,
{
    pub fn new(authorizer: A, repository: R) -> Self {
        Self {
            authorizer,
            repository,
        }
    }

    pub fn list(&self) -> Result<Vec<String>, ProjectServiceError> {
        self.authorizer
            .authorize(Action::List)
            .map_err(ProjectServiceError::Authorization)?;
        self.repository.list().map_err(ProjectServiceError::Store)
    }

    pub fn get(&self, name: &str) -> Result<StoredProject, ProjectServiceError> {
        super::validate_identifier(name)
            .map_err(StoreError::from)
            .map_err(ProjectServiceError::Store)?;
        self.authorizer
            .authorize(Action::Read(name))
            .map_err(ProjectServiceError::Authorization)?;
        self.repository
            .get(name)
            .map_err(ProjectServiceError::Store)
    }

    pub fn create(&self, project: &Project) -> Result<(), ProjectServiceError> {
        project
            .validate()
            .map_err(StoreError::from)
            .map_err(ProjectServiceError::Store)?;
        self.authorizer
            .authorize(Action::Create(project.name()))
            .map_err(ProjectServiceError::Authorization)?;
        self.repository
            .create(project)
            .map_err(ProjectServiceError::Store)
    }

    pub fn replace(
        &self,
        expected: &Revision,
        project: &Project,
    ) -> Result<(), ProjectServiceError> {
        project
            .validate()
            .map_err(StoreError::from)
            .map_err(ProjectServiceError::Store)?;
        self.authorizer
            .authorize(Action::Replace(project.name()))
            .map_err(ProjectServiceError::Authorization)?;
        self.repository
            .replace(expected, project)
            .map_err(ProjectServiceError::Store)
    }

    pub fn delete(&self, name: &str) -> Result<(), ProjectServiceError> {
        super::validate_identifier(name)
            .map_err(StoreError::from)
            .map_err(ProjectServiceError::Store)?;
        self.authorizer
            .authorize(Action::Delete(name))
            .map_err(ProjectServiceError::Authorization)?;
        self.repository
            .delete(name)
            .map_err(ProjectServiceError::Store)
    }
}

#[cfg(test)]
type MemoryRecord = (Zeroizing<Vec<u8>>, Revision);

#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryRepository {
    records: Mutex<HashMap<String, MemoryRecord>>,
}

#[cfg(test)]
impl ProjectRepository for MemoryRepository {
    fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut names: Vec<_> = self.records.lock().unwrap().keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    fn get(&self, name: &str) -> Result<StoredProject, StoreError> {
        let records = self.records.lock().unwrap();
        let (payload, revision) = records.get(name).ok_or(StoreError::NotFound)?.clone();
        let project = Project::decode(&payload).map_err(|_| StoreError::MalformedRecord)?;
        if project.name() != name {
            return Err(StoreError::MalformedRecord);
        }
        Ok(StoredProject { project, revision })
    }

    fn create(&self, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let mut records = self.records.lock().unwrap();
        if records.contains_key(project.name()) {
            return Err(StoreError::AlreadyExists);
        }
        records.insert(
            project.name().into(),
            (project.encode()?, Revision::random()),
        );
        Ok(())
    }

    fn replace(&self, expected: &Revision, project: &Project) -> Result<(), StoreError> {
        project.validate()?;
        let mut records = self.records.lock().unwrap();
        let (_, current_revision) = records.get(project.name()).ok_or(StoreError::NotFound)?;
        if expected != current_revision {
            return Err(StoreError::Conflict);
        }
        records.insert(
            project.name().into(),
            (project.encode()?, Revision::random()),
        );
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.records
            .lock()
            .unwrap()
            .remove(name)
            .map(|_| ())
            .ok_or(StoreError::NotFound)
    }
}

#[cfg(test)]
pub(crate) fn exercise_repository(repository: &dyn ProjectRepository) {
    use super::ProjectRoute;

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

    let first = project("one", "first-key");
    repository.create(&first).unwrap();
    assert_eq!(repository.create(&first), Err(StoreError::AlreadyExists));
    let stored = repository.get("one").unwrap();
    let stale = stored.revision().clone();
    repository
        .replace(stored.revision(), &project("one", "replacement-key"))
        .unwrap();
    assert_eq!(
        repository.replace(&stale, &project("one", "stale-key")),
        Err(StoreError::Conflict)
    );

    let stored = repository.get("one").unwrap();
    let revision = stored.revision().clone();
    let outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| repository.replace(&revision, &project("one", "worker-one")));
        let second = scope.spawn(|| repository.replace(&revision, &project("one", "worker-two")));
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| **result == Err(StoreError::Conflict))
            .count(),
        1
    );
    assert_eq!(
        repository.replace(&stale, &project("missing", "missing-key")),
        Err(StoreError::NotFound)
    );
    repository.delete("one").unwrap();
    assert_eq!(repository.get("one").unwrap_err(), StoreError::NotFound);

    std::thread::scope(|scope| {
        let first = scope.spawn(|| repository.create(&project("two", "second-key")));
        let second = scope.spawn(|| repository.create(&project("three", "third-key")));
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    });
    assert_eq!(repository.list().unwrap(), ["three", "two"]);
    repository.delete("two").unwrap();
    assert!(repository.get("three").is_ok());
    repository.delete("three").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn memory_repository_conforms() {
        exercise_repository(&MemoryRepository::default());
    }

    #[test]
    fn random_revisions_have_one_cross_platform_size() {
        assert_eq!(Revision::random().as_bytes().len(), Revision::BYTES);
    }

    #[test]
    fn malformed_memory_records_fail_generically() {
        let repository = MemoryRepository::default();
        repository.records.lock().unwrap().insert(
            "app".into(),
            (
                Zeroizing::new(b"secret-bearing-malformed-data".to_vec()),
                Revision::random(),
            ),
        );
        assert_eq!(
            repository.get("app").unwrap_err(),
            StoreError::MalformedRecord
        );
    }

    struct RecordingAuthorizer<'a>(&'a AtomicBool);

    impl SessionAuthorizer for RecordingAuthorizer<'_> {
        fn authorize(&self, _action: Action<'_>) -> Result<(), AuthorizationError> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn invalid_names_never_reach_the_authorizer() {
        let called = AtomicBool::new(false);
        let service =
            ProjectService::new(RecordingAuthorizer(&called), MemoryRepository::default());
        assert!(matches!(
            service.get("bad\u{1b}name"),
            Err(ProjectServiceError::Store(StoreError::InvalidProject(_)))
        ));
        assert!(!called.load(Ordering::SeqCst));
    }
}
