use crate::SessionManifest;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAX_SENSITIVE_BYTES: usize = 64 * 1024;
const MAX_TRUSTED_DOCUMENT_BYTES: u64 = 16 << 20;

#[derive(Default)]
pub struct PasswordInput {
    descriptor: Option<i32>,
    file: Option<PathBuf>,
}

impl PasswordInput {
    pub fn set_descriptor(&mut self, descriptor: i32) -> Result<(), String> {
        if descriptor < 3 {
            return Err("password file descriptors must be 3 or greater".into());
        }
        if self.file.is_some() {
            return Err("vault password was supplied more than once".into());
        }
        if self.descriptor.replace(descriptor).is_some() {
            return Err("--password-fd was specified more than once".into());
        }
        Ok(())
    }

    pub fn set_file(&mut self, path: PathBuf) -> Result<(), String> {
        if self.descriptor.is_some() {
            return Err("vault password was supplied more than once".into());
        }
        if self.file.replace(path).is_some() {
            return Err("--password-file was specified more than once".into());
        }
        Ok(())
    }

    pub fn resolve(
        self,
        prompt: impl FnOnce() -> Result<String, String>,
    ) -> Result<Zeroizing<String>, String> {
        let value = match self.descriptor {
            Some(descriptor) => read_sensitive_fd(descriptor, "vault password")?,
            None => match self.file {
                Some(path) => read_sensitive_file(&path, "vault password")?,
                None => prompt()?,
            },
        };
        if value.is_empty() {
            return Err("vault password must not be empty".into());
        }
        Ok(Zeroizing::new(value))
    }

    pub fn uses_descriptor(&self) -> bool {
        self.descriptor.is_some()
    }

    pub fn uses_noninteractive_source(&self) -> bool {
        self.descriptor.is_some() || self.file.is_some()
    }
}

pub fn read_trusted_document(path: &str) -> Result<Zeroizing<String>, String> {
    let mut raw = Zeroizing::new(String::new());
    if path == "-" {
        std::io::stdin()
            .lock()
            .take(MAX_TRUSTED_DOCUMENT_BYTES + 1)
            .read_to_string(&mut raw)
            .map_err(|error| format!("reading trusted route document from stdin: {error}"))?;
    } else {
        std::fs::File::open(path)
            .map_err(|error| format!("opening trusted route document {path}: {error}"))?
            .take(MAX_TRUSTED_DOCUMENT_BYTES + 1)
            .read_to_string(&mut raw)
            .map_err(|error| format!("reading trusted route document {path}: {error}"))?;
    }
    if raw.len() as u64 > MAX_TRUSTED_DOCUMENT_BYTES {
        return Err("trusted route document is too large".into());
    }
    Ok(raw)
}

/// Atomically replace the agent-visible session manifest. It contains only
/// local URLs, fake credentials, and the short-lived session token.
pub fn write_session_manifest(path: &Path, manifest: &SessionManifest) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("session manifest path must name a file")?;
    let temporary = temporary_path(parent, name);
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o640);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("creating session manifest {}: {error}", path.display()))?;
        let mut encoded = serde_json::to_vec_pretty(manifest)
            .map_err(|_| "session manifest could not be encoded".to_string())?;
        encoded.push(b'\n');
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("writing session manifest {}: {error}", path.display()))?;
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("installing session manifest {}: {error}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn read_sensitive_fd(descriptor: i32, label: &str) -> Result<String, String> {
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags == -1
        || unsafe {
            libc::fcntl(
                descriptor,
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } == -1
    {
        return Err(format!(
            "preparing {label} file descriptor {descriptor}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take((MAX_SENSITIVE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading {label} file descriptor {descriptor}: {error}"))?;
    if bytes.len() > MAX_SENSITIVE_BYTES {
        return Err(format!(
            "{label} from file descriptor {descriptor} exceeds {MAX_SENSITIVE_BYTES} bytes"
        ));
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| format!("{label} from file descriptor {descriptor} is not valid UTF-8"))
}

#[cfg(not(unix))]
fn read_sensitive_fd(_descriptor: i32, _label: &str) -> Result<String, String> {
    Err("sensitive file descriptors are available only on Unix platforms".into())
}

fn read_sensitive_file(path: &Path, label: &str) -> Result<String, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .map_err(|error| format!("opening {label} file {}: {error}", path.display()))?
        .take((MAX_SENSITIVE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading {label} file {}: {error}", path.display()))?;
    if bytes.len() > MAX_SENSITIVE_BYTES {
        return Err(format!(
            "{label} file {} exceeds {MAX_SENSITIVE_BYTES} bytes",
            path.display()
        ));
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| format!("{label} file {} is not valid UTF-8", path.display()))
}

fn temporary_path(parent: &Path, name: &str) -> PathBuf {
    let mut random = [0u8; 12];
    OsRng.fill_bytes(&mut random);
    parent.join(format!(".{name}.tmp-{}", URL_SAFE_NO_PAD.encode(random)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn dedicated_password_descriptor_is_consumed_and_closed() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"correct horse battery staple\n").unwrap();
        drop(writer);
        let descriptor = reader.into_raw_fd();

        let mut input = PasswordInput::default();
        input.set_descriptor(descriptor).unwrap();
        let password = input.resolve(|| Err("prompt must not run".into())).unwrap();

        assert_eq!(&*password, "correct horse battery staple");
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
    }

    #[test]
    fn towel_only_password_file_is_bounded_and_trimmed() {
        let directory = std::env::temp_dir().join(format!(
            "twl-password-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("password");
        std::fs::write(&path, b"container-secret\n").unwrap();

        let mut input = PasswordInput::default();
        input.set_file(path.clone()).unwrap();
        let password = input.resolve(|| Err("prompt must not run".into())).unwrap();
        assert_eq!(&*password, "container-secret");

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
