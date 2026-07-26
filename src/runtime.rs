use crate::config::{validate_upstream, PARENT_SECRET_ENV, PARENT_UPSTREAM_ENV};
use crate::{secret, SessionMaterial};
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::fd::FromRawFd;

#[cfg(unix)]
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Parent-only inputs collected before the application session is prepared.
#[derive(Default)]
pub struct Inputs {
    secret_fd: Option<i32>,
    upstream: Option<String>,
}

pub struct Resolved {
    pub material: SessionMaterial,
    pub used_environment_secret: bool,
}

impl Inputs {
    pub fn set_upstream(&mut self, upstream: String) -> Result<(), String> {
        if self.upstream.replace(upstream).is_some() {
            return Err("--upstream was specified more than once".into());
        }
        Ok(())
    }

    pub fn set_secret_fd(&mut self, fd: i32) -> Result<(), String> {
        if fd < 3 {
            return Err("secret file descriptors must be 3 or greater".into());
        }
        if self.secret_fd.replace(fd).is_some() {
            return Err("--secret-fd was specified more than once".into());
        }
        Ok(())
    }

    pub fn resolve(
        self,
        prompt: impl FnOnce() -> Result<String, String>,
    ) -> Result<Resolved, String> {
        // Harden the parent before reading any credential source.
        secret::process_preflight()?;

        let environment_upstream = take_environment(PARENT_UPSTREAM_ENV)?;
        let upstream = choose_upstream(self.upstream, environment_upstream)?;
        let environment_secret = take_environment(PARENT_SECRET_ENV)?;
        let (key, used_environment_secret) =
            choose_secret(self.secret_fd, environment_secret, prompt)?;
        if key.is_empty() {
            return Err("empty application credential".into());
        }

        Ok(Resolved {
            material: SessionMaterial { key, upstream },
            used_environment_secret,
        })
    }
}

fn take_environment(name: &str) -> Result<Option<String>, String> {
    let value = std::env::var_os(name);
    std::env::remove_var(name);
    value
        .map(|value| {
            value
                .into_string()
                .map_err(|_| format!("{name} is not valid UTF-8"))
        })
        .transpose()
}

fn choose_upstream(command: Option<String>, environment: Option<String>) -> Result<String, String> {
    let value = match (command, environment) {
        (Some(_), Some(_)) => return Err("upstream was supplied twice".into()),
        (Some(value), None) | (None, Some(value)) => value,
        (None, None) => {
            return Err(format!(
                "application requires --upstream URL or {PARENT_UPSTREAM_ENV}"
            ))
        }
    };
    validate_upstream(&value)
}

fn choose_secret(
    descriptor: Option<i32>,
    environment: Option<String>,
    prompt: impl FnOnce() -> Result<String, String>,
) -> Result<(String, bool), String> {
    match (descriptor, environment) {
        (Some(_), Some(_)) => Err("application credential was supplied twice".into()),
        (Some(fd), None) => read_secret_fd(fd).map(|secret| (secret, false)),
        (None, Some(secret)) => Ok((secret, true)),
        (None, None) => prompt().map(|secret| (secret, false)),
    }
}

#[cfg(unix)]
fn read_secret_fd(fd: i32) -> Result<String, String> {
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags == -1
        || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } == -1
    {
        return Err(format!(
            "preparing secret file descriptor {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading secret file descriptor {fd}: {error}"))?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(format!(
            "secret from file descriptor {fd} exceeds {MAX_SECRET_BYTES} bytes"
        ));
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("secret from file descriptor {fd} is not valid UTF-8"))
}

#[cfg(not(unix))]
fn read_secret_fd(_fd: i32) -> Result<String, String> {
    Err("secret file descriptors are available only on Unix platforms".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn dedicated_descriptor_is_consumed_and_closed() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"real-test-key\n").unwrap();
        drop(writer);
        let fd = reader.into_raw_fd();

        let mut inputs = Inputs::default();
        inputs.set_upstream("http://127.0.0.1:8080".into()).unwrap();
        inputs.set_secret_fd(fd).unwrap();
        let resolved = inputs
            .resolve_protected_for_test(|| Err("prompt must not run".into()))
            .unwrap();

        assert_eq!(
            resolved.material,
            SessionMaterial {
                key: "real-test-key".into(),
                upstream: "http://127.0.0.1:8080".into(),
            }
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    }

    #[test]
    fn duplicate_inputs_are_rejected() {
        let mut inputs = Inputs::default();
        inputs.set_secret_fd(7).unwrap();
        assert!(inputs.set_secret_fd(8).is_err());
        inputs.set_upstream("https://one.example".into()).unwrap();
        assert!(inputs.set_upstream("https://two.example".into()).is_err());
    }

    #[test]
    fn conflicting_sources_do_not_echo_the_secret() {
        let secret = "DO-NOT-PRINT-THIS";
        let error = choose_secret(Some(7), Some(secret.into()), || {
            Err("prompt must not run".into())
        })
        .unwrap_err();

        assert!(error.contains("supplied twice"));
        assert!(!error.contains(secret));
    }

    #[test]
    fn environment_secret_is_marked_as_weaker_input() {
        let (secret, used_environment) = choose_secret(None, Some("canary".into()), || {
            Err("prompt must not run".into())
        })
        .unwrap();

        assert_eq!(secret, "canary");
        assert!(used_environment);
    }

    impl Inputs {
        fn resolve_protected_for_test(
            self,
            prompt: impl FnOnce() -> Result<String, String>,
        ) -> Result<Resolved, String> {
            let upstream = choose_upstream(self.upstream, None)?;
            let (key, used_environment_secret) = choose_secret(self.secret_fd, None, prompt)?;
            Ok(Resolved {
                material: SessionMaterial { key, upstream },
                used_environment_secret,
            })
        }
    }
}
