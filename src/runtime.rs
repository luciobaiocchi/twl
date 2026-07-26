use crate::config::{connector, validate_runtime_upstream, Config, Connector, CredentialSource};
use crate::secret;
use crate::SessionMaterial;
use std::collections::HashMap;
#[cfg(unix)]
use std::io::Read;

#[cfg(unix)]
use std::os::fd::FromRawFd;

#[cfg(unix)]
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Parent-only inputs collected from CLI flags before a session is prepared.
#[derive(Default)]
pub struct Inputs {
    secret_fds: HashMap<String, i32>,
    upstreams: HashMap<String, String>,
}

/// Validated runtime material retained by the parent until it enters a route.
#[derive(Default)]
pub struct Resolved {
    materials: HashMap<String, SessionMaterial>,
    environment_secrets: Vec<(&'static str, &'static str)>,
}

impl Inputs {
    pub fn add_upstream(&mut self, connector: String, upstream: String) -> Result<(), String> {
        if self.upstreams.insert(connector.clone(), upstream).is_some() {
            return Err(format!("duplicate upstream for connector {connector}"));
        }
        Ok(())
    }

    pub fn add_secret_fd(&mut self, connector: String, fd: i32) -> Result<(), String> {
        if fd < 3 {
            return Err("secret file descriptors must be 3 or greater".into());
        }
        if self.secret_fds.values().any(|candidate| *candidate == fd) {
            return Err(format!("file descriptor {fd} is assigned more than once"));
        }
        if self.secret_fds.insert(connector.clone(), fd).is_some() {
            return Err(format!("duplicate secret source for connector {connector}"));
        }
        Ok(())
    }

    pub fn resolve(
        self,
        config: &Config,
        prompt: impl FnMut(&Connector) -> Result<String, String>,
    ) -> Result<Resolved, String> {
        self.validate(config)?;
        let has_runtime = config
            .connectors
            .iter()
            .filter_map(|name| connector(name))
            .any(|connector| {
                matches!(
                    connector.credential_source,
                    CredentialSource::Runtime { .. }
                )
            });
        if !has_runtime {
            return Ok(Resolved::default());
        }

        secret::process_preflight()?;
        self.resolve_protected(config, prompt)
    }

    fn resolve_protected(
        mut self,
        config: &Config,
        mut prompt: impl FnMut(&Connector) -> Result<String, String>,
    ) -> Result<Resolved, String> {
        let mut resolved = Resolved::default();
        for name in &config.connectors {
            let connector = connector(name).ok_or_else(|| format!("unknown connector: {name}"))?;
            let CredentialSource::Runtime {
                parent_secret_env,
                parent_upstream_env,
            } = connector.credential_source
            else {
                continue;
            };

            let upstream = choose_upstream(
                connector.id,
                self.upstreams.remove(connector.id),
                take_environment(parent_upstream_env)?,
                parent_upstream_env,
            )?;
            let (key, used_environment) = choose_secret(
                connector,
                self.secret_fds.remove(connector.id),
                take_environment(parent_secret_env)?,
                &mut prompt,
            )?;
            if key.is_empty() {
                return Err(format!("empty credential for connector {}", connector.id));
            }
            if used_environment {
                resolved
                    .environment_secrets
                    .push((connector.id, parent_secret_env));
            }
            resolved
                .materials
                .insert(connector.id.to_string(), SessionMaterial { key, upstream });
        }
        Ok(resolved)
    }

    fn validate(&self, config: &Config) -> Result<(), String> {
        for name in self.secret_fds.keys().chain(self.upstreams.keys()) {
            let selected = config.connectors.iter().any(|candidate| candidate == name);
            let runtime = connector(name).is_some_and(|connector| {
                matches!(
                    connector.credential_source,
                    CredentialSource::Runtime { .. }
                )
            });
            if !selected || !runtime {
                return Err(format!(
                    "runtime option refers to unselected or non-runtime connector {name}"
                ));
            }
        }
        Ok(())
    }
}

impl Resolved {
    pub fn take_material(&mut self, connector: &Connector) -> Result<SessionMaterial, String> {
        self.materials
            .remove(connector.id)
            .ok_or_else(|| format!("missing runtime material for connector {}", connector.id))
    }

    pub fn environment_secrets(&self) -> &[(&'static str, &'static str)] {
        &self.environment_secrets
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

fn choose_upstream(
    connector: &str,
    command: Option<String>,
    environment: Option<String>,
    environment_name: &str,
) -> Result<String, String> {
    let value = match (command, environment) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "upstream for connector {connector} was supplied twice"
            ))
        }
        (Some(value), None) | (None, Some(value)) => value,
        (None, None) => {
            return Err(format!(
                "connector {connector} requires --upstream {connector}=URL or {environment_name}"
            ))
        }
    };
    validate_runtime_upstream(&value)
}

fn choose_secret(
    connector: &Connector,
    descriptor: Option<i32>,
    environment: Option<String>,
    prompt: &mut impl FnMut(&Connector) -> Result<String, String>,
) -> Result<(String, bool), String> {
    match (descriptor, environment) {
        (Some(_), Some(_)) => Err(format!(
            "credential for connector {} was supplied twice",
            connector.id
        )),
        (Some(fd), None) => read_secret_fd(fd).map(|secret| (secret, false)),
        (None, Some(secret)) => Ok((secret, true)),
        (None, None) => prompt(connector).map(|secret| (secret, false)),
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
        let config = Config::parse("connectors: [openai, application]\n").unwrap();
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"real-test-key\n").unwrap();
        drop(writer);
        let fd = reader.into_raw_fd();

        let mut inputs = Inputs::default();
        inputs
            .add_upstream("application".into(), "http://127.0.0.1:8080".into())
            .unwrap();
        inputs.add_secret_fd("application".into(), fd).unwrap();
        let mut resolved = inputs
            .resolve_protected(&config, |_| Err("prompt must not run".into()))
            .unwrap();

        assert_eq!(
            resolved
                .take_material(connector("application").unwrap())
                .unwrap(),
            SessionMaterial {
                key: "real-test-key".into(),
                upstream: "http://127.0.0.1:8080".into(),
            }
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    }

    #[test]
    fn one_descriptor_cannot_be_assigned_twice() {
        let mut inputs = Inputs::default();
        inputs.add_secret_fd("application".into(), 7).unwrap();
        assert!(inputs.add_secret_fd("another".into(), 7).is_err());
    }

    #[test]
    fn conflicting_sources_do_not_echo_the_secret() {
        let application = connector("application").unwrap();
        let secret = "DO-NOT-PRINT-THIS";
        let error = choose_secret(application, Some(7), Some(secret.into()), &mut |_| {
            Err("prompt must not run".into())
        })
        .unwrap_err();

        assert!(error.contains("supplied twice"));
        assert!(!error.contains(secret));
    }

    #[test]
    fn runtime_options_are_scoped_to_selected_runtime_connectors() {
        let config = Config::parse("connectors: [openai]\n").unwrap();
        let mut inputs = Inputs::default();
        inputs
            .add_upstream("application".into(), "https://service.example".into())
            .unwrap();

        assert!(inputs.validate(&config).is_err());
    }
}
