pub mod config;
pub mod proxy;
pub mod runtime;
pub mod secret;

use config::{connector, Config, Connector, CredentialSource, CONNECTORS};
use proxy::Route;
use std::collections::HashMap;
use std::process::Command;

/// Session-oracle variables are never inherited. Removing the D-Bus address is
/// only defense in depth; secure automatic keyring mode is macOS-only in v0.
pub const STRIP: &[&str] = &["DBUS_SESSION_BUS_ADDRESS"];

pub struct Prepared {
    pub routes: HashMap<String, Route>,
    /// `(environment variable, fake value)` visible to the child.
    pub mocks: Vec<(String, String)>,
    /// `(base URL variable, connector, client-specific suffix)`.
    pub base_urls: Vec<(String, String, String)>,
}

/// A real credential paired with the only upstream allowed to receive it.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionMaterial {
    pub key: String,
    pub upstream: String,
}

fn prepare_inner(
    cfg: &Config,
    mut source: impl FnMut(&Connector) -> Result<SessionMaterial, String>,
) -> Result<Prepared, String> {
    let mut prepared = Prepared {
        routes: HashMap::new(),
        mocks: Vec::new(),
        base_urls: Vec::new(),
    };

    for name in &cfg.connectors {
        let connector = connector(name).ok_or_else(|| format!("unknown connector: {name}"))?;
        let material = source(connector)?;
        let key = material.key;
        if key.is_empty() {
            return Err(format!("empty credential for connector {}", connector.id));
        }
        if key.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(format!(
                "credential for connector {} contains control characters",
                connector.id
            ));
        }
        prepared.routes.insert(
            connector.id.to_string(),
            Route {
                upstream: material.upstream,
                auth: connector.auth,
                key,
                allowed: connector.allowed,
            },
        );
        prepared.mocks.push((
            connector.secret_env.to_string(),
            secret::mock(connector.mock_prefix),
        ));
        for var in connector.base_url_vars {
            prepared.base_urls.push((
                var.to_string(),
                connector.id.to_string(),
                connector.client_base_suffix.to_string(),
            ));
        }
    }
    Ok(prepared)
}

/// Prepare a session containing only stored connectors. The caller can replace
/// the credential reader for tests; all other policy stays compiled in.
pub fn prepare(
    cfg: &Config,
    mut source: impl FnMut(&Connector) -> Result<String, String>,
) -> Result<Prepared, String> {
    prepare_inner(cfg, |connector| match connector.credential_source {
        CredentialSource::Keychain { upstream } => Ok(SessionMaterial {
            key: source(connector)?,
            upstream: upstream.to_string(),
        }),
        CredentialSource::Runtime { .. } => Err(format!(
            "connector {} requires a runtime credential and upstream",
            connector.id
        )),
    })
}

/// Prepare a session after every connector has been resolved by the trusted
/// parent. Workspace configuration still cannot provide either value.
pub fn prepare_session(
    cfg: &Config,
    source: impl FnMut(&Connector) -> Result<SessionMaterial, String>,
) -> Result<Prepared, String> {
    prepare_inner(cfg, source)
}

/// Prepare a canary-only demonstration against a local generated upstream. It
/// cannot read the keyring or any runtime credential source.
pub fn prepare_demo(cfg: &Config, upstream: &str) -> Result<Prepared, String> {
    prepare_inner(cfg, |connector| {
        Ok(SessionMaterial {
            key: secret::demo(connector.mock_prefix),
            upstream: upstream.to_string(),
        })
    })
}

impl Prepared {
    pub fn env_overrides(&self, port: u16, token: &str) -> Vec<(String, String)> {
        let mut out = self.mocks.clone();
        for (var, connector, suffix) in &self.base_urls {
            out.push((
                var.clone(),
                format!("http://127.0.0.1:{port}/{token}/{connector}{suffix}"),
            ));
        }
        out
    }
}

/// Selected connector variables are replaced by session-local values. Unrelated
/// variables remain available to the child, while parent-only Mithril inputs
/// and session-oracle variables are always removed.
pub fn child_command(program: &str, args: &[String], overrides: &[(String, String)]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for var in STRIP {
        cmd.env_remove(var);
    }
    for connector in CONNECTORS {
        if let CredentialSource::Runtime {
            parent_secret_env,
            parent_upstream_env,
        } = connector.credential_source
        {
            cmd.env_remove(parent_secret_env);
            cmd.env_remove(parent_upstream_env);
        }
    }
    for (key, value) in overrides {
        cmd.env(key, value);
    }
    cmd
}
