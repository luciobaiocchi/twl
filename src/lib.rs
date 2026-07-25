pub mod config;
pub mod proxy;
pub mod secret;

use config::{connector, Config, Connector, CONNECTORS};
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

fn prepare_inner(
    cfg: &Config,
    source: impl Fn(&Connector) -> Result<String, String>,
    demo_upstream: Option<&str>,
) -> Result<Prepared, String> {
    let mut prepared = Prepared {
        routes: HashMap::new(),
        mocks: Vec::new(),
        base_urls: Vec::new(),
    };

    for name in &cfg.connectors {
        let connector = connector(name).ok_or_else(|| format!("unknown connector: {name}"))?;
        let key = source(connector)?;
        if key.is_empty() {
            return Err(format!("empty credential for connector {}", connector.id));
        }
        prepared.routes.insert(
            connector.id.to_string(),
            Route {
                upstream: demo_upstream.unwrap_or(connector.upstream).to_string(),
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

/// Prepare a real session. The caller can supply a test source, but destination,
/// authentication mode, secret identity, and route policy always come from the
/// compiled connector table.
pub fn prepare(
    cfg: &Config,
    source: impl Fn(&Connector) -> Result<String, String>,
) -> Result<Prepared, String> {
    prepare_inner(cfg, source, None)
}

/// Prepare a canary-only demonstration. This is the only path that can replace
/// an upstream, and it cannot read the keyring.
pub fn prepare_demo(cfg: &Config, upstream: &str) -> Result<Prepared, String> {
    prepare_inner(
        cfg,
        |connector| Ok(secret::demo(connector.mock_prefix)),
        Some(upstream),
    )
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

/// The child inherits ordinary configuration, but never an ambient supported
/// credential or stale provider base URL. Selected values are then replaced by
/// the session-scoped mocks and local URLs.
pub fn child_command(program: &str, args: &[String], overrides: &[(String, String)]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for var in STRIP {
        cmd.env_remove(var);
    }
    for connector in CONNECTORS {
        cmd.env_remove(connector.secret_env);
        for var in connector.base_url_vars {
            cmd.env_remove(var);
        }
    }
    for (key, value) in overrides {
        cmd.env(key, value);
    }
    cmd
}
