pub mod config;
pub mod proxy;
pub mod sandbox;
pub mod secret;

use config::{connector, Config};
use proxy::Route;
use std::collections::HashMap;
use std::process::Command;

/// Variables that never pass to the child. On Linux, `DBUS_SESSION_BUS_ADDRESS`
/// is the path to the Secret Service: removing it on its own would only raise
/// the bar, because the socket is still guessable at `/run/user/<uid>/bus`.
/// The actual barrier is set by `sandbox`, which drops the path from the mount
/// namespace; this is the first line of defense, and the only one when bwrap
/// isn't available.
pub const STRIP: &[&str] = &["DBUS_SESSION_BUS_ADDRESS"];

pub struct Prepared {
    pub routes: HashMap<String, Route>,
    /// (variable name, fake value) — what the agent sees.
    pub mocks: Vec<(String, String)>,
    /// (variable name, connector name) for the base URLs.
    pub base_urls: Vec<(String, String)>,
}

/// Resolves the real values, generates the mocks, and builds the proxy routes.
/// `source` is the only point where the real value enters the process.
pub fn prepare(
    cfg: &Config,
    source: impl Fn(&str) -> Result<String, String>,
) -> Result<Prepared, String> {
    let mut p = Prepared {
        routes: HashMap::new(),
        mocks: Vec::new(),
        base_urls: Vec::new(),
    };
    for decl in &cfg.secrets {
        let c = connector(&decl.connector).ok_or("unknown connector")?;
        if p.routes.contains_key(&decl.connector) {
            return Err(format!("two secrets on connector {}", decl.connector));
        }
        p.routes.insert(
            decl.connector.clone(),
            Route {
                upstream: decl
                    .upstream
                    .clone()
                    .unwrap_or_else(|| c.upstream.to_string()),
                auth: c.auth,
                key: source(&decl.name)?,
            },
        );
        p.mocks
            .push((decl.name.clone(), secret::mock(c.mock_prefix)));
        for var in c.base_url_vars {
            p.base_urls.push((var.to_string(), decl.connector.clone()));
        }
    }
    Ok(p)
}

impl Prepared {
    /// The session token is the first path segment. The proxy listens on
    /// loopback, reachable by any process on the machine: without a token,
    /// another local user could discover the port and spend your key. The
    /// child receives it here, and no one else knows it.
    pub fn env_overrides(&self, port: u16, token: &str) -> Vec<(String, String)> {
        let mut out = self.mocks.clone();
        for (var, conn) in &self.base_urls {
            out.push((
                var.clone(),
                format!("http://127.0.0.1:{port}/{token}/{conn}"),
            ));
        }
        out
    }
}

/// The child inherits the current environment, minus the STRIP variables and
/// with mocks in place of the declared values. Everything else passes through
/// unchanged: Capshell only touches what it's been told to touch.
pub fn child_command(program: &str, args: &[String], overrides: &[(String, String)]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for var in STRIP {
        cmd.env_remove(var);
    }
    for (k, v) in overrides {
        cmd.env(k, v);
    }
    cmd
}

/// Outcome of the attempt to close the session's credential channels.
pub enum Isolation {
    /// The listed sockets don't exist in the child's mount namespace.
    Closed(String),
    /// There was nothing to close, or the platform doesn't need it.
    NotNeeded,
    /// The command runs anyway: degrade with a warning, don't refuse to work.
    Failed(String),
}

/// On Linux, wraps the command in bwrap to strip the keyring and agent
/// sockets from the child. Not needed on macOS: the Keychain authorizes by
/// binary signature, so the barrier is already there and more precise.
pub fn isolated_child_command(
    program: &str,
    args: &[String],
    overrides: &[(String, String)],
) -> (Command, Isolation) {
    if !cfg!(target_os = "linux") {
        return (
            child_command(program, args, overrides),
            Isolation::NotNeeded,
        );
    }
    let channels = sandbox::from_environment();
    if channels.nothing_to_close() {
        return (
            child_command(program, args, overrides),
            Isolation::NotNeeded,
        );
    }
    let bwrap_args = channels.bwrap_args();
    match sandbox::bwrap_usable(&bwrap_args) {
        Err(reason) => (
            child_command(program, args, overrides),
            Isolation::Failed(reason),
        ),
        Ok(()) => {
            let mut all = bwrap_args;
            all.push("--".into());
            all.push(program.to_string());
            all.extend(args.iter().cloned());
            (
                child_command("bwrap", &all, overrides),
                Isolation::Closed(channels.description()),
            )
        }
    }
}
