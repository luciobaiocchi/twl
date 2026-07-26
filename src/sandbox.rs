//! Closing the session's credential channels, on Linux.
//!
//! The Secret Service doesn't authorize per application: any process running
//! as your user that reaches the D-Bus session bus can ask for your items.
//! But the bus is a socket on a filesystem path, so it's enough that the path
//! doesn't exist in the child's mount namespace: `connect()` fails and no
//! environment variable can recover it.
//!
//! We're not confining the filesystem — `/` stays mounted as-is. We're
//! removing sockets. Same for ssh-agent, gpg-agent, and the Docker socket,
//! which are the other credential oracles within the agent's reach.

use std::path::{Path, PathBuf};

/// What to hide from the child, resolved from the parent's environment.
#[derive(Debug, Default, PartialEq)]
pub struct Channels {
    /// Needs a tmpfs on top: holds `bus`, `keyring/`, `gnupg/`.
    pub xdg_runtime: Option<PathBuf>,
    /// Individual sockets, each covered with /dev/null.
    pub sockets: Vec<PathBuf>,
    /// A bus on an abstract socket lives in the network namespace, not the
    /// filesystem: the mount namespace can't touch it, and that needs saying.
    pub abstract_bus: bool,
}

const KNOWN_SOCKETS: &[&str] = &["/var/run/docker.sock", "/run/docker.sock"];

pub fn channels(var: impl Fn(&str) -> Option<String>, exists: impl Fn(&Path) -> bool) -> Channels {
    let mut c = Channels::default();

    let xdg = var("XDG_RUNTIME_DIR").map(PathBuf::from);
    if let Some(dir) = xdg.as_ref().filter(|d| exists(d)) {
        c.xdg_runtime = Some(dir.clone());
    }

    // `unix:path=/run/user/1000/bus` or `unix:abstract=/tmp/dbus-XXXX`.
    if let Some(addr) = var("DBUS_SESSION_BUS_ADDRESS") {
        if addr.contains("abstract=") {
            c.abstract_bus = true;
        } else if let Some(path) = addr.split("path=").nth(1) {
            let path = PathBuf::from(path.split(',').next().unwrap_or(path));
            let inside_xdg = c.xdg_runtime.as_ref().is_some_and(|d| path.starts_with(d));
            if !inside_xdg && exists(&path) {
                c.sockets.push(path);
            }
        }
    }

    let mut add = |path: PathBuf| {
        let inside_xdg = c.xdg_runtime.as_ref().is_some_and(|d| path.starts_with(d));
        if !inside_xdg && exists(&path) {
            c.sockets.push(path);
        }
    };

    if let Some(path) = var("SSH_AUTH_SOCK") {
        add(PathBuf::from(path));
    }
    if let Some(home) = var("HOME") {
        add(PathBuf::from(home).join(".gnupg/S.gpg-agent"));
    }
    for known in KNOWN_SOCKETS {
        add(PathBuf::from(known));
    }

    c
}

impl Channels {
    pub fn nothing_to_close(&self) -> bool {
        self.xdg_runtime.is_none() && self.sockets.is_empty()
    }

    /// bwrap arguments up to `--`, excluding the command.
    ///
    /// `--dev-bind / /` keeps the filesystem as-is: this isn't a sandbox,
    /// it's a view with a few sockets missing. In particular, `--unshare-net`
    /// is **never** passed — that would also take away the loopback, and the
    /// child would no longer be able to reach the proxy.
    pub fn bwrap_args(&self) -> Vec<String> {
        let mut a = vec![
            "--dev-bind".into(),
            "/".into(),
            "/".into(),
            "--die-with-parent".into(),
        ];
        if let Some(dir) = &self.xdg_runtime {
            a.push("--tmpfs".into());
            a.push(dir.display().to_string());
        }
        for s in &self.sockets {
            a.push("--bind".into());
            a.push("/dev/null".into());
            a.push(s.display().to_string());
        }
        a
    }

    pub fn description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(d) = &self.xdg_runtime {
            parts.push(d.display().to_string());
        }
        parts.extend(self.sockets.iter().map(|s| s.display().to_string()));
        parts.join(", ")
    }
}

pub fn from_environment() -> Channels {
    channels(|k| std::env::var(k).ok(), |p| p.exists())
}

/// Checks that bwrap is usable *before* launching the real command with it:
/// unprivileged user namespaces can be disabled, and a failure halfway
/// through would be indistinguishable from an error in the user's command.
pub fn bwrap_usable(args: &[String]) -> Result<(), String> {
    let mut probe = std::process::Command::new("bwrap");
    probe.args(args).arg("--").arg("true");
    match probe.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err("bwrap not installed".into()),
        Err(e) => Err(e.to_string()),
    }
}
