//! Chiusura dei canali di credenziali della sessione, su Linux.
//!
//! Il Secret Service non autorizza per applicazione: qualunque processo del tuo
//! utente che raggiunge il bus D-Bus puo' chiedere i tuoi item. Ma il bus e' un
//! socket su un path del filesystem, quindi basta che quel path non esista nel
//! mount namespace del figlio: la `connect()` fallisce e nessuna variabile
//! d'ambiente puo' recuperarlo.
//!
//! Non stiamo confinando il filesystem — `/` resta montato com'e'. Stiamo
//! togliendo dei socket. Lo stesso vale per ssh-agent, gpg-agent e il socket
//! Docker, che sono gli altri oracoli di credenziali a portata dell'agente.

use std::path::{Path, PathBuf};

/// Cosa nascondere al figlio, risolto dall'ambiente del padre.
#[derive(Debug, Default, PartialEq)]
pub struct Canali {
    /// Va coperta con un tmpfs: contiene `bus`, `keyring/`, `gnupg/`.
    pub xdg_runtime: Option<PathBuf>,
    /// Socket singoli, coperti uno a uno con /dev/null.
    pub socket: Vec<PathBuf>,
    /// Un bus su socket astratto vive nel network namespace, non nel
    /// filesystem: il mount namespace non lo tocca e va detto.
    pub bus_astratto: bool,
}

const SOCKET_NOTI: &[&str] = &["/var/run/docker.sock", "/run/docker.sock"];

pub fn canali(var: impl Fn(&str) -> Option<String>, esiste: impl Fn(&Path) -> bool) -> Canali {
    let mut c = Canali::default();

    let xdg = var("XDG_RUNTIME_DIR").map(PathBuf::from);
    if let Some(dir) = xdg.as_ref().filter(|d| esiste(d)) {
        c.xdg_runtime = Some(dir.clone());
    }

    // `unix:path=/run/user/1000/bus` oppure `unix:abstract=/tmp/dbus-XXXX`.
    if let Some(addr) = var("DBUS_SESSION_BUS_ADDRESS") {
        if addr.contains("abstract=") {
            c.bus_astratto = true;
        } else if let Some(path) = addr.split("path=").nth(1) {
            let path = PathBuf::from(path.split(',').next().unwrap_or(path));
            let dentro_xdg = c.xdg_runtime.as_ref().is_some_and(|d| path.starts_with(d));
            if !dentro_xdg && esiste(&path) {
                c.socket.push(path);
            }
        }
    }

    let mut aggiungi = |path: PathBuf| {
        let dentro_xdg = c.xdg_runtime.as_ref().is_some_and(|d| path.starts_with(d));
        if !dentro_xdg && esiste(&path) {
            c.socket.push(path);
        }
    };

    if let Some(path) = var("SSH_AUTH_SOCK") {
        aggiungi(PathBuf::from(path));
    }
    if let Some(home) = var("HOME") {
        aggiungi(PathBuf::from(home).join(".gnupg/S.gpg-agent"));
    }
    for noto in SOCKET_NOTI {
        aggiungi(PathBuf::from(noto));
    }

    c
}

impl Canali {
    pub fn nulla_da_chiudere(&self) -> bool {
        self.xdg_runtime.is_none() && self.socket.is_empty()
    }

    /// Argomenti di bwrap fino al `--`, escluso il comando.
    ///
    /// `--dev-bind / /` tiene il filesystem come sta: non e' un sandbox, e'
    /// una vista da cui mancano dei socket. In particolare **non** si passa
    /// `--unshare-net`, altrimenti il figlio perderebbe anche il loopback e
    /// non arriverebbe piu' al proxy.
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
        for s in &self.socket {
            a.push("--bind".into());
            a.push("/dev/null".into());
            a.push(s.display().to_string());
        }
        a
    }

    pub fn descrizione(&self) -> String {
        let mut parti = Vec::new();
        if let Some(d) = &self.xdg_runtime {
            parti.push(d.display().to_string());
        }
        parti.extend(self.socket.iter().map(|s| s.display().to_string()));
        parti.join(", ")
    }
}

pub fn dall_ambiente() -> Canali {
    canali(|k| std::env::var(k).ok(), |p| p.exists())
}

/// Verifica che bwrap sia utilizzabile *prima* di lanciarci il comando vero:
/// gli unprivileged user namespace possono essere disabilitati, e un fallimento
/// a meta' strada sarebbe indistinguibile da un errore del comando dell'utente.
pub fn bwrap_utilizzabile(args: &[String]) -> Result<(), String> {
    let mut prova = std::process::Command::new("bwrap");
    prova.args(args).arg("--").arg("true");
    match prova.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err("bwrap non installato".into()),
        Err(e) => Err(e.to_string()),
    }
}
