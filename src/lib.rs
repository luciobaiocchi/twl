pub mod config;
pub mod proxy;
pub mod secret;

use config::{connector, Config};
use proxy::Route;
use std::collections::HashMap;
use std::process::Command;

/// Variabili che non passano al figlio. Su Linux `DBUS_SESSION_BUS_ADDRESS` e'
/// la strada per il Secret Service: toglierla alza l'asticella, ma il socket
/// resta indovinabile — la barriera vera arriva in M1 col mount namespace.
pub const STRIP: &[&str] = &["DBUS_SESSION_BUS_ADDRESS"];

pub struct Prepared {
    pub routes: HashMap<String, Route>,
    /// (nome della variabile, valore finto) — quello che vede l'agente.
    pub mocks: Vec<(String, String)>,
    /// (nome della variabile, nome del connector) per i base URL.
    pub base_urls: Vec<(String, String)>,
}

/// Risolve i valori reali, genera i mock e costruisce le rotte del proxy.
/// `source` e' l'unico punto in cui il valore vero entra nel processo.
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
        let c = connector(&decl.connector).ok_or("connector sconosciuto")?;
        if p.routes.contains_key(&decl.connector) {
            return Err(format!("due segreti sul connector {}", decl.connector));
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
    pub fn env_overrides(&self, port: u16) -> Vec<(String, String)> {
        let mut out = self.mocks.clone();
        for (var, conn) in &self.base_urls {
            out.push((var.clone(), format!("http://127.0.0.1:{port}/{conn}")));
        }
        out
    }
}

/// Il figlio eredita l'environment corrente, meno le variabili di STRIP e con i
/// mock al posto dei valori dichiarati. Tutto il resto passa invariato:
/// Capshell tocca solo cio' che gli e' stato detto di toccare.
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
