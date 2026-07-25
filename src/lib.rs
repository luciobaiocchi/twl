pub mod config;
pub mod proxy;
pub mod sandbox;
pub mod secret;

use config::{connector, Config};
use proxy::Route;
use std::collections::HashMap;
use std::process::Command;

/// Variabili che non passano al figlio. Su Linux `DBUS_SESSION_BUS_ADDRESS` e'
/// la strada per il Secret Service: toglierla da sola alzerebbe solo l'asticella,
/// perche' il socket resta indovinabile su `/run/user/<uid>/bus`. La barriera la
/// mette `sandbox`, togliendo il path dal mount namespace; questa e' la prima
/// riga di difesa, e l'unica quando bwrap non c'e'.
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
    /// Il token di sessione e' il primo segmento del path. Il proxy ascolta su
    /// loopback, raggiungibile da qualunque processo della macchina: senza
    /// token, un altro utente locale potrebbe scoprire la porta e spendere la
    /// tua chiave. Il figlio lo riceve qui dentro, nessun altro lo conosce.
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

/// Esito del tentativo di chiudere i canali di credenziali della sessione.
pub enum Chiusura {
    /// I socket elencati non esistono nel mount namespace del figlio.
    Chiusi(String),
    /// Non c'era niente da chiudere, o la piattaforma non ne ha bisogno.
    NonNecessaria,
    /// Il comando parte comunque: degradare con un avviso, non rifiutarsi
    /// di funzionare.
    Fallita(String),
}

/// Su Linux avvolge il comando in bwrap per togliere al figlio i socket del
/// portachiavi e degli agent. Su macOS non serve: il Keychain autorizza per
/// firma del binario, quindi la barriera c'e' gia' ed e' piu' precisa.
pub fn child_command_isolato(
    program: &str,
    args: &[String],
    overrides: &[(String, String)],
) -> (Command, Chiusura) {
    if !cfg!(target_os = "linux") {
        return (
            child_command(program, args, overrides),
            Chiusura::NonNecessaria,
        );
    }
    let canali = sandbox::dall_ambiente();
    if canali.nulla_da_chiudere() {
        return (
            child_command(program, args, overrides),
            Chiusura::NonNecessaria,
        );
    }
    let bwrap_args = canali.bwrap_args();
    match sandbox::bwrap_utilizzabile(&bwrap_args) {
        Err(motivo) => (
            child_command(program, args, overrides),
            Chiusura::Fallita(motivo),
        ),
        Ok(()) => {
            let mut tutti = bwrap_args;
            tutti.push("--".into());
            tutti.push(program.to_string());
            tutti.extend(args.iter().cloned());
            (
                child_command("bwrap", &tutti, overrides),
                Chiusura::Chiusi(canali.descrizione()),
            )
        }
    }
}
