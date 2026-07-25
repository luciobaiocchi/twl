use capshell::config::{connector, Config};
use capshell::{child_command_isolato, prepare, proxy, sandbox, secret, Chiusura};
use std::collections::HashMap;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("secret") => secret_cmd(&args[1..]),
        Some("mock-upstream") => mock_upstream(&args[1..]),
        _ => {
            eprintln!(
                "capshell run [--config capshell.yaml] [--env .env] -- <comando> [args...]\n\
                 capshell secret set <NOME>\n\
                 capshell secret import <file.env> [--config capshell.yaml]\n\
                 capshell mock-upstream [--port 9000]"
            );
            exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("capshell: {e}");
        exit(1);
    }
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn run(args: &[String]) -> Result<(), String> {
    let split = args
        .iter()
        .position(|a| a == "--")
        .ok_or("manca `-- <comando>`")?;
    let (flags, rest) = (&args[..split], &args[split + 1..]);
    let program = rest.first().ok_or("manca il comando da eseguire")?;

    let cfg = Config::load(&opt(flags, "--config").unwrap_or_else(|| "capshell.yaml".into()))?;

    // Sorgente dei valori: il portachiavi, o un .env come percorso di migrazione.
    let from_file: Option<HashMap<String, String>> = match opt(flags, "--env") {
        Some(path) => {
            let raw = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
            Some(secret::parse_env_file(&raw).into_iter().collect())
        }
        None => None,
    };
    let mut prepared = prepare(&cfg, |name| match &from_file {
        Some(map) => map
            .get(name)
            .cloned()
            .ok_or(format!("{name} assente dal file --env")),
        None => secret::get(name),
    })?;

    let budget = cfg.budget.map(|b| b.max_requests);
    let routes = std::mem::take(&mut prepared.routes);
    let handle = proxy::spawn(routes, budget).map_err(|e| e.to_string())?;

    // Le variabili del file non dichiarate in capshell.yaml passano invariate:
    // il .env dell'utente contiene anche configurazione che serve all'app.
    let declared: Vec<&str> = cfg.secrets.iter().map(|s| s.name.as_str()).collect();
    let mut overrides: Vec<(String, String)> = from_file
        .iter()
        .flatten()
        .filter(|(k, _)| !declared.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    avvisa_non_dichiarate(&overrides);
    overrides.extend(prepared.env_overrides(handle.port));

    eprintln!(
        "capshell: proxy su 127.0.0.1:{} — {} segreti mascherati{}",
        handle.port,
        prepared.mocks.len(),
        budget
            .map(|b| format!(", budget {b} richieste"))
            .unwrap_or_default()
    );

    let (mut cmd, chiusura) = child_command_isolato(program, &rest[1..], &overrides);
    match chiusura {
        Chiusura::Chiusi(cosa) => eprintln!("capshell: canali chiusi al figlio — {cosa}"),
        Chiusura::NonNecessaria => {}
        Chiusura::Fallita(motivo) => eprintln!(
            "capshell: il portachiavi resta raggiungibile dal processo figlio ({motivo}).\n\
             Su Linux serve bubblewrap per chiudere il canale D-Bus."
        ),
    }
    if sandbox::dall_ambiente().bus_astratto {
        eprintln!(
            "capshell: il bus D-Bus usa un socket astratto, che vive nel network\n\
             namespace e non nel filesystem: il mount namespace non lo chiude."
        );
    }

    let status = cmd.status().map_err(|e| format!("{program}: {e}"))?;

    // Il fallimento piu' probabile al primo avvio: il client ignora il base URL,
    // chiama il provider vero, prende 401, e l'utente da' la colpa a Capshell.
    if handle.seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        eprintln!(
            "capshell: nessuna richiesta e' arrivata al proxy.\n\
             Il client sta ignorando il base URL: verifica che rispetti una di {:?}",
            prepared
                .base_urls
                .iter()
                .map(|(v, _)| v)
                .collect::<Vec<_>>()
        );
    }
    exit(status.code().unwrap_or(1));
}

/// Un'euristica non decide mai cosa proteggere — quello lo dichiara l'utente.
/// Ma segnalare cio' che *sembra* una credenziale e non e' dichiarato costa
/// nulla e intercetta l'errore piu' probabile: aggiungere una chiave al .env e
/// dimenticarsi di dichiararla.
fn avvisa_non_dichiarate(passthrough: &[(String, String)]) {
    const PREFISSI: &[&str] = &[
        "sk-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "AKIA",
        "AIza",
        "gsk_",
    ];
    const SUFFISSI: &[&str] = &["_KEY", "_TOKEN", "_SECRET", "_PASSWORD"];

    let sospette: Vec<&str> = passthrough
        .iter()
        .filter(|(k, v)| {
            PREFISSI.iter().any(|p| v.starts_with(p)) || SUFFISSI.iter().any(|s| k.ends_with(s))
        })
        .map(|(k, _)| k.as_str())
        .collect();
    if !sospette.is_empty() {
        eprintln!(
            "capshell: sembrano credenziali ma non sono dichiarate in capshell.yaml,\n\
             quindi il figlio le riceve in chiaro: {}",
            sospette.join(", ")
        );
    }
}

fn secret_cmd(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("set") => {
            let name = args.get(1).ok_or("manca il nome del segreto")?;
            // Da terminale si legge con l'eco disabilitato; da pipe si legge una
            // riga, cosi' `echo … | capshell secret set NOME` funziona.
            let value = match rpassword::prompt_password(format!("{name}: ")) {
                Ok(v) => v,
                Err(_) => {
                    let mut riga = String::new();
                    std::io::stdin()
                        .read_line(&mut riga)
                        .map_err(|e| format!("lettura del valore: {e}"))?;
                    riga.trim_end_matches('\n').to_string()
                }
            };
            if value.is_empty() {
                return Err("valore vuoto".into());
            }
            secret::set(name, &value)?;
            println!("{name} nel portachiavi.");
            Ok(())
        }
        Some("import") => {
            let path = args.get(1).ok_or("manca il file .env")?;
            let cfg =
                Config::load(&opt(args, "--config").unwrap_or_else(|| "capshell.yaml".into()))?;
            let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let found: HashMap<String, String> = secret::parse_env_file(&raw).into_iter().collect();

            let mut replacements = Vec::new();
            for decl in &cfg.secrets {
                let Some(value) = found.get(&decl.name) else {
                    continue;
                };
                let c = connector(&decl.connector).ok_or("connector sconosciuto")?;
                secret::set(&decl.name, value)?;
                replacements.push((decl.name.clone(), secret::mock(c.mock_prefix)));
            }
            if replacements.is_empty() {
                return Err(format!("nessun segreto dichiarato trovato in {path}"));
            }
            std::fs::write(format!("{path}.bak"), &raw).map_err(|e| e.to_string())?;
            std::fs::write(path, secret::rewrite_env_file(&raw, &replacements))
                .map_err(|e| e.to_string())?;
            println!(
                "{} segreti nel portachiavi. {path} riscritto con i placeholder, originale in {path}.bak",
                replacements.len()
            );
            Ok(())
        }
        _ => Err("uso: capshell secret set <NOME> | capshell secret import <file.env>".into()),
    }
}

/// Finto provider per provare il giro completo senza una chiave vera: rimanda
/// indietro quello che ha ricevuto, credenziale inclusa.
fn mock_upstream(args: &[String]) -> Result<(), String> {
    let port: u16 = opt(args, "--port")
        .unwrap_or_else(|| "9000".into())
        .parse()
        .map_err(|_| "porta non valida")?;
    let server = tiny_http::Server::http(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    eprintln!("mock-upstream su http://127.0.0.1:{port}");
    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let seen: Vec<String> = req
            .headers()
            .iter()
            .map(|h| {
                let name = h.field.to_string().to_ascii_lowercase();
                let value = h.value.to_string().replace('"', "'");
                // La credenziale arrivata non torna indietro per intero: si
                // mostra che c'e' e come inizia, non quanto vale. Altrimenti il
                // proxy scarta la risposta — giustamente — e non si vede nulla.
                let shown = if name == "authorization" || name == "x-api-key" {
                    let head: String = value.chars().take(18).collect();
                    format!("<ricevuta, {} byte, inizia con {head}>", value.len())
                } else {
                    value
                };
                format!("\"{name}\":\"{shown}\"")
            })
            .collect();
        eprintln!("  {} {}", req.method(), url);
        let resp = if url.starts_with("/redirect") {
            // Per verificare che il proxy non segua i 3xx e non riallegi la chiave.
            tiny_http::Response::from_data(Vec::new())
                .with_status_code(302)
                .with_header(
                    tiny_http::Header::from_bytes("location", "http://evil.example/").unwrap(),
                )
        } else {
            let body = format!("{{\"path\":\"{url}\",\"headers\":{{{}}}}}", seen.join(","));
            tiny_http::Response::from_data(body.into_bytes())
                .with_status_code(200)
                .with_header(
                    tiny_http::Header::from_bytes("content-type", "application/json").unwrap(),
                )
        };
        let _ = req.respond(resp);
    }
    Ok(())
}
