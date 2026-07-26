use capshell::config::{connector, Config};
use capshell::{isolated_child_command, prepare, proxy, sandbox, secret, Isolation};
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
                "capshell run [--config capshell.yaml] [--env .env] -- <command> [args...]\n\
                 capshell secret set <NAME>\n\
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
        .ok_or("missing `-- <command>`")?;
    let (flags, rest) = (&args[..split], &args[split + 1..]);
    let program = rest.first().ok_or("missing command to run")?;

    let cfg = Config::load(&opt(flags, "--config").unwrap_or_else(|| "capshell.yaml".into()))?;

    // Value source: the keyring, or a .env as a migration path.
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
            .ok_or(format!("{name} missing from the --env file")),
        None => secret::get(name),
    })?;

    let budget = cfg.budget.map(|b| b.max_requests);
    let routes = std::mem::take(&mut prepared.routes);
    let handle = proxy::spawn(routes, budget).map_err(|e| e.to_string())?;

    // Variables from the file not declared in capshell.yaml pass through
    // unchanged: the user's .env also carries config the app needs.
    let declared: Vec<&str> = cfg.secrets.iter().map(|s| s.name.as_str()).collect();
    let mut overrides: Vec<(String, String)> = from_file
        .iter()
        .flatten()
        .filter(|(k, _)| !declared.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    warn_undeclared(&overrides);
    overrides.extend(prepared.env_overrides(handle.port, &handle.token));

    eprintln!(
        "capshell: proxy on 127.0.0.1:{} — {} secret(s) masked{}",
        handle.port,
        prepared.mocks.len(),
        budget
            .map(|b| format!(", budget {b} requests"))
            .unwrap_or_default()
    );

    let (mut cmd, isolation) = isolated_child_command(program, &rest[1..], &overrides);
    match isolation {
        Isolation::Closed(what) => eprintln!("capshell: channels closed to the child — {what}"),
        Isolation::NotNeeded => {}
        Isolation::Failed(reason) => eprintln!(
            "capshell: the keyring stays reachable from the child process ({reason}).\n\
             On Linux, bubblewrap is required to close the D-Bus channel."
        ),
    }
    if sandbox::from_environment().abstract_bus {
        eprintln!(
            "capshell: the D-Bus bus uses an abstract socket, which lives in the network\n\
             namespace rather than the filesystem: the mount namespace can't close it."
        );
    }

    let status = cmd.status().map_err(|e| format!("{program}: {e}"))?;

    // The most likely failure on first run: the client ignores the base URL,
    // calls the real provider, gets a 401, and the user blames Capshell.
    if handle.seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        eprintln!(
            "capshell: no request reached the proxy.\n\
             The client is ignoring the base URL: check that it honors one of {:?}",
            prepared
                .base_urls
                .iter()
                .map(|(v, _)| v)
                .collect::<Vec<_>>()
        );
    }
    exit(status.code().unwrap_or(1));
}

/// A heuristic never decides what to protect — the user declares that. But
/// flagging what *looks like* a credential and isn't declared costs nothing
/// and catches the most likely mistake: adding a key to the .env and
/// forgetting to declare it.
fn warn_undeclared(passthrough: &[(String, String)]) {
    const PREFIXES: &[&str] = &[
        "sk-",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "AKIA",
        "AIza",
        "gsk_",
    ];
    const SUFFIXES: &[&str] = &["_KEY", "_TOKEN", "_SECRET", "_PASSWORD"];

    let suspicious: Vec<&str> = passthrough
        .iter()
        .filter(|(k, v)| {
            PREFIXES.iter().any(|p| v.starts_with(p)) || SUFFIXES.iter().any(|s| k.ends_with(s))
        })
        .map(|(k, _)| k.as_str())
        .collect();
    if !suspicious.is_empty() {
        eprintln!(
            "capshell: these look like credentials but aren't declared in capshell.yaml,\n\
             so the child receives them in plaintext: {}",
            suspicious.join(", ")
        );
    }
}

fn secret_cmd(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("set") => {
            let name = args.get(1).ok_or("missing secret name")?;
            // From a terminal it's read with echo disabled; from a pipe it
            // reads a line, so `echo … | capshell secret set NAME` works.
            let value = match rpassword::prompt_password(format!("{name}: ")) {
                Ok(v) => v,
                Err(_) => {
                    let mut line = String::new();
                    std::io::stdin()
                        .read_line(&mut line)
                        .map_err(|e| format!("reading the value: {e}"))?;
                    line.trim_end_matches('\n').to_string()
                }
            };
            if value.is_empty() {
                return Err("empty value".into());
            }
            secret::set(name, &value)?;
            println!("{name} stored in the keyring.");
            Ok(())
        }
        Some("import") => {
            let path = args.get(1).ok_or("missing .env file")?;
            let cfg =
                Config::load(&opt(args, "--config").unwrap_or_else(|| "capshell.yaml".into()))?;
            let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let found: HashMap<String, String> = secret::parse_env_file(&raw).into_iter().collect();

            let mut replacements = Vec::new();
            for decl in &cfg.secrets {
                let Some(value) = found.get(&decl.name) else {
                    continue;
                };
                let c = connector(&decl.connector).ok_or("unknown connector")?;
                secret::set(&decl.name, value)?;
                replacements.push((decl.name.clone(), secret::mock(c.mock_prefix)));
            }
            if replacements.is_empty() {
                return Err(format!("no declared secret found in {path}"));
            }
            std::fs::write(format!("{path}.bak"), &raw).map_err(|e| e.to_string())?;
            std::fs::write(path, secret::rewrite_env_file(&raw, &replacements))
                .map_err(|e| e.to_string())?;
            println!(
                "{} secret(s) stored in the keyring. {path} rewritten with placeholders, original in {path}.bak",
                replacements.len()
            );
            Ok(())
        }
        _ => Err("usage: capshell secret set <NAME> | capshell secret import <file.env>".into()),
    }
}

/// Fake provider for trying out the whole round trip without a real key:
/// echoes back what it received, credential included.
fn mock_upstream(args: &[String]) -> Result<(), String> {
    let port: u16 = opt(args, "--port")
        .unwrap_or_else(|| "9000".into())
        .parse()
        .map_err(|_| "invalid port")?;
    let server = tiny_http::Server::http(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    eprintln!("mock-upstream on http://127.0.0.1:{port}");
    // One request at a time would choke the proxy, which sends several in
    // parallel over keep-alive connections.
    std::thread::scope(|s| {
        for req in server.incoming_requests() {
            s.spawn(|| serve_fake(req));
        }
    });
    Ok(())
}

fn serve_fake(req: tiny_http::Request) {
    {
        let url = req.url().to_string();
        let seen: Vec<String> = req
            .headers()
            .iter()
            .map(|h| {
                let name = h.field.to_string().to_ascii_lowercase();
                let value = h.value.to_string().replace('"', "'");
                // The received credential doesn't go back in full: we show
                // that it's there and how it starts, not its value.
                // Otherwise the proxy discards the response — rightly — and
                // nothing would be visible.
                let shown = if name == "authorization" || name == "x-api-key" {
                    let head: String = value.chars().take(18).collect();
                    format!("<received, {} bytes, starts with {head}>", value.len())
                } else {
                    value
                };
                format!("\"{name}\":\"{shown}\"")
            })
            .collect();
        eprintln!("  {} {}", req.method(), url);
        let resp = if url.starts_with("/redirect") {
            // To verify the proxy doesn't follow 3xx and doesn't reattach the key.
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
}
