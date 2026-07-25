use mithril::config::{connector, Config};
use mithril::{child_command, prepare, prepare_demo, proxy, secret, Prepared};
use std::collections::HashMap;
use std::path::Path;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("demo") => demo(&args[1..]),
        Some("secret") => secret_command(&args[1..]).map(|_| 0),
        Some("doctor") => {
            doctor();
            Ok(0)
        }
        _ => Err(usage()),
    };

    match result {
        Ok(code) => exit(code),
        Err(error) => {
            eprintln!("mtl: {error}");
            exit(1);
        }
    }
}

fn usage() -> String {
    "usage:\n\
     mtl run [--config mithril.yaml] -- <command> [args...]\n\
     mtl demo [--config mithril.yaml] -- <command> [args...]\n\
     mtl secret set <connector>\n\
     mtl secret import <file.env> [--config mithril.yaml]\n\
     mtl secret delete <connector>\n\
     mtl doctor"
        .into()
}

fn config_path(flags: &[String]) -> Result<String, String> {
    let mut path = "mithril.yaml".to_string();
    let mut index = 0;
    while index < flags.len() {
        if flags[index] != "--config" {
            return Err(format!("unknown option: {}", flags[index]));
        }
        path = flags
            .get(index + 1)
            .cloned()
            .ok_or("--config requires a path")?;
        index += 2;
    }
    Ok(path)
}

fn invocation(args: &[String]) -> Result<(Config, &str, &[String]), String> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `-- <command>`")?;
    let config = Config::load(&config_path(&args[..split])?)?;
    let command = args.get(split + 1).ok_or("missing command")?;
    Ok((config, command, &args[split + 2..]))
}

fn run(args: &[String]) -> Result<i32, String> {
    let (config, command, command_args) = invocation(args)?;
    eprintln!(
        "mtl: requesting human authorization for: {}",
        config.connectors.join(", ")
    );
    let prepared = prepare(&config, |connector| secret::get(connector.id))?;
    run_prepared(config, prepared, command, command_args)
}

fn demo(args: &[String]) -> Result<i32, String> {
    let (config, command, command_args) = invocation(args)?;
    let upstream = spawn_demo_upstream()?;
    let prepared = prepare_demo(&config, &upstream)?;
    eprintln!("mtl: demo mode uses generated canaries; no keyring access");
    run_prepared(config, prepared, command, command_args)
}

fn run_prepared(
    config: Config,
    mut prepared: Prepared,
    command: &str,
    command_args: &[String],
) -> Result<i32, String> {
    let budget = config.budget.map(|budget| budget.max_requests);
    let routes = std::mem::take(&mut prepared.routes);
    let handle = proxy::spawn(routes, budget).map_err(|error| error.to_string())?;
    let overrides = prepared.env_overrides(handle.port, &handle.token);

    eprintln!(
        "mtl: session proxy on 127.0.0.1:{} — {} connector(s){}",
        handle.port,
        prepared.mocks.len(),
        budget
            .map(|max| format!(", advisory budget {max} requests"))
            .unwrap_or_default()
    );
    let status = child_command(command, command_args, &overrides)
        .status()
        .map_err(|error| format!("{command}: {error}"))?;

    if handle.seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        eprintln!(
            "mtl: no authorized request reached the proxy; verify that the client honors one of {:?}",
            prepared
                .base_urls
                .iter()
                .map(|(variable, _, _)| variable)
                .collect::<Vec<_>>()
        );
    }
    Ok(status.code().unwrap_or(1))
}

fn secret_command(args: &[String]) -> Result<(), String> {
    if matches!(
        args.first().map(String::as_str),
        Some("set" | "import" | "delete")
    ) {
        secret::preflight()?;
    }
    match args.first().map(String::as_str) {
        Some("set") => {
            let name = args.get(1).ok_or("missing connector")?;
            if args.len() != 2 {
                return Err("usage: mtl secret set <connector>".into());
            }
            let connector = connector(name).ok_or_else(|| format!("unknown connector: {name}"))?;
            let value = rpassword::prompt_password(format!("{}: ", connector.secret_env))
                .map_err(|error| format!("reading from terminal: {error}"))?;
            if value.is_empty() {
                return Err("empty credential".into());
            }
            secret::set(connector.id, &value)?;
            println!("Stored {} with user-presence protection.", connector.id);
            Ok(())
        }
        Some("import") => import_secret(args),
        Some("delete") => {
            let name = args.get(1).ok_or("missing connector")?;
            if args.len() != 2 {
                return Err("usage: mtl secret delete <connector>".into());
            }
            let connector = connector(name).ok_or_else(|| format!("unknown connector: {name}"))?;
            secret::delete(connector.id)?;
            println!("Deleted {} from the keyring.", connector.id);
            Ok(())
        }
        _ => {
            Err("usage: mtl secret set <connector> | import <file.env> | delete <connector>".into())
        }
    }
}

fn import_secret(args: &[String]) -> Result<(), String> {
    let path = args.get(1).ok_or("missing .env path")?;
    let config = Config::load(&config_path(&args[2..])?)?;
    let raw = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    let found: HashMap<String, String> = secret::parse_env_file(&raw).into_iter().collect();

    let mut values = Vec::new();
    for name in &config.connectors {
        let connector = connector(name).ok_or_else(|| format!("unknown connector: {name}"))?;
        let value = found
            .get(connector.secret_env)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{} is missing from {path}", connector.secret_env))?;
        values.push((connector, value.clone()));
    }

    let mut replacements = Vec::new();
    for (connector, value) in values {
        secret::set(connector.id, &value)?;
        replacements.push((
            connector.secret_env.to_string(),
            secret::mock(connector.mock_prefix),
        ));
    }
    let rewritten = secret::rewrite_env_file(&raw, &replacements);
    secret::atomic_rewrite(Path::new(path), &rewritten)?;
    println!(
        "Imported {} credential(s); {path} was atomically rewritten without a plaintext backup.",
        replacements.len()
    );
    Ok(())
}

fn doctor() {
    println!("Mithril diagnostic");
    match secret::preflight() {
        Ok(()) => {
            println!("  secure keyring sessions: available (native user presence + Keychain ACL)")
        }
        Err(error) => {
            println!("  secure keyring sessions: unavailable ({error})");
            println!("  safe local option:       mtl demo");
            println!("  real credentials:        unavailable in this build");
        }
    }
}

fn spawn_demo_upstream() -> Result<String, String> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let port = server
        .server_addr()
        .to_ip()
        .ok_or("demo upstream did not bind an IP socket")?
        .port();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            std::thread::spawn(move || serve_demo_upstream(request));
        }
    });
    Ok(format!("http://127.0.0.1:{port}"))
}

fn serve_demo_upstream(request: tiny_http::Request) {
    let path = request.url().replace(['"', '\\'], "'");
    let headers: Vec<String> = request
        .headers()
        .iter()
        .map(|header| {
            let name = header.field.to_string().to_ascii_lowercase();
            let value = header.value.to_string().replace(['"', '\\'], "'");
            let shown = if name == "authorization" || name == "x-api-key" {
                let prefix: String = value.chars().take(18).collect();
                format!("<received, {} bytes, starts with {prefix}>", value.len())
            } else {
                value
            };
            format!("\"{name}\":\"{shown}\"")
        })
        .collect();
    let body = format!(
        "{{\"path\":\"{path}\",\"headers\":{{{}}}}}",
        headers.join(",")
    );
    let header = tiny_http::Header::from_bytes("content-type", "application/json").unwrap();
    let _ = request.respond(
        tiny_http::Response::from_data(body.into_bytes())
            .with_status_code(200)
            .with_header(header),
    );
}
