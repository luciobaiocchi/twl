use std::path::PathBuf;
use std::process::exit;
use twl::config::{Config, CHILD_BASE_URL_ENV};
use twl::runtime::PasswordInput;
use twl::{child_command, prepare_demo, prepare_from, runtime, secret, vault, Prepared};
use zeroize::Zeroizing;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("vault") => vault_command(&args[1..]),
        Some("run") => run(&args[1..]),
        Some("serve") => serve(&args[1..]),
        Some("demo") => demo(&args[1..]),
        Some("doctor") if args.len() == 1 => {
            doctor();
            Ok(0)
        }
        _ => Err(usage()),
    };

    match result {
        Ok(code) => exit(code),
        Err(error) => {
            eprintln!("twl: {error}");
            exit(1);
        }
    }
}

fn usage() -> String {
    "usage:\n\
     twl vault seal --input TRUSTED.yaml|- --output towel.vault [--password-fd FD|--password-file PATH]\n\
     twl run --vault towel.vault --allow-route ID [--allow-route ID...] [--config towel.yaml] [--password-fd FD] -- <command> [args...]\n\
     twl serve --vault towel.vault --allow-route ID [--allow-route ID...] --session-file PATH [--config towel.yaml] [--password-fd FD|--password-file PATH]\n\
     twl demo [--config towel.yaml] -- <command> [args...]\n\
     twl doctor"
        .into()
}

#[derive(Default)]
struct SessionFlags {
    vault: Option<PathBuf>,
    config: Option<String>,
    authorized_routes: Vec<String>,
    password: PasswordInput,
}

fn parse_session_flags(
    flags: &[String],
    allow_password_file: bool,
) -> Result<SessionFlags, String> {
    let mut parsed = SessionFlags::default();
    let mut index = 0;
    while index < flags.len() {
        let option = flags[index].as_str();
        let value = flags
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--vault" => {
                if parsed.vault.replace(PathBuf::from(value)).is_some() {
                    return Err("--vault was specified more than once".into());
                }
            }
            "--config" => {
                if parsed.config.replace(value.clone()).is_some() {
                    return Err("--config was specified more than once".into());
                }
            }
            "--allow-route" => parsed.authorized_routes.push(value.clone()),
            "--password-fd" => parsed.password.set_descriptor(parse_descriptor(value)?)?,
            "--password-file" if allow_password_file => {
                parsed.password.set_file(PathBuf::from(value))?
            }
            "--password-file" => {
                return Err("--password-file is restricted to vault seal and isolated serve mode; use --password-fd for native run".into())
            }
            _ => return Err(format!("unknown option: {option}")),
        }
        index += 2;
    }
    if parsed.vault.is_none() {
        return Err("--vault is required".into());
    }
    Ok(parsed)
}

fn load_config(path: Option<&str>) -> Result<Config, String> {
    path.map(Config::load)
        .transpose()
        .map(|config| config.unwrap_or_default())
}

fn prepare_vault_session(flags: SessionFlags) -> Result<Prepared, String> {
    // Harden the trusted process before any password or decrypted credential is
    // read into memory.
    secret::process_preflight()?;
    let config = load_config(flags.config.as_deref())?;
    let request = config.grant_request(&flags.authorized_routes)?;
    let password = flags.password.resolve(|| {
        rpassword::prompt_password("Vault password: ")
            .map_err(|error| format!("reading vault password from terminal: {error}"))
    })?;
    let payload = vault::load(
        flags.vault.as_deref().expect("validated vault path"),
        &password,
    )?;
    prepare_from(&payload, &request)
}

fn run(args: &[String]) -> Result<i32, String> {
    let split = args
        .iter()
        .position(|argument| argument == "--")
        .ok_or("missing `-- <command>`")?;
    let flags = parse_session_flags(&args[..split], false)?;
    let command = args.get(split + 1).ok_or("missing command")?;
    let command_args = &args[split + 2..];
    let prepared = prepare_vault_session(flags)?;
    run_prepared(prepared, command, command_args)
}

fn serve(args: &[String]) -> Result<i32, String> {
    let mut session_flags = Vec::new();
    let mut session_file = None;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        if option == "--session-file" {
            if session_file.replace(PathBuf::from(value)).is_some() {
                return Err("--session-file was specified more than once".into());
            }
        } else {
            session_flags.push(args[index].clone());
            session_flags.push(value.clone());
        }
        index += 2;
    }
    let session_file = session_file.ok_or("--session-file is required")?;
    let prepared = prepare_vault_session(parse_session_flags(&session_flags, true)?)?;
    let (handle, manifest) = prepared.start()?;
    runtime::write_session_manifest(&session_file, &manifest)?;
    eprintln!(
        "twl: isolated session ready on 127.0.0.1:{} with {} route(s); manifest {}",
        handle.port,
        manifest.routes.len(),
        session_file.display()
    );
    loop {
        std::thread::park();
    }
}

fn vault_command(args: &[String]) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        Some("seal") => seal_vault(&args[1..]),
        _ => Err(
            "usage: twl vault seal --input TRUSTED.yaml|- --output towel.vault [--password-fd FD|--password-file PATH]"
                .into(),
        ),
    }
}

fn seal_vault(args: &[String]) -> Result<i32, String> {
    let mut input = None;
    let mut output = None;
    let mut password_input = PasswordInput::default();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--input" => {
                if input.replace(value.clone()).is_some() {
                    return Err("--input was specified more than once".into());
                }
            }
            "--output" => {
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err("--output was specified more than once".into());
                }
            }
            "--password-fd" => password_input.set_descriptor(parse_descriptor(value)?)?,
            "--password-file" => password_input.set_file(PathBuf::from(value))?,
            _ => return Err(format!("unknown option: {option}")),
        }
        index += 2;
    }
    let input = input.ok_or("--input is required")?;
    let output = output.ok_or("--output is required")?;
    // Vault creation handles the same reusable credentials as runtime opening,
    // so it requires the same protected Towel process boundary.
    secret::process_preflight()?;
    let noninteractive_password = password_input.uses_noninteractive_source();
    let password = password_input.resolve(|| {
        rpassword::prompt_password("New vault password: ")
            .map_err(|error| format!("reading vault password from terminal: {error}"))
    })?;
    if !noninteractive_password {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Confirm vault password: ")
                .map_err(|error| format!("reading vault password confirmation: {error}"))?,
        );
        if confirmation.as_str() != password.as_str() {
            return Err("vault password confirmation did not match".into());
        }
    }

    let trusted = runtime::read_trusted_document(&input)?;
    let payload = twl::policy::VaultPayload::parse_trusted_yaml(&trusted)?;
    let encoded = vault::seal(&payload, &password)?;
    vault::write_new(&output, &encoded)?;
    eprintln!("twl: wrote encrypted vault {}", output.display());
    if input != "-" {
        eprintln!(
            "twl: warning: trusted plaintext source {} was not removed",
            input
        );
    }
    Ok(0)
}

fn demo(args: &[String]) -> Result<i32, String> {
    let split = args
        .iter()
        .position(|argument| argument == "--")
        .ok_or("missing `-- <command>`")?;
    let config_path = match &args[..split] {
        [] => None,
        [option, path] if option == "--config" => Some(path.as_str()),
        [option, ..] if option != "--config" => {
            return Err(format!("unknown option: {option}"));
        }
        _ => return Err("usage: twl demo [--config towel.yaml] -- <command> [args...]".into()),
    };
    let command = args.get(split + 1).ok_or("missing command")?;
    let command_args = &args[split + 2..];
    let config = load_config(config_path)?;
    let authorized = vec!["application".to_string()];
    let request = config.grant_request(&authorized)?;
    let upstream = spawn_demo_upstream()?;
    let prepared = prepare_demo(&upstream, &request)?;
    eprintln!("twl: demo mode uses a generated canary; no real credential is read");
    run_prepared(prepared, command, command_args)
}

fn run_prepared(prepared: Prepared, command: &str, command_args: &[String]) -> Result<i32, String> {
    let (handle, manifest) = prepared.start()?;
    let overrides = manifest.environment();
    eprintln!(
        "twl: application broker on 127.0.0.1:{} with {} route(s)",
        handle.port,
        manifest.routes.len()
    );
    let status = child_command(command, command_args, &overrides)
        .status()
        .map_err(|error| format!("{command}: {error}"))?;

    if handle.seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        eprintln!(
            "twl: no authorized request reached the broker; verify that the application uses {CHILD_BASE_URL_ENV} or a TWL_ROUTE_*_URL"
        );
    }
    Ok(status.code().unwrap_or(1))
}

fn doctor() {
    println!("Towel diagnostic");
    match secret::process_preflight() {
        Ok(()) => println!("  protected broker sessions: available"),
        Err(error) => println!("  protected broker sessions: unavailable ({error})"),
    }
    println!("  portable encrypted vault: Argon2id + XChaCha20-Poly1305");
    println!("  canary-only demo:         available");
}

fn parse_descriptor(value: &str) -> Result<i32, String> {
    value
        .parse()
        .map_err(|_| "file descriptors must be numeric".to_string())
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
            let shown = if name == "authorization" {
                format!("<received, {} bytes>", value.len())
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
