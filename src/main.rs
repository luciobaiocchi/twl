use mithril::config::{Config, CHILD_BASE_URL_ENV, CHILD_SECRET_ENV, PARENT_SECRET_ENV};
use mithril::{child_command, prepare_demo, prepare_session, runtime, secret, Prepared};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
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
            eprintln!("mtl: {error}");
            exit(1);
        }
    }
}

fn usage() -> String {
    "usage:\n\
     mtl run [--config mithril.yaml] --upstream URL [--secret-fd FD] -- <command> [args...]\n\
     mtl demo [--config mithril.yaml] -- <command> [args...]\n\
     mtl doctor"
        .into()
}

#[derive(Default)]
struct RunFlags {
    config: Option<String>,
    runtime: runtime::Inputs,
}

fn run_flags(flags: &[String]) -> Result<RunFlags, String> {
    let mut parsed = RunFlags::default();
    let mut index = 0;
    while index < flags.len() {
        let option = flags[index].as_str();
        let value = flags
            .get(index + 1)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--config" => {
                if parsed.config.replace(value.clone()).is_some() {
                    return Err("--config was specified more than once".into());
                }
            }
            "--upstream" => parsed.runtime.set_upstream(value.clone())?,
            "--secret-fd" => {
                let fd = value
                    .parse()
                    .map_err(|_| "--secret-fd requires a numeric descriptor".to_string())?;
                parsed.runtime.set_secret_fd(fd)?;
            }
            _ => return Err(format!("unknown option: {option}")),
        }
        index += 2;
    }
    Ok(parsed)
}

fn config_flags(flags: &[String]) -> Result<Option<String>, String> {
    match flags {
        [] => Ok(None),
        [option, path] if option == "--config" => Ok(Some(path.clone())),
        [option, ..] if option != "--config" => Err(format!("unknown option: {option}")),
        _ => Err("usage: --config mithril.yaml".into()),
    }
}

fn load_config(path: Option<&str>) -> Result<Config, String> {
    path.map(Config::load)
        .transpose()
        .map(|config| config.unwrap_or_default())
}

fn run_invocation(args: &[String]) -> Result<(Config, RunFlags, &str, &[String]), String> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `-- <command>`")?;
    let flags = run_flags(&args[..split])?;
    let config = load_config(flags.config.as_deref())?;
    let command = args.get(split + 1).ok_or("missing command")?;
    Ok((config, flags, command, &args[split + 2..]))
}

fn demo_invocation(args: &[String]) -> Result<(Config, &str, &[String]), String> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `-- <command>`")?;
    let config_path = config_flags(&args[..split])?;
    let config = load_config(config_path.as_deref())?;
    let command = args.get(split + 1).ok_or("missing command")?;
    Ok((config, command, &args[split + 2..]))
}

fn run(args: &[String]) -> Result<i32, String> {
    let (config, flags, command, command_args) = run_invocation(args)?;
    eprintln!("mtl: requesting the project application credential");
    let resolved = flags.runtime.resolve(|| {
        rpassword::prompt_password(format!("{CHILD_SECRET_ENV}: "))
            .map_err(|error| format!("reading from terminal: {error}"))
    })?;
    if resolved.used_environment_secret {
        eprintln!(
            "mtl: warning: {PARENT_SECRET_ENV} is a weaker input because parent environments can leak through shell history, logs, or process metadata; prefer --secret-fd FD"
        );
    }
    run_prepared(
        config,
        prepare_session(resolved.material)?,
        command,
        command_args,
    )
}

fn demo(args: &[String]) -> Result<i32, String> {
    let (config, command, command_args) = demo_invocation(args)?;
    let upstream = spawn_demo_upstream()?;
    let prepared = prepare_demo(&upstream)?;
    eprintln!("mtl: demo mode uses a generated canary; no real credential is read");
    run_prepared(config, prepared, command, command_args)
}

fn run_prepared(
    config: Config,
    prepared: Prepared,
    command: &str,
    command_args: &[String],
) -> Result<i32, String> {
    let budget = config.budget.map(|budget| budget.max_requests);
    let (handle, overrides) = prepared.start(budget).map_err(|error| error.to_string())?;

    eprintln!(
        "mtl: application proxy on 127.0.0.1:{}{}",
        handle.port,
        budget
            .map(|max| format!(", request budget {max}"))
            .unwrap_or_default()
    );
    let status = child_command(command, command_args, &overrides)
        .status()
        .map_err(|error| format!("{command}: {error}"))?;

    if handle.seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        eprintln!(
            "mtl: no authorized request reached the proxy; verify that the application uses {CHILD_BASE_URL_ENV}"
        );
    }
    Ok(status.code().unwrap_or(1))
}

fn doctor() {
    println!("Mithril diagnostic");
    match secret::process_preflight() {
        Ok(()) => println!("  protected project sessions: available"),
        Err(error) => println!("  protected project sessions: unavailable ({error})"),
    }
    println!("  canary-only demo:           available");
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
