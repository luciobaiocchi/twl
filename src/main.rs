use std::io::{self, Write};
use std::process::exit;
use twl::config::Config;
use twl::project::{
    validate_identifier, MacKeychainProjectStore, Project, ProjectRoute, ProjectStore,
};
use twl::{child_command, prepare_demo, prepare_project, secret, Prepared};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("project") => project_command(&args[1..]).map(|_| 0),
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
            eprintln!("twl: {error}");
            exit(1);
        }
    }
}

fn usage() -> String {
    "usage:\n\
     twl project add <name>\n\
     twl project list\n\
     twl project show <name>\n\
     twl project edit <name>\n\
     twl project delete <name>\n\
     twl run --project <name> -- <command> [args...]\n\
     twl demo [--config towel.yaml] -- <command> [args...]\n\
     twl doctor"
        .into()
}

fn one_name(args: &[String], operation: &str) -> Result<String, String> {
    let [name] = args else {
        return Err(format!("usage: twl project {operation} <name>"));
    };
    validate_identifier(name, "project name")?;
    Ok(name.clone())
}

fn project_command(args: &[String]) -> Result<(), String> {
    let store = MacKeychainProjectStore::new();
    match args.first().map(String::as_str) {
        Some("add") => {
            let name = one_name(&args[1..], "add")?;
            secret::process_preflight()?;
            let project = prompt_project(name, None)?;
            store.create(&project)?;
            println!(
                "Added project {} with {} route(s).",
                project.name,
                project.routes.len()
            );
            Ok(())
        }
        Some("list") if args.len() == 1 => {
            for name in store.list()? {
                println!("{name}");
            }
            Ok(())
        }
        Some("show") => {
            let name = one_name(&args[1..], "show")?;
            show_project(&store.get(&name)?);
            Ok(())
        }
        Some("edit") => {
            let name = one_name(&args[1..], "edit")?;
            let existing = store.get(&name)?;
            let project = prompt_project(name, Some(&existing))?;
            store.replace(&project)?;
            println!(
                "Updated project {} with {} route(s).",
                project.name,
                project.routes.len()
            );
            Ok(())
        }
        Some("delete") => {
            let name = one_name(&args[1..], "delete")?;
            store.delete(&name)?;
            println!("Deleted project {name}.");
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn prompt(label: &str) -> Result<String, String> {
    eprint!("{label}: ");
    io::stderr().flush().map_err(|error| error.to_string())?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("reading input: {error}"))?;
    Ok(value.trim().to_string())
}

fn prompt_default(label: &str, default: Option<&str>) -> Result<String, String> {
    let shown = default
        .map(|value| format!(" [{value}]"))
        .unwrap_or_default();
    let value = prompt(&format!("{label}{shown}"))?;
    Ok(if value.is_empty() {
        default.unwrap_or_default().to_string()
    } else {
        value
    })
}

fn prompt_project(name: String, existing: Option<&Project>) -> Result<Project, String> {
    eprintln!("Enter routes. Leave the route name blank when finished.");
    let mut routes = Vec::new();
    let mut position = 0;
    loop {
        let old = existing.and_then(|project| project.routes.get(position));
        let route_name = prompt_default("Route name", old.map(|route| route.name.as_str()))?;
        if route_name.is_empty() {
            break;
        }
        validate_identifier(&route_name, "route name")?;
        let matching = existing
            .and_then(|project| project.routes.iter().find(|route| route.name == route_name));
        let base_url = prompt_default(
            "Exact HTTPS base URL",
            matching.map(|route| route.base_url.as_str()),
        )?;
        let api_key_env = prompt_default(
            "Application API-key environment variable",
            matching.map(|route| route.api_key_env.as_str()),
        )?;
        let base_url_env = prompt_default(
            "Application base-URL environment variable",
            matching.map(|route| route.base_url_env.as_str()),
        )?;
        let key_label = if matching.is_some() {
            "Static Bearer API key (leave blank to keep existing): "
        } else {
            "Static Bearer API key: "
        };
        let entered = rpassword::prompt_password(key_label)
            .map_err(|error| format!("reading API key from terminal: {error}"))?;
        let api_key = if entered.is_empty() {
            matching
                .map(|route| route.api_key.clone())
                .ok_or("API key must not be empty")?
        } else {
            entered
        };
        routes.push(ProjectRoute {
            name: route_name,
            base_url,
            api_key,
            api_key_env,
            base_url_env,
        });
        position += 1;
    }
    Project::new(name, routes)
}

fn show_project(project: &Project) {
    print!("{}", project.description());
}

fn run(args: &[String]) -> Result<i32, String> {
    let (name, command, command_args) = run_invocation(args)?;
    let store = MacKeychainProjectStore::new();
    let project = store.get(name)?;
    let route_count = project.routes.len();
    let prepared = prepare_project(project)?;
    eprintln!("twl: authorized project {name} with {route_count} route(s) for this session");
    run_prepared(prepared, command, command_args, None)
}

fn run_invocation(args: &[String]) -> Result<(&str, &str, &[String]), String> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `-- <command>`")?;
    let name = match &args[..split] {
        [option, name] if option == "--project" => name.as_str(),
        [option, ..] if option != "--project" => return Err(format!("unknown option: {option}")),
        _ => return Err("usage: twl run --project <name> -- <command> [args...]".into()),
    };
    validate_identifier(name, "project name")?;
    let command = args.get(split + 1).ok_or("missing command")?;
    Ok((name, command, &args[split + 2..]))
}

fn demo(args: &[String]) -> Result<i32, String> {
    let (config, command, command_args) = demo_invocation(args)?;
    let upstream = spawn_demo_upstream()?;
    let prepared = prepare_demo(&upstream)?;
    eprintln!("twl: demo mode uses a generated canary; no real credential is read");
    run_prepared(
        prepared,
        command,
        command_args,
        config.budget.map(|budget| budget.max_requests),
    )
}

fn demo_invocation(args: &[String]) -> Result<(Config, &str, &[String]), String> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `-- <command>`")?;
    let config = match &args[..split] {
        [] => Config::default(),
        [option, path] if option == "--config" => Config::load(path)?,
        [option, ..] => return Err(format!("unknown option: {option}")),
    };
    let command = args.get(split + 1).ok_or("missing command")?;
    Ok((config, command, &args[split + 2..]))
}

fn run_prepared(
    prepared: Prepared,
    command: &str,
    command_args: &[String],
    budget: Option<u64>,
) -> Result<i32, String> {
    let (handle, overrides) = prepared.start(budget).map_err(|error| error.to_string())?;
    eprintln!("twl: project broker listening on loopback");
    let status = child_command(command, command_args, &overrides)
        .status()
        .map_err(|error| format!("{command}: {error}"))?;
    if handle.seen.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        eprintln!(
            "twl: no authorized request reached the broker; verify the application base-URL environment variables"
        );
    }
    Ok(status.code().unwrap_or(1))
}

fn doctor() {
    println!("Towel diagnostic");
    match secret::process_preflight() {
        Ok(()) => println!("  protected macOS project sessions: available"),
        Err(error) => println!("  protected macOS project sessions: unavailable ({error})"),
    }
    println!("  canary-only demo:                 available");
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
