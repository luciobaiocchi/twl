use std::io::{self, Write};
use std::process::exit;
use twl::config::Config;
use twl::project::{
    open_project_service, validate_identifier, PlatformProjectService, Project, ProjectRoute,
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
    validate_identifier(name).map_err(|error| error.to_string())?;
    Ok(name.clone())
}

fn project_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("add") => {
            let name = one_name(&args[1..], "add")?;
            let store = project_service()?;
            let project = prompt_project(name, None)?;
            store.create(&project).map_err(|error| error.to_string())?;
            println!(
                "Added project {} with {} route(s).",
                project.name(),
                project.routes().len()
            );
            Ok(())
        }
        Some("list") if args.len() == 1 => {
            let store = project_service()?;
            for name in store.list().map_err(|error| error.to_string())? {
                println!("{name}");
            }
            Ok(())
        }
        Some("show") => {
            let name = one_name(&args[1..], "show")?;
            let store = project_service()?;
            let stored = store.get(&name).map_err(|error| error.to_string())?;
            show_project(stored.project());
            Ok(())
        }
        Some("edit") => {
            let name = one_name(&args[1..], "edit")?;
            let store = project_service()?;
            let existing = store.get(&name).map_err(|error| error.to_string())?;
            let project = prompt_project(name, Some(existing.project()))?;
            store
                .replace(existing.revision(), &project)
                .map_err(|error| error.to_string())?;
            println!(
                "Updated project {} with {} route(s).",
                project.name(),
                project.routes().len()
            );
            Ok(())
        }
        Some("delete") => {
            let name = one_name(&args[1..], "delete")?;
            let store = project_service()?;
            store.delete(&name).map_err(|error| error.to_string())?;
            println!("Deleted project {name}.");
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn project_service() -> Result<PlatformProjectService, String> {
    open_project_service().map_err(|error| error.to_string())
}

fn terminal_line(label: &str) -> Result<String, String> {
    eprint!("{label}: ");
    io::stderr().flush().map_err(|error| error.to_string())?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("reading input: {error}"))?;
    Ok(value.trim().to_string())
}

fn ask(
    read_line: &mut impl FnMut(&str) -> Result<String, String>,
    label: &str,
    default: Option<&str>,
) -> Result<String, String> {
    let shown = default
        .map(|value| format!(" [{value}]"))
        .unwrap_or_default();
    let value = read_line(&format!("{label}{shown}"))?;
    Ok(if value.is_empty() {
        default.unwrap_or_default().to_string()
    } else {
        value
    })
}

fn prompt_project(name: String, existing: Option<&Project>) -> Result<Project, String> {
    collect_project(name, existing, terminal_line, |label| {
        rpassword::prompt_password(label)
            .map_err(|error| format!("reading API key from terminal: {error}"))
    })
}

fn collect_project(
    name: String,
    existing: Option<&Project>,
    mut read_line: impl FnMut(&str) -> Result<String, String>,
    mut read_password: impl FnMut(&str) -> Result<String, String>,
) -> Result<Project, String> {
    eprintln!("Enter routes. Leave the route name blank when finished.");
    let mut routes = Vec::new();
    if let Some(project) = existing {
        for (position, old) in project.routes().iter().enumerate() {
            let action = ask(
                &mut read_line,
                &format!(
                    "Route {}: [k]eep, [e]dit/rename, [d]elete, or [f]inish",
                    old.name()
                ),
                Some("k"),
            )?;
            match action.to_ascii_lowercase().as_str() {
                "k" | "keep" => routes.push(old.clone()),
                "d" | "delete" => {}
                "e" | "edit" => {
                    routes.push(prompt_route(Some(old), &mut read_line, &mut read_password)?)
                }
                "f" | "finish" | "done" => {
                    routes.extend(project.routes()[position..].iter().cloned());
                    return Project::new(name, routes).map_err(|error| error.to_string());
                }
                _ => return Err("route action must be keep, edit, delete, or finish".into()),
            }
        }
    }

    loop {
        let route_name = ask(&mut read_line, "New route name", None)?;
        if route_name.is_empty() {
            break;
        }
        validate_identifier(&route_name).map_err(|error| error.to_string())?;
        routes.push(prompt_route_with_name(
            route_name,
            None,
            &mut read_line,
            &mut read_password,
        )?);
    }
    Project::new(name, routes).map_err(|error| error.to_string())
}

fn prompt_route(
    existing: Option<&ProjectRoute>,
    read_line: &mut impl FnMut(&str) -> Result<String, String>,
    read_password: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<ProjectRoute, String> {
    let route_name = ask(read_line, "Route name", existing.map(ProjectRoute::name))?;
    validate_identifier(&route_name).map_err(|error| error.to_string())?;
    prompt_route_with_name(route_name, existing, read_line, read_password)
}

fn prompt_route_with_name(
    route_name: String,
    existing: Option<&ProjectRoute>,
    read_line: &mut impl FnMut(&str) -> Result<String, String>,
    read_password: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<ProjectRoute, String> {
    let base_url = ask(
        read_line,
        "Exact HTTPS base URL",
        existing.map(ProjectRoute::base_url),
    )?;
    let api_key_env = ask(
        read_line,
        "Application API-key environment variable",
        existing.map(ProjectRoute::api_key_env),
    )?;
    let base_url_env = ask(
        read_line,
        "Application base-URL environment variable",
        existing.map(ProjectRoute::base_url_env),
    )?;
    let key_label = if existing.is_some() {
        "Static Bearer API key (leave blank to keep existing): "
    } else {
        "Static Bearer API key: "
    };
    let entered = read_password(key_label)?;
    let api_key = if entered.is_empty() {
        existing
            .cloned()
            .map(ProjectRoute::into_parts)
            .map(|(_, _, key, _, _)| key)
            .ok_or("API key must not be empty")?
    } else {
        entered
    };
    ProjectRoute::new(route_name, base_url, api_key, api_key_env, base_url_env)
        .map_err(|error| error.to_string())
}

fn show_project(project: &Project) {
    print!("{}", project.description());
}

fn run(args: &[String]) -> Result<i32, String> {
    let (name, command, command_args) = run_invocation(args)?;
    let store = open_project_service().map_err(|error| error.to_string())?;
    let stored = store.get(name).map_err(|error| error.to_string())?;
    let route_count = stored.project().routes().len();
    let project = stored.into_parts().0;
    // On Linux this closes the vault directory descriptor and zeroizes the session password
    // before the selected credentials move into the broker.
    drop(store);
    let prepared = prepare_project(project)?;
    eprintln!("twl: authorized project {name} with {route_count} route(s) for this session");
    run_prepared(prepared, command, command_args, None, true)
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
    validate_identifier(name).map_err(|error| error.to_string())?;
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
        false,
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
    mask_vault: bool,
) -> Result<i32, String> {
    let (handle, overrides) = prepared.start(budget).map_err(|error| error.to_string())?;
    eprintln!("twl: project broker listening on loopback");
    #[cfg(target_os = "linux")]
    let mut child = if mask_vault {
        let (child, vault_masked) =
            twl::project::linux_project_child_command(command, command_args, &overrides)?;
        if vault_masked {
            eprintln!("twl: encrypted vault directory masked with Bubblewrap");
        } else {
            eprintln!(
                "twl: Bubblewrap unavailable; encrypted vault is enabled but filesystem masking is disabled"
            );
        }
        child
    } else {
        child_command(command, command_args, &overrides)
    };
    #[cfg(not(target_os = "linux"))]
    let mut child = {
        let _ = mask_vault;
        child_command(command, command_args, &overrides)
    };
    let status = child
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
    #[cfg(target_os = "macos")]
    match secret::process_preflight() {
        Ok(()) => println!("  protected macOS project sessions: available"),
        Err(error) => println!("  protected macOS project sessions: unavailable ({error})"),
    }
    #[cfg(target_os = "linux")]
    match secret::process_preflight() {
        Ok(()) => println!("  encrypted Linux project sessions: available"),
        Err(error) => println!("  encrypted Linux project sessions: unavailable ({error})"),
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    println!("  protected project sessions:       unavailable on this platform");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn route(name: &str, key: &str, prefix: &str) -> ProjectRoute {
        ProjectRoute::new(
            name.into(),
            format!("https://{name}.example.test/v1"),
            key.into(),
            format!("{prefix}_KEY"),
            format!("{prefix}_URL"),
        )
        .unwrap()
    }

    #[test]
    fn edit_can_delete_and_rename_routes_while_retaining_the_key() {
        let existing = Project::new(
            "app".into(),
            vec![
                route("billing", "billing-key", "BILLING"),
                route("search", "search-key", "SEARCH"),
            ],
        )
        .unwrap();
        let mut lines: VecDeque<String> = ["d", "e", "renamed", "", "", "", ""]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut passwords: VecDeque<String> = [""].into_iter().map(str::to_string).collect();

        let edited = collect_project(
            "app".into(),
            Some(&existing),
            |_| Ok(lines.pop_front().unwrap()),
            |_| Ok(passwords.pop_front().unwrap()),
        )
        .unwrap();

        assert_eq!(edited.routes().len(), 1);
        assert_eq!(edited.routes()[0].name(), "renamed");
        assert_eq!(edited.routes()[0].clone().into_parts().2, "search-key");
        assert!(!edited.description().contains("search-key"));
    }

    #[test]
    fn finish_keeps_the_current_and_remaining_routes() {
        let existing = Project::new(
            "app".into(),
            vec![
                route("billing", "billing-key", "BILLING"),
                route("search", "search-key", "SEARCH"),
            ],
        )
        .unwrap();
        let edited = collect_project(
            "app".into(),
            Some(&existing),
            |_| Ok("finish".into()),
            |_| Err("password prompt must not run".into()),
        )
        .unwrap();
        assert_eq!(edited, existing);
    }
}
