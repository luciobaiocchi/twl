pub mod config;
pub mod project;
pub mod proxy;
pub mod secret;

use config::{validate_upstream, CHILD_BASE_URL_ENV, CHILD_SECRET_ENV};
use project::Project;
use std::process::Command;

/// Session-oracle variables are never inherited by the agent process.
pub const STRIP: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "TWL_APPLICATION_API_KEY",
    "TWL_APPLICATION_UPSTREAM",
];

pub struct Prepared {
    routes: Vec<proxy::Route>,
    environment: Vec<RouteEnvironment>,
}

struct RouteEnvironment {
    route: String,
    api_key_env: String,
    base_url_env: String,
    fake_key: String,
}

pub fn prepare_project(project: Project) -> Result<Prepared, String> {
    project.validate()?;
    let mut routes = Vec::with_capacity(project.routes.len());
    let mut environment = Vec::with_capacity(project.routes.len());
    for route in project.routes {
        let upstream = validate_upstream(&route.base_url)?;
        routes.push(proxy::Route {
            name: route.name.clone(),
            upstream,
            key: route.api_key,
        });
        environment.push(RouteEnvironment {
            route: route.name,
            api_key_env: route.api_key_env,
            base_url_env: route.base_url_env,
            fake_key: secret::mock(),
        });
    }
    Ok(Prepared {
        routes,
        environment,
    })
}

/// Prepare a canary-only demonstration against a local generated upstream.
pub fn prepare_demo(upstream: &str) -> Result<Prepared, String> {
    Ok(Prepared {
        routes: vec![proxy::Route {
            name: "application".into(),
            upstream: validate_upstream(upstream)?,
            key: secret::demo(),
        }],
        environment: vec![RouteEnvironment {
            route: "application".into(),
            api_key_env: CHILD_SECRET_ENV.into(),
            base_url_env: CHILD_BASE_URL_ENV.into(),
            fake_key: secret::mock(),
        }],
    })
}

impl Prepared {
    pub fn start(
        self,
        max_requests: Option<u64>,
    ) -> std::io::Result<(proxy::Handle, Vec<(String, String)>)> {
        let Self {
            routes,
            environment,
        } = self;
        let handle = proxy::spawn(routes, max_requests)?;
        let overrides = environment_overrides(&environment, handle.port, &handle.token);
        Ok((handle, overrides))
    }

    pub fn environment_overrides(&self, port: u16, token: &str) -> Vec<(String, String)> {
        environment_overrides(&self.environment, port, token)
    }
}

fn environment_overrides(
    environment: &[RouteEnvironment],
    port: u16,
    token: &str,
) -> Vec<(String, String)> {
    environment
        .iter()
        .flat_map(|route| {
            [
                (route.api_key_env.clone(), route.fake_key.clone()),
                (
                    route.base_url_env.clone(),
                    format!("http://127.0.0.1:{port}/{token}/{}", route.route),
                ),
            ]
        })
        .collect()
}

/// Replace the application credential with a fake value and remove every
/// parent-only input before launching the agent.
pub fn child_command(program: &str, args: &[String], overrides: &[(String, String)]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    for variable in STRIP {
        command.env_remove(variable);
    }
    for (key, value) in overrides {
        command.env(key, value);
    }
    command
}
