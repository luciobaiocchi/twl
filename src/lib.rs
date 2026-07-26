pub mod config;
pub mod proxy;
pub mod runtime;
pub mod secret;

use config::{
    validate_upstream, CHILD_BASE_URL_ENV, CHILD_SECRET_ENV, PARENT_SECRET_ENV, PARENT_UPSTREAM_ENV,
};
use std::process::Command;

/// Session-oracle variables are never inherited by the agent process.
pub const STRIP: &[&str] = &["DBUS_SESSION_BUS_ADDRESS"];

pub struct Prepared {
    route: proxy::Route,
    mock: String,
}

/// A real credential paired with the only upstream allowed to receive it.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionMaterial {
    pub key: String,
    pub upstream: String,
}

fn prepare(material: SessionMaterial, mock: String) -> Result<Prepared, String> {
    if material.key.is_empty() {
        return Err("empty application credential".into());
    }
    if material.key.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("application credential contains control characters".into());
    }

    let upstream = validate_upstream(&material.upstream)?;
    Ok(Prepared {
        route: proxy::Route {
            upstream,
            key: material.key,
        },
        mock,
    })
}

pub fn prepare_session(material: SessionMaterial) -> Result<Prepared, String> {
    prepare(material, secret::mock())
}

/// Prepare a canary-only demonstration against a local generated upstream.
pub fn prepare_demo(upstream: &str) -> Result<Prepared, String> {
    prepare(
        SessionMaterial {
            key: secret::demo(),
            upstream: upstream.to_string(),
        },
        secret::mock(),
    )
}

impl Prepared {
    pub fn start(
        self,
        max_requests: Option<u64>,
    ) -> std::io::Result<(proxy::Handle, Vec<(String, String)>)> {
        let handle = proxy::spawn(self.route, max_requests)?;
        let overrides = vec![
            (CHILD_SECRET_ENV.into(), self.mock),
            (
                CHILD_BASE_URL_ENV.into(),
                format!("http://127.0.0.1:{}/{}", handle.port, handle.token),
            ),
        ];
        Ok((handle, overrides))
    }

    pub fn env_overrides(&self, port: u16, token: &str) -> Vec<(String, String)> {
        vec![
            (CHILD_SECRET_ENV.into(), self.mock.clone()),
            (
                CHILD_BASE_URL_ENV.into(),
                format!("http://127.0.0.1:{port}/{token}"),
            ),
        ]
    }
}

/// Replace the application credential with a fake value and remove every
/// parent-only input before launching the agent.
pub fn child_command(program: &str, args: &[String], overrides: &[(String, String)]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    for variable in STRIP {
        command.env_remove(variable);
    }
    for variable in [PARENT_SECRET_ENV, PARENT_UPSTREAM_ENV] {
        command.env_remove(variable);
    }
    for (key, value) in overrides {
        command.env(key, value);
    }
    command
}
