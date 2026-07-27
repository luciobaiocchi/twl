pub mod config;
pub mod grant;
pub mod policy;
pub mod proxy;
pub mod runtime;
pub mod secret;
pub mod vault;

use config::{BROKER_URL_ENV, CHILD_BASE_URL_ENV, CHILD_SECRET_ENV, SESSION_TOKEN_ENV};
use grant::{GrantProvider, GrantRequest, TrustedGrant};
use policy::{
    AuthenticationFormat, AuthenticationLocation, AuthenticationPolicy, OriginPolicy, RoutePolicy,
    SecretValue, VaultPayload, ABSOLUTE_MAX_BODY_BYTES, ABSOLUTE_MAX_ROUTE_CONCURRENCY,
    ALLOWED_METHODS, VAULT_PAYLOAD_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// Parent/session-oracle variables that are never inherited by a native agent.
pub const STRIP: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "TWL_VAULT_PASSWORD",
    "TWL_APPLICATION_API_KEY",
    "TWL_APPLICATION_UPSTREAM",
];

pub struct Prepared {
    grant: TrustedGrant,
    fake_credentials: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionManifest {
    pub version: u32,
    pub broker_url: String,
    pub session_token: String,
    pub routes: BTreeMap<String, RouteAccess>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteAccess {
    pub url: String,
    pub credential: String,
}

pub fn prepare_grant(grant: TrustedGrant) -> Result<Prepared, String> {
    grant.validate()?;
    let mut fake_credentials = BTreeMap::new();
    let mut environment_names = BTreeSet::new();
    for route in &grant.routes {
        let environment_name = route_environment_name(&route.id);
        if !environment_names.insert(environment_name) {
            return Err("route IDs collide after conversion to environment variable names".into());
        }
        fake_credentials.insert(route.id.clone(), secret::mock());
    }
    Ok(Prepared {
        grant,
        fake_credentials,
    })
}

pub fn prepare_from(
    provider: &impl GrantProvider,
    request: &GrantRequest,
) -> Result<Prepared, String> {
    prepare_grant(provider.issue_grant(request)?)
}

/// Prepare the canary-only demonstration through the same grant/session path as
/// a real encrypted vault.
pub fn prepare_demo(upstream: &str, request: &GrantRequest) -> Result<Prepared, String> {
    let parsed = url::Url::parse(upstream).map_err(|_| "demo upstream is invalid")?;
    let hostname = parsed
        .host_str()
        .ok_or("demo upstream is missing a hostname")?
        .trim_matches(['[', ']'])
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or("demo upstream is missing a port")?;
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("demo upstream must be an origin".into());
    }

    let mut credentials = BTreeMap::new();
    credentials.insert("demo".into(), SecretValue::new(secret::demo())?);
    let mut routes = BTreeMap::new();
    routes.insert(
        "application".into(),
        RoutePolicy {
            origin: OriginPolicy {
                scheme: parsed.scheme().into(),
                hostname,
                port,
            },
            credential: "demo".into(),
            authentication: AuthenticationPolicy {
                location: AuthenticationLocation::Header,
                name: "Authorization".into(),
                format: AuthenticationFormat::Bearer,
            },
            allowed_methods: ALLOWED_METHODS
                .iter()
                .map(|method| (*method).to_string())
                .collect(),
            path_prefixes: None,
            request_count_budget: 1_000,
            max_request_bytes: ABSOLUTE_MAX_BODY_BYTES,
            max_response_bytes: ABSOLUTE_MAX_BODY_BYTES,
            max_concurrent_requests: ABSOLUTE_MAX_ROUTE_CONCURRENCY,
            session_expiry_seconds: 60 * 60,
        },
    );
    let payload = VaultPayload {
        version: VAULT_PAYLOAD_VERSION,
        credentials,
        routes,
    };
    prepare_from(&payload, request)
}

impl Prepared {
    pub fn start(self) -> Result<(proxy::Handle, SessionManifest), String> {
        let route_ids: Vec<String> = self
            .grant
            .routes
            .iter()
            .map(|route| route.id.clone())
            .collect();
        let handle = proxy::spawn(self.grant)?;
        let broker_url = format!("http://127.0.0.1:{}", handle.port);
        let routes = route_ids
            .into_iter()
            .map(|id| {
                let access = RouteAccess {
                    url: format!("{broker_url}/{}/{id}", handle.token),
                    credential: self
                        .fake_credentials
                        .get(&id)
                        .expect("prepared route has fake credential")
                        .clone(),
                };
                (id, access)
            })
            .collect();
        let manifest = SessionManifest {
            version: 1,
            broker_url,
            session_token: handle.token.clone(),
            routes,
        };
        Ok((handle, manifest))
    }
}

impl SessionManifest {
    pub fn environment(&self) -> Vec<(String, String)> {
        let mut variables = vec![
            (BROKER_URL_ENV.into(), self.broker_url.clone()),
            (SESSION_TOKEN_ENV.into(), self.session_token.clone()),
        ];
        for (id, route) in &self.routes {
            let prefix = route_environment_name(id);
            variables.push((format!("TWL_ROUTE_{prefix}_URL"), route.url.clone()));
            variables.push((
                format!("TWL_ROUTE_{prefix}_CREDENTIAL"),
                route.credential.clone(),
            ));
        }
        if self.routes.len() == 1 {
            let route = self.routes.values().next().expect("one route");
            variables.push((CHILD_SECRET_ENV.into(), route.credential.clone()));
            variables.push((CHILD_BASE_URL_ENV.into(), route.url.clone()));
        }
        variables
    }
}

/// Remove parent-only inputs and stale broker variables before installing the
/// fresh, fake session material for a native child.
pub fn child_command(program: &str, args: &[String], overrides: &[(String, String)]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    for variable in STRIP {
        command.env_remove(variable);
    }
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("TWL_ROUTE_") {
            command.env_remove(name);
        }
    }
    for variable in [
        BROKER_URL_ENV,
        SESSION_TOKEN_ENV,
        CHILD_SECRET_ENV,
        CHILD_BASE_URL_ENV,
    ] {
        command.env_remove(variable);
    }
    for (key, value) in overrides {
        command.env(key, value);
    }
    command
}

fn route_environment_name(route_id: &str) -> String {
    route_id
        .chars()
        .map(|character| match character {
            '-' => '_',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}
