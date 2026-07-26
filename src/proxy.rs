use crate::config::{AllowedRoute, Auth};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_BODY: u64 = 16 << 20;
const MAX_IN_FLIGHT: usize = 16;

const FORWARD: &[&str] = &[
    "content-type",
    "accept",
    "anthropic-version",
    "anthropic-beta",
    "openai-organization",
    "openai-beta",
];

pub struct Route {
    pub upstream: String,
    pub auth: Auth,
    pub key: String,
    pub allowed: &'static [AllowedRoute],
}

/// The listener exists only while its session handle exists.
pub struct Handle {
    pub port: u16,
    pub token: String,
    pub seen: Arc<AtomicU64>,
    server: Arc<tiny_http::Server>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

pub type Denied = (u16, &'static str);

fn random_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn equal_constant_time(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// Resolve a local request using only compiled route policy. The first path
/// segment is a session capability; the second is a connector identifier.
pub fn resolve<'a>(
    url: &str,
    token: &str,
    method: &str,
    routes: &'a HashMap<String, Route>,
) -> Result<(&'a Route, String), Denied> {
    if !url.starts_with('/') || url.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err((400, "request target is not valid origin-form"));
    }
    let (path, query) = match url.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (url, None),
    };
    if path.contains('\\') || path.contains('%') {
        return Err((400, "encoded or non-normalized path"));
    }

    let segments: Vec<&str> = path.split('/').collect();
    if segments.first() != Some(&"") {
        return Err((400, "non-normalized path"));
    }
    if segments
        .get(1)
        .is_none_or(|candidate| !equal_constant_time(candidate, token))
    {
        return Err((404, "not found"));
    }
    if segments.len() < 4
        || segments[1..]
            .iter()
            .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err((400, "non-normalized path"));
    }

    let route = routes.get(segments[2]).ok_or((404, "not found"))?;
    let provider_path = format!("/{}", segments[3..].join("/"));
    let path_allowed = route
        .allowed
        .iter()
        .any(|rule| rule.matches_path(&provider_path));
    if !path_allowed {
        return Err((403, "provider path is not allowed"));
    }
    if !route
        .allowed
        .iter()
        .any(|rule| rule.allows(method, &provider_path))
    {
        return Err((405, "method is not allowed"));
    }

    let mut target = format!("{}{}", route.upstream.trim_end_matches('/'), provider_path);
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    Ok((route, target))
}

struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn spawn(routes: HashMap<String, Route>, max_requests: Option<u64>) -> std::io::Result<Handle> {
    let server = Arc::new(
        tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );
    let port = server.server_addr().to_ip().expect("socket ip").port();
    let token = Arc::new(random_token());
    let public_token = token.to_string();
    let routes = Arc::new(routes);
    let seen = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let agent = Arc::new(
        ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout(Duration::from_secs(120))
            .build(),
    );

    let listener = server.clone();
    let accepted = seen.clone();
    std::thread::spawn(move || {
        while let Ok(request) = listener.recv() {
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
                active.fetch_sub(1, Ordering::SeqCst);
                respond_error(request, 503, "local proxy concurrency limit reached");
                continue;
            }
            let guard = InFlight(active.clone());
            let routes = routes.clone();
            let token = token.clone();
            let agent = agent.clone();
            let accepted = accepted.clone();
            std::thread::spawn(move || {
                let _guard = guard;
                serve(request, &token, &routes, &agent, &accepted, max_requests);
            });
        }
    });

    Ok(Handle {
        port,
        token: public_token,
        seen,
        server,
    })
}

fn reserve(counter: &AtomicU64, max: Option<u64>) -> Result<(), Denied> {
    match max {
        Some(max) => counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current < max).then_some(current + 1)
            })
            .map(|_| ())
            .map_err(|_| (429, "session request budget exhausted")),
        None => {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>, ()> {
    let mut data = Vec::new();
    reader
        .take(MAX_BODY + 1)
        .read_to_end(&mut data)
        .map_err(|_| ())?;
    if data.len() as u64 > MAX_BODY {
        return Err(());
    }
    Ok(data)
}

fn serve(
    mut request: tiny_http::Request,
    token: &str,
    routes: &HashMap<String, Route>,
    agent: &ureq::Agent,
    accepted: &AtomicU64,
    max_requests: Option<u64>,
) {
    let url = request.url().to_string();
    let method = request.method().as_str().to_string();
    let (route, target) = match resolve(&url, token, &method, routes) {
        Ok(resolved) => resolved,
        Err((code, message)) => {
            respond_error(request, code, message);
            return;
        }
    };

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|header| {
            (
                header.field.to_string().to_ascii_lowercase(),
                header.value.to_string(),
            )
        })
        .collect();
    if headers
        .iter()
        .any(|(_, value)| value.bytes().any(|byte| byte < 0x20 || byte == 0x7f))
    {
        respond_error(request, 400, "header contains control characters");
        return;
    }

    let body = match read_limited(request.as_reader()) {
        Ok(body) => body,
        Err(()) => {
            respond_error(request, 413, "request body is too large or unreadable");
            return;
        }
    };
    if let Err((code, message)) = reserve(accepted, max_requests) {
        respond_error(request, code, message);
        return;
    }

    match forward(route, &target, &method, &headers, body, agent) {
        Ok((code, content_type, data)) => {
            let header = tiny_http::Header::from_bytes("content-type", content_type).unwrap();
            let _ = request.respond(
                tiny_http::Response::from_data(data)
                    .with_status_code(code)
                    .with_header(header),
            );
        }
        Err((code, message)) => respond_error(request, code, message),
    }
}

fn forward(
    route: &Route,
    target: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    agent: &ureq::Agent,
) -> Result<(u16, &'static str, Vec<u8>), Denied> {
    let mut upstream = agent.request(method, target);
    for (name, value) in headers {
        if FORWARD.contains(&name.as_str()) {
            upstream = upstream.set(name, value);
        }
    }
    upstream = match route.auth {
        Auth::Bearer => upstream.set("authorization", &format!("Bearer {}", route.key)),
        Auth::XApiKey => upstream.set("x-api-key", &route.key),
    };

    let response = match if body.is_empty() {
        upstream.call()
    } else {
        upstream.send_bytes(&body)
    } {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return Err((502, "upstream is unreachable")),
    };
    let status = response.status();
    let content_type = canonical_content_type(response.header("content-type"));
    let data = read_limited(response.into_reader())
        .map_err(|_| (502, "upstream response is too large or unreadable"))?;
    if contains_secret(&data, &route.key) {
        return Err((502, "upstream response contained the credential"));
    }
    Ok((status, content_type, data))
}

fn canonical_content_type(value: Option<&str>) -> &'static str {
    let value = value.unwrap_or_default().to_ascii_lowercase();
    if value.starts_with("application/json") {
        "application/json"
    } else if value.starts_with("text/event-stream") {
        "text/event-stream"
    } else {
        "application/octet-stream"
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_secret(data: &[u8], key: &str) -> bool {
    let bearer = format!("Bearer {key}");
    [key, bearer.as_str()].iter().any(|secret| {
        contains_bytes(data, secret.as_bytes())
            || contains_bytes(data, STANDARD.encode(secret).as_bytes())
            || contains_bytes(data, STANDARD_NO_PAD.encode(secret).as_bytes())
            || contains_bytes(data, URL_SAFE_NO_PAD.encode(secret).as_bytes())
    })
}

fn respond_error(request: tiny_http::Request, code: u16, message: &'static str) {
    let body = format!("{{\"error\":{{\"source\":\"mtl\",\"message\":\"{message}\"}}}}");
    let header = tiny_http::Header::from_bytes("content-type", "application/json").unwrap();
    let _ = request.respond(
        tiny_http::Response::from_data(body.into_bytes())
            .with_status_code(code)
            .with_header(header),
    );
}
