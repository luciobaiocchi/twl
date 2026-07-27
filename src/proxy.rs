use crate::grant::{GrantedRoute, TrustedGrant};
use crate::policy::{validate_path, RoutePolicy, SecretValue};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_SESSION_IN_FLIGHT: usize = 32;
const FORWARD_HEADERS: &[&str] = &["content-type", "accept"];

pub type Denied = (u16, &'static str);

struct ActiveRoute {
    policy: RoutePolicy,
    base_url: String,
    credential: SecretValue,
    accepted: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    expires_at: Instant,
}

struct Session {
    routes: BTreeMap<String, Arc<ActiveRoute>>,
    reflection_patterns: Vec<Vec<u8>>,
    active: Arc<AtomicUsize>,
}

/// The listener and its route-bound token exist only while this handle exists.
pub struct Handle {
    pub port: u16,
    pub token: String,
    pub seen: Arc<AtomicU64>,
    route_seen: BTreeMap<String, Arc<AtomicU64>>,
    server: Arc<tiny_http::Server>,
}

impl Handle {
    pub fn route_seen(&self, route_id: &str) -> Option<u64> {
        self.route_seen
            .get(route_id)
            .map(|value| value.load(Ordering::SeqCst))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

pub fn spawn(grant: TrustedGrant) -> Result<Handle, String> {
    grant.validate()?;
    let server = Arc::new(
        tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| format!("binding loopback proxy: {error}"))?,
    );
    let port = server
        .server_addr()
        .to_ip()
        .ok_or("loopback proxy did not bind an IP socket")?
        .port();
    let token = random_token();
    let seen = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));

    let mut routes = BTreeMap::new();
    let mut route_seen = BTreeMap::new();
    let mut reflection_patterns = Vec::new();
    for route in grant.routes {
        add_reflection_patterns(&mut reflection_patterns, route.credential.expose());
        let (id, active_route) = activate_route(route)?;
        route_seen.insert(id.clone(), active_route.accepted.clone());
        routes.insert(id, Arc::new(active_route));
    }
    reflection_patterns.sort();
    reflection_patterns.dedup();

    let session = Arc::new(Session {
        routes,
        reflection_patterns,
        active,
    });
    let agent = Arc::new(
        ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout(Duration::from_secs(120))
            .build(),
    );
    let private_token = Arc::new(token.clone());

    let listener = server.clone();
    let accepted = seen.clone();
    std::thread::spawn(move || {
        while let Ok(request) = listener.recv() {
            let method = request.method().as_str().to_string();
            let resolved = match authorize(request.url(), &private_token, &method, &session) {
                Ok(resolved) => resolved,
                Err((code, message)) => {
                    respond_error(request, code, message);
                    continue;
                }
            };
            let guard = match InFlight::reserve(
                &session.active,
                &resolved.route.active,
                resolved.route.policy.max_concurrent_requests as usize,
            ) {
                Ok(guard) => guard,
                Err((code, message)) => {
                    respond_error(request, code, message);
                    continue;
                }
            };

            let agent = agent.clone();
            let session = session.clone();
            let accepted = accepted.clone();
            std::thread::spawn(move || {
                let _guard = guard;
                serve(request, resolved, &agent, &session, &accepted);
            });
        }
    });

    Ok(Handle {
        port,
        token,
        seen,
        route_seen,
        server,
    })
}

struct Resolved {
    route: Arc<ActiveRoute>,
    target: String,
    method: String,
}

fn activate_route(route: GrantedRoute) -> Result<(String, ActiveRoute), String> {
    let base_url = route.policy.origin.base_url()?;
    let expires_at = Instant::now()
        .checked_add(Duration::from_secs(route.policy.session_expiry_seconds))
        .ok_or("route expiry is outside the supported clock range")?;
    Ok((
        route.id,
        ActiveRoute {
            policy: route.policy,
            base_url,
            credential: route.credential,
            accepted: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            expires_at,
        },
    ))
}

fn authorize(url: &str, token: &str, method: &str, session: &Session) -> Result<Resolved, Denied> {
    if !url.starts_with('/') || url.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err((400, "request target is not valid origin-form"));
    }
    let (path, query) = match url.split_once('?') {
        Some((path, query)) => {
            if query
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f || byte == b'#')
            {
                return Err((400, "query contains invalid characters"));
            }
            (path, Some(query))
        }
        None => (url, None),
    };
    if path.contains(['\\', '%', '#']) {
        return Err((400, "encoded or non-normalized path"));
    }

    let mut segments = path[1..].splitn(3, '/');
    let candidate = segments.next().unwrap_or_default();
    if !equal_constant_time(candidate, token) {
        return Err((404, "not found"));
    }
    let route_id = segments.next().ok_or((404, "not found"))?;
    let route = session
        .routes
        .get(route_id)
        .cloned()
        .ok_or((404, "not found"))?;
    if Instant::now() >= route.expires_at {
        return Err((401, "session route has expired"));
    }
    if !route
        .policy
        .allowed_methods
        .iter()
        .any(|allowed| allowed == method)
    {
        return Err((405, "method is not allowed for this route"));
    }

    let application_path = match segments.next() {
        Some("") | None => "/".to_string(),
        Some(value) => format!("/{value}"),
    };
    validate_path(&application_path).map_err(|_| (400, "non-normalized application path"))?;
    if !route.policy.allows_path(&application_path) {
        return Err((403, "path is not allowed for this route"));
    }

    let mut target = format!("{}{}", route.base_url, application_path);
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    Ok(Resolved {
        route,
        target,
        method: method.to_string(),
    })
}

struct InFlight {
    session: Arc<AtomicUsize>,
    route: Arc<AtomicUsize>,
}

impl InFlight {
    fn reserve(
        session: &Arc<AtomicUsize>,
        route: &Arc<AtomicUsize>,
        route_maximum: usize,
    ) -> Result<Self, Denied> {
        if !try_reserve(session, MAX_SESSION_IN_FLIGHT) {
            return Err((503, "local proxy concurrency limit reached"));
        }
        if !try_reserve(route, route_maximum) {
            session.fetch_sub(1, Ordering::SeqCst);
            return Err((503, "route concurrency limit reached"));
        }
        Ok(Self {
            session: session.clone(),
            route: route.clone(),
        })
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.route.fetch_sub(1, Ordering::SeqCst);
        self.session.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_reserve(counter: &AtomicUsize, maximum: usize) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            (current < maximum).then_some(current + 1)
        })
        .is_ok()
}

fn serve(
    mut request: tiny_http::Request,
    resolved: Resolved,
    agent: &ureq::Agent,
    session: &Session,
    total_accepted: &AtomicU64,
) {
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

    let body = match read_limited(request.as_reader(), resolved.route.policy.max_request_bytes) {
        Ok(body) => body,
        Err(()) => {
            respond_error(request, 413, "request body is too large or unreadable");
            return;
        }
    };
    if Instant::now() >= resolved.route.expires_at {
        respond_error(request, 401, "session route has expired");
        return;
    }
    if reserve_budget(
        &resolved.route.accepted,
        resolved.route.policy.request_count_budget,
    )
    .is_err()
    {
        respond_error(request, 429, "route request budget exhausted");
        return;
    }
    total_accepted.fetch_add(1, Ordering::SeqCst);

    match forward(
        &resolved,
        &headers,
        body,
        agent,
        &session.reflection_patterns,
    ) {
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

fn reserve_budget(counter: &AtomicU64, maximum: u64) -> Result<(), ()> {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            (current < maximum).then_some(current + 1)
        })
        .map(|_| ())
        .map_err(|_| ())
}

fn read_limited(reader: impl Read, maximum: u64) -> Result<Vec<u8>, ()> {
    let mut data = Vec::new();
    reader
        .take(maximum + 1)
        .read_to_end(&mut data)
        .map_err(|_| ())?;
    if data.len() as u64 > maximum {
        return Err(());
    }
    Ok(data)
}

fn forward(
    resolved: &Resolved,
    headers: &[(String, String)],
    body: Vec<u8>,
    agent: &ureq::Agent,
    reflection_patterns: &[Vec<u8>],
) -> Result<(u16, &'static str, Vec<u8>), Denied> {
    let mut upstream = agent.request(&resolved.method, &resolved.target);
    for (name, value) in headers {
        if FORWARD_HEADERS.contains(&name.as_str()) {
            upstream = upstream.set(name, value);
        }
    }
    upstream = upstream.set(
        "authorization",
        &format!("Bearer {}", resolved.route.credential.expose()),
    );

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
    let data = read_limited(
        response.into_reader(),
        resolved.route.policy.max_response_bytes,
    )
    .map_err(|_| (502, "upstream response is too large or unreadable"))?;
    if contains_reflection(&data, reflection_patterns) {
        return Err((502, "upstream response contained a session credential"));
    }
    Ok((status, content_type, data))
}

fn canonical_content_type(value: Option<&str>) -> &'static str {
    let value = value.unwrap_or_default().to_ascii_lowercase();
    if value.starts_with("application/json") {
        "application/json"
    } else if value.starts_with("text/plain") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn add_reflection_patterns(patterns: &mut Vec<Vec<u8>>, credential: &str) {
    let bearer = format!("Bearer {credential}");
    for secret in [credential, bearer.as_str()] {
        patterns.push(secret.as_bytes().to_vec());
        patterns.push(STANDARD.encode(secret).into_bytes());
        patterns.push(STANDARD_NO_PAD.encode(secret).into_bytes());
        patterns.push(URL_SAFE.encode(secret).into_bytes());
        patterns.push(URL_SAFE_NO_PAD.encode(secret).into_bytes());
    }
}

fn contains_reflection(data: &[u8], patterns: &[Vec<u8>]) -> bool {
    patterns.iter().any(|pattern| {
        !pattern.is_empty()
            && data
                .windows(pattern.len())
                .any(|window| window == pattern.as_slice())
    })
}

fn random_token() -> String {
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
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

fn respond_error(request: tiny_http::Request, code: u16, message: &'static str) {
    let body = format!("{{\"error\":{{\"source\":\"twl\",\"message\":\"{message}\"}}}}");
    let header = tiny_http::Header::from_bytes("content-type", "application/json").unwrap();
    let _ = request.respond(
        tiny_http::Response::from_data(body.into_bytes())
            .with_status_code(code)
            .with_header(header),
    );
}
