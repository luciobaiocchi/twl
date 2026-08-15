use crate::broker::{
    read_limited, target_url, Broker, BrokerError, BrokerRequest, RequestLimits,
    DEFAULT_MAX_BODY_BYTES, FORWARD_HEADERS,
};
use crate::project::HttpMethod;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;

pub use crate::broker::Route;

const MAX_IN_FLIGHT: usize = 16;

/// The listener exists only while its session handle exists.
pub struct Handle {
    pub port: u16,
    pub token: String,
    pub seen: Arc<AtomicU64>,
    server: Arc<tiny_http::Server>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.token.zeroize();
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

fn resolve_parts<'a>(
    url: &str,
    token: &str,
    method: &str,
    routes: &'a [Route],
) -> Result<(String, Option<String>, &'a Route), Denied> {
    if !url.starts_with('/') || url.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err((400, "request target is not valid origin-form"));
    }
    let (path, query) = match url.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (url, None),
    };
    if path.contains(['\\', '%', '#']) {
        return Err((400, "encoded or non-normalized path"));
    }

    let mut segments = path.splitn(4, '/');
    if segments.next() != Some("") {
        return Err((400, "non-normalized path"));
    }
    if segments
        .next()
        .is_none_or(|candidate| !equal_constant_time(candidate, token))
    {
        return Err((404, "not found"));
    }
    let route_name = segments.next().ok_or((404, "not found"))?;
    let route = routes
        .iter()
        .find(|route| equal_constant_time(&route.name, route_name))
        .ok_or((404, "not found"))?;
    let application_path = segments
        .next()
        .ok_or((400, "application path is missing"))?;
    let application_path = format!("/{application_path}");
    crate::broker::validate_origin_path(&application_path)
        .map_err(|_| (400, "non-normalized path"))?;
    if let Some(query) = query.as_deref() {
        crate::broker::validate_query(query).map_err(|_| (400, "request query is not valid"))?;
    }
    HttpMethod::from_str(method).map_err(|_| (405, "method is not allowed"))?;
    Ok((application_path, query, route))
}

/// Resolve an origin-form request beneath the unguessable session prefix.
/// The destination is always derived from the trusted parent-owned route.
pub fn resolve<'a>(
    url: &str,
    token: &str,
    method: &str,
    routes: &'a [Route],
) -> Result<(String, &'a Route), Denied> {
    let (path, query, route) = resolve_parts(url, token, method, routes)?;
    Ok((target_url(route, &path, query.as_deref()), route))
}

struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn spawn(routes: Vec<Route>, max_requests: Option<u64>) -> std::io::Result<Handle> {
    let server = Arc::new(
        tiny_http::Server::http("127.0.0.1:0")
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );
    let port = server.server_addr().to_ip().expect("socket ip").port();
    let token = Arc::new(random_token());
    let public_token = token.to_string();
    let broker = Broker::new(routes);
    let seen = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));

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
            let broker = broker.clone();
            let token = token.clone();
            let accepted = accepted.clone();
            std::thread::spawn(move || {
                let _guard = guard;
                serve(request, &token, &broker, &accepted, max_requests);
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

fn serve(
    mut request: tiny_http::Request,
    token: &str,
    broker: &Broker,
    accepted: &AtomicU64,
    max_requests: Option<u64>,
) {
    let url = request.url().to_string();
    let method_text = request.method().as_str().to_string();
    let (path, query, route) = match resolve_parts(&url, token, &method_text, broker.routes()) {
        Ok(resolved) => resolved,
        Err((code, message)) => {
            respond_error(request, code, message);
            return;
        }
    };
    let route_name = route.name.clone();
    let method = HttpMethod::from_str(&method_text).expect("resolve_parts checked the method");

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|header| {
            let name = header.field.to_string().to_ascii_lowercase();
            FORWARD_HEADERS
                .contains(&name.as_str())
                .then(|| (name, header.value.to_string()))
        })
        .collect();
    let body = match read_limited(request.as_reader(), DEFAULT_MAX_BODY_BYTES) {
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

    match broker.execute_route(
        &route_name,
        BrokerRequest {
            method,
            path,
            query,
            headers,
            body,
        },
        RequestLimits::default(),
    ) {
        Ok(response) => {
            let header =
                tiny_http::Header::from_bytes("content-type", response.content_type).unwrap();
            let _ = request.respond(
                tiny_http::Response::from_data(response.body)
                    .with_status_code(response.status)
                    .with_header(header),
            );
        }
        Err(error) => respond_broker_error(request, error),
    }
}

fn respond_broker_error(request: tiny_http::Request, error: BrokerError) {
    let message = match error {
        BrokerError::InvalidRequest => "header contains control characters",
        BrokerError::RouteNotFound => "not found",
        BrokerError::RequestTooLarge => "request body is too large or unreadable",
        BrokerError::ResponseTooLarge => "upstream response is too large or unreadable",
        BrokerError::UpstreamUnreachable => "upstream is unreachable",
        BrokerError::SecretReflection => "upstream response contained the credential",
    };
    respond_error(request, error.application_status(), message);
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
