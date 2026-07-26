use crate::config::Auth;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const MAX_BODY: u64 = 32 << 20;

/// The only headers that reach the upstream. Allowlist, not denylist: this
/// way `Host`, `X-Forwarded-*`, the client's `Authorization`, and everything
/// else can't influence the authenticated request.
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
}

/// The proxy listens for as long as this exists. When it's dropped, the
/// accepting thread exits: without this it would stay blocked in `recv()`
/// forever, and with multiple sessions in the same process the threads would
/// pile up until they choked it.
pub struct Handle {
    pub port: u16,
    /// Session secret, the first segment of every URL. The proxy listens on
    /// loopback, which is reachable by *any* process on the machine: without
    /// this, another local user could discover the port and spend your key.
    /// The child has it in its environment; no one else does.
    pub token: String,
    pub seen: Arc<AtomicU64>,
    server: Arc<tiny_http::Server>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

type Denied = (u16, &'static str);

fn random_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Comparison without early exit: response time must not reveal how many
/// characters of the token were right.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// INV-DEST: the destination host comes from the connector, never from the
/// request. The only thing the agent chooses is the path after the
/// connector's name.
pub fn resolve<'a>(
    url: &str,
    token: &str,
    routes: &'a HashMap<String, Route>,
) -> Result<(&'a Route, String), Denied> {
    if !url.starts_with('/') {
        return Err((400, "request is not in origin-form"));
    }
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url, None),
    };
    let mut segs = path.split('/').filter(|s| !s.is_empty());

    // A wrong token gets the same response as an unknown path: whoever is
    // probing the port shouldn't even learn there's a proxy behind it.
    if !segs.next().is_some_and(|t| constant_time_eq(t, token)) {
        return Err((404, "not found"));
    }
    let name = segs.next().ok_or((404, "not found"))?;
    let rest: Vec<&str> = segs.collect();
    if rest
        .iter()
        .any(|s| *s == ".." || *s == "." || s.contains('\\'))
    {
        return Err((400, "non-normalized path"));
    }
    let route = routes.get(name).ok_or((404, "unknown connector"))?;
    let mut target = format!(
        "{}/{}",
        route.upstream.trim_end_matches('/'),
        rest.join("/")
    );
    if let Some(q) = query {
        target.push('?');
        target.push_str(q);
    }
    Ok((route, target))
}

pub fn spawn(routes: HashMap<String, Route>, max_requests: Option<u64>) -> std::io::Result<Handle> {
    let server = Arc::new(
        tiny_http::Server::http("127.0.0.1:0").map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let port = server.server_addr().to_ip().expect("socket ip").port();
    let token = Arc::new(random_token());
    let routes = Arc::new(routes);
    let seen = Arc::new(AtomicU64::new(0));

    // Every request gets served right away, on a thread of its own. Queuing
    // them for a worker pool looks tidier but jams up: as long as we hold a
    // `Request` without answering it, tiny_http won't read the next request
    // off that connection, and under concurrent load it stops delivering
    // them. Measured: with a pool the proxy only received 111 of 120, and the
    // clients left without a response waited forever.
    let agent = Arc::new(
        ureq::AgentBuilder::new()
            .redirects(0)
            // An upstream that never answers must not hang the child forever.
            .timeout(std::time::Duration::from_secs(120))
            .build(),
    );
    let public_token = token.to_string();
    let acceptor = server.clone();
    let counter = seen.clone();
    std::thread::spawn(move || {
        while let Ok(req) = acceptor.recv() {
            // The counter increments BEFORE forwarding: counting afterward
            // would let more than N through under concurrent requests.
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let (routes, token, agent) = (routes.clone(), token.clone(), agent.clone());
            std::thread::spawn(move || serve(req, &token, &routes, &agent, max_requests, n));
        }
    });
    Ok(Handle {
        port,
        token: public_token,
        seen,
        server,
    })
}

fn serve(
    mut req: tiny_http::Request,
    token: &str,
    routes: &HashMap<String, Route>,
    agent: &ureq::Agent,
    max: Option<u64>,
    n: u64,
) {
    let url = req.url().to_string();
    let method = req.method().as_str().to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|h| {
            (
                h.field.to_string().to_ascii_lowercase(),
                h.value.to_string(),
            )
        })
        .collect();
    let mut body = Vec::new();
    let _ = req.as_reader().take(MAX_BODY).read_to_end(&mut body);

    let outcome = forward(&url, token, &method, &headers, body, routes, agent, max, n);
    let (code, ctype, data) = match outcome {
        Ok(v) => v,
        Err((code, msg)) => (
            code,
            "application/json".to_string(),
            format!("{{\"error\":{{\"source\":\"capshell\",\"message\":\"{msg}\"}}}}").into_bytes(),
        ),
    };
    let header = tiny_http::Header::from_bytes("content-type", ctype)
        .unwrap_or_else(|_| tiny_http::Header::from_bytes("content-type", "text/plain").unwrap());
    let _ = req.respond(
        tiny_http::Response::from_data(data)
            .with_status_code(code)
            .with_header(header),
    );
}

#[allow(clippy::too_many_arguments)]
fn forward(
    url: &str,
    token: &str,
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    routes: &HashMap<String, Route>,
    agent: &ureq::Agent,
    max: Option<u64>,
    n: u64,
) -> Result<(u16, String, Vec<u8>), Denied> {
    if max.is_some_and(|m| n > m) {
        return Err((429, "session budget exhausted"));
    }
    if !matches!(method, "GET" | "POST") {
        return Err((405, "method not allowed"));
    }
    let (route, target) = resolve(url, token, routes)?;

    let mut r = agent.request(method, &target);
    for (k, v) in headers {
        if !FORWARD.contains(&k.as_str()) {
            continue;
        }
        // A value with control characters could split the request and inject
        // headers of its own. We don't delegate this check to the HTTP
        // client: if it's malformed, the request dies here.
        if v.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err((400, "header contains control characters"));
        }
        r = r.set(k, v);
    }
    r = match route.auth {
        Auth::Bearer => r.set("authorization", &format!("Bearer {}", route.key)),
        Auth::XApiKey => r.set("x-api-key", &route.key),
    };

    // redirects(0): a 3xx goes back to the client as-is, and we never follow
    // it. Location isn't forwarded back either, so the key can't end up going
    // to a destination chosen by the upstream's response.
    let resp = match if body.is_empty() {
        r.call()
    } else {
        r.send_bytes(&body)
    } {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(_) => return Err((502, "upstream is unreachable")),
    };
    let code = resp.status();
    let ctype = resp
        .header("content-type")
        .unwrap_or("application/octet-stream")
        .to_string();
    let mut data = Vec::new();
    resp.into_reader()
        .take(MAX_BODY)
        .read_to_end(&mut data)
        .map_err(|_| (502u16, "upstream response is unreadable"))?;

    // INV-SECRET: the key never goes back, even if the upstream reflects it.
    if contains(&data, route.key.as_bytes()) {
        return Err((
            502,
            "upstream response discarded: it contained the credential",
        ));
    }
    Ok((code, ctype, data))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
