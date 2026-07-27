#![allow(dead_code)]

use base64::Engine;
use std::sync::{Arc, Mutex};
use twl::grant::{GrantedRoute, TrustedGrant};
use twl::policy::{
    AuthenticationFormat, AuthenticationLocation, AuthenticationPolicy, OriginPolicy, RoutePolicy,
    SecretValue,
};

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub type Log = Arc<Mutex<Vec<Seen>>>;

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

pub fn upstream() -> (String, Log) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let sink = sink.clone();
            std::thread::spawn(move || serve_upstream(request, &sink));
        }
    });
    (format!("http://127.0.0.1:{port}"), log)
}

fn serve_upstream(mut request: tiny_http::Request, sink: &Log) {
    let method = request.method().as_str().to_string();
    let url = request.url().to_string();
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
    let authentication = headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let mut body = Vec::new();
    request.as_reader().read_to_end(&mut body).unwrap();
    sink.lock().unwrap().push(Seen {
        method,
        url: url.clone(),
        headers,
        body,
    });

    if url.starts_with("/slow") {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let response = if url.starts_with("/redirect") {
        tiny_http::Response::from_data(Vec::new())
            .with_status_code(302)
            .with_header(
                tiny_http::Header::from_bytes("location", "http://127.0.0.1:1/evil").unwrap(),
            )
    } else if url.starts_with("/echo-key-base64-url-no-pad") {
        tiny_http::Response::from_data(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(authentication)
                .into_bytes(),
        )
        .with_status_code(200)
    } else if url.starts_with("/echo-key-base64-url") {
        tiny_http::Response::from_data(
            base64::engine::general_purpose::URL_SAFE
                .encode(authentication)
                .into_bytes(),
        )
        .with_status_code(200)
    } else if url.starts_with("/echo-key-base64-no-pad") {
        tiny_http::Response::from_data(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(authentication)
                .into_bytes(),
        )
        .with_status_code(200)
    } else if url.starts_with("/echo-key-base64") {
        tiny_http::Response::from_data(
            base64::engine::general_purpose::STANDARD
                .encode(authentication)
                .into_bytes(),
        )
        .with_status_code(200)
    } else if url.starts_with("/echo-key-header") {
        tiny_http::Response::from_data(b"ok".to_vec())
            .with_status_code(200)
            .with_header(
                tiny_http::Header::from_bytes(
                    "content-type",
                    format!("application/json; reflected={authentication}"),
                )
                .unwrap(),
            )
    } else if url.starts_with("/echo-key") {
        tiny_http::Response::from_data(authentication.into_bytes()).with_status_code(200)
    } else if url.starts_with("/large-response") {
        tiny_http::Response::from_data(vec![b'x'; 1024]).with_status_code(200)
    } else {
        tiny_http::Response::from_data(br#"{"authenticated":true}"#.to_vec())
            .with_status_code(200)
            .with_header(tiny_http::Header::from_bytes("content-type", "application/json").unwrap())
    };
    let _ = request.respond(response);
}

pub fn granted_route(id: &str, upstream: &str, key: &str) -> GrantedRoute {
    let parsed = url::Url::parse(upstream).unwrap();
    GrantedRoute {
        id: id.into(),
        policy: RoutePolicy {
            origin: OriginPolicy {
                scheme: parsed.scheme().into(),
                hostname: parsed.host_str().unwrap().trim_matches(['[', ']']).into(),
                port: parsed.port_or_known_default().unwrap(),
            },
            credential: format!("credential-{id}"),
            authentication: AuthenticationPolicy {
                location: AuthenticationLocation::Header,
                name: "Authorization".into(),
                format: AuthenticationFormat::Bearer,
            },
            allowed_methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            path_prefixes: None,
            request_count_budget: 100,
            max_request_bytes: 16 << 20,
            max_response_bytes: 16 << 20,
            max_concurrent_requests: 16,
            session_expiry_seconds: 3_600,
        },
        credential: SecretValue::new(key.into()).unwrap(),
    }
}

pub fn grant(routes: Vec<GrantedRoute>) -> TrustedGrant {
    TrustedGrant { routes }
}

pub fn raw(port: u16, request_line_and_headers: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "{request_line_and_headers}\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let code = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (code, response)
}

pub fn client() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(5))
        .build()
}

pub fn call(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    call_body(port, method, path, headers, &[])
}

pub fn call_body(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    call_with(&client(), port, method, path, headers, body)
}

pub fn call_with(
    agent: &ureq::Agent,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let mut request = agent.request(method, &format!("http://127.0.0.1:{port}{path}"));
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let result = if body.is_empty() {
        request.call()
    } else {
        request.send_bytes(body)
    };
    match result {
        Ok(response) => (
            response.status(),
            response.into_string().unwrap_or_default(),
        ),
        Err(ureq::Error::Status(code, response)) => {
            (code, response.into_string().unwrap_or_default())
        }
        Err(error) => panic!("request failed: {error}"),
    }
}
