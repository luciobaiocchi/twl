#![allow(dead_code)]

use base64::Engine;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct Seen {
    pub url: String,
    pub headers: Vec<(String, String)>,
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

fn serve_upstream(request: tiny_http::Request, sink: &Log) {
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
    sink.lock().unwrap().push(Seen {
        url: url.clone(),
        headers,
    });

    let response = if url.starts_with("/v1/redirect") {
        tiny_http::Response::from_data(Vec::new())
            .with_status_code(302)
            .with_header(
                tiny_http::Header::from_bytes("location", "http://127.0.0.1:1/evil").unwrap(),
            )
    } else if url.starts_with("/v1/echo-key-base64-no-pad") {
        tiny_http::Response::from_data(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(authentication)
                .into_bytes(),
        )
        .with_status_code(200)
    } else if url.starts_with("/v1/echo-key-base64") {
        tiny_http::Response::from_data(
            base64::engine::general_purpose::STANDARD
                .encode(authentication)
                .into_bytes(),
        )
        .with_status_code(200)
    } else if url.starts_with("/v1/echo-key-header") {
        tiny_http::Response::from_data(b"ok".to_vec())
            .with_status_code(200)
            .with_header(
                tiny_http::Header::from_bytes(
                    "content-type",
                    format!("application/json; reflected={authentication}"),
                )
                .unwrap(),
            )
    } else if url.starts_with("/v1/echo-key") {
        tiny_http::Response::from_data(authentication.into_bytes()).with_status_code(200)
    } else {
        tiny_http::Response::from_data(br#"{"authenticated":true}"#.to_vec())
            .with_status_code(200)
            .with_header(tiny_http::Header::from_bytes("content-type", "application/json").unwrap())
    };
    let _ = request.respond(response);
}

pub fn raw(port: u16, request_line_and_headers: &str) -> u16 {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "{request_line_and_headers}\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

pub fn client() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(5))
        .build()
}

pub fn call(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    call_with(&client(), port, method, path, headers)
}

pub fn call_with(
    agent: &ureq::Agent,
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut request = agent.request(method, &format!("http://127.0.0.1:{port}{path}"));
    for (name, value) in headers {
        request = request.set(name, value);
    }
    match request.call() {
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
