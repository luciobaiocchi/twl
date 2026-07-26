// Every test file includes this module but only uses part of it: without
// this, each binary would flag as dead what the others need.
#![allow(dead_code)]

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
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Fake provider: records what it receives instead of echoing it back, so
/// tests can verify key injection without the value passing through the
/// response.
pub fn upstream() -> (String, Log) {
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
    let port = server.server_addr().to_ip().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));

    // A single thread accepts and hands each request to a thread of its own.
    // Serving in sequence would choke the proxy's workers, which hold
    // keep-alive connections: the first one grabs the server and the rest wait.
    let sink = log.clone();
    std::thread::spawn(move || {
        while let Ok(req) = server.recv() {
            let sink = sink.clone();
            std::thread::spawn(move || {
                let url = req.url().to_string();
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
                let auth = headers
                    .iter()
                    .find(|(k, _)| k == "authorization")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                sink.lock().unwrap().push(Seen {
                    url: url.clone(),
                    headers,
                });

                let resp = if url.starts_with("/redirect") {
                    tiny_http::Response::from_data(Vec::new())
                        .with_status_code(302)
                        .with_header(
                            tiny_http::Header::from_bytes("location", "http://127.0.0.1:1/evil")
                                .unwrap(),
                        )
                } else if url.starts_with("/echo-key") {
                    // Upstream that reflects the credential: the proxy must discard it.
                    tiny_http::Response::from_data(auth.into_bytes()).with_status_code(200)
                } else {
                    tiny_http::Response::from_data(b"ok".to_vec()).with_status_code(200)
                };
                let _ = req.respond(resp);
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), log)
}

/// Raw request: HTTP clients normalize the path and refuse to send an
/// absolute URI, so verifying what the server does with hostile input means
/// writing to the socket by hand. Returns 0 if the server closes without
/// responding, which is also a rejection.
pub fn raw(port: u16, request_line: &str) -> u16 {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "{request_line}\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// Client with a reused connection, like a real SDK. Opening a new connection
/// per request is a different stress scenario, not the actual use case.
///
/// The timeout isn't decorative: a test that hangs is much worse than one
/// that fails, because it jams the suite instead of saying what's wrong.
pub fn client() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(10))
        .build()
}

pub fn call_with(agent: &ureq::Agent, port: u16, method: &str, path: &str) -> u16 {
    match agent
        .request(method, &format!("http://127.0.0.1:{port}{path}"))
        .call()
    {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("request failed: {e}"),
    }
}

pub fn call(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let agent = client();
    let mut r = agent.request(method, &format!("http://127.0.0.1:{port}{path}"));
    for (k, v) in headers {
        r = r.set(k, v);
    }
    match r.call() {
        Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => panic!("request failed: {e}"),
    }
}
