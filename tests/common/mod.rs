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

/// Finto provider: registra quello che riceve invece di rimandarlo indietro,
/// cosi' i test possono verificare l'iniezione della chiave senza che il valore
/// passi dalla risposta.
pub fn upstream() -> (String, Log) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    std::thread::spawn(move || {
        for req in server.incoming_requests() {
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
                // Upstream che riflette la credenziale: il proxy deve scartarla.
                tiny_http::Response::from_data(auth.into_bytes()).with_status_code(200)
            } else {
                tiny_http::Response::from_data(b"ok".to_vec()).with_status_code(200)
            };
            let _ = req.respond(resp);
        }
    });
    (format!("http://127.0.0.1:{port}"), log)
}

/// Richiesta grezza: i client HTTP normalizzano il path e rifiutano di mandare
/// un URI assoluto, quindi per verificare cosa fa il server davanti a un input
/// ostile bisogna scrivere sul socket a mano. Ritorna 0 se il server chiude
/// senza rispondere, che e' anch'esso un rifiuto.
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

pub fn call(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut r = agent.request(method, &format!("http://127.0.0.1:{port}{path}"));
    for (k, v) in headers {
        r = r.set(k, v);
    }
    match r.call() {
        Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => panic!("richiesta fallita: {e}"),
    }
}
