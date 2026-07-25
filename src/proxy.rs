use crate::config::Auth;
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const MAX_BODY: u64 = 32 << 20;

/// Gli unici header che arrivano all'upstream. Allowlist, non denylist: cosi'
/// `Host`, `X-Forwarded-*`, `Authorization` del client e tutto il resto non
/// possono influenzare la richiesta autenticata.
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

pub struct Handle {
    pub port: u16,
    pub seen: Arc<AtomicU64>,
}

type Denied = (u16, &'static str);

/// INV-DEST: l'host di destinazione viene dal connector, mai dalla richiesta.
/// L'unica cosa che l'agente sceglie e' il path dopo il nome del connector.
pub fn resolve<'a>(
    url: &str,
    routes: &'a HashMap<String, Route>,
) -> Result<(&'a Route, String), Denied> {
    if !url.starts_with('/') {
        return Err((400, "richiesta non in origin-form"));
    }
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url, None),
    };
    let mut segs = path.split('/').filter(|s| !s.is_empty());
    let name = segs.next().ok_or((404, "connector non specificato"))?;
    let rest: Vec<&str> = segs.collect();
    if rest
        .iter()
        .any(|s| *s == ".." || *s == "." || s.contains('\\'))
    {
        return Err((400, "path non normalizzato"));
    }
    let route = routes.get(name).ok_or((404, "connector sconosciuto"))?;
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
    let server =
        tiny_http::Server::http("127.0.0.1:0").map_err(|e| std::io::Error::other(e.to_string()))?;
    let port = server.server_addr().to_ip().expect("socket ip").port();
    let seen = Arc::new(AtomicU64::new(0));
    let counter = seen.clone();

    std::thread::spawn(move || {
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        for req in server.incoming_requests() {
            // Il contatore si incrementa PRIMA di inoltrare: contare a valle
            // lascerebbe passare piu' di N con richieste concorrenti.
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            serve(req, &routes, &agent, max_requests, n);
        }
    });
    Ok(Handle { port, seen })
}

fn serve(
    mut req: tiny_http::Request,
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

    let (code, ctype, data) = match forward(&url, &method, &headers, body, routes, agent, max, n) {
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
    method: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    routes: &HashMap<String, Route>,
    agent: &ureq::Agent,
    max: Option<u64>,
    n: u64,
) -> Result<(u16, String, Vec<u8>), Denied> {
    if max.is_some_and(|m| n > m) {
        return Err((429, "budget della sessione esaurito"));
    }
    if !matches!(method, "GET" | "POST") {
        return Err((405, "metodo non consentito"));
    }
    let (route, target) = resolve(url, routes)?;

    let mut r = agent.request(method, &target);
    for (k, v) in headers {
        if FORWARD.contains(&k.as_str()) {
            r = r.set(k, v);
        }
    }
    r = match route.auth {
        Auth::Bearer => r.set("authorization", &format!("Bearer {}", route.key)),
        Auth::XApiKey => r.set("x-api-key", &route.key),
    };

    // redirects(0): un 3xx torna al client cosi' com'e', e non lo seguiamo mai.
    // Location non viene inoltrato indietro, quindi la chiave non puo' finire
    // su una destinazione scelta dalla risposta dell'upstream.
    let resp = match if body.is_empty() {
        r.call()
    } else {
        r.send_bytes(&body)
    } {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(_) => return Err((502, "upstream irraggiungibile")),
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
        .map_err(|_| (502u16, "risposta upstream illeggibile"))?;

    // INV-SECRET: la chiave non torna indietro nemmeno se l'upstream la riflette.
    if contains(&data, route.key.as_bytes()) {
        return Err((502, "risposta upstream scartata: conteneva la credenziale"));
    }
    Ok((code, ctype, data))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
