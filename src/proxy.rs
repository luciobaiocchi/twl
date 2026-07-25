use crate::config::Auth;
use rand::distributions::Alphanumeric;
use rand::Rng;
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

/// Finche' esiste, il proxy ascolta. Quando cade, il thread che accetta esce:
/// senza questo resterebbe bloccato in `recv()` per sempre, e con piu' sessioni
/// nello stesso processo i thread si accumulerebbero fino a inchiodarlo.
pub struct Handle {
    pub port: u16,
    /// Segreto di sessione, primo segmento di ogni URL. Il proxy ascolta su
    /// loopback, che e' raggiungibile da *qualunque* processo della macchina:
    /// senza questo, un altro utente locale potrebbe scoprire la porta e
    /// spendere la tua chiave. Il figlio ce l'ha nell'environment, nessun altro.
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

fn token_casuale() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Confronto senza uscita anticipata: il tempo di risposta non deve dire
/// quanti caratteri del token erano giusti.
fn uguali(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// INV-DEST: l'host di destinazione viene dal connector, mai dalla richiesta.
/// L'unica cosa che l'agente sceglie e' il path dopo il nome del connector.
pub fn resolve<'a>(
    url: &str,
    token: &str,
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

    // Un token sbagliato risponde come un path sconosciuto: chi sonda la porta
    // non deve nemmeno capire che c'e' un proxy.
    if !segs.next().is_some_and(|t| uguali(t, token)) {
        return Err((404, "non trovato"));
    }
    let name = segs.next().ok_or((404, "non trovato"))?;
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
    let server = Arc::new(
        tiny_http::Server::http("127.0.0.1:0").map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    let port = server.server_addr().to_ip().expect("socket ip").port();
    let token = Arc::new(token_casuale());
    let routes = Arc::new(routes);
    let seen = Arc::new(AtomicU64::new(0));

    // Ogni richiesta va servita subito, in un thread suo. Metterle in coda per
    // un pool di worker sembra piu' ordinato ma si inceppa: finche' tratteniamo
    // un `Request` senza rispondere, tiny_http non legge la richiesta successiva
    // da quella connessione, e sotto carico concorrente smette di consegnarne.
    // Misurato: con un pool il proxy ne riceveva 111 su 120, e i client rimasti
    // senza risposta aspettavano per sempre.
    let agent = Arc::new(
        ureq::AgentBuilder::new()
            .redirects(0)
            // Un upstream che non risponde mai non deve tenere appeso il figlio.
            .timeout(std::time::Duration::from_secs(120))
            .build(),
    );
    let token_pubblico = token.to_string();
    let accettatore = server.clone();
    let contatore = seen.clone();
    std::thread::spawn(move || {
        while let Ok(req) = accettatore.recv() {
            // Il contatore si incrementa PRIMA di inoltrare: contare a valle
            // lascerebbe passare piu' di N con richieste concorrenti.
            let n = contatore.fetch_add(1, Ordering::SeqCst) + 1;
            let (routes, token, agent) = (routes.clone(), token.clone(), agent.clone());
            std::thread::spawn(move || serve(req, &token, &routes, &agent, max_requests, n));
        }
    });
    Ok(Handle {
        port,
        token: token_pubblico,
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

    let esito = forward(&url, token, &method, &headers, body, routes, agent, max, n);
    let (code, ctype, data) = match esito {
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
        return Err((429, "budget della sessione esaurito"));
    }
    if !matches!(method, "GET" | "POST") {
        return Err((405, "metodo non consentito"));
    }
    let (route, target) = resolve(url, token, routes)?;

    let mut r = agent.request(method, &target);
    for (k, v) in headers {
        if !FORWARD.contains(&k.as_str()) {
            continue;
        }
        // Un valore con caratteri di controllo puo' spezzare la richiesta e
        // iniettare header nostri. Non deleghiamo il controllo al client HTTP:
        // se e' malformato la richiesta muore qui.
        if v.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err((400, "header con caratteri di controllo"));
        }
        r = r.set(k, v);
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
