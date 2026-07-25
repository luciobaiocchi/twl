//! Il budget si incrementa prima dell'inoltro. Con un proxy multi-thread la
//! corsa e' reale, quindi la promessa va verificata sotto carico.
//!
//! Sta in un file suo, e non insieme agli altri attacchi, perche' cargo esegue
//! ogni file di test in un processo separato: sotto carico, sei proxy vivi
//! nello stesso processo si contendono le risorse e falsano il risultato. In
//! produzione c'e' un proxy per processo, quindi il caso da misurare e' questo.

mod common;

use capshell::config::Auth;
use capshell::proxy::{self, Route};
use common::{call_con, client, upstream};
use std::collections::HashMap;

const KEY: &str = "sk-CANARY-CHIAVE-VERA-0123456789";

fn proxy_su(up: &str, budget: Option<u64>) -> (proxy::Handle, String) {
    let routes = HashMap::from([(
        "openai".to_string(),
        Route {
            upstream: up.to_string(),
            auth: Auth::Bearer,
            key: KEY.to_string(),
        },
    )]);
    let h = proxy::spawn(routes, budget).unwrap();
    let token = h.token.clone();
    (h, token)
}

#[test]
fn il_budget_regge_le_richieste_concorrenti() {
    const CAP: u64 = 20;
    const CLIENT: usize = 12;
    const A_TESTA: usize = 10;

    let (up, log) = upstream();
    let (h, token) = proxy_su(&up, Some(CAP));
    let port = h.port;

    // Le thread vanno avviate tutte prima di aspettarne una, altrimenti la
    // concorrenza sparisce e il test non prova niente. Ogni client riusa la sua
    // connessione, come farebbe un SDK.
    let clienti: Vec<_> = (0..CLIENT)
        .map(|_| {
            let token = token.clone();
            std::thread::spawn(move || {
                let agente = client();
                let path = format!("/{token}/openai/v1/models");
                (0..A_TESTA)
                    .filter(|_| call_con(&agente, port, "GET", &path) == 200)
                    .count()
            })
        })
        .collect();

    let esiti: Vec<_> = clienti.into_iter().map(|h| h.join()).collect();
    let accettate = h.seen.load(std::sync::atomic::Ordering::SeqCst);
    let arrivate_up = log.lock().unwrap().len();
    let ok: usize = esiti
        .into_iter()
        .map(|e| {
            e.unwrap_or_else(|_| {
                panic!(
                    "un client non ha avuto risposta. \
                     Il proxy aveva accettato {accettate} richieste su {} \
                     e ne aveva inoltrate {arrivate_up} all'upstream",
                    CLIENT * A_TESTA
                )
            })
        })
        .sum();
    let arrivate = arrivate_up;

    assert_eq!(ok, CAP as usize, "esattamente CAP richieste devono passare");
    assert_eq!(
        arrivate, CAP as usize,
        "e l'upstream non deve vederne una in piu': {arrivate} contro {CAP}"
    );
}
