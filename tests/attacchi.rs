//! Attacchi che devono fallire. Stanno nella suite principale e non su un
//! branch a parte apposta: un test che dimostra che un attacco non funziona
//! deve girare a ogni commit, altrimenti il giorno in cui la proprieta' si
//! rompe non se ne accorge nessuno.

mod common;

use capshell::config::Auth;
use capshell::proxy::{self, Route};
use common::{call, raw, upstream};
use std::collections::HashMap;

const KEY: &str = "sk-CANARY-CHIAVE-VERA-0123456789";

/// L'Handle va tenuto vivo: quando cade, il proxy si spegne.
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

// ---------------------------------------------------------------------------
// 1. Il proxy ascolta su loopback, che e' raggiungibile da qualunque processo
//    della macchina: un altro utente locale non deve poter spendere la chiave.
// ---------------------------------------------------------------------------

#[test]
fn senza_token_il_proxy_non_serve_nessuno() {
    let (up, log) = upstream();
    let (h, _token) = proxy_su(&up, None);

    // Esattamente cio' che farebbe chi trova la porta aperta e prova a usarla.
    for tentativo in [
        "/openai/v1/models",
        "/v1/models",
        "/openai",
        "/sbagliato/openai/v1/models",
        "//openai/v1/models",
    ] {
        let (code, _) = call(h.port, "GET", tentativo, &[]);
        assert_eq!(code, 404, "{tentativo} non doveva essere servito");
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "nessuna di quelle richieste deve raggiungere l'upstream con la chiave"
    );
}

#[test]
fn un_token_sbagliato_e_indistinguibile_da_un_path_inesistente() {
    let (up, _log) = upstream();
    let (h, token) = proxy_su(&up, None);

    // Stessa risposta per "token errato" e "non esiste": chi sonda la porta non
    // deve capire che dietro c'e' un proxy, ne' quanto ci e' andato vicino.
    let quasi = format!("/{}X/openai/v1/models", &token[..token.len() - 1]);
    let (a, corpo_a) = call(h.port, "GET", &quasi, &[]);
    let (b, corpo_b) = call(h.port, "GET", "/qualsiasi/cosa", &[]);

    assert_eq!(a, 404);
    assert_eq!(b, 404);
    assert_eq!(
        corpo_a, corpo_b,
        "la risposta non deve distinguere i due casi"
    );
}

#[test]
fn col_token_giusto_la_richiesta_passa() {
    let (up, log) = upstream();
    let (h, token) = proxy_su(&up, None);

    let (code, _) = call(h.port, "GET", &format!("/{token}/openai/v1/models"), &[]);

    assert_eq!(code, 200);
    assert_eq!(log.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 2. Il client controlla il valore degli header che inoltriamo: non deve
//    poterci infilare dentro una riga in piu'.
// ---------------------------------------------------------------------------

#[test]
fn header_con_caratteri_di_controllo_rifiutato() {
    let (up, log) = upstream();
    let (h, token) = proxy_su(&up, None);

    // CR nudo dentro un valore che sta nell'allowlist: se arrivasse intatto al
    // client HTTP, l'upstream vedrebbe un header che non abbiamo scritto noi.
    let code = raw(
        h.port,
        &format!(
            "GET /{token}/openai/v1/models HTTP/1.1\r\n\
             Content-Type: text/plain\rX-Iniettato: si"
        ),
    );

    assert!(
        code == 400 || code == 0,
        "rifiutato o connessione chiusa, mai inoltrato: {code}"
    );
    let visti = log.lock().unwrap();
    if let Some(visto) = visti.first() {
        assert_eq!(
            visto.header("x-iniettato"),
            None,
            "header iniettato a monte"
        );
    }
}

#[test]
fn una_riga_di_header_in_piu_non_supera_l_allowlist() {
    let (up, log) = upstream();
    let (h, token) = proxy_su(&up, None);

    // Header aggiuntivi ben formati: passano il parser, ma non l'allowlist.
    call(
        h.port,
        "GET",
        &format!("/{token}/openai/v1/models"),
        &[
            ("X-Iniettato", "si"),
            ("Cookie", "a=b"),
            ("Proxy-Authorization", "Basic x"),
        ],
    );

    let seen = log.lock().unwrap();
    for vietato in ["x-iniettato", "cookie", "proxy-authorization"] {
        assert_eq!(
            seen[0].header(vietato),
            None,
            "{vietato} non doveva passare"
        );
    }
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}")),
        "e la credenziale deve restare quella nostra"
    );
}
