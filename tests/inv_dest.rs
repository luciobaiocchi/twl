mod common;

use capshell::config::Auth;
use capshell::proxy::{self, resolve, Route};
use common::{call, raw, upstream};
use std::collections::HashMap;

const KEY: &str = "sk-CANARY-CHIAVE-VERA-0123456789";

fn routes(up: &str) -> HashMap<String, Route> {
    HashMap::from([(
        "openai".to_string(),
        Route {
            upstream: up.to_string(),
            auth: Auth::Bearer,
            key: KEY.to_string(),
        },
    )])
}

/// L'Handle va tenuto vivo: quando cade, il proxy si spegne.
fn proxy_su(up: &str, budget: Option<u64>) -> (proxy::Handle, String) {
    let h = proxy::spawn(routes(up), budget).unwrap();
    let prefisso = format!("/{}", h.token);
    (h, prefisso)
}

#[test]
fn la_chiave_vera_arriva_all_upstream_cablato() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    let (code, _) = call(h.port, "GET", &format!("{t}/openai/v1/models"), &[]);
    assert_eq!(code, 200);

    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "/v1/models");
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn host_ostile_non_cambia_la_destinazione() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    let (code, _) = call(
        h.port,
        "GET",
        &format!("{t}/openai/v1/models"),
        &[("Host", "evil.example")],
    );

    assert_eq!(code, 200, "la richiesta deve comunque andare a buon fine");
    let seen = log.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "l'unico upstream contattato e' quello del connector"
    );
    assert_ne!(seen[0].header("host"), Some("evil.example"));
}

#[test]
fn gli_header_di_forwarding_non_passano() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    call(
        h.port,
        "GET",
        &format!("{t}/openai/v1/models"),
        &[
            ("X-Forwarded-Host", "evil.example"),
            ("X-Original-URL", "http://evil.example"),
        ],
    );

    let seen = log.lock().unwrap();
    assert_eq!(seen[0].header("x-forwarded-host"), None);
    assert_eq!(seen[0].header("x-original-url"), None);
}

#[test]
fn il_client_non_puo_sovrascrivere_authorization() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    call(
        h.port,
        "GET",
        &format!("{t}/openai/v1/models"),
        &[("Authorization", "Bearer sk-scelta-dall-agente")],
    );

    let seen = log.lock().unwrap();
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn i_redirect_non_vengono_seguiti() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    let (code, _) = call(h.port, "GET", &format!("{t}/openai/redirect"), &[]);

    assert_eq!(code, 302, "il 3xx torna al client cosi' com'e'");
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "nessuna seconda richiesta con la chiave allegata"
    );
}

#[test]
fn connector_sconosciuto_rifiutato() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    let (code, _) = call(h.port, "GET", &format!("{t}/altro/v1/models"), &[]);

    assert_eq!(code, 404);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn metodo_non_consentito_rifiutato() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    let (code, _) = call(h.port, "DELETE", &format!("{t}/openai/v1/models"), &[]);

    assert_eq!(code, 405);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn traversal_rifiutato() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, None);

    assert_eq!(
        raw(h.port, &format!("GET {t}/openai/../../etc/passwd HTTP/1.1")),
        400
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn uri_assoluto_rifiutato() {
    let (up, log) = upstream();
    let (h, _t) = proxy_su(&up, None);

    let code = raw(h.port, "GET http://evil.example/v1/models HTTP/1.1");

    assert!(
        code == 400 || code == 0,
        "rifiutato o connessione chiusa, mai inoltrato: {code}"
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn nessun_path_puo_cambiare_l_host_di_destinazione() {
    let r = routes("https://api.openai.com");
    const T: &str = "tokenditest";
    for ostile in [
        "http://evil.example/v1",
        "//evil.example/v1",
        &format!("/{T}/openai/../../../evil.example"),
        &format!("/{T}/openai/@evil.example/v1"),
        &format!("/{T}/openai/v1#@evil.example"),
    ] {
        match resolve(ostile, T, &r) {
            Err(_) => {}
            Ok((_, target)) => assert!(
                target.starts_with("https://api.openai.com/"),
                "{ostile} ha prodotto {target}"
            ),
        }
    }
}

#[test]
fn la_chiave_non_torna_indietro_nella_risposta() {
    let (up, _log) = upstream();
    let (h, t) = proxy_su(&up, None);

    let (code, body) = call(h.port, "GET", &format!("{t}/openai/echo-key"), &[]);

    assert_eq!(
        code, 502,
        "una risposta che contiene la credenziale viene scartata"
    );
    assert!(!body.contains(KEY));
}

#[test]
fn il_budget_fallisce_chiuso() {
    let (up, log) = upstream();
    let (h, t) = proxy_su(&up, Some(2));

    assert_eq!(call(h.port, "GET", &format!("{t}/openai/a"), &[]).0, 200);
    assert_eq!(call(h.port, "GET", &format!("{t}/openai/b"), &[]).0, 200);
    let (code, body) = call(h.port, "GET", &format!("{t}/openai/c"), &[]);

    assert_eq!(code, 429);
    assert!(body.contains("budget"));
    assert_eq!(
        log.lock().unwrap().len(),
        2,
        "la terza non raggiunge l'upstream"
    );
}
