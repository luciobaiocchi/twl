mod common;

use capshell::config::Auth;
use capshell::proxy::{self, resolve, Route};
use common::{call, raw, upstream};
use std::collections::HashMap;

const KEY: &str = "sk-CANARY-REAL-KEY-0123456789";

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

/// The Handle must stay alive: when it's dropped, the proxy shuts down.
fn proxy_on(up: &str, budget: Option<u64>) -> (proxy::Handle, String) {
    let h = proxy::spawn(routes(up), budget).unwrap();
    let prefix = format!("/{}", h.token);
    (h, prefix)
}

#[test]
fn the_real_key_reaches_the_hardwired_upstream() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

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
fn a_hostile_host_header_does_not_change_the_destination() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

    let (code, _) = call(
        h.port,
        "GET",
        &format!("{t}/openai/v1/models"),
        &[("Host", "evil.example")],
    );

    assert_eq!(code, 200, "the request must still succeed");
    let seen = log.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "the only upstream contacted is the connector's"
    );
    assert_ne!(seen[0].header("host"), Some("evil.example"));
}

#[test]
fn forwarding_headers_do_not_pass_through() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

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
fn the_client_cannot_override_authorization() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

    call(
        h.port,
        "GET",
        &format!("{t}/openai/v1/models"),
        &[("Authorization", "Bearer sk-chosen-by-the-agent")],
    );

    let seen = log.lock().unwrap();
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn redirects_are_not_followed() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

    let (code, _) = call(h.port, "GET", &format!("{t}/openai/redirect"), &[]);

    assert_eq!(code, 302, "the 3xx goes back to the client as-is");
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "no second request with the key attached"
    );
}

#[test]
fn unknown_connector_is_rejected() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

    let (code, _) = call(h.port, "GET", &format!("{t}/other/v1/models"), &[]);

    assert_eq!(code, 404);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn disallowed_method_is_rejected() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

    let (code, _) = call(h.port, "DELETE", &format!("{t}/openai/v1/models"), &[]);

    assert_eq!(code, 405);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn traversal_is_rejected() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, None);

    assert_eq!(
        raw(h.port, &format!("GET {t}/openai/../../etc/passwd HTTP/1.1")),
        400
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn absolute_uri_is_rejected() {
    let (up, log) = upstream();
    let (h, _t) = proxy_on(&up, None);

    let code = raw(h.port, "GET http://evil.example/v1/models HTTP/1.1");

    assert!(
        code == 400 || code == 0,
        "rejected or connection closed, never forwarded: {code}"
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn no_path_can_change_the_destination_host() {
    let r = routes("https://api.openai.com");
    const T: &str = "testtoken";
    for hostile in [
        "http://evil.example/v1",
        "//evil.example/v1",
        &format!("/{T}/openai/../../../evil.example"),
        &format!("/{T}/openai/@evil.example/v1"),
        &format!("/{T}/openai/v1#@evil.example"),
    ] {
        match resolve(hostile, T, &r) {
            Err(_) => {}
            Ok((_, target)) => assert!(
                target.starts_with("https://api.openai.com/"),
                "{hostile} produced {target}"
            ),
        }
    }
}

#[test]
fn the_key_does_not_come_back_in_the_response() {
    let (up, _log) = upstream();
    let (h, t) = proxy_on(&up, None);

    let (code, body) = call(h.port, "GET", &format!("{t}/openai/echo-key"), &[]);

    assert_eq!(
        code, 502,
        "a response containing the credential gets discarded"
    );
    assert!(!body.contains(KEY));
}

#[test]
fn the_budget_fails_closed() {
    let (up, log) = upstream();
    let (h, t) = proxy_on(&up, Some(2));

    assert_eq!(call(h.port, "GET", &format!("{t}/openai/a"), &[]).0, 200);
    assert_eq!(call(h.port, "GET", &format!("{t}/openai/b"), &[]).0, 200);
    let (code, body) = call(h.port, "GET", &format!("{t}/openai/c"), &[]);

    assert_eq!(code, 429);
    assert!(body.contains("budget"));
    assert_eq!(
        log.lock().unwrap().len(),
        2,
        "the third one never reaches the upstream"
    );
}
