//! Attacks that must fail. These live in the main suite and not on a
//! separate throwaway branch: a test that proves an attack doesn't work has
//! to run on every commit, otherwise the day the property breaks nobody
//! notices.

mod common;

use capshell::config::Auth;
use capshell::proxy::{self, Route};
use common::{call, raw, upstream};
use std::collections::HashMap;

const KEY: &str = "sk-CANARY-REAL-KEY-0123456789";

/// The Handle must stay alive: when it's dropped, the proxy shuts down.
fn proxy_on(up: &str, budget: Option<u64>) -> (proxy::Handle, String) {
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
// 1. The proxy listens on loopback, which is reachable by any process on the
//    machine: another local user must not be able to spend the key.
// ---------------------------------------------------------------------------

#[test]
fn without_a_token_the_proxy_serves_no_one() {
    let (up, log) = upstream();
    let (h, _token) = proxy_on(&up, None);

    // Exactly what someone who found the open port and tries it would do.
    for attempt in [
        "/openai/v1/models",
        "/v1/models",
        "/openai",
        "/wrong/openai/v1/models",
        "//openai/v1/models",
    ] {
        let (code, _) = call(h.port, "GET", attempt, &[]);
        assert_eq!(code, 404, "{attempt} should not have been served");
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "none of these requests should reach the upstream with the key"
    );
}

#[test]
fn a_wrong_token_is_indistinguishable_from_a_missing_path() {
    let (up, _log) = upstream();
    let (h, token) = proxy_on(&up, None);

    // Same response for "wrong token" and "doesn't exist": whoever is probing
    // the port must not learn there's a proxy behind it, nor how close they got.
    let almost = format!("/{}X/openai/v1/models", &token[..token.len() - 1]);
    let (a, body_a) = call(h.port, "GET", &almost, &[]);
    let (b, body_b) = call(h.port, "GET", "/anything/at/all", &[]);

    assert_eq!(a, 404);
    assert_eq!(b, 404);
    assert_eq!(
        body_a, body_b,
        "the response must not distinguish the two cases"
    );
}

#[test]
fn with_the_right_token_the_request_goes_through() {
    let (up, log) = upstream();
    let (h, token) = proxy_on(&up, None);

    let (code, _) = call(h.port, "GET", &format!("/{token}/openai/v1/models"), &[]);

    assert_eq!(code, 200);
    assert_eq!(log.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 2. The client controls the value of the headers we forward: it must not be
//    able to sneak an extra line in.
// ---------------------------------------------------------------------------

#[test]
fn a_header_with_control_characters_is_rejected() {
    let (up, log) = upstream();
    let (h, token) = proxy_on(&up, None);

    // Bare CR inside a value that's in the allowlist: if it went through
    // intact to the HTTP client, the upstream would see a header we never wrote.
    let code = raw(
        h.port,
        &format!(
            "GET /{token}/openai/v1/models HTTP/1.1\r\n\
             Content-Type: text/plain\rX-Injected: yes"
        ),
    );

    assert!(
        code == 400 || code == 0,
        "rejected or connection closed, never forwarded: {code}"
    );
    let seen = log.lock().unwrap();
    if let Some(seen) = seen.first() {
        assert_eq!(seen.header("x-injected"), None, "header injected upstream");
    }
}

#[test]
fn an_extra_header_line_does_not_clear_the_allowlist() {
    let (up, log) = upstream();
    let (h, token) = proxy_on(&up, None);

    // Extra, well-formed headers: they pass the parser, but not the allowlist.
    call(
        h.port,
        "GET",
        &format!("/{token}/openai/v1/models"),
        &[
            ("X-Injected", "yes"),
            ("Cookie", "a=b"),
            ("Proxy-Authorization", "Basic x"),
        ],
    );

    let seen = log.lock().unwrap();
    for forbidden in ["x-injected", "cookie", "proxy-authorization"] {
        assert_eq!(
            seen[0].header(forbidden),
            None,
            "{forbidden} should not have passed through"
        );
    }
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}")),
        "and the credential must remain ours"
    );
}
