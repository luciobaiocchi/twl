mod common;

use common::{call, raw, upstream};
use mithril::config::{connector, AllowedRoute, Auth};
use mithril::proxy::{self, resolve, Route};
use std::collections::HashMap;
use std::io::{Read, Write};

const KEY: &str = "sk-CANARY-REAL-KEY-0123456789";
const TEST_ROUTES: &[AllowedRoute] = &[
    AllowedRoute::exact("GET", "/v1/models"),
    AllowedRoute::exact("GET", "/v1/redirect"),
    AllowedRoute::exact("GET", "/v1/echo-key"),
    AllowedRoute::exact("GET", "/v1/echo-key-base64"),
    AllowedRoute::exact("GET", "/v1/echo-key-base64-no-pad"),
    AllowedRoute::exact("GET", "/v1/echo-key-header"),
    AllowedRoute::exact("GET", "/v1/a"),
    AllowedRoute::exact("GET", "/v1/b"),
];

fn routes(upstream: &str, allowed: &'static [AllowedRoute]) -> HashMap<String, Route> {
    HashMap::from([(
        "openai".to_string(),
        Route {
            upstream: upstream.to_string(),
            auth: Auth::Bearer,
            key: KEY.to_string(),
            allowed,
        },
    )])
}

fn test_proxy(upstream: &str, budget: Option<u64>) -> (proxy::Handle, String) {
    let handle = proxy::spawn(routes(upstream, TEST_ROUTES), budget).unwrap();
    let prefix = format!("/{}/openai", handle.token);
    (handle, prefix)
}

#[test]
fn real_key_reaches_only_the_fixed_upstream() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);
    assert_eq!(
        call(handle.port, "GET", &format!("{prefix}/v1/models"), &[]).0,
        200
    );

    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "/v1/models");
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn runtime_application_accepts_general_paths_but_keeps_one_destination() {
    let (upstream, log) = upstream();
    let application = connector("application").unwrap();
    let routes = HashMap::from([(
        "application".to_string(),
        Route {
            upstream,
            auth: application.auth,
            key: KEY.to_string(),
            allowed: application.allowed,
        },
    )]);
    let handle = proxy::spawn(routes, None).unwrap();
    let path = format!("/{}/application/projects/42/tasks", handle.token);

    assert_eq!(call(handle.port, "POST", &path, &[]).0, 200);
    let seen = log.lock().unwrap();
    assert_eq!(seen[0].url, "/projects/42/tasks");
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn hostile_host_and_forwarding_headers_are_ignored() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);
    let headers = [
        ("Host", "evil.example"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Original-URL", "http://evil.example"),
        ("Authorization", "Bearer attacker-choice"),
    ];
    assert_eq!(
        call(handle.port, "GET", &format!("{prefix}/v1/models"), &headers).0,
        200
    );

    let seen = log.lock().unwrap();
    assert_ne!(seen[0].header("host"), Some("evil.example"));
    assert_eq!(seen[0].header("x-forwarded-host"), None);
    assert_eq!(seen[0].header("x-original-url"), None);
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn missing_or_wrong_session_token_reaches_nothing() {
    let (upstream, log) = upstream();
    let (handle, _prefix) = test_proxy(&upstream, None);
    for path in ["/openai/v1/models", "/wrong/openai/v1/models", "/openai"] {
        assert_eq!(call(handle.port, "GET", path, &[]).0, 404, "{path}");
    }
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn redirects_are_returned_but_never_followed() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);
    let (code, _) = call(handle.port, "GET", &format!("{prefix}/v1/redirect"), &[]);
    assert_eq!(code, 302);
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn unknown_connector_method_and_provider_path_are_rejected() {
    let (upstream, log) = upstream();
    let production = connector("openai").unwrap();
    let handle = proxy::spawn(routes(&upstream, production.allowed), None).unwrap();
    let prefix = format!("/{}/openai", handle.token);

    assert_eq!(
        call(
            handle.port,
            "GET",
            &format!("/{}/unknown/v1/models", handle.token),
            &[]
        )
        .0,
        404
    );
    assert_eq!(
        call(handle.port, "DELETE", &format!("{prefix}/v1/models"), &[]).0,
        405
    );
    assert_eq!(
        call(
            handle.port,
            "POST",
            &format!("{prefix}/v1/organization/api_keys"),
            &[]
        )
        .0,
        403
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn malformed_targets_never_reach_upstream() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);

    assert_eq!(
        raw(
            handle.port,
            &format!("GET {prefix}/v1/../../etc/passwd HTTP/1.1")
        ),
        400
    );
    assert_eq!(
        raw(
            handle.port,
            &format!("GET {prefix}/v1/models/%2e%2e/admin HTTP/1.1")
        ),
        400
    );
    let absolute = raw(handle.port, "GET http://evil.example/v1/models HTTP/1.1");
    assert!(absolute == 400 || absolute == 0);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn no_path_can_change_the_destination_host() {
    let routes = routes("https://api.openai.com", TEST_ROUTES);
    let token = "TESTTOKEN";
    for hostile in [
        "http://evil.example/v1",
        "//evil.example/v1",
        "/TESTTOKEN/openai/v1/@evil.example",
        "/TESTTOKEN/openai/v1/models#@evil.example",
    ] {
        match resolve(hostile, token, "GET", &routes) {
            Err(_) => {}
            Ok((_, target)) => assert!(target.starts_with("https://api.openai.com/")),
        }
    }
}

#[test]
fn credential_reflection_is_blocked_in_plaintext_base64_and_headers() {
    let (upstream, _log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);

    for path in ["echo-key", "echo-key-base64", "echo-key-base64-no-pad"] {
        let (code, body) = call(handle.port, "GET", &format!("{prefix}/v1/{path}"), &[]);
        assert_eq!(code, 502, "{path}");
        assert!(!body.contains(KEY));
    }

    let (code, body) = call(
        handle.port,
        "GET",
        &format!("{prefix}/v1/echo-key-header"),
        &[],
    );
    assert_eq!(code, 200);
    assert!(!body.contains(KEY));
}

#[test]
fn invalid_requests_do_not_consume_budget() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, Some(1));

    assert_eq!(
        call(handle.port, "GET", "/wrong/openai/v1/models", &[]).0,
        404
    );
    assert_eq!(
        call(handle.port, "GET", &format!("{prefix}/v1/a"), &[]).0,
        200
    );
    assert_eq!(
        call(handle.port, "GET", &format!("{prefix}/v1/b"), &[]).0,
        429
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn rejected_body_is_drained_before_keep_alive_reuse() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);
    let body = "x".repeat(2048);
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    write!(
        stream,
        "POST /wrong/openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}GET {prefix}/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        body.len(),
        body
    )
    .unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let statuses: Vec<u16> = response
        .split("HTTP/1.1 ")
        .skip(1)
        .filter_map(|part| part.split_whitespace().next()?.parse().ok())
        .collect();

    assert_eq!(statuses, [404, 200]);
    assert_eq!(log.lock().unwrap().len(), 1);
}
