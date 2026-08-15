mod common;

use common::{call, raw, upstream};
use std::io::{Read, Write};
use twl::proxy::{self, resolve, Route};

const KEY: &str = "project-canary-real-key-0123456789";

fn route(upstream: &str) -> Route {
    Route {
        name: "application".into(),
        upstream: upstream.to_string(),
        key: KEY.to_string(),
    }
}

fn test_proxy(upstream: &str, budget: Option<u64>) -> (proxy::Handle, String) {
    let handle = proxy::spawn(vec![route(upstream)], budget).unwrap();
    let prefix = format!("/{}/application", handle.token);
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
fn multiple_routes_bind_each_credential_to_its_own_upstream() {
    let (billing_upstream, billing_log) = upstream();
    let (search_upstream, search_log) = upstream();
    let handle = proxy::spawn(
        vec![
            Route {
                name: "billing".into(),
                upstream: format!("{billing_upstream}/billing-base"),
                key: "billing-real-key".into(),
            },
            Route {
                name: "search".into(),
                upstream: format!("{search_upstream}/search-base"),
                key: "search-real-key".into(),
            },
        ],
        None,
    )
    .unwrap();

    assert_eq!(
        call(
            handle.port,
            "GET",
            &format!("/{}/billing/invoices", handle.token),
            &[],
        )
        .0,
        200
    );
    assert_eq!(
        call(
            handle.port,
            "POST",
            &format!("/{}/search/query", handle.token),
            &[],
        )
        .0,
        200
    );

    let billing = billing_log.lock().unwrap();
    let search = search_log.lock().unwrap();
    assert_eq!(billing[0].url, "/billing-base/invoices");
    assert_eq!(
        billing[0].header("authorization"),
        Some("Bearer billing-real-key")
    );
    assert_eq!(search[0].url, "/search-base/query");
    assert_eq!(
        search[0].header("authorization"),
        Some("Bearer search-real-key")
    );
}

#[test]
fn ordinary_application_paths_and_methods_are_forwarded() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);

    assert_eq!(
        call(
            handle.port,
            "POST",
            &format!("{prefix}/projects/42/tasks?dry_run=true"),
            &[],
        )
        .0,
        200
    );
    assert_eq!(call(handle.port, "GET", &format!("{prefix}/"), &[]).0, 200);

    let seen = log.lock().unwrap();
    assert_eq!(seen[0].url, "/projects/42/tasks?dry_run=true");
    assert_eq!(seen[1].url, "/");
}

#[test]
fn hostile_host_and_auth_headers_are_ignored() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);
    let headers = [
        ("Host", "evil.example"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Original-URL", "http://evil.example"),
        ("Authorization", "Bearer attacker-choice"),
        ("X-Api-Key", "attacker-choice"),
    ];
    assert_eq!(
        call(handle.port, "GET", &format!("{prefix}/v1/models"), &headers).0,
        200
    );

    let seen = log.lock().unwrap();
    assert_ne!(seen[0].header("host"), Some("evil.example"));
    assert_eq!(seen[0].header("x-forwarded-host"), None);
    assert_eq!(seen[0].header("x-original-url"), None);
    assert_eq!(seen[0].header("x-api-key"), None);
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn valid_unknown_header_names_are_ignored() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);

    for name in ["X_Test", "X.Test", "X*Test"] {
        assert_eq!(
            raw(
                handle.port,
                &format!("GET {prefix}/v1/models HTTP/1.1\r\n{name}: ignored"),
            ),
            200,
            "valid unknown header {name} should be ignored",
        );
    }

    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 3);
    for request in seen.iter() {
        for name in ["x_test", "x.test", "x*test"] {
            assert_eq!(request.header(name), None);
        }
    }
}

#[test]
fn missing_or_wrong_session_token_reaches_nothing() {
    let (upstream, log) = upstream();
    let (handle, _prefix) = test_proxy(&upstream, None);
    for path in ["/v1/models", "/wrong/v1/models", "/wrong"] {
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
fn unsupported_methods_are_rejected() {
    let (upstream, log) = upstream();
    let (handle, prefix) = test_proxy(&upstream, None);

    assert_eq!(
        call(handle.port, "OPTIONS", &format!("{prefix}/v1/models"), &[]).0,
        405
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
    let routes = [route("https://service.example/api")];
    let token = "TESTTOKEN";
    for hostile in [
        "http://evil.example/v1",
        "//evil.example/v1",
        "/TESTTOKEN/application//evil.example/v1",
        "/TESTTOKEN/application/v1/@evil.example",
        "/TESTTOKEN/application/v1/models#@evil.example",
    ] {
        match resolve(hostile, token, "GET", &routes) {
            Err(_) => {}
            Ok((target, _)) => assert!(target.starts_with("https://service.example/api/")),
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

    assert_eq!(call(handle.port, "GET", "/wrong/v1/models", &[]).0, 404);
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
        "POST /wrong/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}GET {prefix}/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
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
