mod common;

use common::{call, call_body, grant, granted_route, raw, upstream};
use std::io::{Read, Write};
use twl::proxy;

const ALPHA_KEY: &str = "alpha-real-key-0123456789";
const BETA_KEY: &str = "beta-real-key-9876543210";

fn test_proxy(routes: Vec<twl::grant::GrantedRoute>) -> proxy::Handle {
    proxy::spawn(grant(routes)).unwrap()
}

fn route_path(handle: &proxy::Handle, route: &str, path: &str) -> String {
    format!("/{}/{route}{path}", handle.token)
}

#[test]
fn two_routes_keep_destinations_and_credentials_isolated() {
    let (alpha_upstream, alpha_log) = upstream();
    let (beta_upstream, beta_log) = upstream();
    let handle = test_proxy(vec![
        granted_route("alpha", &alpha_upstream, ALPHA_KEY),
        granted_route("beta", &beta_upstream, BETA_KEY),
    ]);

    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "alpha", "/v1/models"),
            &[]
        )
        .0,
        200
    );
    assert_eq!(
        call(
            handle.port,
            "POST",
            &route_path(&handle, "beta", "/projects/42?dry_run=true"),
            &[]
        )
        .0,
        200
    );

    let alpha = alpha_log.lock().unwrap();
    let beta = beta_log.lock().unwrap();
    assert_eq!(alpha.len(), 1);
    assert_eq!(beta.len(), 1);
    assert_eq!(alpha[0].url, "/v1/models");
    assert_eq!(beta[0].url, "/projects/42?dry_run=true");
    assert_eq!(
        alpha[0].header("authorization"),
        Some(&*format!("Bearer {ALPHA_KEY}"))
    );
    assert_eq!(
        beta[0].header("authorization"),
        Some(&*format!("Bearer {BETA_KEY}"))
    );
    assert!(!alpha[0]
        .headers
        .iter()
        .any(|(_, value)| value.contains(BETA_KEY)));
    assert!(!beta[0]
        .headers
        .iter()
        .any(|(_, value)| value.contains(ALPHA_KEY)));
}

#[test]
fn route_method_and_path_policies_are_enforced() {
    let (upstream, log) = upstream();
    let mut route = granted_route("limited", &upstream, ALPHA_KEY);
    route.policy.allowed_methods = vec!["GET".into(), "POST".into()];
    route.policy.path_prefixes = Some(vec!["/v1".into()]);
    let handle = test_proxy(vec![route]);

    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "limited", "/v1/models"),
            &[]
        )
        .0,
        200
    );
    assert_eq!(
        call(
            handle.port,
            "DELETE",
            &route_path(&handle, "limited", "/v1/models"),
            &[]
        )
        .0,
        405
    );
    for path in ["/admin", "/v10", "/"] {
        assert_eq!(
            call(
                handle.port,
                "GET",
                &route_path(&handle, "limited", path),
                &[]
            )
            .0,
            403,
            "{path}"
        );
    }
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn hostile_auth_host_and_forwarding_headers_are_stripped() {
    let (upstream, log) = upstream();
    let handle = test_proxy(vec![granted_route("alpha", &upstream, ALPHA_KEY)]);
    let headers = [
        ("Host", "evil.example"),
        ("Forwarded", "host=evil.example"),
        ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-For", "203.0.113.9"),
        ("X-Original-URL", "http://evil.example"),
        ("Proxy-Authorization", "Basic attacker"),
        ("Authorization", "Bearer attacker-choice"),
        ("X-Api-Key", "attacker-choice"),
    ];
    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "alpha", "/v1/models"),
            &headers
        )
        .0,
        200
    );

    let seen = log.lock().unwrap();
    assert_ne!(seen[0].header("host"), Some("evil.example"));
    for name in [
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-for",
        "x-original-url",
        "proxy-authorization",
        "x-api-key",
    ] {
        assert_eq!(seen[0].header(name), None, "forwarded {name}");
    }
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {ALPHA_KEY}"))
    );
}

#[test]
fn token_is_bound_to_only_the_routes_in_its_session() {
    let (alpha_upstream, alpha_log) = upstream();
    let (beta_upstream, beta_log) = upstream();
    let alpha = test_proxy(vec![granted_route("alpha", &alpha_upstream, ALPHA_KEY)]);
    let beta = test_proxy(vec![granted_route("beta", &beta_upstream, BETA_KEY)]);

    for path in [
        "/v1/models".to_string(),
        "/wrong/alpha/v1/models".to_string(),
        format!("/{}/beta/v1/models", alpha.token),
        format!("/{}/alpha/v1/models", beta.token),
    ] {
        assert_eq!(call(alpha.port, "GET", &path, &[]).0, 404, "{path}");
    }
    assert_eq!(
        call(
            beta.port,
            "GET",
            &format!("/{}/beta/v1/models", alpha.token),
            &[]
        )
        .0,
        404
    );
    assert!(alpha_log.lock().unwrap().is_empty());
    assert!(beta_log.lock().unwrap().is_empty());
}

#[test]
fn redirects_are_not_followed_and_location_is_not_exposed() {
    let (upstream, log) = upstream();
    let handle = test_proxy(vec![granted_route("alpha", &upstream, ALPHA_KEY)]);
    let path = route_path(&handle, "alpha", "/redirect");
    let (code, response) = raw(handle.port, &format!("GET {path} HTTP/1.1"));

    assert_eq!(code, 302);
    assert!(!response.to_ascii_lowercase().contains("\r\nlocation:"));
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn malformed_targets_never_reach_an_upstream() {
    let (upstream, log) = upstream();
    let handle = test_proxy(vec![granted_route("alpha", &upstream, ALPHA_KEY)]);
    let prefix = format!("/{}/alpha", handle.token);

    for target in [
        format!("{prefix}/v1/../../etc/passwd"),
        format!("{prefix}/v1/models/%2e%2e/admin"),
        format!("{prefix}//evil.example/v1"),
    ] {
        assert_eq!(
            raw(handle.port, &format!("GET {target} HTTP/1.1")).0,
            400,
            "{target}"
        );
    }
    let absolute = raw(handle.port, "GET http://evil.example/v1/models HTTP/1.1").0;
    assert!(absolute == 400 || absolute == 0);
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn credential_reflection_is_blocked_in_plaintext_base64_and_headers() {
    let (upstream, _log) = upstream();
    let handle = test_proxy(vec![granted_route("alpha", &upstream, ALPHA_KEY)]);

    for path in [
        "/echo-key",
        "/echo-key-base64",
        "/echo-key-base64-no-pad",
        "/echo-key-base64-url",
        "/echo-key-base64-url-no-pad",
    ] {
        let (code, body) = call(handle.port, "GET", &route_path(&handle, "alpha", path), &[]);
        assert_eq!(code, 502, "{path}");
        assert!(!body.contains(ALPHA_KEY));
    }

    let (code, body) = call(
        handle.port,
        "GET",
        &route_path(&handle, "alpha", "/echo-key-header"),
        &[],
    );
    assert_eq!(code, 200);
    assert!(!body.contains(ALPHA_KEY));
}

#[test]
fn invalid_requests_do_not_consume_route_budget() {
    let (upstream, log) = upstream();
    let mut route = granted_route("alpha", &upstream, ALPHA_KEY);
    route.policy.request_count_budget = 1;
    let handle = test_proxy(vec![route]);

    assert_eq!(call(handle.port, "GET", "/wrong/alpha/v1", &[]).0, 404);
    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "alpha", "/v1/a"),
            &[]
        )
        .0,
        200
    );
    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "alpha", "/v1/b"),
            &[]
        )
        .0,
        429
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn request_and_response_size_limits_are_route_specific() {
    let (upstream, log) = upstream();
    let mut route = granted_route("alpha", &upstream, ALPHA_KEY);
    route.policy.max_request_bytes = 4;
    route.policy.max_response_bytes = 100;
    let handle = test_proxy(vec![route]);

    assert_eq!(
        call_body(
            handle.port,
            "POST",
            &route_path(&handle, "alpha", "/upload"),
            &[],
            b"12345",
        )
        .0,
        413
    );
    assert!(log.lock().unwrap().is_empty());

    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "alpha", "/large-response"),
            &[]
        )
        .0,
        502
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn expired_route_fails_before_forwarding() {
    let (upstream, log) = upstream();
    let mut route = granted_route("alpha", &upstream, ALPHA_KEY);
    route.policy.session_expiry_seconds = 1;
    let handle = test_proxy(vec![route]);
    std::thread::sleep(std::time::Duration::from_millis(1_100));

    assert_eq!(
        call(
            handle.port,
            "GET",
            &route_path(&handle, "alpha", "/v1/models"),
            &[]
        )
        .0,
        401
    );
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn rejected_body_is_drained_before_keep_alive_reuse() {
    let (upstream, log) = upstream();
    let handle = test_proxy(vec![granted_route("alpha", &upstream, ALPHA_KEY)]);
    let valid = route_path(&handle, "alpha", "/v1/models");
    let body = "x".repeat(2_048);
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    write!(
        stream,
        "POST /wrong/alpha/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}GET {valid} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
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
