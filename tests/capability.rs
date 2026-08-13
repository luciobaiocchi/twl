mod common;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{upstream, Log};
use std::io::Write;
use std::io::{BufRead, BufReader, Cursor};
use std::process::{Command, Stdio};
use twl::broker::{Broker, BrokerError, BrokerRequest, RequestLimits, Route};
use twl::capability::{
    serve_stdio, CapabilityBroker, CapabilityError, CapabilityInvocation, MAX_PROTOCOL_LINE_BYTES,
};
use twl::project::{AgentCapability, HttpMethod};

const KEY: &str = "capability-real-canary-0123456789";

fn capability(max_response_bytes: u64) -> AgentCapability {
    AgentCapability::new(
        "github-read".into(),
        "Read repository resources.".into(),
        "github".into(),
        [HttpMethod::GET],
        vec!["/v1/".into()],
        max_response_bytes,
    )
    .unwrap()
}

fn harness(upstream: String, maximum: u64) -> CapabilityBroker {
    CapabilityBroker::new(
        vec![Route {
            name: "github".into(),
            upstream,
            key: KEY.into(),
        }],
        vec![capability(maximum)],
    )
    .unwrap()
}

fn invocation(method: &str, path: &str) -> CapabilityInvocation {
    CapabilityInvocation {
        capability: "github-read".into(),
        method: method.into(),
        path: path.into(),
        query: None,
        headers: vec![("accept".into(), "application/json".into())],
        body: Vec::new(),
    }
}

fn assert_no_request(log: &Log) {
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn allowed_request_uses_trusted_route_and_real_bearer() {
    let (destination, log) = upstream();
    let broker = harness(destination, 1 << 20);
    let mut request = invocation("GET", "/v1/models");
    request.query = Some("state=open&next=https://evil.example".into());

    let response = broker.invoke(request).unwrap();

    assert_eq!(response.status, 200);
    assert!(!response
        .body
        .windows(KEY.len())
        .any(|window| window == KEY.as_bytes()));
    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].url,
        "/v1/models?state=open&next=https://evil.example"
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {KEY}"))
    );
}

#[test]
fn method_path_and_unknown_capability_are_denied_before_upstream() {
    for (mut request, expected) in [
        (
            invocation("DELETE", "/v1/models"),
            CapabilityError::MethodDenied,
        ),
        (
            invocation("GET", "/outside/models"),
            CapabilityError::PathDenied,
        ),
        (
            invocation("GET", "/v1/../admin"),
            CapabilityError::InvalidRequest,
        ),
        (
            invocation("GET", "https://evil.example/v1/models"),
            CapabilityError::InvalidRequest,
        ),
    ] {
        let (destination, log) = upstream();
        let broker = harness(destination, 1 << 20);
        assert_eq!(broker.invoke(request.clone()).unwrap_err(), expected);
        assert_no_request(&log);

        request.capability = "missing".into();
        assert_eq!(
            broker.invoke(request).unwrap_err(),
            CapabilityError::CapabilityNotFound
        );
        assert_no_request(&log);
    }
}

#[test]
fn authorization_override_and_fragment_query_fail_before_upstream() {
    let (destination, log) = upstream();
    let broker = harness(destination, 1 << 20);
    let mut authorization = invocation("GET", "/v1/models");
    authorization
        .headers
        .push(("Authorization".into(), "Bearer attacker".into()));
    assert_eq!(
        broker.invoke(authorization).unwrap_err(),
        CapabilityError::InvalidRequest
    );
    let mut fragment = invocation("GET", "/v1/models");
    fragment.query = Some("safe=true#https://evil.example".into());
    assert_eq!(
        broker.invoke(fragment).unwrap_err(),
        CapabilityError::InvalidRequest
    );
    assert_no_request(&log);
}

#[test]
fn shared_broker_rejects_request_bodies_before_upstream() {
    let (destination, log) = upstream();
    let broker = Broker::new(vec![Route {
        name: "github".into(),
        upstream: destination,
        key: KEY.into(),
    }]);
    let error = broker
        .execute_route(
            "github",
            BrokerRequest {
                method: HttpMethod::POST,
                path: "/v1/models".into(),
                query: None,
                headers: Vec::new(),
                body: b"too large".to_vec(),
            },
            RequestLimits {
                max_request_bytes: 1,
                max_response_bytes: 1 << 20,
            },
        )
        .unwrap_err();

    assert_eq!(error, BrokerError::RequestTooLarge);
    assert_no_request(&log);
}

#[test]
fn shared_broker_ignores_ambient_proxy_configuration() {
    const CHILD: &str = "TWL_CAPABILITY_PROXY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shared_broker_ignores_ambient_proxy_configuration",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("https_proxy", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env("no_proxy", "")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let (destination, _log) = upstream();
    let response = harness(destination, 1 << 20)
        .invoke(invocation("GET", "/v1/models"))
        .unwrap();
    assert_eq!(response.status, 200);
}

#[test]
fn response_bounds_and_secret_reflection_are_enforced_by_shared_broker() {
    let (destination, _log) = upstream();
    let bounded = harness(destination, 1);
    assert_eq!(
        bounded.invoke(invocation("GET", "/v1/models")).unwrap_err(),
        CapabilityError::ResponseTooLarge
    );

    let (destination, _log) = upstream();
    let reflection = harness(destination, 1 << 20);
    assert_eq!(
        reflection
            .invoke(invocation("GET", "/v1/echo-key"))
            .unwrap_err(),
        CapabilityError::SecretReflection
    );
}

#[test]
fn stdio_protocol_lists_invokes_denies_and_recovers_after_bad_json() {
    let (destination, log) = upstream();
    let broker = harness(destination, 1 << 20);
    let input = concat!(
        "{\"op\":\"hello\",\"protocol\":1}\n",
        "{\"id\":\"list\",\"op\":\"list\"}\n",
        "not json\n",
        "{\"id\":\"allowed\",\"op\":\"invoke\",\"capability\":\"github-read\",\"method\":\"GET\",\"path\":\"/v1/models\"}\n",
        "{\"id\":\"denied\",\"op\":\"invoke\",\"capability\":\"github-read\",\"method\":\"DELETE\",\"path\":\"/v1/models\"}\n",
    );
    let mut output = Vec::new();
    serve_stdio(broker, Cursor::new(input), &mut output).unwrap();

    let text = String::from_utf8(output).unwrap();
    let frames: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 5);
    assert_eq!(frames[0]["protocol"], 1);
    assert_eq!(frames[1]["capabilities"][0]["name"], "github-read");
    assert_eq!(frames[2]["error"]["code"], "INVALID_REQUEST");
    assert_eq!(frames[3]["status"], 200);
    assert_eq!(frames[3]["body_encoding"], "base64");
    assert_eq!(frames[4]["error"]["code"], "METHOD_DENIED");
    assert_eq!(log.lock().unwrap().len(), 1);

    for encoded in [
        KEY.to_string(),
        STANDARD.encode(KEY),
        STANDARD_NO_PAD.encode(KEY),
        URL_SAFE_NO_PAD.encode(KEY),
    ] {
        assert!(!text.contains(&encoded));
    }
}

#[test]
fn stdio_requires_versioned_handshake_and_bounds_each_line() {
    let (destination, _log) = upstream();
    let broker = harness(destination, 1 << 20);
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"id\":1,\"op\":\"list\"}\n");
    input.extend(std::iter::repeat(b'x').take(MAX_PROTOCOL_LINE_BYTES + 1));
    input.push(b'\n');
    input.extend_from_slice(b"{\"op\":\"hello\",\"protocol\":99}\n");
    input.extend_from_slice(b"{\"op\":\"hello\",\"protocol\":1}\n");
    input.extend_from_slice(b"{\"id\":2,\"op\":\"list\"}\n");
    let mut output = Vec::new();
    serve_stdio(broker, Cursor::new(input), &mut output).unwrap();

    let frames: Vec<serde_json::Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames[0]["error"]["code"], "PROTOCOL_MISMATCH");
    assert_eq!(frames[1]["error"]["code"], "REQUEST_TOO_LARGE");
    assert_eq!(frames[2]["error"]["code"], "PROTOCOL_MISMATCH");
    assert_eq!(frames[3]["ok"], true);
    assert_eq!(frames[4]["id"], 2);
}

#[test]
fn cli_canary_demo_proves_protocol_allow_and_deny_without_a_secret_store() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args(["capability", "demo", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = concat!(
        "{\"op\":\"hello\",\"protocol\":1}\n",
        "{\"id\":\"list\",\"op\":\"list\"}\n",
        "{\"id\":\"allowed\",\"op\":\"invoke\",\"capability\":\"demo-read\",\"method\":\"GET\",\"path\":\"/allowed/resource\"}\n",
        "{\"id\":\"github\",\"op\":\"invoke\",\"capability\":\"github-read\",\"method\":\"GET\",\"path\":\"/repos/luciobaiocchi/twl\"}\n",
        "{\"id\":\"method\",\"op\":\"invoke\",\"capability\":\"demo-read\",\"method\":\"DELETE\",\"path\":\"/allowed/resource\"}\n",
        "{\"id\":\"path\",\"op\":\"invoke\",\"capability\":\"demo-read\",\"method\":\"GET\",\"path\":\"/forbidden/resource\"}\n",
        "{\"id\":\"host\",\"op\":\"invoke\",\"capability\":\"demo-read\",\"method\":\"GET\",\"path\":\"/allowed/resource\",\"host\":\"evil.example\"}\n",
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let frames: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames[1]["capabilities"][0]["name"], "demo-read");
    assert_eq!(frames[2]["status"], 200);
    assert_eq!(frames[3]["status"], 200);
    let github_body = STANDARD
        .decode(frames[3]["body"].as_str().unwrap())
        .unwrap();
    assert!(String::from_utf8(github_body)
        .unwrap()
        .contains("/repos/luciobaiocchi/twl"));
    assert_eq!(frames[4]["error"]["code"], "METHOD_DENIED");
    assert_eq!(frames[5]["error"]["code"], "PATH_DENIED");
    assert_eq!(frames[6]["error"]["code"], "INVALID_REQUEST");
    let all_output = format!("{stdout}\n{}", String::from_utf8_lossy(&output.stderr));
    assert!(!all_output.contains("twl-demo-canary-"));
}

#[cfg(unix)]
#[test]
fn stdio_service_shuts_down_cleanly_on_sigterm() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_twl"))
        .args(["capability", "demo", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(b"{\"op\":\"hello\",\"protocol\":1}\n")
        .unwrap();
    stdin.flush().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut hello = String::new();
    stdout.read_line(&mut hello).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&hello).unwrap()["ok"],
        true
    );

    // SAFETY: the child pid is live and belongs to this test; SIGTERM is handled by the
    // capability service and this test retains the Child handle for cleanup.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("capability service did not exit after SIGTERM");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(status.success());
}
