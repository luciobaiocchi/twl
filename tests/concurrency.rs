//! The budget increments before forwarding. With a multi-threaded proxy the
//! race is real, so the promise needs to be verified under load.
//!
//! This lives in its own file, separate from the other attacks, because
//! cargo runs each test file in its own process: under load, six proxies
//! alive in the same process would contend for resources and skew the
//! result. In production there's one proxy per process, so that's the case
//! worth measuring.

mod common;

use capshell::config::Auth;
use capshell::proxy::{self, Route};
use common::{call_with, client, upstream};
use std::collections::HashMap;

const KEY: &str = "sk-CANARY-REAL-KEY-0123456789";

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

#[test]
fn the_budget_holds_up_under_concurrent_requests() {
    const CAP: u64 = 20;
    const CLIENTS: usize = 12;
    const PER_CLIENT: usize = 10;

    let (up, log) = upstream();
    let (h, token) = proxy_on(&up, Some(CAP));
    let port = h.port;

    // Every thread must be started before we wait on any of them, or the
    // concurrency disappears and the test proves nothing. Each client reuses
    // its own connection, the way a real SDK would.
    let clients: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let token = token.clone();
            std::thread::spawn(move || {
                let agent = client();
                let path = format!("/{token}/openai/v1/models");
                (0..PER_CLIENT)
                    .filter(|_| call_with(&agent, port, "GET", &path) == 200)
                    .count()
            })
        })
        .collect();

    let outcomes: Vec<_> = clients.into_iter().map(|h| h.join()).collect();
    let accepted = h.seen.load(std::sync::atomic::Ordering::SeqCst);
    let received_upstream = log.lock().unwrap().len();
    let ok: usize = outcomes
        .into_iter()
        .map(|e| {
            e.unwrap_or_else(|_| {
                panic!(
                    "a client got no response. \
                     The proxy had accepted {accepted} of {} requests \
                     and forwarded {received_upstream} to the upstream",
                    CLIENTS * PER_CLIENT
                )
            })
        })
        .sum();

    assert_eq!(ok, CAP as usize, "exactly CAP requests must go through");
    assert_eq!(
        received_upstream, CAP as usize,
        "and the upstream must not see even one more: {received_upstream} vs {CAP}"
    );
}
