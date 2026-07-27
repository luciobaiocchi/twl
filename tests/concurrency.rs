mod common;

use common::{call_with, client, grant, granted_route, upstream};
use std::sync::{Arc, Barrier};
use twl::proxy;

#[test]
fn concurrent_route_budget_is_reserved_before_forwarding() {
    const CLIENTS: usize = 12;
    const BUDGET: u64 = 5;

    let (upstream, log) = upstream();
    let mut route = granted_route("application", &upstream, "project-canary");
    route.policy.request_count_budget = BUDGET;
    let handle = proxy::spawn(grant(vec![route])).unwrap();
    let port = handle.port;
    let path = format!("/{}/application/v1/models", handle.token);
    let barrier = Arc::new(Barrier::new(CLIENTS));

    let workers: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                call_with(&client(), port, "GET", &path, &[], &[]).0
            })
        })
        .collect();
    let statuses: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();

    assert_eq!(
        statuses.iter().filter(|status| **status == 200).count(),
        BUDGET as usize
    );
    assert_eq!(
        statuses.iter().filter(|status| **status == 429).count(),
        CLIENTS - BUDGET as usize
    );
    assert_eq!(log.lock().unwrap().len(), BUDGET as usize);
}

#[test]
fn route_concurrency_is_capped() {
    const CLIENTS: usize = 8;

    let (upstream, log) = upstream();
    let mut route = granted_route("application", &upstream, "project-canary");
    route.policy.max_concurrent_requests = 2;
    let handle = proxy::spawn(grant(vec![route])).unwrap();
    let port = handle.port;
    let path = format!("/{}/application/slow", handle.token);
    let barrier = Arc::new(Barrier::new(CLIENTS));

    let workers: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                call_with(&client(), port, "GET", &path, &[], &[]).0
            })
        })
        .collect();
    let statuses: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();

    assert_eq!(statuses.iter().filter(|status| **status == 200).count(), 2);
    assert_eq!(statuses.iter().filter(|status| **status == 503).count(), 6);
    assert_eq!(log.lock().unwrap().len(), 2);
}
