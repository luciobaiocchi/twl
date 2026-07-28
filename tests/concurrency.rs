mod common;

use common::{call_with, client, upstream};
use twl::proxy::{self, Route};

#[test]
fn concurrent_budget_is_reserved_before_forwarding() {
    const CLIENTS: usize = 12;
    const BUDGET: u64 = 5;

    let (upstream, log) = upstream();
    let handle = proxy::spawn(
        vec![Route {
            name: "application".into(),
            upstream,
            key: "project-canary".into(),
        }],
        Some(BUDGET),
    )
    .unwrap();
    let port = handle.port;
    let path = format!("/{}/application/v1/models", handle.token);

    let workers: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || call_with(&client(), port, "GET", &path, &[]).0)
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
