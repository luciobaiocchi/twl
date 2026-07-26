use capshell::sandbox::{bwrap_usable, channels, Channels};
use std::path::{Path, PathBuf};

fn fake(vars: &[(&str, &str)], existing: &[&str]) -> Channels {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let existing: Vec<PathBuf> = existing.iter().map(PathBuf::from).collect();
    channels(
        |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
        |p: &Path| existing.iter().any(|e| e == p),
    )
}

#[test]
fn the_runtime_dir_covers_bus_and_keyring() {
    let c = fake(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        ],
        &["/run/user/1000", "/run/user/1000/bus"],
    );

    assert_eq!(c.xdg_runtime, Some(PathBuf::from("/run/user/1000")));
    assert!(
        c.sockets.is_empty(),
        "the bus sits inside the runtime dir: covering it twice is pointless"
    );
}

#[test]
fn a_bus_outside_the_runtime_dir_gets_covered_separately() {
    let c = fake(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/dbus-abc,guid=xyz",
            ),
        ],
        &["/run/user/1000", "/tmp/dbus-abc"],
    );

    assert!(c.sockets.contains(&PathBuf::from("/tmp/dbus-abc")));
}

#[test]
fn a_bus_on_an_abstract_socket_is_reported_not_closed() {
    let c = fake(
        &[(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:abstract=/tmp/dbus-Xyz,guid=1",
        )],
        &[],
    );

    // An abstract socket lives in the network namespace: the mount namespace
    // can't see it, so there's nothing to mount over. That needs saying, not hiding.
    assert!(c.abstract_bus);
    assert!(c.sockets.is_empty());
}

#[test]
fn other_credential_oracles_get_closed() {
    let c = fake(
        &[
            ("SSH_AUTH_SOCK", "/tmp/ssh-XXX/agent.42"),
            ("HOME", "/home/someone"),
        ],
        &[
            "/tmp/ssh-XXX/agent.42",
            "/home/someone/.gnupg/S.gpg-agent",
            "/var/run/docker.sock",
        ],
    );

    for expected in [
        "/tmp/ssh-XXX/agent.42",
        "/home/someone/.gnupg/S.gpg-agent",
        "/var/run/docker.sock",
    ] {
        assert!(
            c.sockets.contains(&PathBuf::from(expected)),
            "missing {expected}"
        );
    }
}

#[test]
fn what_does_not_exist_is_not_mounted() {
    let c = fake(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("SSH_AUTH_SOCK", "/tmp/never-existed"),
        ],
        &[],
    );

    assert!(c.nothing_to_close());
    assert!(c.bwrap_args().iter().all(|a| a != "--tmpfs"));
}

#[test]
fn the_arguments_confine_neither_network_nor_filesystem() {
    let c = fake(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("SSH_AUTH_SOCK", "/tmp/agent.42"),
        ],
        &["/run/user/1000", "/tmp/agent.42"],
    );
    let args = c.bwrap_args();

    assert_eq!(
        &args[..3],
        &["--dev-bind", "/", "/"],
        "the filesystem stays as-is"
    );
    assert!(
        !args.iter().any(|a| a.starts_with("--unshare")),
        "unshare-net would cut the loopback and the child couldn't reach the proxy anymore: {args:?}"
    );
    assert!(args.windows(2).any(|w| w == ["--tmpfs", "/run/user/1000"]));
    assert!(args
        .windows(3)
        .any(|w| w == ["--bind", "/dev/null", "/tmp/agent.42"]));
}

/// The test that matters: after bwrap the socket is no longer reachable by the child.
#[cfg(target_os = "linux")]
#[test]
fn bwrap_really_removes_the_socket_from_the_child() {
    let dir = std::env::temp_dir().join(format!("capshell-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bus"), b"fake bus socket").unwrap();

    let c = Channels {
        xdg_runtime: Some(dir.clone()),
        ..Default::default()
    };
    let args = c.bwrap_args();

    let Ok(()) = bwrap_usable(&args) else {
        eprintln!("bwrap not usable here: the test only verifies the fallback");
        return;
    };

    let visible = |inside: bool| {
        let mut cmd = std::process::Command::new(if inside { "bwrap" } else { "sh" });
        if inside {
            cmd.args(&args).arg("--").arg("sh");
        }
        let out = cmd
            .arg("-c")
            .arg(format!("cat {}/bus 2>/dev/null", dir.display()))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).contains("fake bus socket")
    };

    assert!(visible(false), "the file reads outside the namespace");
    assert!(
        !visible(true),
        "the file must not exist inside the namespace"
    );

    std::fs::remove_dir_all(&dir).ok();
}
