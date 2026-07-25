use capshell::sandbox::{bwrap_utilizzabile, canali, Canali};
use std::path::{Path, PathBuf};

fn finto(vars: &[(&str, &str)], esistenti: &[&str]) -> Canali {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let esistenti: Vec<PathBuf> = esistenti.iter().map(PathBuf::from).collect();
    canali(
        |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
        |p: &Path| esistenti.iter().any(|e| e == p),
    )
}

#[test]
fn la_runtime_dir_copre_bus_e_keyring() {
    let c = finto(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        ],
        &["/run/user/1000", "/run/user/1000/bus"],
    );

    assert_eq!(c.xdg_runtime, Some(PathBuf::from("/run/user/1000")));
    assert!(
        c.socket.is_empty(),
        "il bus sta dentro la runtime dir: coprirlo due volte non serve"
    );
}

#[test]
fn un_bus_fuori_dalla_runtime_dir_viene_coperto_a_parte() {
    let c = finto(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/dbus-abc,guid=xyz",
            ),
        ],
        &["/run/user/1000", "/tmp/dbus-abc"],
    );

    assert!(c.socket.contains(&PathBuf::from("/tmp/dbus-abc")));
}

#[test]
fn il_bus_su_socket_astratto_viene_segnalato_non_chiuso() {
    let c = finto(
        &[(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:abstract=/tmp/dbus-Xyz,guid=1",
        )],
        &[],
    );

    // Un socket astratto vive nel network namespace: il mount namespace non lo
    // vede, quindi non c'e' niente da montarci sopra. Va detto, non nascosto.
    assert!(c.bus_astratto);
    assert!(c.socket.is_empty());
}

#[test]
fn gli_altri_oracoli_di_credenziali_vengono_chiusi() {
    let c = finto(
        &[
            ("SSH_AUTH_SOCK", "/tmp/ssh-XXX/agent.42"),
            ("HOME", "/home/tizio"),
        ],
        &[
            "/tmp/ssh-XXX/agent.42",
            "/home/tizio/.gnupg/S.gpg-agent",
            "/var/run/docker.sock",
        ],
    );

    for atteso in [
        "/tmp/ssh-XXX/agent.42",
        "/home/tizio/.gnupg/S.gpg-agent",
        "/var/run/docker.sock",
    ] {
        assert!(c.socket.contains(&PathBuf::from(atteso)), "manca {atteso}");
    }
}

#[test]
fn cio_che_non_esiste_non_viene_montato() {
    let c = finto(
        &[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("SSH_AUTH_SOCK", "/tmp/mai-esistito"),
        ],
        &[],
    );

    assert!(c.nulla_da_chiudere());
    assert!(c.bwrap_args().iter().all(|a| a != "--tmpfs"));
}

#[test]
fn gli_argomenti_non_confinano_ne_la_rete_ne_il_filesystem() {
    let c = finto(
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
        "il filesystem resta com'e'"
    );
    assert!(
        !args.iter().any(|a| a.starts_with("--unshare")),
        "unshare-net taglierebbe il loopback e il figlio non arriverebbe piu' al proxy: {args:?}"
    );
    assert!(args.windows(2).any(|w| w == ["--tmpfs", "/run/user/1000"]));
    assert!(args
        .windows(3)
        .any(|w| w == ["--bind", "/dev/null", "/tmp/agent.42"]));
}

/// Il test che conta: dopo bwrap il socket non e' piu' raggiungibile dal figlio.
#[cfg(target_os = "linux")]
#[test]
fn bwrap_toglie_davvero_il_socket_al_figlio() {
    let dir = std::env::temp_dir().join(format!("capshell-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bus"), b"finto socket del bus").unwrap();

    let c = Canali {
        xdg_runtime: Some(dir.clone()),
        ..Default::default()
    };
    let args = c.bwrap_args();

    let Ok(()) = bwrap_utilizzabile(&args) else {
        eprintln!("bwrap non utilizzabile qui: il test verifica solo il fallback");
        return;
    };

    let visibile = |dentro: bool| {
        let mut cmd = std::process::Command::new(if dentro { "bwrap" } else { "sh" });
        if dentro {
            cmd.args(&args).arg("--").arg("sh");
        }
        let out = cmd
            .arg("-c")
            .arg(format!("cat {}/bus 2>/dev/null", dir.display()))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).contains("finto socket")
    };

    assert!(visibile(false), "fuori dal namespace il file si legge");
    assert!(
        !visibile(true),
        "dentro il namespace il file non deve esistere"
    );

    std::fs::remove_dir_all(&dir).ok();
}
