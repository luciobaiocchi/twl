use rand::distributions::Alphanumeric;
use rand::Rng;

const SERVICE: &str = "capshell";

/// Il mock deve avere il formato del provider: diversi SDK validano prefisso e
/// lunghezza prima di chiamare, e un placeholder generico produce errori
/// incomprensibili invece di una richiesta che arriva al proxy.
pub fn mock(prefix: &str) -> String {
    let tail: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect();
    format!("{prefix}capshell{tail}")
}

// macOS e Windows: si passa dalla libreria, non dalla riga di comando. Su macOS
// e' obbligatorio, perche' la ACL del Keychain e' legata alla firma del binario
// che chiede: invocando `/usr/bin/security` la garanzia si attaccherebbe a
// quello, e qualunque processo potrebbe ottenerla.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn get(name: &str) -> Result<String, String> {
    keyring::Entry::new(SERVICE, name)
        .and_then(|e| e.get_password())
        .map_err(|e| format!("portachiavi, {name}: {e}"))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn set(name: &str, value: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, name)
        .and_then(|e| e.set_password(value))
        .map_err(|e| format!("portachiavi, {name}: {e}"))
}

// Linux: si chiama `secret-tool`, lo stesso portachiavi visto da riga di
// comando. La libreria Rust equivalente costa 79 crate per parlare D-Bus e non
// comprerebbe nessuna garanzia in piu': il Secret Service autorizza per utente,
// non per applicazione, quindi la barriera verso l'agente la mette comunque il
// mount namespace di `sandbox`. Qui al portachiavi resta un solo mestiere,
// tenere il valore cifrato a riposo, e per quello la CLI basta.
#[cfg(target_os = "linux")]
pub fn get(name: &str) -> Result<String, String> {
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "service", SERVICE, "account", name])
        .output()
        .map_err(|_| manca_secret_tool())?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(format!("{name} non e' nel portachiavi{}", senza_sessione()));
    }
    let mut valore =
        String::from_utf8(out.stdout).map_err(|_| "valore non testuale".to_string())?;
    if valore.ends_with('\n') {
        valore.pop();
    }
    Ok(valore)
}

#[cfg(target_os = "linux")]
pub fn set(name: &str, value: &str) -> Result<(), String> {
    use std::io::Write;

    let mut figlio = std::process::Command::new("secret-tool")
        .args(["store", "--label", &format!("capshell: {name}")])
        .args(["service", SERVICE, "account", name])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| manca_secret_tool())?;

    // Il valore passa da una pipe, mai da argv: `ps` non deve poterlo vedere.
    figlio
        .stdin
        .take()
        .expect("stdin richiesta")
        .write_all(value.as_bytes())
        .map_err(|e| e.to_string())?;

    match figlio.wait().map_err(|e| e.to_string())? {
        s if s.success() => Ok(()),
        s => Err(format!("secret-tool store: {s}{}", senza_sessione())),
    }
}

#[cfg(target_os = "linux")]
fn manca_secret_tool() -> String {
    "secret-tool non trovato: `apt install libsecret-tools`, oppure usa --env".into()
}

/// Il portachiavi vive sul bus D-Bus di sessione, che esiste solo con una
/// sessione desktop aperta. Via SSH, in container o in CI non c'e', e l'errore
/// della CLI da solo non dice all'utente cosa fare.
#[cfg(target_os = "linux")]
fn senza_sessione() -> &'static str {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        "\n  (nessuna sessione D-Bus: via SSH, in container o in CI usa --env)"
    } else {
        ""
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn get(_name: &str) -> Result<String, String> {
    let _ = SERVICE;
    Err("nessun portachiavi su questa piattaforma: usa --env".into())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn set(_name: &str, _value: &str) -> Result<(), String> {
    Err("nessun portachiavi su questa piattaforma".into())
}

/// Parser minimo di un file .env: `KEY=value`, commenti con `#`, apici opzionali.
pub fn parse_env_file(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("export ").unwrap_or(l).split_once('='))
        .map(|(k, v)| {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            (k.trim().to_string(), v.to_string())
        })
        .collect()
}

/// Sostituisce nel testo del .env i valori dichiarati con i loro placeholder.
/// Il file smette di contenere segreti e puo' anche finire in git.
pub fn rewrite_env_file(raw: &str, replacements: &[(String, String)]) -> String {
    raw.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
            match body.split_once('=') {
                Some((k, _)) => match replacements.iter().find(|(n, _)| n == k.trim()) {
                    Some((_, placeholder)) => {
                        let indent = &line[..line.len() - trimmed.len()];
                        let kw = if trimmed.starts_with("export ") {
                            "export "
                        } else {
                            ""
                        };
                        format!("{indent}{kw}{}={placeholder}", k.trim())
                    }
                    None => line.to_string(),
                },
                None => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
