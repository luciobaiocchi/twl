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

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn get(_name: &str) -> Result<String, String> {
    let _ = SERVICE;
    Err("il portachiavi arriva in M1 su questa piattaforma: usa --env".into())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn set(_name: &str, _value: &str) -> Result<(), String> {
    Err("il portachiavi arriva in M1 su questa piattaforma".into())
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
