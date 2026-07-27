use crate::policy::VaultPayload;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const FORMAT: &str = "towel-encrypted-vault";
const VERSION: u32 = 1;
const KDF_ALGORITHM: &str = "argon2id";
const CIPHER_ALGORITHM: &str = "xchacha20poly1305";
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const MAX_VAULT_BYTES: u64 = 16 << 20;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    version: u32,
    kdf: KdfHeader,
    cipher: Ciphertext,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfHeader {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ciphertext {
    algorithm: String,
    nonce: String,
    data: String,
}

pub fn seal(payload: &VaultPayload, password: &str) -> Result<Vec<u8>, String> {
    validate_password(password)?;
    payload.validate()?;

    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let kdf = KdfHeader {
        algorithm: KDF_ALGORITHM.into(),
        memory_kib: ARGON_MEMORY_KIB,
        iterations: ARGON_ITERATIONS,
        parallelism: ARGON_PARALLELISM,
        salt: URL_SAFE_NO_PAD.encode(salt),
    };
    let key = derive_key(password, &salt)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(payload)
            .map_err(|_| "vault payload could not be encoded".to_string())?,
    );
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "vault cipher could not be initialized".to_string())?;
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &associated_data(&kdf),
            },
        )
        .map_err(|_| "vault payload could not be encrypted".to_string())?;
    let envelope = Envelope {
        format: FORMAT.into(),
        version: VERSION,
        kdf,
        cipher: Ciphertext {
            algorithm: CIPHER_ALGORITHM.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            data: URL_SAFE_NO_PAD.encode(encrypted),
        },
    };
    let mut encoded = serde_json::to_vec_pretty(&envelope)
        .map_err(|_| "vault envelope could not be encoded".to_string())?;
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn open(encoded: &[u8], password: &str) -> Result<VaultPayload, String> {
    validate_password(password)?;
    open_inner(encoded, password).map_err(|_| "vault could not be opened".to_string())
}

fn open_inner(encoded: &[u8], password: &str) -> Result<VaultPayload, ()> {
    if encoded.len() as u64 > MAX_VAULT_BYTES {
        return Err(());
    }
    let envelope: Envelope = serde_json::from_slice(encoded).map_err(|_| ())?;
    if envelope.format != FORMAT
        || envelope.version != VERSION
        || envelope.kdf.algorithm != KDF_ALGORITHM
        || envelope.kdf.memory_kib != ARGON_MEMORY_KIB
        || envelope.kdf.iterations != ARGON_ITERATIONS
        || envelope.kdf.parallelism != ARGON_PARALLELISM
        || envelope.cipher.algorithm != CIPHER_ALGORITHM
    {
        return Err(());
    }
    let salt = URL_SAFE_NO_PAD.decode(&envelope.kdf.salt).map_err(|_| ())?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&envelope.cipher.nonce)
        .map_err(|_| ())?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.cipher.data)
        .map_err(|_| ())?;
    if salt.len() != SALT_BYTES || nonce.len() != NONCE_BYTES || ciphertext.is_empty() {
        return Err(());
    }

    let key = derive_key(password, &salt).map_err(|_| ())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| ())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &associated_data(&envelope.kdf),
                },
            )
            .map_err(|_| ())?,
    );
    let payload: VaultPayload = serde_json::from_slice(plaintext.as_ref()).map_err(|_| ())?;
    payload.validate().map_err(|_| ())?;
    Ok(payload)
}

pub fn load(path: &Path, password: &str) -> Result<VaultPayload, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("opening vault {}: {error}", path.display()))?;
    let mut encoded = Vec::new();
    (&mut file)
        .take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| format!("reading vault {}: {error}", path.display()))?;
    if encoded.len() as u64 > MAX_VAULT_BYTES {
        return Err("vault could not be opened".into());
    }
    open(&encoded, password)
}

/// Persist a new vault without ever replacing an existing target.
pub fn write_new(path: &Path, encoded: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("vault output path must name a file")?;
    if path.exists() {
        return Err(format!("vault already exists: {}", path.display()));
    }

    let temporary = temporary_path(parent, file_name);
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("creating vault {}: {error}", path.display()))?;
        file.write_all(encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("writing vault {}: {error}", path.display()))?;
        std::fs::hard_link(&temporary, path)
            .map_err(|error| format!("installing vault {}: {error}", path.display()))?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
    let parameters = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
        Some(KEY_BYTES),
    )
    .map_err(|_| "vault KDF parameters are invalid".to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| "vault key could not be derived".to_string())?;
    Ok(key)
}

fn associated_data(kdf: &KdfHeader) -> Vec<u8> {
    format!(
        "{FORMAT}|{VERSION}|{}|{}|{}|{}|{}|{CIPHER_ALGORITHM}",
        kdf.algorithm, kdf.memory_kib, kdf.iterations, kdf.parallelism, kdf.salt
    )
    .into_bytes()
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        Err("vault password must not be empty".into())
    } else {
        Ok(())
    }
}

fn temporary_path(parent: &Path, file_name: &str) -> PathBuf {
    let mut random = [0u8; 12];
    OsRng.fill_bytes(&mut random);
    parent.join(format!(
        ".{file_name}.tmp-{}",
        URL_SAFE_NO_PAD.encode(random)
    ))
}
