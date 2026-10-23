//! Import dal backup di andOTP (JSON in chiaro o `.json.aes` cifrato).
//!
//! Formato cifrato (andOTP ≥ 0.6.3):
//! `iterazioni u32 BE | salt(12) | nonce(12) | ciphertext | tag(16)`, con
//! `chiave = PBKDF2-HMAC-SHA1(password, salt, iterazioni, 256 bit)` e AES-256-GCM.
//! Il vecchio formato (chiave = SHA-256 della password, senza salt) non è supportato:
//! è insicuro e andOTP lo ha abbandonato.

use serde::Deserialize;

use crate::{ImportError, Imported, RawAccount, check_len, convert, crypto};

const SALT_LEN: usize = 12;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Deserialize)]
struct Entry {
    secret: String,
    issuer: Option<String>,
    label: String,
    digits: u64,
    #[serde(rename = "type")]
    kind: String,
    algorithm: String,
    period: Option<u64>,
    counter: Option<u64>,
}

/// `true` se i dati sono un backup cifrato (non iniziano con un array JSON).
#[must_use]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'[')
}

/// Importa un backup andOTP. `password` è richiesta solo per i backup cifrati.
///
/// # Errors
/// - [`ImportError::PasswordRequired`] se il backup è cifrato e manca la password;
/// - [`ImportError::Decryption`] per password errata o file manomesso;
/// - [`ImportError::InvalidFormat`], [`ImportError::TooLarge`] per file non validi.
pub fn import(data: &[u8], password: Option<&[u8]>) -> Result<Imported, ImportError> {
    check_len(data)?;
    let entries: Vec<Entry> = if is_encrypted(data) {
        let password = password.ok_or(ImportError::PasswordRequired)?;
        let plaintext = decrypt(data, password)?;
        serde_json::from_slice(&plaintext).map_err(|_| ImportError::InvalidFormat)?
    } else {
        serde_json::from_slice(data).map_err(|_| ImportError::InvalidFormat)?
    };

    let mut imported = Imported::default();
    for entry in &entries {
        // Senza `issuer`, andOTP usava l'etichetta "Issuer - Nome".
        let (issuer, name) = match &entry.issuer {
            Some(issuer) => (Some(issuer.as_str()), entry.label.as_str()),
            None => match entry.label.split_once(" - ") {
                Some((issuer, name)) => (Some(issuer), name),
                None => (None, entry.label.as_str()),
            },
        };
        imported.push(convert(&RawAccount {
            issuer,
            name,
            kind: &entry.kind,
            algorithm: &entry.algorithm,
            digits: entry.digits,
            period: entry.period,
            counter: entry.counter,
            secret_base32: &entry.secret,
        }))?;
    }
    Ok(imported)
}

fn decrypt(data: &[u8], password: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, ImportError> {
    let (iterations, rest) = data
        .split_first_chunk::<4>()
        .ok_or(ImportError::InvalidFormat)?;
    let (salt, rest) = rest
        .split_first_chunk::<SALT_LEN>()
        .ok_or(ImportError::InvalidFormat)?;
    let (nonce, ciphertext) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(ImportError::InvalidFormat)?;
    if ciphertext.len() < TAG_LEN {
        return Err(ImportError::InvalidFormat);
    }
    let key = crypto::pbkdf2_sha1(password, salt, u32::from_be_bytes(*iterations))?;
    crypto::aes_gcm_open(&key, nonce, ciphertext)
}
