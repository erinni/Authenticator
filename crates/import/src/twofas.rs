//! Import dal backup di 2FAS Authenticator (`.2fas`, schema 2–4, in chiaro o cifrato).
//!
//! Formato cifrato: `servicesEncrypted = base64(ciphertext||tag) ":" base64(salt) ":" base64(iv)`,
//! con `chiave = PBKDF2-HMAC-SHA256(password, salt, 10 000, 256 bit)` e AES-256-GCM.

use serde::Deserialize;

use crate::{ImportError, Imported, RawAccount, base64, check_len, convert, crypto};

const ITERATIONS: u32 = 10_000;
const MAX_SCHEMA: u32 = 4;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File {
    schema_version: u32,
    #[serde(default)]
    services: Vec<Service>,
    services_encrypted: Option<String>,
}

#[derive(Deserialize)]
struct Service {
    #[serde(default)]
    name: String,
    secret: String,
    otp: Otp,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Otp {
    #[serde(default)]
    account: String,
    #[serde(default)]
    issuer: String,
    digits: Option<u64>,
    period: Option<u64>,
    counter: Option<u64>,
    algorithm: Option<String>,
    token_type: Option<String>,
}

/// `true` se il backup è cifrato (serve la password).
///
/// # Errors
/// [`ImportError::InvalidFormat`] se il file non è un backup 2FAS.
pub fn is_encrypted(data: &[u8]) -> Result<bool, ImportError> {
    check_len(data)?;
    let file: File = serde_json::from_slice(data).map_err(|_| ImportError::InvalidFormat)?;
    Ok(file.services_encrypted.is_some())
}

/// Importa un backup 2FAS. `password` è richiesta solo per i backup cifrati.
///
/// # Errors
/// - [`ImportError::PasswordRequired`] se il backup è cifrato e manca la password;
/// - [`ImportError::Decryption`] per password errata o file manomesso;
/// - [`ImportError::UnsupportedVersion`], [`ImportError::InvalidFormat`],
///   [`ImportError::TooLarge`] per file non validi.
pub fn import(data: &[u8], password: Option<&[u8]>) -> Result<Imported, ImportError> {
    check_len(data)?;
    let file: File = serde_json::from_slice(data).map_err(|_| ImportError::InvalidFormat)?;
    if !(2..=MAX_SCHEMA).contains(&file.schema_version) {
        return Err(ImportError::UnsupportedVersion);
    }
    let services = match &file.services_encrypted {
        None => file.services,
        Some(encrypted) => {
            let password = password.ok_or(ImportError::PasswordRequired)?;
            let plaintext = decrypt(encrypted, password)?;
            serde_json::from_slice(&plaintext).map_err(|_| ImportError::InvalidFormat)?
        }
    };

    let mut imported = Imported::default();
    for service in &services {
        let otp = &service.otp;
        let issuer = if service.name.is_empty() {
            &otp.issuer
        } else {
            &service.name
        };
        imported.push(convert(&RawAccount {
            issuer: Some(issuer),
            name: &otp.account,
            kind: otp.token_type.as_deref().unwrap_or("TOTP"),
            algorithm: otp.algorithm.as_deref().unwrap_or("SHA1"),
            digits: otp.digits.unwrap_or(6),
            period: otp.period,
            counter: otp.counter,
            secret_base32: &service.secret,
        }))?;
    }
    Ok(imported)
}

fn decrypt(encrypted: &str, password: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, ImportError> {
    let mut parts = encrypted.split(':');
    let (Some(data), Some(salt), Some(iv)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ImportError::InvalidFormat);
    };
    let data = base64::decode(data).ok_or(ImportError::InvalidFormat)?;
    let salt = base64::decode(salt).ok_or(ImportError::InvalidFormat)?;
    let iv: [u8; 12] = base64::decode(iv)
        .and_then(|iv| iv.as_slice().try_into().ok())
        .ok_or(ImportError::InvalidFormat)?;
    let key = crypto::pbkdf2_sha256(password, &salt, ITERATIONS)?;
    crypto::aes_gcm_open(&key, &iv, &data)
}
