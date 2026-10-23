//! Import dall'export di Aegis Authenticator (JSON, in chiaro o cifrato).
//!
//! Formato cifrato: la chiave master (AES-256) è avvolta in uno o più slot.
//! Per gli slot password: `KEK = scrypt(password UTF-8, salt, n, r, p)`,
//! `master = AES-256-GCM(KEK, key_params.nonce, key || key_params.tag)`.
//! Il database è `AES-256-GCM(master, header.params.nonce, base64(db) || header.params.tag)`.

use serde::Deserialize;

use crate::{ImportError, Imported, RawAccount, base64, check_len, convert, crypto, hex};

const SLOT_PASSWORD: u8 = 1;

#[derive(Deserialize)]
struct File {
    version: u32,
    header: Header,
    db: serde_json::Value,
}

#[derive(Deserialize)]
struct Header {
    slots: Option<Vec<Slot>>,
    params: Option<CryptParams>,
}

#[derive(Deserialize)]
struct CryptParams {
    nonce: String,
    tag: String,
}

#[derive(Deserialize)]
struct Slot {
    #[serde(rename = "type")]
    kind: u8,
    key: String,
    key_params: CryptParams,
    n: Option<u64>,
    r: Option<u32>,
    p: Option<u32>,
    salt: Option<String>,
}

#[derive(Deserialize)]
struct Db {
    version: u32,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    #[serde(default)]
    issuer: String,
    info: Info,
}

#[derive(Deserialize)]
struct Info {
    secret: String,
    algo: String,
    digits: u64,
    period: Option<u64>,
    counter: Option<u64>,
}

/// `true` se il file è un export cifrato (serve la password).
///
/// # Errors
/// [`ImportError::InvalidFormat`] se il file non è un export Aegis.
pub fn is_encrypted(data: &[u8]) -> Result<bool, ImportError> {
    check_len(data)?;
    let file: File = serde_json::from_slice(data).map_err(|_| ImportError::InvalidFormat)?;
    Ok(file.header.slots.is_some())
}

/// Importa un export Aegis. `password` è richiesta solo per i file cifrati.
///
/// # Errors
/// - [`ImportError::PasswordRequired`] se il file è cifrato e manca la password;
/// - [`ImportError::Decryption`] per password errata o file manomesso;
/// - [`ImportError::UnsupportedVersion`], [`ImportError::InvalidFormat`],
///   [`ImportError::TooLarge`] per file non validi.
pub fn import(data: &[u8], password: Option<&[u8]>) -> Result<Imported, ImportError> {
    check_len(data)?;
    let file: File = serde_json::from_slice(data).map_err(|_| ImportError::InvalidFormat)?;
    if file.version != 1 {
        return Err(ImportError::UnsupportedVersion);
    }
    let db: Db = match (file.header.slots, file.header.params) {
        (None, None) => serde_json::from_value(file.db).map_err(|_| ImportError::InvalidFormat)?,
        (Some(slots), Some(params)) => {
            let password = password.ok_or(ImportError::PasswordRequired)?;
            let master = unlock_master_key(&slots, password)?;
            let ciphertext = file.db.as_str().ok_or(ImportError::InvalidFormat)?;
            let plaintext = decrypt_with_tag(&master, &params, ciphertext, base64::decode)?;
            serde_json::from_slice(&plaintext).map_err(|_| ImportError::InvalidFormat)?
        }
        _ => return Err(ImportError::InvalidFormat),
    };
    if db.version > 3 {
        return Err(ImportError::UnsupportedVersion);
    }

    let mut imported = Imported::default();
    for entry in &db.entries {
        imported.push(convert(&RawAccount {
            issuer: Some(&entry.issuer),
            name: &entry.name,
            kind: &entry.kind,
            algorithm: &entry.info.algo,
            digits: entry.info.digits,
            period: entry.info.period,
            counter: entry.info.counter,
            secret_base32: &entry.info.secret,
        }))?;
    }
    Ok(imported)
}

/// Decifra `ciphertext` (codificato con `decode`) concatenandogli il tag dei parametri.
fn decrypt_with_tag(
    key: &[u8; 32],
    params: &CryptParams,
    ciphertext: &str,
    decode: fn(&str) -> Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ImportError> {
    let nonce: [u8; 12] = hex::decode_array(&params.nonce).ok_or(ImportError::InvalidFormat)?;
    let tag: [u8; 16] = hex::decode_array(&params.tag).ok_or(ImportError::InvalidFormat)?;
    let mut data = decode(ciphertext).ok_or(ImportError::InvalidFormat)?;
    data.extend_from_slice(&tag);
    crypto::aes_gcm_open(key, &nonce, &data)
}

fn unlock_master_key(slots: &[Slot], password: &[u8]) -> Result<crypto::Key, ImportError> {
    let mut found = false;
    for slot in slots.iter().filter(|s| s.kind == SLOT_PASSWORD) {
        found = true;
        let (Some(n), Some(r), Some(p), Some(salt)) = (slot.n, slot.r, slot.p, &slot.salt) else {
            return Err(ImportError::InvalidFormat);
        };
        let salt = hex::decode(salt).ok_or(ImportError::InvalidFormat)?;
        let kek = crypto::scrypt(password, &salt, n, r, p)?;
        match decrypt_with_tag(&kek, &slot.key_params, &slot.key, hex::decode) {
            Ok(master) => {
                let key: [u8; 32] = master
                    .as_slice()
                    .try_into()
                    .map_err(|_| ImportError::InvalidFormat)?;
                return Ok(zeroize::Zeroizing::new(key));
            }
            Err(ImportError::Decryption) => {}
            Err(e) => return Err(e),
        }
    }
    // Nessuno slot password (es. solo biometria): il file non è importabile con una password.
    Err(if found {
        ImportError::Decryption
    } else {
        ImportError::InvalidFormat
    })
}
