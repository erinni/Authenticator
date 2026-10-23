//! Import degli account da altri authenticator
//! (Google Authenticator, Aegis, 2FAS, andOTP).
//!
//! Ogni parser riceve input non fidato: nessun `unsafe`, limiti di dimensione
//! espliciti, parametri delle KDF limitati, validazione completa tramite
//! [`authenticator_core::OtpAccount::new`].

pub mod aegis;
pub mod andotp;
mod base64;
mod crypto;
pub mod google;
mod hex;
mod protobuf;
pub mod qr;
pub mod twofas;

use core::fmt;

use authenticator_core::otp::{Algorithm, Digits, Period};
use authenticator_core::{OtpAccount, OtpKind, SecretBytes, base32};

/// Dimensione massima di un file di esportazione.
pub const MAX_FILE_LEN: usize = 10 * 1024 * 1024;
/// Numero massimo di account in un file.
pub const MAX_ACCOUNTS: usize = 10_000;

/// Errore di import. Non contiene mai dati dell'input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportError {
    /// Il formato non è riconosciuto o è malformato.
    InvalidFormat,
    /// L'input supera le dimensioni massime consentite.
    TooLarge,
    /// Versione del formato non supportata.
    UnsupportedVersion,
    /// Il file è cifrato: serve la password.
    PasswordRequired,
    /// Password errata o file manomesso.
    Decryption,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "formato di import non valido",
            Self::TooLarge => "dati di import troppo grandi",
            Self::UnsupportedVersion => "versione del formato non supportata",
            Self::PasswordRequired => "il file è cifrato: serve la password",
            Self::Decryption => "password errata o file danneggiato",
        })
    }
}

impl core::error::Error for ImportError {}

/// Risultato di un import da file.
#[derive(Debug, Default)]
pub struct Imported {
    /// Account importati correttamente.
    pub accounts: Vec<OtpAccount>,
    /// Account presenti ma non importabili (tipo non supportato, es. Steam, o dati non validi).
    pub skipped: usize,
}

impl Imported {
    fn push(&mut self, account: Option<OtpAccount>) -> Result<(), ImportError> {
        if self.accounts.len() + self.skipped >= MAX_ACCOUNTS {
            return Err(ImportError::TooLarge);
        }
        match account {
            Some(account) => self.accounts.push(account),
            None => self.skipped += 1,
        }
        Ok(())
    }
}

fn check_len(data: &[u8]) -> Result<(), ImportError> {
    if data.len() > MAX_FILE_LEN {
        Err(ImportError::TooLarge)
    } else {
        Ok(())
    }
}

/// Campi comuni a tutti i formati JSON, già estratti.
struct RawAccount<'a> {
    issuer: Option<&'a str>,
    name: &'a str,
    /// "totp" / "hotp" (senza distinzione di maiuscole); altri tipi vengono saltati.
    kind: &'a str,
    algorithm: &'a str,
    digits: u64,
    period: Option<u64>,
    counter: Option<u64>,
    secret_base32: &'a str,
}

/// Converte un account; `None` se il tipo o i parametri non sono supportati.
fn convert(raw: &RawAccount<'_>) -> Option<OtpAccount> {
    let algorithm = Algorithm::parse(raw.algorithm)?;
    let digits = Digits::new(u8::try_from(raw.digits).ok()?).ok()?;
    let kind = if raw.kind.eq_ignore_ascii_case("totp") {
        let period = match raw.period {
            Some(p) => Period::new(u32::try_from(p).ok()?).ok()?,
            None => Period::default(),
        };
        OtpKind::Totp { period }
    } else if raw.kind.eq_ignore_ascii_case("hotp") {
        OtpKind::Hotp {
            counter: raw.counter.unwrap_or(0),
        }
    } else {
        return None;
    };
    let secret = SecretBytes::new(base32::decode(raw.secret_base32).ok()?.to_vec());
    OtpAccount::new(raw.issuer, raw.name, kind, algorithm, digits, secret).ok()
}
