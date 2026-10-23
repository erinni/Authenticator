//! Import degli account da altri authenticator
//! (Google Authenticator, Aegis, 2FAS, andOTP, …).
//!
//! Ogni parser riceve input non fidato: nessun `unsafe`, limiti di dimensione
//! espliciti, validazione completa tramite [`authenticator_core::OtpAccount::new`].

mod base64;
pub mod google;
mod protobuf;

use core::fmt;

/// Errore di import. Non contiene mai dati dell'input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportError {
    /// Il formato non è riconosciuto o è malformato.
    InvalidFormat,
    /// L'input supera le dimensioni massime consentite.
    TooLarge,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "formato di import non valido",
            Self::TooLarge => "dati di import troppo grandi",
        })
    }
}

impl core::error::Error for ImportError {}
