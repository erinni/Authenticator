//! Errori del core.
//!
//! I messaggi non contengono mai dati sensibili (segreti, password, contenuto del vault).

use core::fmt;

/// Errore restituito dalle operazioni del core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Il segreto Base32 non è valido.
    InvalidBase32,
    /// Il segreto OTP è vuoto o troppo lungo.
    InvalidSecretLength,
    /// Numero di cifre non supportato (ammesse 6–8).
    InvalidDigits,
    /// Periodo TOTP non valido.
    InvalidPeriod,
    /// L'orario è precedente all'epoca TOTP (T0).
    TimeBeforeEpoch,
    /// URI `otpauth://` non valido.
    InvalidUri,
    /// Parametri KDF fuori dai limiti consentiti.
    InvalidKdfParams,
    /// Formato del vault non riconosciuto o corrotto.
    InvalidFormat,
    /// Versione del vault non supportata da questa build.
    UnsupportedVersion,
    /// Decifratura fallita: credenziale errata o dati manomessi.
    ///
    /// Volutamente non distingue i due casi.
    Decryption,
    /// Nessuno slot di sblocco corrisponde alla credenziale fornita.
    NoMatchingSlot,
    /// Operazione che lascerebbe il vault senza slot di sblocco o con troppi slot.
    InvalidSlotCount,
    /// Il generatore di numeri casuali del sistema non è disponibile.
    Rng,
    /// Errore interno inatteso (violazione di un'invariante).
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidBase32 => "segreto Base32 non valido",
            Self::InvalidSecretLength => "lunghezza del segreto non valida",
            Self::InvalidDigits => "numero di cifre non supportato",
            Self::InvalidPeriod => "periodo TOTP non valido",
            Self::TimeBeforeEpoch => "orario precedente all'epoca TOTP",
            Self::InvalidUri => "URI otpauth non valido",
            Self::InvalidKdfParams => "parametri KDF non validi",
            Self::InvalidFormat => "formato del vault non valido",
            Self::UnsupportedVersion => "versione del vault non supportata",
            Self::Decryption => "decifratura fallita",
            Self::NoMatchingSlot => "nessuno slot di sblocco corrispondente",
            Self::InvalidSlotCount => "numero di slot di sblocco non valido",
            Self::Rng => "generatore casuale non disponibile",
            Self::Internal => "errore interno",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}

/// Risultato con [`Error`] del core.
pub type Result<T> = core::result::Result<T, Error>;
