//! Generazione di codici HOTP (RFC 4226) e TOTP (RFC 6238).

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

/// Lunghezza massima del segreto OTP in byte (512 bit, come SHA-512).
pub const MAX_SECRET_LEN: usize = 64;

/// Funzione hash usata dall'HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// HMAC-SHA-1: default delle RFC e della quasi totalità dei servizi.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// Nome usato negli URI `otpauth://`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Interpreta il nome usato negli URI `otpauth://` (senza distinzione di maiuscole).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Sha1, Self::Sha256, Self::Sha512]
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(name))
    }
}

/// Numero di cifre del codice, validato (6–8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digits(u8);

impl Digits {
    /// 6 cifre: il valore più comune.
    pub const SIX: Self = Self(6);
    /// 8 cifre.
    pub const EIGHT: Self = Self(8);

    /// Valida il numero di cifre.
    ///
    /// # Errors
    /// [`Error::InvalidDigits`] se fuori da 6–8.
    pub fn new(digits: u8) -> Result<Self> {
        if (6..=8).contains(&digits) {
            Ok(Self(digits))
        } else {
            Err(Error::InvalidDigits)
        }
    }

    /// Valore numerico.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

impl Default for Digits {
    fn default() -> Self {
        Self::SIX
    }
}

/// Periodo TOTP in secondi, validato (1–300).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Period(u32);

impl Period {
    /// 30 secondi: il valore standard.
    pub const DEFAULT: Self = Self(30);

    /// Valida il periodo.
    ///
    /// # Errors
    /// [`Error::InvalidPeriod`] se fuori da 1–300 secondi.
    pub fn new(seconds: u32) -> Result<Self> {
        if (1..=300).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(Error::InvalidPeriod)
        }
    }

    /// Secondi.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl Default for Period {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Codice OTP generato. `Display` produce le cifre con gli zeri iniziali.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Code {
    value: u32,
    digits: Digits,
}

impl Code {
    /// Valore numerico (senza zeri iniziali).
    #[must_use]
    pub fn value(self) -> u32 {
        self.value
    }

    /// Numero di cifre.
    #[must_use]
    pub fn digits(self) -> Digits {
        self.digits
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:0width$}",
            self.value,
            width = usize::from(self.digits.0)
        )
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Il codice è valido pochi secondi ma resta un'informazione di autenticazione.
        write!(f, "Code([REDATTO; {} cifre])", self.digits.0)
    }
}

fn hmac_digest<M: Mac + KeyInit>(secret: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <M as KeyInit>::new_from_slice(secret).map_err(|_| Error::InvalidSecretLength)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Calcola un codice HOTP (RFC 4226).
///
/// # Errors
/// [`Error::InvalidSecretLength`] se il segreto è vuoto o più lungo di [`MAX_SECRET_LEN`].
pub fn hotp(secret: &[u8], counter: u64, algorithm: Algorithm, digits: Digits) -> Result<Code> {
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(Error::InvalidSecretLength);
    }
    let message = counter.to_be_bytes();
    let digest = zeroize::Zeroizing::new(match algorithm {
        Algorithm::Sha1 => hmac_digest::<Hmac<Sha1>>(secret, &message)?,
        Algorithm::Sha256 => hmac_digest::<Hmac<Sha256>>(secret, &message)?,
        Algorithm::Sha512 => hmac_digest::<Hmac<Sha512>>(secret, &message)?,
    });

    // Dynamic truncation (RFC 4226 §5.3). Il digest è lungo almeno 20 byte e
    // l'offset al massimo 15, quindi la finestra di 4 byte è sempre disponibile.
    let offset = usize::from(digest.last().ok_or(Error::Internal)? & 0x0f);
    let window: [u8; 4] = digest
        .get(offset..offset + 4)
        .and_then(|w| w.try_into().ok())
        .ok_or(Error::Internal)?;
    let binary = u32::from_be_bytes(window) & 0x7fff_ffff;
    let modulus = 10u32.pow(u32::from(digits.0));
    Ok(Code {
        value: binary % modulus,
        digits,
    })
}

/// Parametri di un generatore TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TotpParams {
    /// Funzione hash.
    pub algorithm: Algorithm,
    /// Numero di cifre.
    pub digits: Digits,
    /// Durata di validità di un codice.
    pub period: Period,
}

/// Codice TOTP con le informazioni sulla sua validità.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpCode {
    /// Il codice.
    pub code: Code,
    /// Secondi rimanenti prima che il codice scada.
    pub remaining_seconds: u32,
}

/// Calcola un codice TOTP (RFC 6238) per l'istante `unix_time` (secondi), con T0 = 0.
///
/// # Errors
/// Come [`hotp`].
pub fn totp(secret: &[u8], unix_time: u64, params: TotpParams) -> Result<TotpCode> {
    totp_with_epoch(secret, unix_time, 0, params)
}

/// Come [`totp`] ma con un'epoca T0 arbitraria.
///
/// # Errors
/// [`Error::TimeBeforeEpoch`] se `unix_time < t0`; altrimenti come [`hotp`].
pub fn totp_with_epoch(
    secret: &[u8],
    unix_time: u64,
    t0: u64,
    params: TotpParams,
) -> Result<TotpCode> {
    let elapsed = unix_time.checked_sub(t0).ok_or(Error::TimeBeforeEpoch)?;
    let period = u64::from(params.period.0);
    let counter = elapsed / period;
    let remaining = period - elapsed % period;
    Ok(TotpCode {
        code: hotp(secret, counter, params.algorithm, params.digits)?,
        remaining_seconds: u32::try_from(remaining).map_err(|_| Error::Internal)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    /// RFC 4226, Appendice D.
    #[test]
    fn rfc4226_vectors() {
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, value) in (0u64..).zip(expected) {
            let code = hotp(SEED_SHA1, counter, Algorithm::Sha1, Digits::SIX).unwrap();
            assert_eq!(code.value(), value, "counter {counter}");
        }
    }

    /// RFC 6238, Appendice B.
    #[test]
    fn rfc6238_vectors() {
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in cases {
            for (seed, algorithm, expected) in [
                (SEED_SHA1, Algorithm::Sha1, sha1),
                (SEED_SHA256, Algorithm::Sha256, sha256),
                (SEED_SHA512, Algorithm::Sha512, sha512),
            ] {
                let params = TotpParams {
                    algorithm,
                    digits: Digits::EIGHT,
                    period: Period::DEFAULT,
                };
                let code = totp(seed, time, params).unwrap().code;
                assert_eq!(code.to_string(), expected, "t={time} {algorithm:?}");
            }
        }
    }

    #[test]
    fn leading_zeros_are_kept() {
        let params = TotpParams {
            digits: Digits::EIGHT,
            ..TotpParams::default()
        };
        let code = totp(SEED_SHA1, 1_111_111_109, params).unwrap().code;
        assert_eq!(code.value(), 7_081_804);
        assert_eq!(code.to_string(), "07081804");
    }

    #[test]
    fn remaining_seconds() {
        let p = TotpParams::default();
        assert_eq!(totp(SEED_SHA1, 0, p).unwrap().remaining_seconds, 30);
        assert_eq!(totp(SEED_SHA1, 29, p).unwrap().remaining_seconds, 1);
        assert_eq!(totp(SEED_SHA1, 30, p).unwrap().remaining_seconds, 30);
    }

    #[test]
    fn validation() {
        assert_eq!(Digits::new(5), Err(Error::InvalidDigits));
        assert_eq!(Digits::new(9), Err(Error::InvalidDigits));
        assert_eq!(Period::new(0), Err(Error::InvalidPeriod));
        assert_eq!(
            hotp(&[], 0, Algorithm::Sha1, Digits::SIX),
            Err(Error::InvalidSecretLength)
        );
        assert_eq!(
            hotp(&[0; MAX_SECRET_LEN + 1], 0, Algorithm::Sha1, Digits::SIX),
            Err(Error::InvalidSecretLength)
        );
        assert_eq!(
            totp_with_epoch(SEED_SHA1, 10, 20, TotpParams::default()),
            Err(Error::TimeBeforeEpoch)
        );
    }

    #[test]
    fn debug_does_not_leak_code() {
        let code = hotp(SEED_SHA1, 0, Algorithm::Sha1, Digits::SIX).unwrap();
        assert!(!format!("{code:?}").contains("755224"));
    }

    #[test]
    fn algorithm_names() {
        assert_eq!(Algorithm::parse("sha256"), Some(Algorithm::Sha256));
        assert_eq!(Algorithm::parse("MD5"), None);
    }
}
