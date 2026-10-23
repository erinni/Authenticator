//! Account OTP e URI `otpauth://` (formato "Key Uri Format" di Google Authenticator).

use crate::base32;
use crate::error::{Error, Result};
use crate::otp::{self, Algorithm, Code, Digits, Period, TotpCode, TotpParams};
use crate::secret::SecretBytes;

/// Lunghezza massima di un URI accettato.
pub const MAX_URI_LEN: usize = 4096;
/// Lunghezza massima (in caratteri) di issuer e nome account.
pub const MAX_LABEL_CHARS: usize = 256;

/// Tipo di generatore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    /// Basato sul tempo (RFC 6238).
    Totp {
        /// Periodo di validità del codice.
        period: Period,
    },
    /// Basato su contatore (RFC 4226).
    Hotp {
        /// Prossimo valore del contatore da usare.
        counter: u64,
    },
}

/// Un account OTP con il suo segreto.
#[derive(Debug, PartialEq, Eq)]
pub struct OtpAccount {
    /// Servizio che emette il codice (es. "GitHub").
    pub issuer: Option<String>,
    /// Nome dell'account presso il servizio (es. email o username).
    pub name: String,
    /// TOTP o HOTP.
    pub kind: OtpKind,
    /// Funzione hash.
    pub algorithm: Algorithm,
    /// Numero di cifre.
    pub digits: Digits,
    /// Segreto condiviso (seed).
    pub secret: SecretBytes,
}

impl OtpAccount {
    /// Codice TOTP all'istante `unix_time`.
    ///
    /// # Errors
    /// [`Error::InvalidUri`] se l'account è HOTP; altrimenti come [`otp::totp`].
    pub fn totp_at(&self, unix_time: u64) -> Result<TotpCode> {
        match self.kind {
            OtpKind::Totp { period } => otp::totp(
                self.secret.expose(),
                unix_time,
                TotpParams {
                    algorithm: self.algorithm,
                    digits: self.digits,
                    period,
                },
            ),
            OtpKind::Hotp { .. } => Err(Error::InvalidUri),
        }
    }

    /// Codice HOTP per il contatore corrente; incrementa il contatore.
    ///
    /// # Errors
    /// [`Error::InvalidUri`] se l'account è TOTP; altrimenti come [`otp::hotp`].
    pub fn next_hotp(&mut self) -> Result<Code> {
        match &mut self.kind {
            OtpKind::Hotp { counter } => {
                let code = otp::hotp(self.secret.expose(), *counter, self.algorithm, self.digits)?;
                *counter = counter.checked_add(1).ok_or(Error::Internal)?;
                Ok(code)
            }
            OtpKind::Totp { .. } => Err(Error::InvalidUri),
        }
    }

    /// Interpreta un URI `otpauth://totp/...` o `otpauth://hotp/...`.
    ///
    /// # Errors
    /// [`Error::InvalidUri`] per URI malformati, parametri duplicati o testo con caratteri
    /// di controllo; errori specifici per segreto, cifre o periodo non validi.
    pub fn from_uri(uri: &str) -> Result<Self> {
        if uri.len() > MAX_URI_LEN {
            return Err(Error::InvalidUri);
        }
        let rest = strip_prefix_ignore_case(uri, "otpauth://").ok_or(Error::InvalidUri)?;
        let (kind_str, rest) = rest.split_once('/').ok_or(Error::InvalidUri)?;
        let (label, query) = rest.split_once('?').ok_or(Error::InvalidUri)?;
        if query.contains('#') {
            return Err(Error::InvalidUri);
        }

        let params = parse_query(query)?;
        let get = |key: &str| {
            params
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

        let secret =
            SecretBytes::new(base32::decode(get("secret").ok_or(Error::InvalidUri)?)?.to_vec());
        if secret.is_empty() || secret.len() > otp::MAX_SECRET_LEN {
            return Err(Error::InvalidSecretLength);
        }
        let algorithm = match get("algorithm") {
            Some(a) => Algorithm::parse(a).ok_or(Error::InvalidUri)?,
            None => Algorithm::default(),
        };
        let digits = match get("digits") {
            Some(d) => Digits::new(d.parse().map_err(|_| Error::InvalidDigits)?)?,
            None => Digits::default(),
        };
        let kind = if kind_str.eq_ignore_ascii_case("totp") {
            let period = match get("period") {
                Some(p) => Period::new(p.parse().map_err(|_| Error::InvalidPeriod)?)?,
                None => Period::default(),
            };
            OtpKind::Totp { period }
        } else if kind_str.eq_ignore_ascii_case("hotp") {
            let counter = get("counter").ok_or(Error::InvalidUri)?;
            OtpKind::Hotp {
                counter: counter.parse().map_err(|_| Error::InvalidUri)?,
            }
        } else {
            return Err(Error::InvalidUri);
        };

        let label = percent_decode(label, false)?;
        reject_unsafe_chars(&label)?;
        if let Some(issuer) = get("issuer") {
            reject_unsafe_chars(issuer)?;
        }
        let (label_issuer, name) = match label.split_once(':') {
            Some((issuer, name)) => (Some(issuer.trim().to_owned()), name.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };
        // Il parametro `issuer` prevale sul prefisso dell'etichetta.
        let issuer = get("issuer")
            .map(|i| i.trim().to_owned())
            .or(label_issuer)
            .filter(|i| !i.is_empty());

        if name.is_empty() && issuer.is_none() {
            return Err(Error::InvalidUri);
        }
        if issuer
            .iter()
            .chain(core::iter::once(&name))
            .any(|t| t.chars().count() > MAX_LABEL_CHARS)
        {
            return Err(Error::InvalidUri);
        }

        Ok(Self {
            issuer,
            name,
            kind,
            algorithm,
            digits,
            secret,
        })
    }

    /// Esporta l'account come URI `otpauth://`.
    ///
    /// Il risultato contiene il segreto in chiaro: va mostrato o copiato solo dopo
    /// una ri-autenticazione esplicita dell'utente.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let (kind, extra) = match self.kind {
            OtpKind::Totp { period } => ("totp", format!("&period={}", period.get())),
            OtpKind::Hotp { counter } => ("hotp", format!("&counter={counter}")),
        };
        let label = match &self.issuer {
            Some(issuer) => format!("{}:{}", percent_encode(issuer), percent_encode(&self.name)),
            None => percent_encode(&self.name),
        };
        let issuer_param = self
            .issuer
            .as_ref()
            .map(|i| format!("&issuer={}", percent_encode(i)))
            .unwrap_or_default();
        format!(
            "otpauth://{kind}/{label}?secret={}{issuer_param}&algorithm={}&digits={}{extra}",
            base32::encode(self.secret.expose()),
            self.algorithm.as_str(),
            self.digits.get(),
        )
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| s.get(prefix.len()..))
        .flatten()
}

fn parse_query(query: &str) -> Result<Vec<(String, String)>> {
    let mut params: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key, true)?.to_ascii_lowercase();
        // Parametri duplicati: ambiguità sfruttabile (es. due `secret`), quindi rifiutati.
        if params.iter().any(|(k, _)| *k == key) {
            return Err(Error::InvalidUri);
        }
        params.push((key, percent_decode(value, true)?));
    }
    Ok(params)
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodifica percent-encoding; nella query `+` vale spazio.
fn percent_decode(input: &str, plus_as_space: bool) -> Result<String> {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = bytes.next().and_then(hex_value).ok_or(Error::InvalidUri)?;
                let lo = bytes.next().and_then(hex_value).ok_or(Error::InvalidUri)?;
                out.push(hi << 4 | lo);
            }
            b'+' if plus_as_space => out.push(b' '),
            _ => out.push(b),
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidUri)
}

fn percent_encode(input: &str) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(b));
        } else {
            // Scrivere su una String non fallisce.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Rifiuta caratteri di controllo e override bidirezionali, usabili per falsificare
/// il nome mostrato all'utente (es. "Bank\u{202E}moc.liamg").
fn reject_unsafe_chars(text: &str) -> Result<()> {
    let is_bidi_control = |c: char| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}');
    if text.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        return Err(Error::InvalidUri);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_google_example() {
        let a = OtpAccount::from_uri(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(a.issuer.as_deref(), Some("Example"));
        assert_eq!(a.name, "alice@google.com");
        assert_eq!(
            a.kind,
            OtpKind::Totp {
                period: Period::DEFAULT
            }
        );
        assert_eq!(a.algorithm, Algorithm::Sha1);
        assert_eq!(a.digits, Digits::SIX);
        assert_eq!(a.secret.expose(), b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn parses_all_parameters_and_encoding() {
        let a = OtpAccount::from_uri(
            "OTPAUTH://totp/ACME%20Co%3Ajohn.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\
             &issuer=ACME+Co&algorithm=sha512&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(a.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(a.name, "john.doe@email.com");
        assert_eq!(a.algorithm, Algorithm::Sha512);
        assert_eq!(a.digits, Digits::EIGHT);
        assert_eq!(
            a.kind,
            OtpKind::Totp {
                period: Period::new(60).unwrap()
            }
        );
    }

    #[test]
    fn hotp_counter_increments() {
        let mut a = OtpAccount::from_uri(
            "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0",
        )
        .unwrap();
        assert_eq!(a.next_hotp().unwrap().to_string(), "755224");
        assert_eq!(a.next_hotp().unwrap().to_string(), "287082");
        assert_eq!(a.kind, OtpKind::Hotp { counter: 2 });
    }

    #[test]
    fn rejects_malicious_or_malformed() {
        let bad = [
            "https://totp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x",
            "otpauth://totp/x?issuer=a",
            "otpauth://foo/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBV",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?secret=",
            "otpauth://totp/x%ZZ?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x%FF?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x%0A?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/Bank%E2%80%AEmoc.liamg?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",
        ];
        for uri in bad {
            assert!(OtpAccount::from_uri(uri).is_err(), "accettato: {uri}");
        }
        let long = format!(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&image={}",
            "a".repeat(MAX_URI_LEN)
        );
        assert_eq!(OtpAccount::from_uri(&long), Err(Error::InvalidUri));
    }

    #[test]
    fn uri_roundtrip() {
        let uri = "otpauth://hotp/My%20Bank:m%C3%A1rio%2Bx@example.com?secret=JBSWY3DPEHPK3PXP\
                   &issuer=My%20Bank&algorithm=SHA256&digits=7&counter=42";
        let a = OtpAccount::from_uri(uri).unwrap();
        assert_eq!(a.name, "mário+x@example.com");
        assert_eq!(OtpAccount::from_uri(&a.to_uri()).unwrap(), a);
    }

    proptest! {
        #[test]
        fn from_uri_never_panics(s in "otpauth://(totp|hotp)/.{0,64}\\?.{0,128}") {
            let _ = OtpAccount::from_uri(&s);
        }

        #[test]
        fn roundtrip_arbitrary_labels(
            issuer in "[^\\p{C}:]{1,40}",
            name in "[^\\p{C}]{1,40}",
            secret in proptest::collection::vec(any::<u8>(), 1..=64),
        ) {
            prop_assume!(!issuer.trim().is_empty() && !name.trim().is_empty());
            let account = OtpAccount {
                issuer: Some(issuer.trim().to_owned()),
                name: name.trim().to_owned(),
                kind: OtpKind::Totp { period: Period::DEFAULT },
                algorithm: Algorithm::Sha1,
                digits: Digits::SIX,
                secret: SecretBytes::new(secret),
            };
            prop_assume!(reject_unsafe_chars(&account.name).is_ok());
            prop_assume!(account.issuer.as_deref().is_some_and(|i| reject_unsafe_chars(i).is_ok()));
            prop_assert_eq!(OtpAccount::from_uri(&account.to_uri()).unwrap(), account);
        }
    }
}
