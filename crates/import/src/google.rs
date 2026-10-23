//! Import dall'export di Google Authenticator (`otpauth-migration://offline?data=…`).
//!
//! Il parametro `data` è un messaggio protobuf `MigrationPayload` in Base64:
//!
//! ```text
//! MigrationPayload { repeated OtpParameters otp_parameters = 1; int32 version = 2;
//!                    int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5; }
//! OtpParameters    { bytes secret = 1; string name = 2; string issuer = 3;
//!                    Algorithm algorithm = 4; DigitCount digits = 5; OtpType type = 6;
//!                    int64 counter = 7; }
//! ```

use authenticator_core::otp::{Algorithm, Digits, Period};
use authenticator_core::{OtpAccount, OtpKind, SecretBytes};

use crate::ImportError;
use crate::protobuf::{Reader, Value};

/// Lunghezza massima dell'URI (un QR code ne contiene al massimo ~4 KB).
pub const MAX_URI_LEN: usize = 8 * 1024;
/// Numero massimo di account per batch.
pub const MAX_ACCOUNTS: usize = 1000;

/// Risultato dell'import di un QR code di esportazione.
#[derive(Debug)]
pub struct MigrationBatch {
    /// Account importati correttamente.
    pub accounts: Vec<OtpAccount>,
    /// Account presenti ma non importabili (es. MD5, parametri non validi).
    pub skipped: usize,
    /// Indice di questo QR code nella sequenza (da 0).
    pub batch_index: u32,
    /// Numero totale di QR code della sequenza.
    pub batch_size: u32,
    /// Identificativo comune a tutti i QR code della stessa esportazione.
    pub batch_id: u32,
}

/// Interpreta un URI `otpauth-migration://offline?data=…`.
///
/// # Errors
/// [`ImportError::TooLarge`] per input troppo grandi; [`ImportError::InvalidFormat`] se
/// l'URI o il payload sono malformati.
pub fn parse_migration_uri(uri: &str) -> Result<MigrationBatch, ImportError> {
    if uri.len() > MAX_URI_LEN {
        return Err(ImportError::TooLarge);
    }
    let prefix = "otpauth-migration://offline?";
    let query = uri
        .get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(prefix))
        .and_then(|_| uri.get(prefix.len()..))
        .ok_or(ImportError::InvalidFormat)?;
    let mut data = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("data=")
            && data.replace(value).is_some()
        {
            return Err(ImportError::InvalidFormat);
        }
    }
    let data = percent_decode(data.ok_or(ImportError::InvalidFormat)?)?;
    let payload = crate::base64::decode(&data).ok_or(ImportError::InvalidFormat)?;
    parse_payload(&payload)
}

fn percent_decode(input: &str) -> Result<zeroize::Zeroizing<String>, ImportError> {
    let mut out = zeroize::Zeroizing::new(String::with_capacity(input.len()));
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| ImportError::InvalidFormat)?;
            // Base64 usa solo ASCII: un byte non ASCII indica dati corrotti.
            if hex.len() != 2 || !byte.is_ascii() {
                return Err(ImportError::InvalidFormat);
            }
            out.push(char::from(byte));
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn to_u32(v: u64) -> Result<u32, ImportError> {
    u32::try_from(v).map_err(|_| ImportError::InvalidFormat)
}

/// Interpreta il messaggio `MigrationPayload` già decodificato.
///
/// # Errors
/// [`ImportError::InvalidFormat`] per payload malformati; [`ImportError::TooLarge`] oltre
/// [`MAX_ACCOUNTS`] account.
pub fn parse_payload(payload: &[u8]) -> Result<MigrationBatch, ImportError> {
    let mut batch = MigrationBatch {
        accounts: Vec::new(),
        skipped: 0,
        batch_index: 0,
        batch_size: 1,
        batch_id: 0,
    };
    let mut reader = Reader::new(payload);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Value::Bytes(otp)) => {
                if batch.accounts.len() + batch.skipped >= MAX_ACCOUNTS {
                    return Err(ImportError::TooLarge);
                }
                match parse_otp_parameters(otp)? {
                    Some(account) => batch.accounts.push(account),
                    None => batch.skipped += 1,
                }
            }
            (3, Value::Varint(v)) => batch.batch_size = to_u32(v)?,
            (4, Value::Varint(v)) => batch.batch_index = to_u32(v)?,
            // batch_id è un int32: i valori negativi arrivano estesi a 64 bit.
            (5, Value::Varint(v)) => batch.batch_id = to_u32(v & 0xffff_ffff)?,
            (1 | 3..=5, _) => return Err(ImportError::InvalidFormat),
            _ => {}
        }
    }
    Ok(batch)
}

/// `Ok(None)` per account validi nel formato ma non supportati.
fn parse_otp_parameters(bytes: &[u8]) -> Result<Option<OtpAccount>, ImportError> {
    let mut secret = None;
    let mut name = None;
    let mut issuer = None;
    let mut algorithm = 1;
    let mut digits = 1;
    let mut otp_type = 2;
    let mut counter = 0;

    let mut reader = Reader::new(bytes);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Value::Bytes(b)) => secret = Some(SecretBytes::new(b.to_vec())),
            (2, Value::Bytes(b)) => {
                name = Some(core::str::from_utf8(b).map_err(|_| ImportError::InvalidFormat)?);
            }
            (3, Value::Bytes(b)) => {
                issuer = Some(core::str::from_utf8(b).map_err(|_| ImportError::InvalidFormat)?);
            }
            (4, Value::Varint(v)) => algorithm = v,
            (5, Value::Varint(v)) => digits = v,
            (6, Value::Varint(v)) => otp_type = v,
            (7, Value::Varint(v)) => counter = v,
            (1..=7, _) => return Err(ImportError::InvalidFormat),
            _ => {}
        }
    }

    // 0 = non specificato: Google usa i default (SHA1, 6 cifre).
    let algorithm = match algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Ok(None), // MD5 o sconosciuto
    };
    let digits = match digits {
        0 | 1 => Digits::SIX,
        2 => Digits::EIGHT,
        _ => return Ok(None),
    };
    let kind = match otp_type {
        1 => OtpKind::Hotp { counter },
        0 | 2 => OtpKind::Totp {
            period: Period::DEFAULT,
        },
        _ => return Ok(None),
    };
    let Some(secret) = secret else {
        return Ok(None);
    };
    let issuer = issuer.filter(|i| !i.is_empty());
    let name = name.unwrap_or_default();
    // Il nome spesso ripete l'issuer come prefisso ("Issuer:account").
    let (issuer, name) = match (issuer, name.split_once(':')) {
        (Some(i), Some((prefix, rest))) if prefix.trim() == i.trim() => (Some(i), rest),
        (None, Some((prefix, rest))) if !rest.trim().is_empty() => (Some(prefix), rest),
        (issuer, _) => (issuer, name),
    };
    Ok(OtpAccount::new(issuer, name, kind, algorithm, digits, secret).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Export reale di Google Authenticator con un account di esempio.
    const SAMPLE: &str = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgACjr4JKkAg%3D%3D";

    #[test]
    fn parses_google_export() {
        let batch = parse_migration_uri(SAMPLE).unwrap();
        assert_eq!(batch.accounts.len(), 1);
        assert_eq!(batch.skipped, 0);
        assert_eq!((batch.batch_index, batch.batch_size), (0, 1));
        let a = &batch.accounts[0];
        assert_eq!(a.issuer.as_deref(), Some("Example"));
        assert_eq!(a.name, "alice@google.com");
        assert_eq!(a.secret.expose(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(a.algorithm, Algorithm::Sha1);
        assert_eq!(a.digits, Digits::SIX);
        assert_eq!(
            a.kind,
            OtpKind::Totp {
                period: Period::DEFAULT
            }
        );
    }

    /// Codifica minima di un `OtpParameters` per i test.
    fn otp(
        secret: &[u8],
        name: &str,
        issuer: &str,
        algorithm: u8,
        digits: u8,
        kind: u8,
    ) -> Vec<u8> {
        let mut m = vec![0x0a, u8::try_from(secret.len()).unwrap()];
        m.extend_from_slice(secret);
        m.extend_from_slice(&[0x12, u8::try_from(name.len()).unwrap()]);
        m.extend_from_slice(name.as_bytes());
        m.extend_from_slice(&[0x1a, u8::try_from(issuer.len()).unwrap()]);
        m.extend_from_slice(issuer.as_bytes());
        m.extend_from_slice(&[0x20, algorithm, 0x28, digits, 0x30, kind, 0x38, 5]);
        let mut wrapped = vec![0x0a, u8::try_from(m.len()).unwrap()];
        wrapped.extend(m);
        wrapped
    }

    #[test]
    fn handles_variants_and_unsupported_entries() {
        let mut payload = otp(b"12345678901234567890", "bob", "", 3, 2, 1);
        payload.extend(otp(b"12345678901234567890", "md5", "X", 4, 1, 2));
        payload.extend(otp(b"12345678901234567890", "Acme:carol", "", 1, 1, 2));
        payload.extend(otp(b"12345678901234567890", "evil\u{202e}", "X", 1, 1, 2));
        payload.extend([0x18, 0x02, 0x20, 0x01, 0x28, 0xff, 0xff, 0xff, 0xff, 0x0f]);
        let batch = parse_payload(&payload).unwrap();
        assert_eq!(batch.accounts.len(), 2);
        assert_eq!(batch.skipped, 2);
        assert_eq!(
            (batch.batch_index, batch.batch_size, batch.batch_id),
            (1, 2, u32::MAX)
        );

        let bob = &batch.accounts[0];
        assert_eq!(bob.issuer, None);
        assert_eq!(bob.kind, OtpKind::Hotp { counter: 5 });
        assert_eq!(bob.algorithm, Algorithm::Sha512);
        assert_eq!(bob.digits, Digits::EIGHT);

        let carol = &batch.accounts[1];
        assert_eq!(carol.issuer.as_deref(), Some("Acme"));
        assert_eq!(carol.name, "carol");
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "otpauth://totp/x?secret=AAAA",
            "otpauth-migration://offline?",
            "otpauth-migration://offline?data=%%%",
            "otpauth-migration://offline?data=CgA=&data=CgA=",
            "otpauth-migration://offline?data=!!!!",
            "otpauth-migration://offline?data=Cg%3D%3D", // campo 1 troncato
        ] {
            assert!(parse_migration_uri(bad).is_err(), "{bad}");
        }
        let huge = format!(
            "otpauth-migration://offline?data={}",
            "A".repeat(MAX_URI_LEN)
        );
        assert_eq!(
            parse_migration_uri(&huge).unwrap_err(),
            ImportError::TooLarge
        );
    }

    proptest! {
        #[test]
        fn payload_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_payload(&data);
        }

        #[test]
        fn uri_never_panics(s in "otpauth-migration://offline\\?data=.{0,200}") {
            let _ = parse_migration_uri(&s);
        }
    }
}
