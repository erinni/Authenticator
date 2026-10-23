//! Base32 (RFC 4648, alfabeto standard), usato dai segreti OTP.
//!
//! La decodifica è tollerante come le app esistenti: ignora maiuscole/minuscole,
//! spazi, trattini e padding `=` finale.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Lunghezza massima accettata dell'input (difesa da input malevoli enormi).
pub const MAX_INPUT_LEN: usize = 1024;

/// Codifica in Base32 senza padding.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol((buffer >> bits) & 0x1f));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(symbol((buffer << (5 - bits)) & 0x1f));
    }
    out
}

fn symbol(index: u16) -> char {
    // `index` è sempre < 32 per costruzione (maschera 0x1f).
    ALPHABET
        .get(usize::from(index))
        .map_or('A', |&b| char::from(b))
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Decodifica una stringa Base32. Il risultato è azzerato al drop.
///
/// # Errors
/// [`Error::InvalidBase32`] per caratteri non validi, padding nel mezzo, input troppo
/// lungo o bit residui non nulli (codifica non canonica).
pub fn decode(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > MAX_INPUT_LEN {
        return Err(Error::InvalidBase32);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    let mut padding = false;
    for c in input.bytes() {
        match c {
            b' ' | b'-' | b'\t' => {}
            b'=' => padding = true,
            _ => {
                if padding {
                    return Err(Error::InvalidBase32);
                }
                let v = value(c).ok_or(Error::InvalidBase32)?;
                buffer = (buffer << 5) | u16::from(v);
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| Error::Internal)?);
                    buffer &= (1 << bits) - 1;
                }
            }
        }
    }
    // Un gruppo finale di 5+ bit non forma un byte: lunghezza non valida in RFC 4648.
    if bits >= 5 || buffer != 0 {
        return Err(Error::InvalidBase32);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Test vector RFC 4648 §10.
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ];

    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), *encoded);
            assert_eq!(decode(encoded).unwrap().as_slice(), plain.as_bytes());
        }
    }

    #[test]
    fn accepts_padding_lowercase_and_separators() {
        assert_eq!(decode("MZXW6YTBOI======").unwrap().as_slice(), b"foobar");
        assert_eq!(decode("mzxw 6ytb-oi").unwrap().as_slice(), b"foobar");
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!(decode("MZXW1"), Err(Error::InvalidBase32)); // '1' non è nell'alfabeto
        assert_eq!(decode("MY=A"), Err(Error::InvalidBase32)); // dati dopo il padding
        assert_eq!(decode("M"), Err(Error::InvalidBase32)); // lunghezza impossibile
        assert_eq!(decode("MZ"), Err(Error::InvalidBase32)); // bit residui non nulli
        assert_eq!(
            decode(&"A".repeat(MAX_INPUT_LEN + 1)),
            Err(Error::InvalidBase32)
        );
    }

    proptest! {
        #[test]
        fn roundtrip(data in proptest::collection::vec(any::<u8>(), 0..200)) {
            let decoded = decode(&encode(&data)).unwrap();
            prop_assert_eq!(decoded.as_slice(), data.as_slice());
        }

        #[test]
        fn decode_never_panics(s in ".{0,300}") {
            let _ = decode(&s);
        }
    }
}
