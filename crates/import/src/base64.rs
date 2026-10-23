//! Decodifica Base64 (RFC 4648 §4, alfabeto standard, padding opzionale).

use zeroize::Zeroizing;

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodifica; restituisce `None` per input non valido o non canonico.
pub(crate) fn decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let data = input.trim_end_matches('=');
    if input.len() - data.len() > 2 || data.len() % 4 == 1 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() * 3 / 4));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in data.bytes() {
        buffer = (buffer << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
            buffer &= (1 << bits) - 1;
        }
    }
    // I bit residui devono essere zero (codifica canonica).
    (buffer == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector RFC 4648 §10.
    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(decode(encoded).unwrap().as_slice(), plain.as_bytes());
        }
        assert_eq!(decode("Zm9vYg").unwrap().as_slice(), b"foob");
    }

    #[test]
    fn rejects_invalid() {
        for bad in ["Z", "Zm9v!", "Zh==", "Zg===", "Zm=9"] {
            assert!(decode(bad).is_none(), "{bad}");
        }
    }
}
