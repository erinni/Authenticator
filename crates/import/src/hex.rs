//! Decodifica esadecimale.

use zeroize::Zeroizing;

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodifica una stringa esadecimale; `None` se non valida.
pub(crate) fn decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() / 2));
    for pair in input.as_bytes().chunks_exact(2) {
        let [hi, lo] = pair else { return None };
        out.push(nibble(*hi)? << 4 | nibble(*lo)?);
    }
    Some(out)
}

/// Decodifica una stringa esadecimale di lunghezza fissa.
pub(crate) fn decode_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    decode(input)?.as_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        assert_eq!(decode("00ffA1").unwrap().as_slice(), &[0x00, 0xff, 0xa1]);
        assert_eq!(decode_array::<2>("beef"), Some([0xbe, 0xef]));
        assert!(decode("abc").is_none());
        assert!(decode("zz").is_none());
        assert!(decode_array::<3>("beef").is_none());
    }
}
