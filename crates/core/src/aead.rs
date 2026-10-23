//! Cifratura autenticata XChaCha20-Poly1305 con nonce casuale a 192 bit.
//!
//! Formato del messaggio: `nonce (24) || ciphertext || tag (16)`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::{Key256, random_array};

/// Lunghezza del nonce.
pub const NONCE_LEN: usize = 24;
/// Lunghezza del tag di autenticazione.
pub const TAG_LEN: usize = 16;
/// Overhead totale rispetto al testo in chiaro.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Cifra `plaintext` autenticando anche `aad`.
///
/// # Errors
/// [`Error::Rng`] se non è possibile generare il nonce.
pub fn seal(key: &Key256, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes: [u8; NONCE_LEN] = random_array()?;
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Internal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decifra un messaggio prodotto da [`seal`]. Il risultato è azzerato al drop.
///
/// # Errors
/// [`Error::Decryption`] se la chiave è errata o se messaggio o `aad` sono stati alterati.
pub fn open(key: &Key256, aad: &[u8], message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (nonce_bytes, ciphertext) = message
        .split_at_checked(NONCE_LEN)
        .ok_or(Error::Decryption)?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| Error::Decryption)?;
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .decrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decryption)
}

/// Deriva una sottochiave con HKDF-SHA-256.
///
/// `info` identifica in modo univoco lo scopo della chiave (separazione di dominio).
///
/// # Errors
/// [`Error::Internal`] solo in caso di violazione delle invarianti di HKDF.
pub fn derive_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<Key256> {
    let mut key = Key256::zeroed();
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, key.expose_mut())
        .map_err(|_| Error::Internal)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let key = Key256::generate().unwrap();
        let msg = seal(&key, b"aad", b"ciao").unwrap();
        assert_eq!(msg.len(), 4 + OVERHEAD);
        assert_eq!(open(&key, b"aad", &msg).unwrap().as_slice(), b"ciao");

        assert_eq!(open(&key, b"altro", &msg), Err(Error::Decryption));
        assert_eq!(
            open(&Key256::generate().unwrap(), b"aad", &msg),
            Err(Error::Decryption)
        );
        for i in 0..msg.len() {
            let mut tampered = msg.clone();
            tampered[i] ^= 0x01;
            assert_eq!(
                open(&key, b"aad", &tampered),
                Err(Error::Decryption),
                "byte {i}"
            );
        }
        assert_eq!(open(&key, b"aad", &msg[..10]), Err(Error::Decryption));
    }

    #[test]
    fn nonces_are_unique() {
        let key = Key256::generate().unwrap();
        let a = seal(&key, b"", b"x").unwrap();
        let b = seal(&key, b"", b"x").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    /// RFC 5869, test case 1 (HKDF-SHA-256), primi 32 byte dell'OKM.
    #[test]
    fn hkdf_rfc5869_vector() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = derive_key(&ikm, Some(&salt), &info).unwrap();
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf,
        ];
        assert_eq!(okm.expose(), &expected);
    }
}
