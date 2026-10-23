//! Primitive usate dai formati cifrati di altre app.
//!
//! I parametri delle KDF vengono dal file (input non fidato): sono limitati per
//! evitare che un file malevolo blocchi l'app o ne esaurisca la memoria.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::ImportError;

/// Iterazioni PBKDF2 massime accettate (come Aegis).
pub(crate) const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// Memoria massima per scrypt: 256 MiB.
const MAX_SCRYPT_MEMORY: u64 = 256 * 1024 * 1024;
/// Parallelismo massimo per scrypt.
const MAX_SCRYPT_P: u32 = 16;

pub(crate) type Key = Zeroizing<[u8; 32]>;

/// AES-256-GCM senza AAD; `ciphertext` include il tag finale da 16 byte.
pub(crate) fn aes_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ImportError::Decryption)
}

/// PBKDF2-HMAC-SHA1 (andOTP).
pub(crate) fn pbkdf2_sha1(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Key, ImportError> {
    if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(ImportError::InvalidFormat);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, key.as_mut_slice());
    Ok(key)
}

/// PBKDF2-HMAC-SHA256 (2FAS).
pub(crate) fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Key, ImportError> {
    if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(ImportError::InvalidFormat);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, key.as_mut_slice());
    Ok(key)
}

/// scrypt (Aegis). `n` deve essere una potenza di due.
pub(crate) fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
) -> Result<Key, ImportError> {
    if !n.is_power_of_two() || n < 2 || r == 0 || p == 0 || p > MAX_SCRYPT_P {
        return Err(ImportError::InvalidFormat);
    }
    // Memoria richiesta: 128 * r * n byte.
    let memory = 128u64
        .checked_mul(u64::from(r))
        .and_then(|m| m.checked_mul(n));
    if memory.is_none_or(|m| m > MAX_SCRYPT_MEMORY) {
        return Err(ImportError::InvalidFormat);
    }
    let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| ImportError::InvalidFormat)?;
    let params = scrypt::Params::new(log_n, r, p).map_err(|_| ImportError::InvalidFormat)?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &params, key.as_mut_slice())
        .map_err(|_| ImportError::InvalidFormat)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6070, test case 2 (PBKDF2-HMAC-SHA1, 2 iterazioni), primi 20 byte.
    #[test]
    fn pbkdf2_sha1_rfc6070() {
        let key = pbkdf2_sha1(b"password", b"salt", 2).unwrap();
        let expected = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        assert_eq!(&key[..20], &expected);
    }

    /// RFC 7914 §12, secondo vettore: `scrypt("password", "NaCl", N=1024, r=8, p=16)`.
    #[test]
    fn scrypt_rfc7914() {
        let key = scrypt(b"password", b"NaCl", 1024, 8, 16).unwrap();
        let expected = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
            0x4b, 0x37, 0x31, 0x62,
        ];
        assert_eq!(*key, expected);
    }

    #[test]
    fn rejects_dangerous_parameters() {
        assert!(pbkdf2_sha1(b"p", b"s", 0).is_err());
        assert!(pbkdf2_sha256(b"p", b"s", MAX_PBKDF2_ITERATIONS + 1).is_err());
        assert!(scrypt(b"p", b"s", 1000, 8, 1).is_err()); // non potenza di 2
        assert!(scrypt(b"p", b"s", 1 << 30, 8, 1).is_err()); // 128 GiB
        assert!(scrypt(b"p", b"s", 1024, 8, 1000).is_err());
    }
}
