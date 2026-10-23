//! Tipi per materiale segreto: azzerati in memoria al drop e mai stampati.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// Byte segreti di lunghezza variabile (es. seed OTP, payload del vault in chiaro).
///
/// `Debug` è redatto, non implementa `Clone` né `Display`, e il contenuto viene
/// azzerato al drop.
#[derive(Default, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Prende possesso dei byte.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Accesso in sola lettura ai byte segreti.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Lunghezza in byte.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` se vuoto.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDATTO; {} byte])", self.0.len())
    }
}

/// Chiave simmetrica a 256 bit.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key256([u8; 32]);

impl Key256 {
    /// Lunghezza della chiave in byte.
    pub const LEN: usize = 32;

    /// Genera una chiave casuale con il CSPRNG del sistema.
    ///
    /// # Errors
    /// [`Error::Rng`] se il CSPRNG non è disponibile.
    pub fn generate() -> Result<Self> {
        let mut key = Self([0; 32]);
        getrandom::fill(&mut key.0).map_err(|_| Error::Rng)?;
        Ok(key)
    }

    /// Costruisce la chiave da byte esistenti.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Accesso in sola lettura ai byte della chiave.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Accesso in scrittura, per riempire la chiave da una KDF senza copie intermedie.
    pub(crate) fn expose_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    /// Chiave azzerata, da riempire con [`Key256::expose_mut`].
    pub(crate) fn zeroed() -> Self {
        Self([0; 32])
    }
}

impl PartialEq for Key256 {
    /// Confronto a tempo costante.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Key256 {}

impl fmt::Debug for Key256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key256([REDATTO])")
    }
}

/// Riempie un array con byte casuali dal CSPRNG del sistema.
///
/// # Errors
/// [`Error::Rng`] se il CSPRNG non è disponibile.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Rng)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretBytes::new(b"supersegreto".to_vec());
        let key = Key256::from_bytes([0x41; 32]);
        assert!(!format!("{secret:?}").contains("supersegreto"));
        assert!(!format!("{key:?}").contains("41"));
        assert!(!format!("{key:?}").contains("AAAA"));
    }

    #[test]
    fn generated_keys_differ() {
        let a = Key256::generate().unwrap();
        let b = Key256::generate().unwrap();
        assert_ne!(a, b);
    }
}
