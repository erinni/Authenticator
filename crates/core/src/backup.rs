//! Backup cifrato ed export in chiaro dell'elenco account.
//!
//! Un backup è un file vault (vedi [`crate::vault`]) con una DEK propria e un unico
//! slot password scelto al momento dell'export: è indipendente dal vault dell'app e
//! dalle sue credenziali, quindi può essere conservato altrove o importato su un
//! altro dispositivo.

use zeroize::Zeroizing;

use crate::error::Result;
use crate::store::Store;
use crate::vault::{Credential, KdfParams, Vault};

/// Estensione consigliata per i file di backup.
pub const FILE_EXTENSION: &str = "authbackup";

/// Crea un backup cifrato dell'elenco account.
///
/// # Errors
/// Come [`Vault::create`] e [`Vault::seal`].
pub fn export_encrypted(store: &Store, password: &[u8], params: KdfParams) -> Result<Vec<u8>> {
    let vault = Vault::create(password, params)?;
    vault.seal(&store.encode()?)
}

/// Legge un backup creato con [`export_encrypted`].
///
/// # Errors
/// [`crate::Error::Decryption`] per password errata o file manomesso; come
/// [`Vault::open`] e [`Store::decode`] per file non validi.
pub fn import_encrypted(data: &[u8], password: &[u8]) -> Result<Store> {
    let (_, payload) = Vault::open(data, Credential::Password(password))?;
    Store::decode(payload.expose())
}

/// Esporta gli account come URI `otpauth://`, uno per riga, per il passaggio ad altre app.
///
/// Il risultato contiene **tutti i segreti in chiaro**: va prodotto solo dopo una
/// ri-autenticazione esplicita e mai salvato senza avvisare l'utente.
#[must_use]
pub fn export_uris(store: &Store) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for entry in store.entries() {
        out.push_str(&Zeroizing::new(entry.account.to_uri()));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, OtpAccount};

    fn store() -> Store {
        let mut store = Store::new();
        for uri in [
            "otpauth://totp/GitHub:mario?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "otpauth://hotp/VPN?secret=GEZDGNBVGY3TQOJQ&counter=3",
        ] {
            store
                .add(OtpAccount::from_uri(uri).unwrap(), 1_700_000_000)
                .unwrap();
        }
        store
    }

    #[test]
    fn encrypted_roundtrip() {
        let store = store();
        let file = export_encrypted(&store, b"password del backup", KdfParams::MINIMUM).unwrap();
        assert_eq!(
            import_encrypted(&file, b"password del backup").unwrap(),
            store
        );
        assert_eq!(
            import_encrypted(&file, b"altra").unwrap_err(),
            Error::Decryption
        );
        // Il segreto non compare in chiaro nel file.
        let secret = &store.entries()[0].account.secret;
        assert!(!file.windows(secret.len()).any(|w| w == secret.expose()));
    }

    #[test]
    fn uri_export_is_reimportable() {
        let store = store();
        let text = export_uris(&store);
        let reimported: Vec<OtpAccount> = text
            .lines()
            .map(|l| OtpAccount::from_uri(l).unwrap())
            .collect();
        let original: Vec<&OtpAccount> = store.entries().iter().map(|e| &e.account).collect();
        assert_eq!(reimported.iter().collect::<Vec<_>>(), original);
    }
}
