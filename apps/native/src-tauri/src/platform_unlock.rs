//! Sblocco del vault con il sistema operativo.
//!
//! Ogni metodo fornisce il segreto di uno slot "esterno" del vault (lo stesso tipo di slot
//! delle passkey nella PWA), identificato da un id casuale di 16 byte:
//!
//! - **Windows Hello**: una chiave RSA nel TPM (o nel modulo software di Windows) firma una
//!   sfida fissa legata allo slot. La firma PKCS#1 v1.5 è deterministica e diventa il
//!   segreto: su disco non si salva nulla, e ogni sblocco richiede PIN, impronta o volto.
//! - **Secret Service** (Linux): un segreto casuale di 32 byte nel portachiavi della
//!   sessione. Nessuna biometria: vale quanto la sessione utente, e la UI lo dice.
//!
//! Il segreto non attraversa mai la webview: lo usa direttamente il core nativo.

use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
#[path = "platform_unlock/secret_service.rs"]
mod imp;
#[cfg(windows)]
#[path = "platform_unlock/windows_hello.rs"]
mod imp;
#[cfg(not(any(windows, target_os = "linux")))]
#[path = "platform_unlock/unsupported.rs"]
mod imp;

/// Metodo di sblocco disponibile su questo sistema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Method {
    /// Windows Hello (PIN, impronta o volto; chiave nel TPM).
    #[cfg_attr(not(windows), allow(dead_code))]
    WindowsHello,
    /// Portachiavi della sessione via Secret Service (`GNOME Keyring`, `KWallet`…).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    SecretService,
}

/// Segreto di uno slot, azzerato al drop.
pub(crate) type Secret = Zeroizing<Vec<u8>>;

/// Id di uno slot esterno del vault.
pub(crate) type SlotId = [u8; 16];

/// Metodo disponibile, se il sistema lo supporta in questo momento.
pub(crate) async fn method() -> Option<Method> {
    match imp::METHOD {
        Some(method) if imp::available().await => Some(method),
        _ => None,
    }
}

/// Crea il segreto per un nuovo slot (con la conferma dell'utente, dove prevista).
pub(crate) async fn enroll(slot: SlotId) -> Result<Secret, String> {
    imp::enroll(slot).await
}

/// Segreto di uno slot creato su questo dispositivo, o `None` se non esiste qui.
pub(crate) async fn secret(slot: SlotId) -> Result<Option<Secret>, String> {
    imp::secret(slot).await
}

/// Elimina il segreto di uno slot dal sistema (nessun errore se non esiste).
pub(crate) async fn forget(slot: SlotId) -> Result<(), String> {
    imp::forget(slot).await
}

/// Nuovo id di slot casuale.
pub(crate) fn new_slot_id() -> Result<SlotId, String> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    Ok(id)
}

/// Nome dell'applicazione negli archivi di sistema.
#[cfg(any(windows, target_os = "linux"))]
const APP_ID: &str = "io.github.erinni.authenticator";
