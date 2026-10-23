//! Windows: Windows Hello (`KeyCredentialManager`), con la chiave nel TPM quando presente.
//!
//! Il segreto è la firma, con la chiave dello slot, di una sfida fissa: RSA PKCS#1 v1.5 è
//! deterministico, quindi la stessa chiave produce sempre lo stesso segreto. La chiave non è
//! esportabile e ogni firma richiede la verifica dell'utente (PIN, impronta o volto).

use authenticator_session::format_id;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::core::{Array, HSTRING};
use zeroize::Zeroizing;

use super::{APP_ID, Method, Secret, SlotId};

pub(super) const METHOD: Option<Method> = Some(Method::WindowsHello);

const CHALLENGE_DOMAIN: &[u8] = b"authenticator/v1/windows-hello/";

fn text(e: impl core::fmt::Display) -> String {
    format!("Windows Hello non disponibile: {e}")
}

fn name(slot: &SlotId) -> HSTRING {
    HSTRING::from(format!("{APP_ID}/{}", format_id(slot)))
}

fn check(status: KeyCredentialStatus) -> Result<(), String> {
    match status {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled => Err("Operazione annullata.".into()),
        KeyCredentialStatus::UserPrefersPassword => Err("Usa la password per sbloccare.".into()),
        KeyCredentialStatus::NotFound => Err("Credenziale Windows Hello non trovata.".into()),
        KeyCredentialStatus::SecurityDeviceLocked => {
            Err("Windows Hello è bloccato: riprova più tardi.".into())
        }
        _ => Err("Windows Hello non disponibile.".into()),
    }
}

/// Esegue un'operazione bloccante (le API `WinRT` attendono la risposta dell'utente) fuori
/// dal runtime asincrono.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(text)?
}

fn sign(credential: &KeyCredential, slot: &SlotId) -> Result<Secret, String> {
    let challenge = [CHALLENGE_DOMAIN, slot.as_slice()].concat();
    let data = CryptographicBuffer::CreateFromByteArray(&challenge).map_err(text)?;
    let result = credential
        .RequestSignAsync(&data)
        .and_then(|op| op.join())
        .map_err(text)?;
    check(result.Status().map_err(text)?)?;
    let signature = result.Result().map_err(text)?;
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(text)?;
    Ok(Zeroizing::new(bytes.to_vec()))
}

pub(super) async fn available() -> bool {
    blocking(|| {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .map_err(text)
    })
    .await
    .unwrap_or(false)
}

pub(super) async fn enroll(slot: SlotId) -> Result<Secret, String> {
    blocking(move || {
        let result = KeyCredentialManager::RequestCreateAsync(
            &name(&slot),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(text)?;
        check(result.Status().map_err(text)?)?;
        sign(&result.Credential().map_err(text)?, &slot)
    })
    .await
}

pub(super) async fn secret(slot: SlotId) -> Result<Option<Secret>, String> {
    blocking(move || {
        let result = KeyCredentialManager::OpenAsync(&name(&slot))
            .and_then(|op| op.join())
            .map_err(text)?;
        match result.Status().map_err(text)? {
            KeyCredentialStatus::NotFound => Ok(None),
            status => {
                check(status)?;
                sign(&result.Credential().map_err(text)?, &slot).map(Some)
            }
        }
    })
    .await
}

pub(super) async fn forget(slot: SlotId) -> Result<(), String> {
    blocking(move || {
        match KeyCredentialManager::DeleteAsync(&name(&slot)).and_then(|op| op.join()) {
            Ok(()) => Ok(()),
            // Credenziale già assente: nulla da eliminare.
            Err(_) if !exists(&slot) => Ok(()),
            Err(e) => Err(text(e)),
        }
    })
    .await
}

fn exists(slot: &SlotId) -> bool {
    KeyCredentialManager::OpenAsync(&name(slot))
        .and_then(|op| op.join())
        .and_then(|result| result.Status())
        .is_ok_and(|status| status != KeyCredentialStatus::NotFound)
}
