//! macOS: voce del portachiavi protetta da access control con presenza utente.
//!
//! Il gate lo applica Security.framework: ogni lettura mostra Touch ID o chiede la
//! password del Mac. La voce resta nel portachiavi di login, senza sincronizzazione.

use authenticator_session::format_id;
use security::error::status;
use security::{
    AccessControl, AccessControlFlags, AccessControlProtection, Keychain, KeychainOptions,
    SecurityError,
};
use zeroize::Zeroizing;

use super::{APP_ID, Method, Secret, SlotId};

pub(super) const METHOD: Option<Method> = Some(Method::TouchId);

const SECRET_LEN: usize = 32;

fn text(e: impl core::fmt::Display) -> String {
    format!("Touch ID non disponibile: {e}")
}

fn keychain_error(e: SecurityError) -> String {
    match e.code().map(|code| code as i32) {
        Some(code) if code == status::USER_CANCELED => "Autenticazione annullata.".into(),
        Some(code) if code == status::AUTH_FAILED => "Autenticazione non riuscita.".into(),
        Some(code) if code == status::MISSING_ENTITLEMENT => {
            "Touch ID richiede una build firmata con un Developer ID.".into()
        }
        _ => text(e),
    }
}

fn user_presence() -> Result<AccessControl, String> {
    AccessControl::create(
        AccessControlProtection::WhenPasscodeSetThisDeviceOnly,
        AccessControlFlags::USER_PRESENCE,
    )
    .map_err(keychain_error)
}

fn store_options() -> Result<KeychainOptions, String> {
    Ok(KeychainOptions::default()
        .accessibility(AccessControlProtection::WhenPasscodeSetThisDeviceOnly)
        .access_control(user_presence()?))
}

pub(super) async fn available() -> bool {
    // Senza un codice del Mac questo access control non potrebbe mai essere soddisfatto.
    user_presence().is_ok()
}

pub(super) async fn enroll(slot: SlotId) -> Result<Secret, String> {
    let mut secret = Zeroizing::new(vec![0u8; SECRET_LEN]);
    getrandom::fill(&mut secret).map_err(text)?;
    Keychain::set_with_options(
        &format_id(&slot),
        APP_ID,
        secret.as_slice(),
        &store_options()?,
    )
    .map_err(keychain_error)?;
    Ok(secret)
}

pub(super) async fn secret(slot: SlotId) -> Result<Option<Secret>, String> {
    let account = format_id(&slot);
    // La lettura può attendere il prompt del sistema: fuori dal runtime asincrono.
    tauri::async_runtime::spawn_blocking(move || match Keychain::get(&account, APP_ID) {
        Ok(secret) => Ok(Some(Zeroizing::new(secret.as_bytes().to_vec()))),
        Err(SecurityError::ItemNotFound(_)) => Ok(None),
        Err(e) => Err(keychain_error(e)),
    })
    .await
    .map_err(text)?
}

pub(super) async fn forget(slot: SlotId) -> Result<(), String> {
    match Keychain::delete(&format_id(&slot), APP_ID) {
        Ok(()) | Err(SecurityError::ItemNotFound(_)) => Ok(()),
        Err(e) => Err(keychain_error(e)),
    }
}
