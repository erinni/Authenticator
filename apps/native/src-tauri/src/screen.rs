//! Cattura dello schermo per la scansione dei QR di attivazione.
//!
//! Le schermate restano in questo processo: vengono analizzate dal core e azzerate,
//! senza passare dalla webview. Su Windows e macOS si catturano direttamente tutti i
//! monitor; su Linux (Wayland e X11) si passa dal portale XDG, che chiede il consenso
//! dell'utente a ogni cattura.

use authenticator_session::Screenshot;

#[cfg(target_os = "linux")]
#[path = "screen/portal.rs"]
mod platform;
#[cfg(not(target_os = "linux"))]
#[path = "screen/monitors.rs"]
mod platform;

/// Cattura tutti gli schermi.
///
/// # Errors
/// Cattura non disponibile, non autorizzata o annullata (`screen:cancelled`).
pub(crate) async fn capture() -> Result<Vec<Screenshot>, String> {
    platform::capture().await
}
