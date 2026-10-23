//! Cattura diretta dei monitor (Windows, macOS) con `xcap`.
//!
//! Su macOS serve il permesso "Registrazione schermo": senza, il sistema lo chiede alla
//! prima cattura e restituisce un errore.

use authenticator_session::Screenshot;
use zeroize::Zeroizing;

use super::super::text;

pub(super) async fn capture() -> Result<Vec<Screenshot>, String> {
    tauri::async_runtime::spawn_blocking(capture_monitors)
        .await
        .map_err(text)?
}

fn capture_monitors() -> Result<Vec<Screenshot>, String> {
    let mut screens = Vec::new();
    for monitor in xcap::Monitor::all().map_err(text)? {
        let image = monitor.capture_image().map_err(text)?;
        let (width, height) = image.dimensions();
        screens.push(Screenshot {
            width,
            height,
            rgba: Zeroizing::new(image.into_raw()),
        });
    }
    if screens.is_empty() {
        return Err("nessuno schermo da catturare".into());
    }
    Ok(screens)
}
