//! Avvio dell'app desktop.

// Nessuna console accanto alla finestra nelle build di release su Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), tauri::Error> {
    authenticator_native::run()
}
