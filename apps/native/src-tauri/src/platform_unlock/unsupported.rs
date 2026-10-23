//! Sistemi senza sblocco di sistema (per ora macOS, in attesa della firma Developer ID).

// Stesse firme `async` delle altre piattaforme.
#![allow(clippy::unused_async)]

use super::{Method, Secret, SlotId};

pub(super) const METHOD: Option<Method> = None;

const UNAVAILABLE: &str = "Sblocco di sistema non disponibile su questo computer.";

pub(super) async fn available() -> bool {
    false
}

pub(super) async fn enroll(_slot: SlotId) -> Result<Secret, String> {
    Err(UNAVAILABLE.into())
}

pub(super) async fn secret(_slot: SlotId) -> Result<Option<Secret>, String> {
    Ok(None)
}

pub(super) async fn forget(_slot: SlotId) -> Result<(), String> {
    Ok(())
}
