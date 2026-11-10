//! Aggiornamenti dell'app con il plugin updater di Tauri.
//!
//! Il manifesto `latest.json` è letto dall'ultima release pubblicata su GitHub; il
//! pacchetto scaricato viene installato solo se è firmato con la chiave dell'updater
//! (la cui parte pubblica è incorporata nell'app dalla build di release) e se la firma
//! lega proprio la versione annunciata, così un manifesto alterato non può riportare
//! l'app a una versione vecchia. L'installazione parte solo su richiesta dell'utente.
//!
//! La chiave pubblica è vuota nelle build di sviluppo: lì gli aggiornamenti sono
//! disattivati.

use std::fs;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Runtime};
use tauri_plugin_updater::{Update, UpdaterExt};

/// Risultato di un controllo.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateCheck {
    /// Versione installata.
    current: String,
    /// Versione disponibile, se più recente.
    available: Option<String>,
    /// Note della release disponibile.
    notes: Option<String>,
}

/// Avanzamento del download, in byte.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Progress {
    downloaded: u64,
    total: Option<u64>,
}

/// Aggiornamento trovato dall'ultimo controllo, in attesa di conferma.
#[derive(Default)]
pub(crate) struct PendingUpdate(Mutex<Option<Update>>);

/// File che, se presente nella cartella dati, disattiva il controllo all'avvio.
const AUTO_CHECK_OFF: &str = "update-check-disabled";

/// `true` se il controllo all'avvio è attivo (lo è finché l'utente non lo spegne).
pub(crate) fn auto_check(data_dir: &Path) -> bool {
    !data_dir.join(AUTO_CHECK_OFF).exists()
}

/// Attiva o disattiva il controllo all'avvio.
///
/// # Errors
/// Cartella dati non scrivibile.
pub(crate) fn set_auto_check(data_dir: &Path, enabled: bool) -> std::io::Result<()> {
    let marker = data_dir.join(AUTO_CHECK_OFF);
    if enabled {
        match fs::remove_file(marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        fs::create_dir_all(data_dir)?;
        fs::write(marker, b"")
    }
}

/// `true` se la build contiene la chiave pubblica dell'updater.
fn configured<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|updater| updater.get("pubkey"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|key| !key.trim().is_empty())
}

/// Cerca un aggiornamento.
///
/// # Errors
/// Aggiornamenti non configurati in questa build, rete o manifesto non validi.
pub(crate) async fn check<R: Runtime>(
    app: &AppHandle<R>,
    pending: &PendingUpdate,
) -> Result<UpdateCheck, String> {
    let current = app.package_info().version.to_string();
    if !configured(app) {
        return Err("updates:unavailable".into());
    }
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?;
    let result = UpdateCheck {
        current,
        available: update.as_ref().map(|u| u.version.clone()),
        notes: update.as_ref().and_then(|u| u.body.clone()),
    };
    *pending.0.lock().unwrap_or_else(PoisonError::into_inner) = update;
    Ok(result)
}

/// Scarica, verifica e installa l'aggiornamento trovato, poi riavvia l'app.
///
/// # Errors
/// Nessun aggiornamento in attesa, download non riuscito o firma non valida.
pub(crate) async fn install<R: Runtime>(
    app: &AppHandle<R>,
    pending: &PendingUpdate,
    progress: Channel<Progress>,
) -> Result<(), String> {
    let update = pending
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or("nessun aggiornamento da installare")?;
    let mut downloaded: u64 = 0;
    update
        .download_and_install(
            |chunk, total| {
                downloaded = downloaded.saturating_add(u64::try_from(chunk).unwrap_or(0));
                let _ = progress.send(Progress { downloaded, total });
            },
            || {},
        )
        .await
        .map_err(|e| e.to_string())?;
    app.restart()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_check_preference_roundtrip() {
        let dir =
            std::env::temp_dir().join(format!("authenticator-updates-{}", std::process::id()));
        assert!(auto_check(&dir));
        set_auto_check(&dir, false).unwrap();
        assert!(!auto_check(&dir));
        set_auto_check(&dir, true).unwrap();
        set_auto_check(&dir, true).unwrap();
        assert!(auto_check(&dir));
        fs::remove_dir_all(&dir).unwrap();
    }
}
