//! Blocco automatico nel processo nativo: dopo la sospensione o l'ibernazione del
//! computer e con la finestra ridotta a icona per più di [`MINIMIZED_LOCK`].
//!
//! La sospensione si riconosce dal salto dell'orologio: un thread si risveglia ogni
//! [`TICK`] e, se l'ora di sistema è avanzata molto di più, il computer è stato fermo.
//! Non servono API specifiche del sistema operativo. Un cambio manuale dell'ora in
//! avanti blocca anch'esso il vault, che è il comportamento prudente.
//!
//! Il blocco azzera la sessione qui, anche se la webview è rallentata o sospesa, e
//! avvisa l'interfaccia sul canale registrato con il comando `watch_lock`.

use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime};

use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, Runtime};

use super::Core;

/// Intervallo del controllo.
const TICK: Duration = Duration::from_secs(5);
/// Avanzamento dell'orologio oltre il quale il computer è stato sospeso.
const SUSPEND_GAP: Duration = Duration::from_secs(30);
/// Tempo con la finestra ridotta a icona prima del blocco (come la scheda nascosta nella PWA).
pub(crate) const MINIMIZED_LOCK: Duration = Duration::from_mins(1);

/// Canale dell'interfaccia da avvisare quando il vault viene bloccato.
#[derive(Default)]
pub(crate) struct LockWatch(Mutex<Option<Channel<()>>>);

impl LockWatch {
    pub(crate) fn set(&self, channel: Channel<()>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(channel);
    }
}

/// Avvia il controllo per tutta la durata dell'app.
///
/// # Errors
/// Il thread non può essere creato.
pub(crate) fn start<R: Runtime>(app: AppHandle<R>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("auto-lock".into())
        .spawn(move || watch(&app))
        .map(drop)
}

fn watch<R: Runtime>(app: &AppHandle<R>) {
    let mut last = SystemTime::now();
    let mut minimized = Duration::ZERO;
    loop {
        thread::sleep(TICK);
        let now = SystemTime::now();
        // Un orologio che torna indietro (sincronizzazione NTP) non indica una sospensione.
        let elapsed = now.duration_since(last).unwrap_or(TICK);
        last = now;

        let hidden = app
            .get_webview_window("main")
            .is_some_and(|window| window.is_minimized().unwrap_or(false));
        minimized = if hidden {
            minimized + elapsed
        } else {
            Duration::ZERO
        };

        if suspended(elapsed) || minimized >= MINIMIZED_LOCK {
            lock(app);
        }
    }
}

/// `true` se tra due controlli è passato molto più tempo del previsto.
fn suspended(elapsed: Duration) -> bool {
    elapsed > TICK + SUSPEND_GAP
}

/// Azzera la sessione, se sbloccata, e avvisa l'interfaccia.
fn lock<R: Runtime>(app: &AppHandle<R>) {
    let core = app.state::<Core>();
    let mut session = core.session.lock().unwrap_or_else(PoisonError::into_inner);
    if session.take().is_none() {
        return;
    }
    drop(session);
    let watch = app.state::<LockWatch>();
    if let Some(channel) = watch
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
    {
        let _ = channel.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_suspension_from_clock_jumps() {
        assert!(!suspended(TICK));
        assert!(!suspended(TICK + Duration::from_secs(20)));
        assert!(suspended(Duration::from_hours(1)));
    }
}
