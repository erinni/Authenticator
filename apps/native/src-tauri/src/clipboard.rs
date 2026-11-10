//! Appunti di sistema per i codici copiati.
//!
//! Un thread dedicato possiede gli appunti (su Linux il contenuto è servito dal processo
//! che lo ha copiato) e, dopo [`CLEAR_AFTER`], li svuota solo se contengono ancora il
//! codice copiato: se nel frattempo l'utente ha copiato altro, non viene toccato.
//! Su Windows il codice è escluso dalla cronologia degli appunti e dalla
//! sincronizzazione cloud; su macOS e Linux viene segnalato ai gestori di appunti come
//! dato da non conservare.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Durata prima che il codice copiato venga rimosso dagli appunti.
const CLEAR_AFTER: Duration = Duration::from_secs(30);
/// Lunghezza massima di un codice (TOTP/HOTP fino a 10 cifre, Steam 5 caratteri).
const MAX_CODE_LEN: usize = 10;

/// Richiesta al thread: il codice da copiare e dove rispondere.
type Request = (Zeroizing<String>, mpsc::Sender<Result<(), String>>);

/// Canale verso il thread degli appunti, avviato al primo uso.
#[derive(Default)]
pub(crate) struct Clipboard(Mutex<Option<mpsc::Sender<Request>>>);

impl Clipboard {
    /// Copia un codice negli appunti.
    ///
    /// # Errors
    /// Codice non valido (accetta solo lettere e cifre) o appunti non disponibili.
    pub(crate) fn copy(&self, code: Zeroizing<String>) -> Result<(), String> {
        if code.is_empty()
            || code.len() > MAX_CODE_LEN
            || !code.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err("codice non valido".into());
        }
        let (reply, result) = mpsc::channel();
        {
            let mut sender = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if sender.is_none() {
                let (tx, rx) = mpsc::channel();
                thread::Builder::new()
                    .name("clipboard".into())
                    .spawn(move || serve(&rx))
                    .map_err(|e| e.to_string())?;
                *sender = Some(tx);
            }
            sender
                .as_ref()
                .ok_or("appunti non disponibili")?
                .send((code, reply))
                .map_err(|e| e.to_string())?;
        }
        result.recv().map_err(|e| e.to_string())?
    }
}

/// Ciclo del thread: copia i codici richiesti e svuota gli appunti alla scadenza.
fn serve(requests: &mpsc::Receiver<Request>) {
    let mut clipboard: Option<arboard::Clipboard> = None;
    let mut pending: Option<(Zeroizing<String>, Instant)> = None;
    loop {
        let request = match &pending {
            Some((_, deadline)) => {
                requests.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => requests.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match request {
            Ok((code, reply)) => {
                let result = copy(&mut clipboard, &code);
                if result.is_ok() {
                    pending = Some((code, Instant::now() + CLEAR_AFTER));
                }
                let _ = reply.send(result.map_err(|e| e.to_string()));
            }
            Err(RecvTimeoutError::Timeout) => {
                if let (Some(board), Some((code, _))) = (clipboard.as_mut(), pending.take()) {
                    // Gli appunti vengono svuotati solo se contengono ancora il codice.
                    let current = board.get_text().map(Zeroizing::new);
                    if current.is_ok_and(|text| *text == *code) {
                        let _ = board.clear();
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn copy(clipboard: &mut Option<arboard::Clipboard>, code: &str) -> Result<(), arboard::Error> {
    let board = match clipboard {
        Some(board) => board,
        None => clipboard.insert(arboard::Clipboard::new()?),
    };
    let set = board.set();
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_history().exclude_from_cloud()
    };
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple;
        set.exclude_from_history()
    };
    #[cfg(target_os = "linux")]
    let set = {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    };
    set.text(code)
}
