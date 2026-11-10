//! App desktop: la UI della PWA in una webview Tauri, il core in Rust nativo.
//!
//! Il vault sbloccato vive solo in questo processo ([`Core`]): la webview riceve
//! metadati e codici, come dal Web Worker nella PWA, e non carica né WebAssembly né
//! il segreto di alcun account. I comandi rispecchiano `CoreApi` di
//! `apps/web/src/lib/protocol.ts`, più la lettura e il salvataggio del file del vault.
//!
//! I buffer ricevuti (password, file importati) vengono azzerati appena usati; le
//! copie intermedie create dalla deserializzazione IPC non sono sotto il nostro
//! controllo, come le stringhe JavaScript lato UI.

mod auto_lock;
mod clipboard;
mod platform_unlock;
mod screen;
mod storage;
mod updates;

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use authenticator_core::KdfParams;
use authenticator_session::Session;
use tauri::Manager;
use zeroize::Zeroizing;

/// Parametri Argon2id per le password create su desktop.
const KDF: KdfParams = KdfParams::NATIVE;

/// Errore restituito alla UI (che lo mostra o ne traduce il codice).
type CommandResult<T> = Result<T, String>;

/// Stato dell'app: la sessione sbloccata (se c'è) e il percorso del vault.
struct Core {
    session: Mutex<Option<Session>>,
    vault_path: PathBuf,
}

impl Core {
    /// Sostituisce la sessione: quella precedente viene rilasciata e azzerata.
    fn replace(&self, next: Option<Session>) {
        *self.session.lock().unwrap_or_else(PoisonError::into_inner) = next;
    }

    /// Esegue `f` sulla sessione sbloccata.
    fn with<T>(
        &self,
        f: impl FnOnce(&mut Session) -> authenticator_session::Result<T>,
    ) -> CommandResult<T> {
        let mut guard = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        let session = guard.as_mut().ok_or("vault bloccato")?;
        f(session).map_err(|e| e.to_string())
    }
}

fn text(e: impl core::fmt::Display) -> String {
    e.to_string()
}

/// Rende i buffer ricevuti dalla UI azzerabili al termine del comando.
fn secret(bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes)
}

// I comandi `async` girano fuori dal thread principale: Argon2id (centinaia di
// millisecondi) non blocca la finestra. Gli argomenti per valore sono richiesti da Tauri.
#[allow(clippy::needless_pass_by_value)]
mod commands {
    use std::collections::BTreeMap;

    use authenticator_session::{
        AccountView, CodeView, ImportView, ScanView, Session,
        external_slots as peek_external_slots, parse_id, unix_seconds,
    };
    use tauri::ipc::{Channel, InvokeBody, Request, Response};
    use tauri::{Manager, State};
    use zeroize::Zeroizing;

    use super::auto_lock::LockWatch;
    use super::clipboard::Clipboard;
    use super::updates::{self, PendingUpdate, Progress, UpdateCheck};
    use super::{CommandResult, Core, KDF, platform_unlock, screen, secret, storage, text};

    /// Vault cifrato salvato (vuoto se non esiste ancora: un vault reale non lo è mai).
    #[tauri::command(async)]
    pub(super) fn load_vault(core: State<'_, Core>) -> CommandResult<Response> {
        let data = storage::load(&core.vault_path).map_err(text)?;
        Ok(Response::new(data.unwrap_or_default()))
    }

    #[tauri::command(async)]
    pub(super) fn save_vault(request: Request<'_>, core: State<'_, Core>) -> CommandResult<()> {
        let InvokeBody::Raw(data) = request.body() else {
            return Err("vault non valido".into());
        };
        storage::save(&core.vault_path, data).map_err(text)
    }

    #[tauri::command(async)]
    pub(super) fn create(password: Vec<u8>, core: State<'_, Core>) -> CommandResult<()> {
        let password = secret(password);
        core.replace(Some(Session::create(&password, KDF).map_err(text)?));
        Ok(())
    }

    #[tauri::command(async)]
    pub(super) fn open(
        file: Vec<u8>,
        password: Vec<u8>,
        core: State<'_, Core>,
    ) -> CommandResult<()> {
        let password = secret(password);
        core.replace(Some(Session::open(&file, &password, KDF).map_err(text)?));
        Ok(())
    }

    #[tauri::command(async)]
    pub(super) fn open_recovery(
        file: Vec<u8>,
        recovery_key: String,
        core: State<'_, Core>,
    ) -> CommandResult<()> {
        let recovery_key = Zeroizing::new(recovery_key);
        let session = Session::open_recovery(&file, &recovery_key, KDF).map_err(text)?;
        core.replace(Some(session));
        Ok(())
    }

    #[tauri::command(async)]
    pub(super) fn open_external(
        file: Vec<u8>,
        slot_id: Vec<u8>,
        secret: Vec<u8>,
        core: State<'_, Core>,
    ) -> CommandResult<()> {
        let secret = super::secret(secret);
        let session = Session::open_external(&file, &slot_id, &secret, KDF).map_err(text)?;
        core.replace(Some(session));
        Ok(())
    }

    #[tauri::command(async)]
    pub(super) fn external_slots(file: Vec<u8>) -> CommandResult<Vec<String>> {
        peek_external_slots(&file).map_err(text)
    }

    /// Verifica la password su un vault salvato senza toccare la sessione corrente.
    #[tauri::command(async)]
    pub(super) fn verify(file: Vec<u8>, password: Vec<u8>) -> bool {
        let password = secret(password);
        Session::open(&file, &password, KDF).is_ok()
    }

    #[tauri::command(async)]
    pub(super) fn lock(core: State<'_, Core>) {
        core.replace(None);
    }

    #[tauri::command(async)]
    pub(super) fn seal(core: State<'_, Core>) -> CommandResult<Response> {
        core.with(|s| s.seal()).map(Response::new)
    }

    #[tauri::command(async)]
    pub(super) fn accounts(core: State<'_, Core>) -> CommandResult<Vec<AccountView>> {
        core.with(|s| Ok(s.accounts()))
    }

    #[tauri::command(async)]
    pub(super) fn codes(
        now: f64,
        core: State<'_, Core>,
    ) -> CommandResult<BTreeMap<String, CodeView>> {
        let now = unix_seconds(now).map_err(text)?;
        core.with(|s| s.totp_all(now))
    }

    #[tauri::command(async)]
    pub(super) fn next_hotp(id: String, core: State<'_, Core>) -> CommandResult<String> {
        core.with(|s| s.next_hotp(&id))
    }

    #[tauri::command(async)]
    pub(super) fn add_uri(uri: String, now: f64, core: State<'_, Core>) -> CommandResult<String> {
        // L'URI contiene il segreto dell'account.
        let uri = Zeroizing::new(uri);
        let now = unix_seconds(now).map_err(text)?;
        core.with(|s| s.add_uri(&uri, now))
    }

    #[tauri::command(async)]
    pub(super) fn remove(id: String, core: State<'_, Core>) -> CommandResult<bool> {
        core.with(|s| s.remove(&id))
    }

    #[tauri::command(async)]
    pub(super) fn import_data(
        format: String,
        data: Vec<u8>,
        password: Option<Vec<u8>>,
        now: f64,
        core: State<'_, Core>,
    ) -> CommandResult<ImportView> {
        let data = secret(data);
        let password = password.map(secret);
        let format = format.parse().map_err(text)?;
        let now = unix_seconds(now).map_err(text)?;
        core.with(|s| s.import(format, &data, password.as_deref().map(Vec::as_slice), now))
    }

    /// Fotogramma RGBA come corpo binario (evita di serializzare milioni di byte in
    /// JSON); dimensioni e orario negli header `width`, `height` e `now`.
    #[tauri::command(async)]
    pub(super) fn scan_qr(request: Request<'_>, core: State<'_, Core>) -> CommandResult<ScanView> {
        let InvokeBody::Raw(rgba) = request.body() else {
            return Err("immagine non valida".into());
        };
        let header = |name: &str| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| format!("header {name} mancante"))
        };
        let width = header("width")?.parse::<u32>().map_err(text)?;
        let height = header("height")?.parse::<u32>().map_err(text)?;
        let now = unix_seconds(header("now")?.parse::<f64>().map_err(text)?).map_err(text)?;
        core.with(|s| s.scan_qr(width, height, rgba, now))
    }

    /// Cattura lo schermo e aggiunge gli account dei QR visibili. La schermata resta
    /// nel processo nativo e viene azzerata dopo l'analisi.
    #[tauri::command]
    pub(super) async fn scan_screen(now: f64, core: State<'_, Core>) -> CommandResult<ScanView> {
        let now = unix_seconds(now).map_err(text)?;
        let screens = screen::capture().await?;
        core.with(|s| s.scan_screens(screens, now))
    }

    /// Copia un codice negli appunti di sistema; viene rimosso dopo 30 secondi se
    /// nel frattempo non è stato copiato altro.
    #[tauri::command(async)]
    pub(super) fn copy_code(code: String, clipboard: State<'_, Clipboard>) -> CommandResult<()> {
        clipboard.copy(Zeroizing::new(code))
    }

    /// Registra il canale su cui l'interfaccia riceve i blocchi automatici del processo
    /// nativo (sospensione del computer, finestra ridotta a icona).
    #[tauri::command]
    pub(super) fn watch_lock(on_lock: Channel<()>, watch: State<'_, LockWatch>) {
        watch.set(on_lock);
    }

    /// Cerca un aggiornamento dell'app (solo nelle build di release).
    #[tauri::command]
    pub(super) async fn check_update(
        app: tauri::AppHandle,
        pending: State<'_, PendingUpdate>,
    ) -> CommandResult<UpdateCheck> {
        updates::check(&app, &pending).await
    }

    /// Preferenza: cercare aggiornamenti all'avvio.
    #[tauri::command(async)]
    pub(super) fn update_auto_check(app: tauri::AppHandle) -> CommandResult<bool> {
        Ok(updates::auto_check(
            &app.path().app_data_dir().map_err(text)?,
        ))
    }

    #[tauri::command(async)]
    pub(super) fn set_update_auto_check(enabled: bool, app: tauri::AppHandle) -> CommandResult<()> {
        updates::set_auto_check(&app.path().app_data_dir().map_err(text)?, enabled).map_err(text)
    }

    /// Installa l'aggiornamento trovato dall'ultimo controllo e riavvia l'app.
    #[tauri::command]
    pub(super) async fn install_update(
        on_progress: Channel<Progress>,
        app: tauri::AppHandle,
        pending: State<'_, PendingUpdate>,
    ) -> CommandResult<()> {
        updates::install(&app, &pending, on_progress).await
    }

    #[tauri::command(async)]
    pub(super) fn change_password(password: Vec<u8>, core: State<'_, Core>) -> CommandResult<()> {
        let password = secret(password);
        core.with(|s| s.change_password(&password))
    }

    #[tauri::command(async)]
    pub(super) fn create_recovery_key(core: State<'_, Core>) -> CommandResult<String> {
        core.with(Session::create_recovery_key)
    }

    #[tauri::command(async)]
    pub(super) fn set_external(
        slot_id: Vec<u8>,
        secret: Vec<u8>,
        core: State<'_, Core>,
    ) -> CommandResult<()> {
        let secret = super::secret(secret);
        core.with(|s| s.set_external(&slot_id, &secret))
    }

    #[tauri::command(async)]
    pub(super) fn remove_external(slot_id: Vec<u8>, core: State<'_, Core>) -> CommandResult<()> {
        core.with(|s| s.remove_external(&slot_id))
    }

    #[tauri::command(async)]
    pub(super) fn export_backup(
        password: Vec<u8>,
        core: State<'_, Core>,
    ) -> CommandResult<Response> {
        let password = secret(password);
        core.with(|s| s.export_backup(&password)).map(Response::new)
    }

    #[tauri::command(async)]
    pub(super) fn restore_backup(
        data: Vec<u8>,
        password: Vec<u8>,
        now: f64,
        core: State<'_, Core>,
    ) -> CommandResult<ImportView> {
        let data = secret(data);
        let password = secret(password);
        let now = unix_seconds(now).map_err(text)?;
        core.with(|s| s.restore_backup(&data, &password, now))
    }

    /// Sblocco di sistema disponibile su questo computer (`null` se nessuno).
    #[tauri::command]
    pub(super) async fn platform_unlock() -> Option<platform_unlock::Method> {
        platform_unlock::method().await
    }

    /// Aggiunge al vault sbloccato uno slot sbloccabile con il sistema. Il segreto resta
    /// nel processo nativo; la UI salva poi il vault come dopo ogni modifica.
    #[tauri::command]
    pub(super) async fn enable_platform_unlock(core: State<'_, Core>) -> CommandResult<()> {
        // Prima di chiedere PIN o impronta: il vault deve essere aperto.
        core.with(|_| Ok(()))?;
        let slot = platform_unlock::new_slot_id()?;
        let secret = platform_unlock::enroll(slot).await?;
        if let Err(e) = core.with(|s| s.set_external(&slot, &secret)) {
            // Slot non aggiunto: il segreto appena creato non serve più.
            let _ = platform_unlock::forget(slot).await;
            return Err(e);
        }
        Ok(())
    }

    /// Apre il vault con il primo slot esterno che ha un segreto su questo dispositivo.
    #[tauri::command]
    pub(super) async fn unlock_with_platform(
        file: Vec<u8>,
        core: State<'_, Core>,
    ) -> CommandResult<()> {
        // Gli slot si leggono dal file, non dalla UI.
        for id in peek_external_slots(&file).map_err(text)? {
            let slot = parse_id(&id).map_err(text)?;
            if let Some(secret) = platform_unlock::secret(slot).await? {
                let session = Session::open_external(&file, &slot, &secret, KDF).map_err(text)?;
                core.replace(Some(session));
                return Ok(());
            }
        }
        Err("Lo sblocco di sistema non è attivo per questo vault su questo computer.".into())
    }

    /// Rimuove uno slot dal vault sbloccato ed elimina il suo segreto dal sistema.
    #[tauri::command]
    pub(super) async fn disable_platform_unlock(
        slot_id: String,
        core: State<'_, Core>,
    ) -> CommandResult<()> {
        let slot = parse_id(&slot_id).map_err(text)?;
        core.with(|s| s.remove_external(&slot))?;
        platform_unlock::forget(slot).await
    }
}

/// Avvia l'app.
///
/// # Errors
/// Webview non disponibile o cartella dati dell'app non determinabile.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        // Nessun permesso concesso alla webview: il plugin è usato solo dai comandi
        // `check_update` e `install_update`.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let vault_path = app.path().app_data_dir()?.join(storage::VAULT_FILE);
            app.manage(Core {
                session: Mutex::new(None),
                vault_path,
            });
            app.manage(clipboard::Clipboard::default());
            app.manage(auto_lock::LockWatch::default());
            app.manage(updates::PendingUpdate::default());
            auto_lock::start(app.handle().clone())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::load_vault,
            commands::save_vault,
            commands::create,
            commands::open,
            commands::open_recovery,
            commands::open_external,
            commands::external_slots,
            commands::verify,
            commands::lock,
            commands::seal,
            commands::accounts,
            commands::codes,
            commands::next_hotp,
            commands::add_uri,
            commands::remove,
            commands::import_data,
            commands::scan_qr,
            commands::change_password,
            commands::create_recovery_key,
            commands::set_external,
            commands::remove_external,
            commands::export_backup,
            commands::restore_backup,
            commands::platform_unlock,
            commands::enable_platform_unlock,
            commands::unlock_with_platform,
            commands::disable_platform_unlock,
            commands::scan_screen,
            commands::copy_code,
            commands::watch_lock,
            commands::check_update,
            commands::install_update,
            commands::update_auto_check,
            commands::set_update_auto_check,
        ])
        .run(tauri::generate_context!())
}
