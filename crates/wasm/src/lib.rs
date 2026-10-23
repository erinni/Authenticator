//! Binding WebAssembly del core per la PWA.
//!
//! Il vault sbloccato e i segreti OTP restano **solo** nella memoria WebAssembly:
//! JavaScript riceve metadati (issuer, nome, tipo) e i codici generati, mai i seed
//! né le chiavi. La logica è in `authenticator-session`, condivisa con le app native;
//! qui si convertono solo i tipi e si serializzano i risultati strutturati in JSON.

use authenticator_core::KdfParams;
use authenticator_core::otp::Digits;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Parametri Argon2id: WebAssembly è single-thread.
const KDF: KdfParams = KdfParams::WEB;

/// Sessione con il vault sbloccato. Liberarla (`free()` lato JS) azzera le chiavi.
#[wasm_bindgen]
pub struct Session(authenticator_session::Session);

fn err(e: impl core::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn to_json(value: &impl Serialize) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(err)
}

fn unix_seconds(value: f64) -> Result<u64, JsError> {
    authenticator_session::unix_seconds(value).map_err(err)
}

#[wasm_bindgen]
impl Session {
    /// Crea un nuovo vault vuoto protetto da `password` (UTF-8, già normalizzata NFC).
    ///
    /// # Errors
    /// Password vuota o CSPRNG non disponibile.
    pub fn create(password: &[u8]) -> Result<Session, JsError> {
        Ok(Self(
            authenticator_session::Session::create(password, KDF).map_err(err)?,
        ))
    }

    /// Apre un vault salvato.
    ///
    /// # Errors
    /// Password errata, file manomesso o non valido.
    pub fn open(file: &[u8], password: &[u8]) -> Result<Session, JsError> {
        Ok(Self(
            authenticator_session::Session::open(file, password, KDF).map_err(err)?,
        ))
    }

    /// Apre un vault con un segreto della piattaforma (es. output `WebAuthn` PRF).
    ///
    /// # Errors
    /// Segreto errato, slot inesistente o file non valido.
    pub fn open_external(file: &[u8], id: &[u8], secret: &[u8]) -> Result<Session, JsError> {
        Ok(Self(
            authenticator_session::Session::open_external(file, id, secret, KDF).map_err(err)?,
        ))
    }

    /// Apre un vault con la recovery key.
    ///
    /// # Errors
    /// Recovery key errata o file non valido.
    pub fn open_recovery(file: &[u8], recovery_key: &str) -> Result<Session, JsError> {
        Ok(Self(
            authenticator_session::Session::open_recovery(file, recovery_key, KDF).map_err(err)?,
        ))
    }

    /// Cifra il vault corrente: il risultato è l'unica cosa da salvare su disco.
    ///
    /// # Errors
    /// Errore interno di serializzazione o cifratura.
    pub fn seal(&self) -> Result<Vec<u8>, JsError> {
        self.0.seal().map_err(err)
    }

    /// Elenco degli account (JSON): `[{id, issuer, name, kind, digits, period}]`.
    ///
    /// # Errors
    /// Errore interno di serializzazione.
    pub fn accounts(&self) -> Result<String, JsError> {
        to_json(&self.0.accounts())
    }

    /// Codice TOTP all'istante `unix_time` (JSON): `{code, remaining, period}`.
    ///
    /// # Errors
    /// Id sconosciuto, account HOTP o orario non valido.
    pub fn totp(&self, id: &str, unix_time: f64) -> Result<String, JsError> {
        to_json(&self.0.totp(id, unix_seconds(unix_time)?).map_err(err)?)
    }

    /// Codici TOTP di tutti gli account all'istante `unix_time` (JSON):
    /// `{id: {code, remaining, period}}`. Gli account HOTP sono esclusi.
    ///
    /// # Errors
    /// Orario non valido.
    pub fn totp_all(&self, unix_time: f64) -> Result<String, JsError> {
        to_json(&self.0.totp_all(unix_seconds(unix_time)?).map_err(err)?)
    }

    /// Prossimo codice HOTP; avanza il contatore (salvare poi con [`Session::seal`]).
    ///
    /// # Errors
    /// Id sconosciuto o account TOTP.
    pub fn next_hotp(&mut self, id: &str) -> Result<String, JsError> {
        self.0.next_hotp(id).map_err(err)
    }

    /// Aggiunge un account da URI `otpauth://` (es. da QR code). Restituisce l'id.
    ///
    /// # Errors
    /// URI non valido o account già presente (`duplicate`).
    pub fn add_uri(&mut self, uri: &str, now: f64) -> Result<String, JsError> {
        self.0.add_uri(uri, unix_seconds(now)?).map_err(err)
    }

    /// Cerca QR code in un fotogramma RGBA (`ImageData` di un canvas) e aggiunge gli
    /// account trovati (`otpauth://` e `otpauth-migration://`). JSON:
    /// `{found, unsupported, added, duplicates, skipped}`.
    ///
    /// Il contenuto dei QR (che include i segreti) non viene mai restituito a JavaScript.
    ///
    /// # Errors
    /// Immagine troppo grande o dimensioni non coerenti con i dati.
    pub fn scan_qr(
        &mut self,
        width: u32,
        height: u32,
        rgba: &[u8],
        now: f64,
    ) -> Result<String, JsError> {
        let now = unix_seconds(now)?;
        to_json(&self.0.scan_qr(width, height, rgba, now).map_err(err)?)
    }

    /// Rimuove un account. Restituisce `true` se esisteva.
    ///
    /// # Errors
    /// Id malformato.
    pub fn remove(&mut self, id: &str) -> Result<bool, JsError> {
        self.0.remove(id).map_err(err)
    }

    /// Importa da un file o URI di un'altra app (JSON): `{added, duplicates, skipped}`.
    ///
    /// `format`: `google` (URI `otpauth-migration://`), `aegis`, `andotp`, `2fas`.
    ///
    /// # Errors
    /// Codici `import:*` per file non validi o password mancante/errata.
    pub fn import(
        &mut self,
        format: &str,
        data: &[u8],
        password: Option<Vec<u8>>,
        now: f64,
    ) -> Result<String, JsError> {
        let password = password.map(zeroize::Zeroizing::new);
        let password = password.as_deref().map(Vec::as_slice);
        let format = format.parse().map_err(err)?;
        let now = unix_seconds(now)?;
        to_json(&self.0.import(format, data, password, now).map_err(err)?)
    }

    /// Cambia la password del vault (gli altri slot restano validi).
    ///
    /// # Errors
    /// Password vuota.
    pub fn change_password(&mut self, password: &[u8]) -> Result<(), JsError> {
        self.0.change_password(password).map_err(err)
    }

    /// Genera una nuova recovery key e la restituisce **una sola volta**, da mostrare
    /// all'utente perché la trascriva. Sostituisce la precedente.
    ///
    /// # Errors
    /// CSPRNG non disponibile.
    pub fn create_recovery_key(&mut self) -> Result<String, JsError> {
        self.0.create_recovery_key().map_err(err)
    }

    /// Aggiunge uno slot sbloccabile con un segreto della piattaforma (es. passkey PRF).
    ///
    /// # Errors
    /// Id non di 16 byte, segreto troppo corto o troppi slot.
    pub fn set_external(&mut self, id: &[u8], secret: &[u8]) -> Result<(), JsError> {
        self.0.set_external(id, secret).map_err(err)
    }

    /// Rimuove lo slot esterno con l'id indicato (es. passkey revocata).
    ///
    /// # Errors
    /// Id non di 16 byte o slot inesistente.
    pub fn remove_external(&mut self, id: &[u8]) -> Result<(), JsError> {
        self.0.remove_external(id).map_err(err)
    }

    /// Backup cifrato con una password dedicata (formato `.authbackup`).
    ///
    /// # Errors
    /// Password vuota.
    pub fn export_backup(&self, password: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.export_backup(password).map_err(err)
    }

    /// Ripristina gli account da un backup cifrato, senza duplicati (JSON come [`Session::import`]).
    ///
    /// # Errors
    /// Password errata o file non valido.
    pub fn restore_backup(
        &mut self,
        data: &[u8],
        password: &[u8],
        now: f64,
    ) -> Result<String, JsError> {
        let now = unix_seconds(now)?;
        to_json(&self.0.restore_backup(data, password, now).map_err(err)?)
    }
}

/// Id (esadecimali, JSON) degli slot esterni di un vault salvato, **senza** sbloccarlo:
/// la UI li usa per proporre lo sblocco con passkey.
///
/// # Errors
/// File non valido.
#[wasm_bindgen]
pub fn external_slots(file: &[u8]) -> Result<String, JsError> {
    to_json(&authenticator_session::external_slots(file).map_err(err)?)
}

/// Numero di cifre di default (per la UI di inserimento manuale).
#[wasm_bindgen]
#[must_use]
pub fn default_digits() -> u8 {
    Digits::default().get()
}
