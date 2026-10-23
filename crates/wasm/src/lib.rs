//! Binding WebAssembly del core per la PWA.
//!
//! Il vault sbloccato e i segreti OTP restano **solo** nella memoria WebAssembly:
//! JavaScript riceve metadati (issuer, nome, tipo) e i codici generati, mai i seed
//! né le chiavi. I risultati strutturati sono serializzati in JSON.

use authenticator_core::otp::Digits;
use authenticator_core::{
    Credential, EntryId, KdfParams, OtpAccount, OtpKind, RecoveryKey, Store, Vault, backup,
};
use authenticator_import::{ImportError, aegis, andotp, google, qr, twofas};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Sessione con il vault sbloccato. Liberarla (`free()` lato JS) azzera le chiavi.
#[wasm_bindgen]
pub struct Session {
    vault: Vault,
    store: Store,
}

#[derive(Serialize)]
struct AccountView<'a> {
    id: String,
    issuer: Option<&'a str>,
    name: &'a str,
    kind: &'static str,
    digits: u8,
    period: Option<u32>,
}

#[derive(Serialize)]
struct CodeView {
    code: String,
    remaining: u32,
    period: u32,
}

#[derive(Serialize)]
struct ScanView {
    /// QR trovati nell'immagine.
    found: usize,
    /// QR non riconosciuti come account (es. un link web).
    unsupported: usize,
    added: usize,
    duplicates: usize,
    skipped: usize,
}

#[derive(Serialize)]
struct ImportView {
    added: usize,
    duplicates: usize,
    skipped: usize,
}

fn err(e: impl core::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn to_json(value: &impl Serialize) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(err)
}

/// Converte i secondi Unix passati da JavaScript (number) in `u64`.
fn unix_seconds(value: f64) -> Result<u64, JsError> {
    if !(0.0..=1e12).contains(&value) {
        return Err(JsError::new("orario non valido"));
    }
    // Valore finito, non negativo e < 2^40: la conversione è esatta dopo il floor.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value.floor() as u64)
}

fn parse_id(id: &str) -> Result<EntryId, JsError> {
    let invalid = || JsError::new("id non valido");
    if id.len() != 32 {
        return Err(invalid());
    }
    let mut out = [0u8; 16];
    for (byte, pair) in out.iter_mut().zip(id.as_bytes().chunks_exact(2)) {
        let pair = core::str::from_utf8(pair).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

fn format_id(id: &EntryId) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(32);
    for b in id {
        // Scrivere su una String non fallisce.
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn import_error(e: ImportError) -> JsError {
    // Codici stabili per la UI (che li traduce), invece del testo libero.
    JsError::new(match e {
        ImportError::PasswordRequired => "import:password-required",
        ImportError::Decryption => "import:decryption",
        ImportError::UnsupportedVersion => "import:unsupported-version",
        ImportError::TooLarge => "import:too-large",
        _ => "import:invalid-format",
    })
}

#[wasm_bindgen]
impl Session {
    /// Crea un nuovo vault vuoto protetto da `password` (UTF-8, già normalizzata NFC).
    ///
    /// # Errors
    /// Password vuota o CSPRNG non disponibile.
    pub fn create(password: &[u8]) -> Result<Session, JsError> {
        Ok(Self {
            vault: Vault::create(password, KdfParams::WEB).map_err(err)?,
            store: Store::new(),
        })
    }

    /// Apre un vault salvato.
    ///
    /// # Errors
    /// Password errata, file manomesso o non valido.
    pub fn open(file: &[u8], password: &[u8]) -> Result<Session, JsError> {
        Self::open_with(file, Credential::Password(password))
    }

    /// Apre un vault con un segreto della piattaforma (es. output `WebAuthn` PRF).
    ///
    /// # Errors
    /// Segreto errato, slot inesistente o file non valido.
    pub fn open_external(file: &[u8], id: &[u8], secret: &[u8]) -> Result<Session, JsError> {
        let id: [u8; 16] = id
            .try_into()
            .map_err(|_| JsError::new("id slot non valido"))?;
        Self::open_with(file, Credential::External { id, secret })
    }

    /// Apre un vault con la recovery key.
    ///
    /// # Errors
    /// Recovery key errata o file non valido.
    pub fn open_recovery(file: &[u8], recovery_key: &str) -> Result<Session, JsError> {
        let key = RecoveryKey::parse(recovery_key).map_err(err)?;
        Self::open_with(file, Credential::Recovery(&key))
    }

    fn open_with(file: &[u8], credential: Credential<'_>) -> Result<Session, JsError> {
        let (vault, payload) = Vault::open(file, credential).map_err(err)?;
        let store = Store::decode(payload.expose()).map_err(err)?;
        Ok(Self { vault, store })
    }

    /// Cifra il vault corrente: il risultato è l'unica cosa da salvare su disco.
    ///
    /// # Errors
    /// Errore interno di serializzazione o cifratura.
    pub fn seal(&self) -> Result<Vec<u8>, JsError> {
        self.vault
            .seal(&self.store.encode().map_err(err)?)
            .map_err(err)
    }

    /// Elenco degli account (JSON): `[{id, issuer, name, kind, digits, period}]`.
    ///
    /// # Errors
    /// Errore interno di serializzazione.
    pub fn accounts(&self) -> Result<String, JsError> {
        let views: Vec<AccountView<'_>> = self
            .store
            .entries()
            .iter()
            .map(|e| {
                let (kind, period) = match e.account.kind {
                    OtpKind::Totp { period } => ("totp", Some(period.get())),
                    OtpKind::Hotp { .. } => ("hotp", None),
                };
                AccountView {
                    id: format_id(&e.id),
                    issuer: e.account.issuer.as_deref(),
                    name: &e.account.name,
                    kind,
                    digits: e.account.digits.get(),
                    period,
                }
            })
            .collect();
        to_json(&views)
    }

    /// Codice TOTP all'istante `unix_time` (JSON): `{code, remaining, period}`.
    ///
    /// # Errors
    /// Id sconosciuto, account HOTP o orario non valido.
    pub fn totp(&self, id: &str, unix_time: f64) -> Result<String, JsError> {
        let entry = self
            .store
            .get(&parse_id(id)?)
            .ok_or_else(|| JsError::new("account inesistente"))?;
        let OtpKind::Totp { period } = entry.account.kind else {
            return Err(JsError::new("account non TOTP"));
        };
        let totp = entry
            .account
            .totp_at(unix_seconds(unix_time)?)
            .map_err(err)?;
        to_json(&CodeView {
            code: totp.code.to_string(),
            remaining: totp.remaining_seconds,
            period: period.get(),
        })
    }

    /// Prossimo codice HOTP; avanza il contatore (salvare poi con [`Session::seal`]).
    ///
    /// # Errors
    /// Id sconosciuto o account TOTP.
    pub fn next_hotp(&mut self, id: &str) -> Result<String, JsError> {
        let entry = self
            .store
            .get_mut(&parse_id(id)?)
            .ok_or_else(|| JsError::new("account inesistente"))?;
        Ok(entry.account.next_hotp().map_err(err)?.to_string())
    }

    /// Aggiunge un account da URI `otpauth://` (es. da QR code). Restituisce l'id.
    ///
    /// # Errors
    /// URI non valido o account già presente (`duplicate`).
    pub fn add_uri(&mut self, uri: &str, now: f64) -> Result<String, JsError> {
        let account = OtpAccount::from_uri(uri).map_err(err)?;
        if self.store.contains_secret(&account.secret) {
            return Err(JsError::new("duplicate"));
        }
        let id = self.store.add(account, unix_seconds(now)?).map_err(err)?;
        Ok(format_id(&id))
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
        let luma = qr::rgba_to_luma(rgba).map_err(import_error)?;
        let width = usize::try_from(width).map_err(err)?;
        let height = usize::try_from(height).map_err(err)?;
        let codes = qr::decode_luma(width, height, &luma).map_err(import_error)?;

        let mut view = ScanView {
            found: codes.len(),
            unsupported: 0,
            added: 0,
            duplicates: 0,
            skipped: 0,
        };
        for content in &codes {
            let content = content.trim();
            let (accounts, skipped) = if let Ok(account) = OtpAccount::from_uri(content) {
                (vec![account], 0)
            } else if let Ok(batch) = google::parse_migration_uri(content) {
                (batch.accounts, batch.skipped)
            } else {
                view.unsupported += 1;
                continue;
            };
            let report = self.store.merge(accounts, now).map_err(err)?;
            view.added += report.added;
            view.duplicates += report.duplicates;
            view.skipped += skipped;
        }
        to_json(&view)
    }

    /// Rimuove un account. Restituisce `true` se esisteva.
    ///
    /// # Errors
    /// Id malformato.
    pub fn remove(&mut self, id: &str) -> Result<bool, JsError> {
        Ok(self.store.remove(&parse_id(id)?))
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
        let (accounts, skipped) = match format {
            "google" => {
                let uri = core::str::from_utf8(data)
                    .map_err(|_| import_error(ImportError::InvalidFormat))?;
                let batch = google::parse_migration_uri(uri.trim()).map_err(import_error)?;
                (batch.accounts, batch.skipped)
            }
            "aegis" => split(aegis::import(data, password).map_err(import_error)?),
            "andotp" => split(andotp::import(data, password).map_err(import_error)?),
            "2fas" => split(twofas::import(data, password).map_err(import_error)?),
            _ => return Err(JsError::new("import:unknown-format")),
        };
        let report = self
            .store
            .merge(accounts, unix_seconds(now)?)
            .map_err(err)?;
        to_json(&ImportView {
            added: report.added,
            duplicates: report.duplicates,
            skipped,
        })
    }

    /// Cambia la password del vault (gli altri slot restano validi).
    ///
    /// # Errors
    /// Password vuota.
    pub fn change_password(&mut self, password: &[u8]) -> Result<(), JsError> {
        self.vault
            .set_password(password, KdfParams::WEB)
            .map_err(err)
    }

    /// Genera una nuova recovery key e la restituisce **una sola volta**, da mostrare
    /// all'utente perché la trascriva. Sostituisce la precedente.
    ///
    /// # Errors
    /// CSPRNG non disponibile.
    pub fn create_recovery_key(&mut self) -> Result<String, JsError> {
        let key = self.vault.create_recovery_key().map_err(err)?;
        Ok(key.to_display_string().to_string())
    }

    /// Aggiunge uno slot sbloccabile con un segreto della piattaforma (es. passkey PRF).
    ///
    /// # Errors
    /// Id non di 16 byte, segreto troppo corto o troppi slot.
    pub fn set_external(&mut self, id: &[u8], secret: &[u8]) -> Result<(), JsError> {
        let id: [u8; 16] = id
            .try_into()
            .map_err(|_| JsError::new("id slot non valido"))?;
        self.vault.set_external(id, secret).map_err(err)
    }

    /// Backup cifrato con una password dedicata (formato `.authbackup`).
    ///
    /// # Errors
    /// Password vuota.
    pub fn export_backup(&self, password: &[u8]) -> Result<Vec<u8>, JsError> {
        backup::export_encrypted(&self.store, password, KdfParams::WEB).map_err(err)
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
        let restored = backup::import_encrypted(data, password).map_err(err)?;
        let accounts: Vec<OtpAccount> = restored
            .into_entries()
            .into_iter()
            .map(|e| e.account)
            .collect();
        let report = self
            .store
            .merge(accounts, unix_seconds(now)?)
            .map_err(err)?;
        to_json(&ImportView {
            added: report.added,
            duplicates: report.duplicates,
            skipped: 0,
        })
    }
}

fn split(imported: authenticator_import::Imported) -> (Vec<OtpAccount>, usize) {
    (imported.accounts, imported.skipped)
}

/// Numero di cifre di default (per la UI di inserimento manuale).
#[wasm_bindgen]
#[must_use]
pub fn default_digits() -> u8 {
    Digits::default().get()
}

#[cfg(test)]
mod tests {
    use super::*;

    // JsError richiede un runtime JS: qui si testano solo le parti pure.

    #[test]
    fn ids_roundtrip() {
        let id = [0xab; 16];
        assert_eq!(parse_id(&format_id(&id)).ok(), Some(id));
    }

    #[test]
    fn time_conversion() {
        assert_eq!(unix_seconds(1_700_000_000.9).ok(), Some(1_700_000_000));
    }
}
