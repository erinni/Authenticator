//! Sessione con il vault sbloccato, condivisa dalle piattaforme.
//!
//! La PWA la usa tramite il binding WebAssembly (`crates/wasm`), le app native
//! tramite i comandi Tauri (`apps/native`). In entrambi i casi il vault sbloccato e
//! i segreti OTP restano in Rust: verso l'interfaccia escono solo metadati
//! (issuer, nome, tipo) e i codici generati, mai i seed né le chiavi.

use std::borrow::Cow;
use std::collections::BTreeMap;

use authenticator_core::vault::SlotKind;
use authenticator_core::{
    Credential, EntryId, KdfParams, OtpAccount, OtpKind, RecoveryKey, Store, Vault, backup,
};
use authenticator_import::{ImportError, aegis, andotp, google, qr, twofas};
use serde::Serialize;

/// Errore restituito all'interfaccia: un messaggio, oppure un codice stabile
/// (`duplicate`, `import:*`) che la UI traduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(Cow<'static, str>);

impl Error {
    fn new(message: &'static str) -> Self {
        Self(Cow::Borrowed(message))
    }

    fn from_display(e: impl core::fmt::Display) -> Self {
        Self(Cow::Owned(e.to_string()))
    }

    /// Testo dell'errore.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Risultato delle operazioni della sessione.
pub type Result<T, E = Error> = core::result::Result<T, E>;

fn err(e: impl core::fmt::Display) -> Error {
    Error::from_display(e)
}

/// Metadati di un account, senza segreti.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountView {
    /// Id esadecimale (32 caratteri).
    pub id: String,
    /// Emittente (es. il nome del servizio).
    pub issuer: Option<String>,
    /// Nome dell'account (es. l'indirizzo email).
    pub name: String,
    /// `totp` o `hotp`.
    pub kind: &'static str,
    /// Cifre del codice.
    pub digits: u8,
    /// Periodo in secondi (solo TOTP).
    pub period: Option<u32>,
}

/// Codice TOTP corrente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeView {
    /// Codice (con gli zeri iniziali).
    pub code: String,
    /// Secondi alla scadenza.
    pub remaining: u32,
    /// Periodo in secondi.
    pub period: u32,
}

/// Esito di un import o di un ripristino.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ImportView {
    /// Account aggiunti.
    pub added: usize,
    /// Account già presenti, ignorati.
    pub duplicates: usize,
    /// Account non supportati, ignorati.
    pub skipped: usize,
}

/// Esito della scansione di un fotogramma.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScanView {
    /// QR trovati nell'immagine.
    pub found: usize,
    /// QR non riconosciuti come account (es. un link web).
    pub unsupported: usize,
    /// Account aggiunti.
    pub added: usize,
    /// Account già presenti, ignorati.
    pub duplicates: usize,
    /// Account non supportati, ignorati.
    pub skipped: usize,
}

/// Formati di import da altre app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// URI `otpauth-migration://` di Google Authenticator.
    Google,
    /// Export JSON di Aegis (anche cifrato).
    Aegis,
    /// Export di andOTP (anche cifrato).
    AndOtp,
    /// Export di 2FAS (anche cifrato).
    TwoFas,
}

impl core::str::FromStr for ImportFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "google" => Ok(Self::Google),
            "aegis" => Ok(Self::Aegis),
            "andotp" => Ok(Self::AndOtp),
            "2fas" => Ok(Self::TwoFas),
            _ => Err(Error::new("import:unknown-format")),
        }
    }
}

/// Converte i secondi Unix ricevuti da JavaScript (un `number`) in `u64`.
///
/// # Errors
/// Valore negativo, non finito o oltre l'anno 33658.
pub fn unix_seconds(value: f64) -> Result<u64> {
    if !(0.0..=1e12).contains(&value) {
        return Err(Error::new("orario non valido"));
    }
    // Valore finito, non negativo e < 2^40: la conversione è esatta dopo il floor.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value.floor() as u64)
}

/// Converte un id esadecimale (come in [`AccountView::id`]).
///
/// # Errors
/// Id malformato.
pub fn parse_id(id: &str) -> Result<EntryId> {
    let invalid = || Error::new("id non valido");
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

/// Id in esadecimale minuscolo.
#[must_use]
pub fn format_id(id: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(id.len() * 2);
    for b in id {
        // Scrivere su una String non fallisce.
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn slot_id(id: &[u8]) -> Result<[u8; 16]> {
    id.try_into().map_err(|_| Error::new("id slot non valido"))
}

fn import_error(e: ImportError) -> Error {
    // Codici stabili per la UI (che li traduce), invece del testo libero.
    Error::new(match e {
        ImportError::PasswordRequired => "import:password-required",
        ImportError::Decryption => "import:decryption",
        ImportError::UnsupportedVersion => "import:unsupported-version",
        ImportError::TooLarge => "import:too-large",
        _ => "import:invalid-format",
    })
}

fn split(imported: authenticator_import::Imported) -> (Vec<OtpAccount>, usize) {
    (imported.accounts, imported.skipped)
}

/// Id (esadecimali) degli slot esterni di un vault salvato, **senza** sbloccarlo:
/// la UI li usa per proporre lo sblocco con passkey o con la piattaforma.
///
/// # Errors
/// File non valido.
pub fn external_slots(file: &[u8]) -> Result<Vec<String>> {
    Ok(external_ids(&Vault::peek_slots(file).map_err(err)?))
}

fn external_ids(slots: &[SlotKind]) -> Vec<String> {
    slots
        .iter()
        .filter_map(|kind| match kind {
            SlotKind::External(id) => Some(format_id(id)),
            _ => None,
        })
        .collect()
}

/// Sessione con il vault sbloccato. Al drop il core azzera le chiavi.
pub struct Session {
    vault: Vault,
    store: Store,
    /// Parametri Argon2id per le nuove password (vault e backup).
    kdf: KdfParams,
}

impl Session {
    /// Crea un nuovo vault vuoto protetto da `password` (UTF-8, già normalizzata NFC).
    ///
    /// # Errors
    /// Password vuota o CSPRNG non disponibile.
    pub fn create(password: &[u8], kdf: KdfParams) -> Result<Self> {
        Ok(Self {
            vault: Vault::create(password, kdf).map_err(err)?,
            store: Store::new(),
            kdf,
        })
    }

    /// Apre un vault salvato.
    ///
    /// # Errors
    /// Password errata, file manomesso o non valido.
    pub fn open(file: &[u8], password: &[u8], kdf: KdfParams) -> Result<Self> {
        Self::open_with(file, Credential::Password(password), kdf)
    }

    /// Apre un vault con un segreto della piattaforma (es. output `WebAuthn` PRF).
    ///
    /// # Errors
    /// Segreto errato, slot inesistente o file non valido.
    pub fn open_external(file: &[u8], id: &[u8], secret: &[u8], kdf: KdfParams) -> Result<Self> {
        let id = slot_id(id)?;
        Self::open_with(file, Credential::External { id, secret }, kdf)
    }

    /// Apre un vault con la recovery key.
    ///
    /// # Errors
    /// Recovery key errata o file non valido.
    pub fn open_recovery(file: &[u8], recovery_key: &str, kdf: KdfParams) -> Result<Self> {
        let key = RecoveryKey::parse(recovery_key).map_err(err)?;
        Self::open_with(file, Credential::Recovery(&key), kdf)
    }

    fn open_with(file: &[u8], credential: Credential<'_>, kdf: KdfParams) -> Result<Self> {
        let (vault, payload) = Vault::open(file, credential).map_err(err)?;
        let store = Store::decode(payload.expose()).map_err(err)?;
        Ok(Self { vault, store, kdf })
    }

    /// Cifra il vault corrente: il risultato è l'unica cosa da salvare su disco.
    ///
    /// # Errors
    /// Errore interno di serializzazione o cifratura.
    pub fn seal(&self) -> Result<Vec<u8>> {
        self.vault
            .seal(&self.store.encode().map_err(err)?)
            .map_err(err)
    }

    /// Elenco degli account, senza segreti.
    #[must_use]
    pub fn accounts(&self) -> Vec<AccountView> {
        self.store
            .entries()
            .iter()
            .map(|e| {
                let (kind, period) = match e.account.kind {
                    OtpKind::Totp { period } => ("totp", Some(period.get())),
                    OtpKind::Hotp { .. } => ("hotp", None),
                };
                AccountView {
                    id: format_id(&e.id),
                    issuer: e.account.issuer.clone(),
                    name: e.account.name.clone(),
                    kind,
                    digits: e.account.digits.get(),
                    period,
                }
            })
            .collect()
    }

    /// Codice TOTP di un account all'istante `now` (secondi Unix).
    ///
    /// # Errors
    /// Id sconosciuto o account HOTP.
    pub fn totp(&self, id: &str, now: u64) -> Result<CodeView> {
        let entry = self
            .store
            .get(&parse_id(id)?)
            .ok_or_else(|| Error::new("account inesistente"))?;
        let OtpKind::Totp { period } = entry.account.kind else {
            return Err(Error::new("account non TOTP"));
        };
        let totp = entry.account.totp_at(now).map_err(err)?;
        Ok(CodeView {
            code: totp.code.to_string(),
            remaining: totp.remaining_seconds,
            period: period.get(),
        })
    }

    /// Codici TOTP di tutti gli account all'istante `now`, per id. Gli HOTP sono esclusi.
    ///
    /// # Errors
    /// Orario non rappresentabile.
    pub fn totp_all(&self, now: u64) -> Result<BTreeMap<String, CodeView>> {
        let mut codes = BTreeMap::new();
        for entry in self.store.entries() {
            if let OtpKind::Totp { period } = entry.account.kind {
                let totp = entry.account.totp_at(now).map_err(err)?;
                codes.insert(
                    format_id(&entry.id),
                    CodeView {
                        code: totp.code.to_string(),
                        remaining: totp.remaining_seconds,
                        period: period.get(),
                    },
                );
            }
        }
        Ok(codes)
    }

    /// Prossimo codice HOTP; avanza il contatore (salvare poi con [`Session::seal`]).
    ///
    /// # Errors
    /// Id sconosciuto o account TOTP.
    pub fn next_hotp(&mut self, id: &str) -> Result<String> {
        let entry = self
            .store
            .get_mut(&parse_id(id)?)
            .ok_or_else(|| Error::new("account inesistente"))?;
        Ok(entry.account.next_hotp().map_err(err)?.to_string())
    }

    /// Aggiunge un account da URI `otpauth://` (es. da QR code). Restituisce l'id.
    ///
    /// # Errors
    /// URI non valido o account già presente (`duplicate`).
    pub fn add_uri(&mut self, uri: &str, now: u64) -> Result<String> {
        let account = OtpAccount::from_uri(uri).map_err(err)?;
        if self.store.contains_secret(&account.secret) {
            return Err(Error::new("duplicate"));
        }
        let id = self.store.add(account, now).map_err(err)?;
        Ok(format_id(&id))
    }

    /// Cerca QR code in un fotogramma RGBA e aggiunge gli account trovati
    /// (`otpauth://` e `otpauth-migration://`).
    ///
    /// Il contenuto dei QR (che include i segreti) non viene mai restituito.
    ///
    /// # Errors
    /// Immagine troppo grande o dimensioni non coerenti con i dati.
    pub fn scan_qr(&mut self, width: u32, height: u32, rgba: &[u8], now: u64) -> Result<ScanView> {
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
        Ok(view)
    }

    /// Rimuove un account. Restituisce `true` se esisteva.
    ///
    /// # Errors
    /// Id malformato.
    pub fn remove(&mut self, id: &str) -> Result<bool> {
        Ok(self.store.remove(&parse_id(id)?))
    }

    /// Importa da un file o URI di un'altra app.
    ///
    /// # Errors
    /// Codici `import:*` per file non validi o password mancante/errata.
    pub fn import(
        &mut self,
        format: ImportFormat,
        data: &[u8],
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<ImportView> {
        let (accounts, skipped) = match format {
            ImportFormat::Google => {
                let uri = core::str::from_utf8(data)
                    .map_err(|_| import_error(ImportError::InvalidFormat))?;
                let batch = google::parse_migration_uri(uri.trim()).map_err(import_error)?;
                (batch.accounts, batch.skipped)
            }
            ImportFormat::Aegis => split(aegis::import(data, password).map_err(import_error)?),
            ImportFormat::AndOtp => split(andotp::import(data, password).map_err(import_error)?),
            ImportFormat::TwoFas => split(twofas::import(data, password).map_err(import_error)?),
        };
        let report = self.store.merge(accounts, now).map_err(err)?;
        Ok(ImportView {
            added: report.added,
            duplicates: report.duplicates,
            skipped,
        })
    }

    /// Cambia la password del vault (gli altri slot restano validi).
    ///
    /// # Errors
    /// Password vuota.
    pub fn change_password(&mut self, password: &[u8]) -> Result<()> {
        self.vault.set_password(password, self.kdf).map_err(err)
    }

    /// Genera una nuova recovery key e la restituisce **una sola volta**, da mostrare
    /// all'utente perché la trascriva. Sostituisce la precedente.
    ///
    /// # Errors
    /// CSPRNG non disponibile.
    pub fn create_recovery_key(&mut self) -> Result<String> {
        let key = self.vault.create_recovery_key().map_err(err)?;
        Ok(key.to_display_string().to_string())
    }

    /// Aggiunge uno slot sbloccabile con un segreto della piattaforma (es. passkey PRF).
    ///
    /// # Errors
    /// Id non di 16 byte, segreto troppo corto o troppi slot.
    pub fn set_external(&mut self, id: &[u8], secret: &[u8]) -> Result<()> {
        self.vault.set_external(slot_id(id)?, secret).map_err(err)
    }

    /// Rimuove lo slot esterno con l'id indicato (es. passkey revocata).
    ///
    /// # Errors
    /// Id non di 16 byte o slot inesistente.
    pub fn remove_external(&mut self, id: &[u8]) -> Result<()> {
        self.vault.remove_external(slot_id(id)?).map_err(err)
    }

    /// Backup cifrato con una password dedicata (formato `.authbackup`).
    ///
    /// # Errors
    /// Password vuota.
    pub fn export_backup(&self, password: &[u8]) -> Result<Vec<u8>> {
        backup::export_encrypted(&self.store, password, self.kdf).map_err(err)
    }

    /// Ripristina gli account da un backup cifrato, senza duplicati.
    ///
    /// # Errors
    /// Password errata o file non valido.
    pub fn restore_backup(&mut self, data: &[u8], password: &[u8], now: u64) -> Result<ImportView> {
        let restored = backup::import_encrypted(data, password).map_err(err)?;
        let accounts: Vec<OtpAccount> = restored
            .into_entries()
            .into_iter()
            .map(|e| e.account)
            .collect();
        let report = self.store.merge(accounts, now).map_err(err)?;
        Ok(ImportView {
            added: report.added,
            duplicates: report.duplicates,
            skipped: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const URI: &str =
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    fn session() -> Session {
        Session::create(PASSWORD, KdfParams::MINIMUM).unwrap()
    }

    #[test]
    fn ids_roundtrip() {
        let id = [0xab; 16];
        assert_eq!(parse_id(&format_id(&id)).ok(), Some(id));
        assert!(parse_id("zz").is_err());
    }

    #[test]
    fn time_conversion() {
        assert_eq!(unix_seconds(1_700_000_000.9).ok(), Some(1_700_000_000));
        assert!(unix_seconds(-1.0).is_err());
        assert!(unix_seconds(f64::NAN).is_err());
    }

    #[test]
    fn external_ids_only_lists_external_slots() {
        let slots = [SlotKind::Recovery, SlotKind::External([1; 16])];
        assert_eq!(external_ids(&slots), vec!["01".repeat(16)]);
    }

    #[test]
    fn seal_and_reopen_keeps_accounts() {
        let mut s = session();
        let id = s.add_uri(URI, 1_700_000_000).unwrap();
        assert_eq!(
            s.add_uri(URI, 1_700_000_000).unwrap_err().message(),
            "duplicate"
        );
        let file = s.seal().unwrap();

        let reopened = Session::open(&file, PASSWORD, KdfParams::MINIMUM).unwrap();
        let accounts = reopened.accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, id);
        assert_eq!(accounts[0].issuer.as_deref(), Some("Example"));
        assert!(Session::open(&file, b"wrong", KdfParams::MINIMUM).is_err());

        let codes = reopened.totp_all(59).unwrap();
        assert_eq!(codes[&id].remaining, 1);
        assert_eq!(reopened.totp(&id, 59).unwrap(), codes[&id]);
    }

    #[test]
    fn external_slot_unlocks() {
        let mut s = session();
        s.set_external(&[7; 16], &[9; 32]).unwrap();
        let file = s.seal().unwrap();
        assert_eq!(external_slots(&file).unwrap(), vec!["07".repeat(16)]);
        assert!(Session::open_external(&file, &[7; 16], &[9; 32], KdfParams::MINIMUM).is_ok());
        assert!(Session::open_external(&file, &[7; 3], &[9; 32], KdfParams::MINIMUM).is_err());
    }

    #[test]
    fn unknown_import_format() {
        assert_eq!(
            "csv".parse::<ImportFormat>().unwrap_err().message(),
            "import:unknown-format"
        );
        assert_eq!("2fas".parse::<ImportFormat>(), Ok(ImportFormat::TwoFas));
    }

    #[test]
    fn views_serialize_like_the_web_protocol() {
        let view = ScanView {
            found: 1,
            unsupported: 0,
            added: 1,
            duplicates: 0,
            skipped: 0,
        };
        assert_eq!(
            serde_json::to_string(&view).unwrap(),
            r#"{"found":1,"unsupported":0,"added":1,"duplicates":0,"skipped":0}"#
        );
        assert_eq!(
            serde_json::to_string(&Error::new("duplicate")).unwrap(),
            r#""duplicate""#
        );
    }
}
