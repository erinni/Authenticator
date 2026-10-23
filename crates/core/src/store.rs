//! Elenco degli account salvato (cifrato) nel payload del vault.
//!
//! # Formato del payload (versione 1, interi big-endian)
//!
//! ```text
//! payload := versione u8 | n u32 | entry{n}
//! entry   := id(16) | creato_il u64 | issuer: opt_str | nome: str
//!          | tipo u8 (1 = TOTP, 2 = HOTP) | algoritmo u8 (1 = SHA1, 2 = SHA256, 3 = SHA512)
//!          | cifre u8 | (periodo u32 se TOTP | contatore u64 se HOTP)
//!          | segreto: len u8 | byte
//! str     := len u16 | UTF-8
//! opt_str := 0 | 1 str
//! ```
//!
//! Il payload è autenticato dal vault, ma viene comunque validato in lettura
//! (difesa in profondità contro bug o versioni future).

use zeroize::Zeroizing;

use crate::account::{OtpAccount, OtpKind};
use crate::codec::Reader;
use crate::error::{Error, Result};
use crate::otp::{self, Algorithm, Digits, Period};
use crate::secret::{SecretBytes, random_array};

/// Versione del formato del payload.
pub const PAYLOAD_VERSION: u8 = 1;
/// Numero massimo di account.
pub const MAX_ENTRIES: usize = 10_000;

/// Identificativo casuale e stabile di un account.
pub type EntryId = [u8; 16];

/// Account salvato con i suoi metadati.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    /// Identificativo univoco.
    pub id: EntryId,
    /// Data di creazione (secondi Unix).
    pub created_at: u64,
    /// Dati dell'account.
    pub account: OtpAccount,
}

/// Esito di [`Store::merge`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeReport {
    /// Account aggiunti.
    pub added: usize,
    /// Account ignorati perché già presenti.
    pub duplicates: usize,
}

/// Elenco ordinato degli account.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Store {
    entries: Vec<Entry>,
}

impl Store {
    /// Elenco vuoto.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Account nell'ordine scelto dall'utente.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Consuma l'elenco restituendo gli account.
    #[must_use]
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }

    /// Cerca un account.
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == *id)
    }

    /// Cerca un account per modificarlo (es. avanzare il contatore HOTP).
    pub fn get_mut(&mut self, id: &EntryId) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == *id)
    }

    /// Aggiunge un account e ne restituisce l'id.
    ///
    /// # Errors
    /// [`Error::InvalidFormat`] oltre [`MAX_ENTRIES`]; [`Error::Rng`] se il CSPRNG non è
    /// disponibile.
    pub fn add(&mut self, account: OtpAccount, now: u64) -> Result<EntryId> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::InvalidFormat);
        }
        let id = random_array()?;
        self.entries.push(Entry {
            id,
            created_at: now,
            account,
        });
        Ok(id)
    }

    /// `true` se esiste già un account con lo stesso segreto.
    #[must_use]
    pub fn contains_secret(&self, secret: &SecretBytes) -> bool {
        // Nessuna uscita anticipata: il tempo non rivela quale account corrisponde.
        let found = self
            .entries
            .iter()
            .fold(subtle::Choice::from(0), |found, e| {
                found | e.account.secret.ct_eq(secret)
            });
        found.into()
    }

    /// Aggiunge gli account importati, saltando quelli già presenti (stesso segreto).
    ///
    /// # Errors
    /// Come [`Store::add`]; gli account aggiunti prima dell'errore restano nell'elenco.
    pub fn merge(
        &mut self,
        accounts: impl IntoIterator<Item = OtpAccount>,
        now: u64,
    ) -> Result<MergeReport> {
        let mut report = MergeReport::default();
        for account in accounts {
            if self.contains_secret(&account.secret) {
                report.duplicates += 1;
            } else {
                self.add(account, now)?;
                report.added += 1;
            }
        }
        Ok(report)
    }

    /// Rimuove un account. Restituisce `true` se esisteva.
    pub fn remove(&mut self, id: &EntryId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != *id);
        self.entries.len() != before
    }

    /// Serializza l'elenco. Il buffer contiene i segreti ed è azzerato al drop.
    ///
    /// # Errors
    /// [`Error::InvalidFormat`] se un campo supera i limiti del formato.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(16 + self.entries.len() * 128));
        out.push(PAYLOAD_VERSION);
        let count = u32::try_from(self.entries.len()).map_err(|_| Error::InvalidFormat)?;
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            encode_entry(entry, &mut out)?;
        }
        Ok(out)
    }

    /// Deserializza e valida l'elenco.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`] o [`Error::InvalidFormat`] per payload non validi.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u8()? != PAYLOAD_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let count = usize::try_from(r.u32()?).map_err(|_| Error::InvalidFormat)?;
        if count > MAX_ENTRIES {
            return Err(Error::InvalidFormat);
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(count.min(256));
        for _ in 0..count {
            let entry = decode_entry(&mut r)?;
            if entries.iter().any(|e| e.id == entry.id) {
                return Err(Error::InvalidFormat);
            }
            entries.push(entry);
        }
        if !r.is_empty() {
            return Err(Error::InvalidFormat);
        }
        Ok(Self { entries })
    }
}

fn algorithm_id(a: Algorithm) -> u8 {
    match a {
        Algorithm::Sha1 => 1,
        Algorithm::Sha256 => 2,
        Algorithm::Sha512 => 3,
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let len = u16::try_from(s.len()).map_err(|_| Error::InvalidFormat)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn encode_entry(entry: &Entry, out: &mut Vec<u8>) -> Result<()> {
    let a = &entry.account;
    out.extend_from_slice(&entry.id);
    out.extend_from_slice(&entry.created_at.to_be_bytes());
    match &a.issuer {
        Some(issuer) => {
            out.push(1);
            put_str(out, issuer)?;
        }
        None => out.push(0),
    }
    put_str(out, &a.name)?;
    match a.kind {
        OtpKind::Totp { period } => {
            out.extend_from_slice(&[1, algorithm_id(a.algorithm), a.digits.get()]);
            out.extend_from_slice(&period.get().to_be_bytes());
        }
        OtpKind::Hotp { counter } => {
            out.extend_from_slice(&[2, algorithm_id(a.algorithm), a.digits.get()]);
            out.extend_from_slice(&counter.to_be_bytes());
        }
    }
    let secret = a.secret.expose();
    out.push(u8::try_from(secret.len()).map_err(|_| Error::InvalidFormat)?);
    out.extend_from_slice(secret);
    Ok(())
}

fn decode_entry(r: &mut Reader<'_>) -> Result<Entry> {
    let id = r.array()?;
    let created_at = r.u64()?;
    let issuer = match r.u8()? {
        0 => None,
        1 => Some(r.string()?),
        _ => return Err(Error::InvalidFormat),
    };
    let name = r.string()?;
    let kind_tag = r.u8()?;
    let algorithm = match r.u8()? {
        1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        _ => return Err(Error::InvalidFormat),
    };
    let digits = Digits::new(r.u8()?).map_err(|_| Error::InvalidFormat)?;
    let kind = match kind_tag {
        1 => OtpKind::Totp {
            period: Period::new(r.u32()?).map_err(|_| Error::InvalidFormat)?,
        },
        2 => OtpKind::Hotp { counter: r.u64()? },
        _ => return Err(Error::InvalidFormat),
    };
    let secret_len = usize::from(r.u8()?);
    if secret_len == 0 || secret_len > otp::MAX_SECRET_LEN {
        return Err(Error::InvalidFormat);
    }
    let secret = SecretBytes::new(r.take(secret_len)?.to_vec());
    let account = OtpAccount::new(issuer.as_deref(), &name, kind, algorithm, digits, secret)
        .map_err(|_| Error::InvalidFormat)?;
    Ok(Entry {
        id,
        created_at,
        account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> Store {
        let mut store = Store::new();
        store
            .add(
                OtpAccount::from_uri(
                    "otpauth://totp/GitHub:mario@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                )
                .unwrap(),
                1_700_000_000,
            )
            .unwrap();
        store
            .add(
                OtpAccount::from_uri(
                    "otpauth://hotp/VPN?secret=GEZDGNBVGY3TQOJQ&counter=7&digits=8&algorithm=SHA512",
                )
                .unwrap(),
                1_700_000_001,
            )
            .unwrap();
        store
    }

    #[test]
    fn roundtrip() {
        let store = sample();
        let decoded = Store::decode(&store.encode().unwrap()).unwrap();
        assert_eq!(decoded, store);
        assert_eq!(
            Store::decode(&Store::new().encode().unwrap()).unwrap(),
            Store::new()
        );
    }

    #[test]
    fn add_get_remove() {
        let mut store = sample();
        let id = store.entries()[1].id;
        store.get_mut(&id).unwrap().account.next_hotp().unwrap();
        assert_eq!(
            store.get(&id).unwrap().account.kind,
            OtpKind::Hotp { counter: 8 }
        );
        assert!(store.remove(&id));
        assert!(!store.remove(&id));
        assert_eq!(store.entries().len(), 1);
    }

    #[test]
    fn rejects_invalid_payloads() {
        let bytes = sample().encode().unwrap();
        assert_eq!(Store::decode(&[]), Err(Error::InvalidFormat));
        assert_eq!(
            Store::decode(&[2, 0, 0, 0, 0]),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(
            Store::decode(&[1, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::InvalidFormat)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(Store::decode(&trailing), Err(Error::InvalidFormat));
        for len in 0..bytes.len() {
            assert!(Store::decode(&bytes[..len]).is_err(), "troncato a {len}");
        }
    }

    #[test]
    fn rejects_duplicate_ids() {
        let store = sample();
        let mut bytes = store.encode().unwrap().to_vec();
        let first_id = store.entries()[0].id;
        let second = bytes
            .windows(16)
            .rposition(|w| w == store.entries()[1].id)
            .unwrap();
        bytes[second..second + 16].copy_from_slice(&first_id);
        assert_eq!(Store::decode(&bytes), Err(Error::InvalidFormat));
    }

    #[test]
    fn merge_skips_duplicates() {
        let mut store = sample();
        let again = sample();
        let report = store
            .merge(again.entries.into_iter().map(|e| e.account), 1_700_000_100)
            .unwrap();
        assert_eq!(
            report,
            MergeReport {
                added: 0,
                duplicates: 2
            }
        );
        let new = OtpAccount::from_uri("otpauth://totp/New?secret=MFRGGZDFMZTWQ2LK").unwrap();
        let report = store.merge([new], 1_700_000_200).unwrap();
        assert_eq!(
            report,
            MergeReport {
                added: 1,
                duplicates: 0
            }
        );
        assert_eq!(store.entries().len(), 3);
    }

    proptest! {
        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = Store::decode(&data);
        }
    }
}
