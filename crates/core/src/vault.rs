//! Vault cifrato con più slot di sblocco.
//!
//! Il contenuto è cifrato con una chiave dati (DEK) casuale a 256 bit. Ogni slot
//! "avvolge" la stessa DEK con una chiave di cifratura (KEK) derivata da una diversa
//! credenziale: password (Argon2id), recovery key, oppure un segreto fornito dalla
//! piattaforma (Secure Enclave, Keystore, TPM, `WebAuthn` PRF).
//!
//! # Formato (versione 1, interi big-endian)
//!
//! ```text
//! file  := MAGIC(8) | versione u16 | n_slot u8 | slot{n_slot} | body
//! slot  := tipo u8 | parametri | dek_avvolta(72)
//!   1 = password  : kdf u8 (1 = Argon2id v1.3) | m_kib u32 | t u32 | p u32 | salt(16)
//!   2 = recovery  : salt(16)
//!   3 = esterno   : id(16) | salt(16)
//! body  := nonce(24) | ciphertext | tag(16)
//! ```
//!
//! - DEK avvolta: AEAD con AAD = `MAGIC | versione | tipo | parametri` dello slot.
//! - Body: chiave = HKDF(DEK, info = `authenticator/v1/vault/body`),
//!   AAD = tutto l'header (MAGIC … ultimo slot).
//!
//! Ogni modifica a un qualsiasi byte del file rende impossibile l'apertura.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::aead;
use crate::base32;
use crate::codec::Reader;
use crate::error::{Error, Result};
use crate::secret::{Key256, SecretBytes, random_array};

/// Identificativo del formato.
pub const MAGIC: [u8; 8] = *b"AUTHVLT\0";
/// Versione del formato scritta da questa build.
pub const FORMAT_VERSION: u16 = 1;
/// Numero massimo di slot di sblocco.
pub const MAX_SLOTS: usize = 8;
/// Dimensione massima di un file vault (difesa da input enormi).
pub const MAX_FILE_LEN: usize = 16 * 1024 * 1024;

const SALT_LEN: usize = 16;
const WRAPPED_DEK_LEN: usize = Key256::LEN + aead::OVERHEAD;
const KDF_ARGON2ID_V13: u8 = 1;
const SLOT_PASSWORD: u8 = 1;
const SLOT_RECOVERY: u8 = 2;
const SLOT_EXTERNAL: u8 = 3;

const INFO_BODY: &[u8] = b"authenticator/v1/vault/body";
const INFO_KEK_RECOVERY: &[u8] = b"authenticator/v1/kek/recovery";
const INFO_KEK_EXTERNAL: &[u8] = b"authenticator/v1/kek/external";

/// Parametri Argon2id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// Memoria minima: 19 MiB (raccomandazione minima OWASP).
    pub const MIN_M_COST_KIB: u32 = 19 * 1024;
    /// Memoria massima: 256 MiB (evita esaurimento di memoria con file malevoli).
    pub const MAX_M_COST_KIB: u32 = 256 * 1024;
    /// Iterazioni minime.
    pub const MIN_T_COST: u32 = 2;
    /// Iterazioni massime.
    pub const MAX_T_COST: u32 = 10;
    /// Parallelismo massimo.
    pub const MAX_P_COST: u32 = 8;

    /// Default per il browser (WebAssembly è single-thread): 64 MiB, 3 iterazioni.
    pub const WEB: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
    /// Default per le app native: 64 MiB, 3 iterazioni, 4 lane.
    pub const NATIVE: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };
    /// Parametri minimi consentiti (usati nei test e su dispositivi molto lenti).
    pub const MINIMUM: Self = Self {
        m_cost_kib: Self::MIN_M_COST_KIB,
        t_cost: Self::MIN_T_COST,
        p_cost: 1,
    };

    /// Valida i parametri.
    ///
    /// # Errors
    /// [`Error::InvalidKdfParams`] se fuori dai limiti.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let ok = (Self::MIN_M_COST_KIB..=Self::MAX_M_COST_KIB).contains(&m_cost_kib)
            && (Self::MIN_T_COST..=Self::MAX_T_COST).contains(&t_cost)
            && (1..=Self::MAX_P_COST).contains(&p_cost)
            // Argon2 richiede almeno 8 KiB per lane.
            && m_cost_kib >= 8 * p_cost;
        if ok {
            Ok(Self {
                m_cost_kib,
                t_cost,
                p_cost,
            })
        } else {
            Err(Error::InvalidKdfParams)
        }
    }

    fn derive(self, password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Key256> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(Key256::LEN))
            .map_err(|_| Error::InvalidKdfParams)?;
        let mut key = Key256::zeroed();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, salt, key.expose_mut())
            .map_err(|_| Error::InvalidKdfParams)?;
        Ok(key)
    }
}

/// Recovery key: 256 bit casuali da conservare offline (stampata o trascritta).
pub struct RecoveryKey(Key256);

impl RecoveryKey {
    /// Rappresentazione da mostrare all'utente: Base32 a gruppi di 4 caratteri.
    #[must_use]
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(base32::encode(self.0.expose()));
        let mut out = Zeroizing::new(String::with_capacity(encoded.len() * 5 / 4));
        for (i, c) in encoded.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Interpreta la recovery key digitata dall'utente (spazi, trattini e minuscole ammessi).
    ///
    /// # Errors
    /// [`Error::InvalidBase32`] se il testo non è una recovery key valida.
    pub fn parse(text: &str) -> Result<Self> {
        let bytes = base32::decode(text)?;
        let array: [u8; Key256::LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidBase32)?;
        Ok(Self(Key256::from_bytes(array)))
    }
}

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKey([REDATTO])")
    }
}

/// Credenziale usata per aprire il vault.
#[derive(Debug, Clone, Copy)]
pub enum Credential<'a> {
    /// Password principale (già normalizzata Unicode NFC dal chiamante).
    Password(&'a [u8]),
    /// Recovery key.
    Recovery(&'a RecoveryKey),
    /// Segreto fornito dalla piattaforma (≥ 32 byte ad alta entropia), con l'id del suo slot.
    External {
        /// Identificativo dello slot (es. id della chiave hardware o della passkey).
        id: [u8; 16],
        /// Segreto (es. output `WebAuthn` PRF, chiave sbloccata dalla Secure Enclave).
        secret: &'a [u8],
    },
}

/// Tipo di slot, senza materiale segreto: può essere mostrato nella UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// Password con i suoi parametri Argon2id.
    Password(KdfParams),
    /// Recovery key.
    Recovery,
    /// Segreto della piattaforma con il suo identificativo.
    External([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    kind: SlotKind,
    salt: [u8; SALT_LEN],
    wrapped_dek: Vec<u8>,
}

impl Slot {
    fn encode_params(&self, out: &mut Vec<u8>) {
        match self.kind {
            SlotKind::Password(p) => {
                out.push(SLOT_PASSWORD);
                out.push(KDF_ARGON2ID_V13);
                out.extend_from_slice(&p.m_cost_kib.to_be_bytes());
                out.extend_from_slice(&p.t_cost.to_be_bytes());
                out.extend_from_slice(&p.p_cost.to_be_bytes());
            }
            SlotKind::Recovery => out.push(SLOT_RECOVERY),
            SlotKind::External(id) => {
                out.push(SLOT_EXTERNAL);
                out.extend_from_slice(&id);
            }
        }
        out.extend_from_slice(&self.salt);
    }

    fn wrap_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(&MAGIC);
        aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        self.encode_params(&mut aad);
        aad
    }

    fn new(kind: SlotKind, credential: Credential<'_>, dek: &Key256) -> Result<Self> {
        let mut slot = Self {
            kind,
            salt: random_array()?,
            wrapped_dek: Vec::new(),
        };
        let kek = slot.kek(credential)?.ok_or(Error::Internal)?;
        slot.wrapped_dek = aead::seal(&kek, &slot.wrap_aad(), dek.expose())?;
        Ok(slot)
    }

    /// KEK per questo slot, oppure `None` se la credenziale è di un altro tipo.
    fn kek(&self, credential: Credential<'_>) -> Result<Option<Key256>> {
        match (self.kind, credential) {
            (SlotKind::Password(params), Credential::Password(pw)) => {
                params.derive(pw, &self.salt).map(Some)
            }
            (SlotKind::Recovery, Credential::Recovery(rk)) => {
                aead::derive_key(rk.0.expose(), Some(&self.salt), INFO_KEK_RECOVERY).map(Some)
            }
            (SlotKind::External(slot_id), Credential::External { id, secret }) if slot_id == id => {
                aead::derive_key(secret, Some(&self.salt), INFO_KEK_EXTERNAL).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn unwrap_dek(&self, credential: Credential<'_>) -> Result<Option<Key256>> {
        let Some(kek) = self.kek(credential)? else {
            return Ok(None);
        };
        let dek = aead::open(&kek, &self.wrap_aad(), &self.wrapped_dek)?;
        let bytes: [u8; Key256::LEN] = dek
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        Ok(Some(Key256::from_bytes(bytes)))
    }
}

/// Vault sbloccato: contiene la DEK in memoria (azzerata al drop).
#[derive(Debug)]
pub struct Vault {
    dek: Key256,
    slots: Vec<Slot>,
}

impl Vault {
    /// Crea un nuovo vault protetto da password.
    ///
    /// # Errors
    /// [`Error::InvalidKdfParams`] se la password è vuota; [`Error::Rng`] se il CSPRNG
    /// non è disponibile.
    pub fn create(password: &[u8], params: KdfParams) -> Result<Self> {
        let mut vault = Self {
            dek: Key256::generate()?,
            slots: Vec::new(),
        };
        vault.set_password(password, params)?;
        Ok(vault)
    }

    /// Imposta (o sostituisce) la password. Gli altri slot restano validi.
    ///
    /// # Errors
    /// Come [`Vault::create`].
    pub fn set_password(&mut self, password: &[u8], params: KdfParams) -> Result<()> {
        if password.is_empty() {
            return Err(Error::InvalidKdfParams);
        }
        let slot = Slot::new(
            SlotKind::Password(params),
            Credential::Password(password),
            &self.dek,
        )?;
        self.slots
            .retain(|s| !matches!(s.kind, SlotKind::Password(_)));
        self.push_slot(slot)
    }

    /// Genera una nuova recovery key, sostituendo l'eventuale precedente.
    ///
    /// # Errors
    /// [`Error::Rng`] se il CSPRNG non è disponibile.
    pub fn create_recovery_key(&mut self) -> Result<RecoveryKey> {
        let key = RecoveryKey(Key256::generate()?);
        let slot = Slot::new(SlotKind::Recovery, Credential::Recovery(&key), &self.dek)?;
        self.slots.retain(|s| s.kind != SlotKind::Recovery);
        self.push_slot(slot)?;
        Ok(key)
    }

    /// Aggiunge o sostituisce uno slot sbloccabile con un segreto della piattaforma.
    ///
    /// # Errors
    /// [`Error::InvalidSecretLength`] se il segreto è più corto di 32 byte;
    /// [`Error::InvalidSlotCount`] se si supera [`MAX_SLOTS`].
    pub fn set_external(&mut self, id: [u8; 16], secret: &[u8]) -> Result<()> {
        if secret.len() < Key256::LEN {
            return Err(Error::InvalidSecretLength);
        }
        let slot = Slot::new(
            SlotKind::External(id),
            Credential::External { id, secret },
            &self.dek,
        )?;
        self.slots.retain(|s| s.kind != SlotKind::External(id));
        self.push_slot(slot)
    }

    /// Rimuove uno slot esterno (es. dispositivo o passkey revocati).
    ///
    /// # Errors
    /// [`Error::InvalidSlotCount`] se lo slot non esiste o se il vault resterebbe
    /// senza password.
    pub fn remove_external(&mut self, id: [u8; 16]) -> Result<()> {
        let before = self.slots.len();
        self.slots.retain(|s| s.kind != SlotKind::External(id));
        if self.slots.len() == before {
            return Err(Error::InvalidSlotCount);
        }
        Ok(())
    }

    /// Genera una nuova DEK e lascia solo lo slot password indicato.
    ///
    /// Da usare se una credenziale potrebbe essere compromessa: un vecchio file e la
    /// vecchia credenziale non permettono di leggere i dati salvati dopo la rotazione.
    /// Recovery key e slot esterni vanno ricreati.
    ///
    /// # Errors
    /// Come [`Vault::create`].
    pub fn rotate(&mut self, password: &[u8], params: KdfParams) -> Result<()> {
        *self = Self::create(password, params)?;
        Ok(())
    }

    /// Tipi di slot presenti (per la UI).
    #[must_use]
    pub fn slots(&self) -> Vec<SlotKind> {
        self.slots.iter().map(|s| s.kind).collect()
    }

    fn push_slot(&mut self, slot: Slot) -> Result<()> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(Error::InvalidSlotCount);
        }
        self.slots.push(slot);
        Ok(())
    }

    fn header(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(16 + self.slots.len() * 128);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.push(u8::try_from(self.slots.len()).map_err(|_| Error::InvalidSlotCount)?);
        for slot in &self.slots {
            slot.encode_params(&mut out);
            out.extend_from_slice(&slot.wrapped_dek);
        }
        Ok(out)
    }

    fn body_key(&self) -> Result<Key256> {
        aead::derive_key(self.dek.expose(), None, INFO_BODY)
    }

    /// Cifra `payload` e restituisce il file completo.
    ///
    /// # Errors
    /// [`Error::InvalidSlotCount`] se il vault non ha slot; [`Error::InvalidFormat`] se il
    /// file supererebbe [`MAX_FILE_LEN`].
    pub fn seal(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.slots.is_empty() {
            return Err(Error::InvalidSlotCount);
        }
        let mut file = self.header()?;
        let body = aead::seal(&self.body_key()?, &file, payload)?;
        file.extend_from_slice(&body);
        if file.len() > MAX_FILE_LEN {
            return Err(Error::InvalidFormat);
        }
        Ok(file)
    }

    /// Apre un file vault con la credenziale indicata.
    ///
    /// # Errors
    /// - [`Error::InvalidFormat`] / [`Error::UnsupportedVersion`] per file non validi;
    /// - [`Error::NoMatchingSlot`] se nessuno slot è del tipo della credenziale;
    /// - [`Error::Decryption`] se la credenziale è errata o il file è stato manomesso.
    pub fn open(file: &[u8], credential: Credential<'_>) -> Result<(Self, SecretBytes)> {
        if file.len() > MAX_FILE_LEN {
            return Err(Error::InvalidFormat);
        }
        let (slots, header_len) = parse_header(file)?;
        let (header, body) = file
            .split_at_checked(header_len)
            .ok_or(Error::InvalidFormat)?;

        let mut matched = false;
        let mut dek = None;
        for slot in &slots {
            match slot.unwrap_dek(credential) {
                Ok(Some(key)) => {
                    dek = Some(key);
                    break;
                }
                Ok(None) => {}
                Err(Error::Decryption) => matched = true,
                Err(e) => return Err(e),
            }
        }
        let dek = match dek {
            Some(dek) => dek,
            None if matched => return Err(Error::Decryption),
            None => return Err(Error::NoMatchingSlot),
        };

        let vault = Self { dek, slots };
        let mut payload = aead::open(&vault.body_key()?, header, body)?;
        // Sposta il Vec fuori dal wrapper senza copiarne il contenuto.
        Ok((vault, SecretBytes::new(core::mem::take(&mut *payload))))
    }
}

fn parse_header(file: &[u8]) -> Result<(Vec<Slot>, usize)> {
    let mut r = Reader::new(file);
    if r.array::<8>()? != MAGIC {
        return Err(Error::InvalidFormat);
    }
    if r.u16()? != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let count = usize::from(r.u8()?);
    if count == 0 || count > MAX_SLOTS {
        return Err(Error::InvalidFormat);
    }
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = match r.u8()? {
            SLOT_PASSWORD => {
                if r.u8()? != KDF_ARGON2ID_V13 {
                    return Err(Error::UnsupportedVersion);
                }
                let (m, t, p) = (r.u32()?, r.u32()?, r.u32()?);
                // Parametri fuori limite: possibile file malevolo (DoS o downgrade).
                SlotKind::Password(KdfParams::new(m, t, p).map_err(|_| Error::InvalidFormat)?)
            }
            SLOT_RECOVERY => SlotKind::Recovery,
            SLOT_EXTERNAL => SlotKind::External(r.array()?),
            _ => return Err(Error::InvalidFormat),
        };
        let salt = r.array()?;
        let wrapped_dek = r.take(WRAPPED_DEK_LEN)?.to_vec();
        slots.push(Slot {
            kind,
            salt,
            wrapped_dek,
        });
    }
    Ok((slots, r.position()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"correct horse battery staple";

    fn vault_with_all_slots() -> (Vault, RecoveryKey) {
        let mut vault = Vault::create(PW, KdfParams::MINIMUM).unwrap();
        let rk = vault.create_recovery_key().unwrap();
        vault.set_external([7; 16], &[9; 32]).unwrap();
        (vault, rk)
    }

    #[test]
    fn open_with_every_credential() {
        let (vault, rk) = vault_with_all_slots();
        let file = vault.seal(b"payload segreto").unwrap();
        for credential in [
            Credential::Password(PW),
            Credential::Recovery(&rk),
            Credential::External {
                id: [7; 16],
                secret: &[9; 32],
            },
        ] {
            let (reopened, payload) = Vault::open(&file, credential).unwrap();
            assert_eq!(payload.expose(), b"payload segreto");
            assert_eq!(reopened.dek, vault.dek);
        }
    }

    #[test]
    fn wrong_credentials_fail() {
        let (vault, _) = vault_with_all_slots();
        let file = vault.seal(b"x").unwrap();
        let other_rk = RecoveryKey(Key256::generate().unwrap());
        assert_eq!(
            Vault::open(&file, Credential::Password(b"sbagliata")).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            Vault::open(&file, Credential::Recovery(&other_rk)).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            Vault::open(
                &file,
                Credential::External {
                    id: [7; 16],
                    secret: &[8; 32]
                }
            )
            .unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            Vault::open(
                &file,
                Credential::External {
                    id: [1; 16],
                    secret: &[9; 32]
                }
            )
            .unwrap_err(),
            Error::NoMatchingSlot
        );
    }

    #[test]
    fn any_modified_byte_is_detected() {
        let vault = Vault::create(PW, KdfParams::MINIMUM).unwrap();
        let rk_vault = {
            let mut v = Vault::create(PW, KdfParams::MINIMUM).unwrap();
            let rk = v.create_recovery_key().unwrap();
            (v, rk)
        };
        // Recovery key: HKDF è veloce, quindi possiamo provare ogni singolo byte.
        let file = rk_vault.0.seal(b"dati").unwrap();
        for i in 0..file.len() {
            let mut tampered = file.clone();
            tampered[i] ^= 0x01;
            assert!(
                Vault::open(&tampered, Credential::Recovery(&rk_vault.1)).is_err(),
                "byte {i}"
            );
        }
        // Body modificato con slot password.
        let mut file = vault.seal(b"dati").unwrap();
        let last = file.len() - 1;
        file[last] ^= 1;
        assert_eq!(
            Vault::open(&file, Credential::Password(PW)).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn rejects_malformed_files() {
        let file = Vault::create(PW, KdfParams::MINIMUM)
            .unwrap()
            .seal(b"")
            .unwrap();
        let open = |f: &[u8]| Vault::open(f, Credential::Password(PW)).unwrap_err();

        assert_eq!(open(&[]), Error::InvalidFormat);
        assert_eq!(open(&file[..20]), Error::InvalidFormat);
        let mut bad_magic = file.clone();
        bad_magic[0] = b'X';
        assert_eq!(open(&bad_magic), Error::InvalidFormat);
        let mut bad_version = file.clone();
        bad_version[9] = 2;
        assert_eq!(open(&bad_version), Error::UnsupportedVersion);
        let mut no_slots = file.clone();
        no_slots[10] = 0;
        assert_eq!(open(&no_slots), Error::InvalidFormat);
    }

    #[test]
    fn rejects_dangerous_kdf_params() {
        let file = Vault::create(PW, KdfParams::MINIMUM)
            .unwrap()
            .seal(b"")
            .unwrap();
        // Offset di m_cost: magic(8) + versione(2) + n_slot(1) + tipo(1) + kdf(1).
        for m in [8u32, 4 * 1024 * 1024] {
            let mut f = file.clone();
            f[13..17].copy_from_slice(&m.to_be_bytes());
            assert_eq!(
                Vault::open(&f, Credential::Password(PW)).unwrap_err(),
                Error::InvalidFormat
            );
        }
        assert_eq!(KdfParams::new(1024, 3, 1), Err(Error::InvalidKdfParams));
        assert_eq!(
            KdfParams::new(64 * 1024, 1, 1),
            Err(Error::InvalidKdfParams)
        );
        assert_eq!(
            KdfParams::new(64 * 1024, 3, 0),
            Err(Error::InvalidKdfParams)
        );
        assert!(KdfParams::new(KdfParams::WEB.m_cost_kib, 3, 1).is_ok());
    }

    #[test]
    fn password_change_keeps_other_slots() {
        let (mut vault, rk) = vault_with_all_slots();
        vault
            .set_password(b"nuova password", KdfParams::MINIMUM)
            .unwrap();
        let file = vault.seal(b"x").unwrap();
        assert_eq!(
            Vault::open(&file, Credential::Password(PW)).unwrap_err(),
            Error::Decryption
        );
        assert!(Vault::open(&file, Credential::Password(b"nuova password")).is_ok());
        assert!(Vault::open(&file, Credential::Recovery(&rk)).is_ok());
        assert_eq!(vault.slots().len(), 3);
    }

    #[test]
    fn rotation_invalidates_old_credentials() {
        let (mut vault, rk) = vault_with_all_slots();
        let old_dek = Key256::from_bytes(*vault.dek.expose());
        vault
            .rotate(b"dopo la rotazione", KdfParams::MINIMUM)
            .unwrap();
        assert_ne!(vault.dek, old_dek);
        assert_eq!(vault.slots(), vec![SlotKind::Password(KdfParams::MINIMUM)]);
        let file = vault.seal(b"x").unwrap();
        assert_eq!(
            Vault::open(&file, Credential::Recovery(&rk)).unwrap_err(),
            Error::NoMatchingSlot
        );
    }

    #[test]
    fn slot_management() {
        let (mut vault, _) = vault_with_all_slots();
        assert_eq!(
            vault.set_external([1; 16], &[0; 16]),
            Err(Error::InvalidSecretLength)
        );
        vault.remove_external([7; 16]).unwrap();
        assert_eq!(vault.remove_external([7; 16]), Err(Error::InvalidSlotCount));
        for i in 0..6u8 {
            vault.set_external([i; 16], &[i; 32]).unwrap();
        }
        assert_eq!(
            vault.set_external([99; 16], &[0; 32]),
            Err(Error::InvalidSlotCount)
        );
        assert_eq!(
            Vault::create(b"", KdfParams::MINIMUM).unwrap_err(),
            Error::InvalidKdfParams
        );
    }

    #[test]
    fn recovery_key_text_roundtrip() {
        let rk = RecoveryKey(Key256::generate().unwrap());
        let text = rk.to_display_string();
        assert_eq!(text.len(), 52 + 12);
        let parsed = RecoveryKey::parse(&text.to_lowercase().replace('-', " ")).unwrap();
        assert_eq!(parsed.0, rk.0);
        assert!(RecoveryKey::parse("AAAA-BBBB").is_err());
        assert!(!format!("{rk:?}").contains(&text[..4]));
    }
}
