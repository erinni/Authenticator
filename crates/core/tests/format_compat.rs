//! Compatibilità del formato: un vault scritto da una versione precedente deve restare
//! apribile. Se questo test fallisce, il formato è cambiato in modo incompatibile:
//! serve una nuova versione del formato e una migrazione, non un aggiornamento del file.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)] // codice di test

use authenticator_core::otp::{Algorithm, Digits, Period};
use authenticator_core::{Credential, OtpKind, RecoveryKey, Store, Vault};

/// Vault formato v1 generato il 2026-10-23 (credenziali usate solo per questo test).
const VAULT_V1_HEX: &str = include_str!("data/vault-v1.hex");
const PASSWORD: &[u8] = b"golden password";
const RECOVERY_KEY: &str = "HFLL-3JTF-VC3I-YJGX-3TOP-CVVH-ZBOQ-SBCK-NOCH-PPGR-OSRH-BOAE-7WQQ";

fn vault_v1() -> Vec<u8> {
    let hex: String = VAULT_V1_HEX.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn check_payload(payload: &[u8]) {
    let store = Store::decode(payload).unwrap();
    let [entry] = store.entries() else {
        panic!("attesi 1 account")
    };
    assert_eq!(entry.created_at, 1_761_177_600);
    let account = &entry.account;
    assert_eq!(account.issuer.as_deref(), Some("Example"));
    assert_eq!(account.name, "alice@example.com");
    assert_eq!(account.secret.expose(), b"12345678901234567890");
    assert_eq!(account.algorithm, Algorithm::Sha1);
    assert_eq!(account.digits, Digits::SIX);
    assert_eq!(
        account.kind,
        OtpKind::Totp {
            period: Period::DEFAULT
        }
    );
    // RFC 6238: t = 59 -> 94287082 (8 cifre), quindi 287082 a 6 cifre.
    assert_eq!(account.totp_at(59).unwrap().code.to_string(), "287082");
}

#[test]
fn opens_v1_with_password() {
    let (_, payload) = Vault::open(&vault_v1(), Credential::Password(PASSWORD)).unwrap();
    check_payload(payload.expose());
}

#[test]
fn opens_v1_with_recovery_key() {
    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    let (_, payload) = Vault::open(&vault_v1(), Credential::Recovery(&rk)).unwrap();
    check_payload(payload.expose());
}
