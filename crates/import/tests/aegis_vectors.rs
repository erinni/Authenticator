//! Compatibilità con esportazioni reali di Aegis, andOTP e 2FAS.
//!
//! I file in `data/aegis-vectors/` (dal progetto Aegis, GPL-3.0, vedi `NOTICE.md`)
//! contengono gli stessi account di `plain.txt`: ogni account importato deve essere
//! identico a quello ottenuto interpretando il corrispondente URI `otpauth://`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)] // codice di test

use authenticator_core::OtpAccount;
use authenticator_import::{ImportError, Imported, aegis, andotp, twofas};

const PASSWORD: &[u8] = b"test";

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/data/aegis-vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Account di riferimento. La riga `steam` non è supportata e viene ignorata.
fn reference() -> Vec<OtpAccount> {
    let text = String::from_utf8(data("plain.txt")).unwrap();
    text.lines()
        .filter_map(|line| OtpAccount::from_uri(line).ok())
        .collect()
}

fn check(imported: &Imported, expected_count: usize) {
    let reference = reference();
    assert_eq!(imported.accounts.len(), expected_count, "account importati");
    for account in &imported.accounts {
        let expected = reference
            .iter()
            .find(|r| r.secret == account.secret)
            // Nessun dato dell'account nel messaggio: i messaggi di errore finiscono nei log.
            .expect("account importato con un segreto che non è tra quelli di riferimento");
        assert_eq!(account, expected);
        // Stesso codice generato, a riprova che i parametri coincidono.
        if let Ok(code) = expected.totp_at(1_700_000_000) {
            assert_eq!(account.totp_at(1_700_000_000).unwrap(), code);
        }
    }
}

#[test]
fn reference_vectors_parse() {
    // 7 righe, di cui una `steam` non supportata.
    assert_eq!(reference().len(), 6);
}

#[test]
fn aegis_plain() {
    let data = data("aegis_plain.json");
    assert!(!aegis::is_encrypted(&data).unwrap());
    let imported = aegis::import(&data, None).unwrap();
    check(&imported, 6);
    assert_eq!(imported.skipped, 1); // Steam
}

#[test]
fn aegis_encrypted() {
    let data = data("aegis_encrypted.json");
    assert!(aegis::is_encrypted(&data).unwrap());
    assert_eq!(
        aegis::import(&data, None).unwrap_err(),
        ImportError::PasswordRequired
    );
    assert_eq!(
        aegis::import(&data, Some(b"wrong")).unwrap_err(),
        ImportError::Decryption
    );
    let imported = aegis::import(&data, Some(PASSWORD)).unwrap();
    check(&imported, 6);
    assert_eq!(imported.skipped, 1);
}

#[test]
fn andotp_plain() {
    let data = data("andotp_plain.json");
    assert!(!andotp::is_encrypted(&data));
    let imported = andotp::import(&data, None).unwrap();
    check(&imported, 6);
    assert_eq!(imported.skipped, 1);
}

#[test]
fn andotp_encrypted() {
    let data = data("andotp_encrypted.bin");
    assert!(andotp::is_encrypted(&data));
    assert_eq!(
        andotp::import(&data, None).unwrap_err(),
        ImportError::PasswordRequired
    );
    assert_eq!(
        andotp::import(&data, Some(b"wrong")).unwrap_err(),
        ImportError::Decryption
    );
    let imported = andotp::import(&data, Some(PASSWORD)).unwrap();
    check(&imported, 6);
}

#[test]
fn twofas_plain_and_encrypted() {
    // Il file v4 contiene 4 account supportati più uno Steam; il v3 tutti e 6.
    for (plain, encrypted, expected, skipped) in [
        (
            "2fas_authenticator_plain_v3.2fas",
            "2fas_authenticator_encrypted_v3.2fas",
            6,
            0,
        ),
        (
            "2fas_authenticator_plain_v4.2fas",
            "2fas_authenticator_encrypted_v4.2fas",
            4,
            1,
        ),
    ] {
        let plain = twofas::import(&data(plain), None).unwrap();
        check(&plain, expected);
        assert_eq!(plain.skipped, skipped);

        let encrypted = data(encrypted);
        assert!(twofas::is_encrypted(&encrypted).unwrap());
        assert_eq!(
            twofas::import(&encrypted, None).unwrap_err(),
            ImportError::PasswordRequired
        );
        assert_eq!(
            twofas::import(&encrypted, Some(b"wrong")).unwrap_err(),
            ImportError::Decryption
        );
        check(
            &twofas::import(&encrypted, Some(PASSWORD)).unwrap(),
            expected,
        );
    }
}

#[test]
fn rejects_garbage_and_cross_formats() {
    assert!(aegis::import(b"{}", None).is_err());
    assert!(twofas::import(b"[]", None).is_err());
    assert!(andotp::import(b"[{}]", None).is_err());
    assert!(aegis::import(&data("andotp_plain.json"), None).is_err());
    assert!(andotp::import(&data("aegis_plain.json"), Some(PASSWORD)).is_err());
}
