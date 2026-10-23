//! Test vector Wycheproof per le primitive del core (vedi `data/wycheproof/NOTICE.md`).
//!
//! Oltre ai casi validi, verificano che vengano rifiutati i casi "invalid"
//! (tag alterati, ciphertext modificati, ecc.).

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)] // codice di test

use authenticator_core::{Key256, aead};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/data/wycheproof/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tests(file: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    file["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

#[test]
fn xchacha20_poly1305() {
    let file = load("xchacha20_poly1305_test.json");
    let (mut valid, mut invalid) = (0, 0);
    for (_, t) in tests(&file) {
        let id = &t["tcId"];
        let (key, iv) = (hex(&t["key"]), hex(&t["iv"]));
        // La nostra API accetta solo chiavi da 256 bit e nonce da 192 bit.
        let (Ok(key), true) = (<[u8; 32]>::try_from(key), iv.len() == aead::NONCE_LEN) else {
            assert_eq!(t["result"], "invalid", "tcId {id}");
            continue;
        };
        let key = Key256::from_bytes(key);
        let mut message = iv;
        message.extend(hex(&t["ct"]));
        message.extend(hex(&t["tag"]));
        let result = aead::open(&key, &hex(&t["aad"]), &message);
        match t["result"].as_str().unwrap() {
            "valid" => {
                assert_eq!(
                    result.unwrap().as_slice(),
                    hex(&t["msg"]).as_slice(),
                    "tcId {id}"
                );
                valid += 1;
            }
            "invalid" => {
                assert!(result.is_err(), "tcId {id} accettato");
                invalid += 1;
            }
            other => panic!("risultato inatteso {other}"),
        }
    }
    assert!(
        valid > 100 && invalid > 50,
        "valid {valid}, invalid {invalid}"
    );
}

#[test]
fn hkdf_sha256() {
    let file = load("hkdf_sha256_test.json");
    let mut checked = 0;
    for (_, t) in tests(&file) {
        // `derive_key` produce sempre 256 bit: si verificano i casi con quella lunghezza.
        if t["size"] != 32 || t["result"] != "valid" {
            continue;
        }
        let okm =
            aead::derive_key(&hex(&t["ikm"]), Some(&hex(&t["salt"])), &hex(&t["info"])).unwrap();
        assert_eq!(
            okm.expose().as_slice(),
            hex(&t["okm"]).as_slice(),
            "tcId {}",
            t["tcId"]
        );
        checked += 1;
    }
    assert!(checked >= 10, "{checked}");
}
