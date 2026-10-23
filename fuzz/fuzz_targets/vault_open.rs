#![no_main]

use authenticator_core::{Credential, RecoveryKey, Vault};
use libfuzzer_sys::fuzz_target;

// Recovery key fissa: HKDF è veloce, quindi il fuzzer esplora il parser e non Argon2.
const RECOVERY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fuzz_target!(|file: &[u8]| {
    let key = RecoveryKey::parse(RECOVERY).expect("recovery key di test");
    let _ = Vault::open(file, Credential::Recovery(&key));
    let _ = Vault::open(file, Credential::External { id: [0; 16], secret: &[0; 32] });
});
