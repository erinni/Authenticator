#![no_main]

use authenticator_import::{aegis, andotp, twofas};
use libfuzzer_sys::fuzz_target;

// Password vuota: il fuzzer esplora parsing e validazione dei parametri delle KDF.
// I parametri sono limitati, quindi un input malevolo non può bloccare il fuzzer.
fuzz_target!(|data: &[u8]| {
    let _ = aegis::is_encrypted(data);
    let _ = aegis::import(data, None);
    let _ = andotp::import(data, None);
    let _ = twofas::is_encrypted(data);
    let _ = twofas::import(data, None);
});
