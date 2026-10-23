#![no_main]

use authenticator_core::base32;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    if let Ok(bytes) = base32::decode(input) {
        // Ogni decodifica valida deve essere stabile dopo una ricodifica.
        let again = base32::decode(&base32::encode(&bytes)).expect("ricodifica non valida");
        assert_eq!(*again, *bytes);
    }
});
