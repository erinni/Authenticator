#![no_main]

use authenticator_core::Store;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|payload: &[u8]| {
    if let Ok(store) = Store::decode(payload) {
        let encoded = store.encode().expect("store decodificato non ricodificabile");
        assert_eq!(Store::decode(&encoded).expect("ricodifica non valida"), store);
    }
});
