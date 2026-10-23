#![no_main]

use authenticator_import::google;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = google::parse_payload(data);
    if let Ok(uri) = core::str::from_utf8(data) {
        let _ = google::parse_migration_uri(uri);
    }
});
