#![no_main]

use authenticator_import::qr;
use libfuzzer_sys::fuzz_target;

// Il primo byte sceglie la larghezza; il resto è l'immagine (luminanze).
fuzz_target!(|data: &[u8]| {
    let Some((&[w], luma)) = data.split_first_chunk::<1>() else { return };
    let width = usize::from(w).max(1);
    let height = luma.len() / width;
    if let Some(pixels) = luma.get(..width * height) {
        let _ = qr::decode_luma(width, height, pixels);
    }
});
