//! Decodifica dei QR code da un'immagine in scala di grigi.
//!
//! Il contenuto di un QR di attivazione è un segreto (URI `otpauth://`): i chiamanti
//! lo interpretano direttamente invece di restituirlo all'interfaccia.

use zeroize::Zeroizing;

use crate::ImportError;

/// Pixel massimi accettati (circa 4 megapixel): limita memoria e tempo di calcolo.
pub const MAX_PIXELS: usize = 2048 * 2048;
/// Lato minimo utile: sotto questa soglia non può esserci un QR leggibile.
const MIN_SIDE: usize = 21;
/// Numero massimo di QR considerati in una singola immagine.
const MAX_CODES: usize = 8;
/// Pixel massimi di una schermata, analizzata a riquadri (copre l'8K).
pub const MAX_SCREEN_PIXELS: usize = 64 * 1024 * 1024;
/// Lato dei riquadri in cui si divide una schermata grande.
const TILE_SIDE: usize = 2048;
/// Sovrapposizione tra riquadri vicini: un QR largo fino a questi pixel sta sempre per
/// intero in almeno un riquadro.
const TILE_OVERLAP: usize = 512;

/// Decodifica tutti i QR presenti in un'immagine `width × height` di luminanze (0–255).
///
/// # Errors
/// [`ImportError::TooLarge`] oltre [`MAX_PIXELS`]; [`ImportError::InvalidFormat`] se le
/// dimensioni non corrispondono ai dati.
pub fn decode_luma(
    width: usize,
    height: usize,
    luma: &[u8],
) -> Result<Vec<Zeroizing<String>>, ImportError> {
    let pixels = width.checked_mul(height).ok_or(ImportError::TooLarge)?;
    if pixels > MAX_PIXELS {
        return Err(ImportError::TooLarge);
    }
    if pixels != luma.len() {
        return Err(ImportError::InvalidFormat);
    }
    if width < MIN_SIDE || height < MIN_SIDE {
        return Ok(Vec::new());
    }
    let mut image = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        luma.get(y * width + x).copied().unwrap_or(255)
    });
    Ok(image
        .detect_grids()
        .into_iter()
        .take(MAX_CODES)
        .filter_map(|grid| grid.decode().ok())
        .map(|(_, content)| Zeroizing::new(content))
        .collect())
}

/// Come [`decode_luma`], ma accetta immagini fino a [`MAX_SCREEN_PIXELS`] (le schermate
/// dei monitor 4K o più grandi): oltre [`MAX_PIXELS`] l'immagine è analizzata a riquadri
/// sovrapposti, così tempo e memoria per riquadro restano quelli di [`decode_luma`].
/// I QR trovati più volte (nella sovrapposizione) sono restituiti una volta sola.
///
/// # Errors
/// [`ImportError::TooLarge`] oltre [`MAX_SCREEN_PIXELS`]; [`ImportError::InvalidFormat`]
/// se le dimensioni non corrispondono ai dati.
pub fn decode_luma_tiled(
    width: usize,
    height: usize,
    luma: &[u8],
) -> Result<Vec<Zeroizing<String>>, ImportError> {
    let pixels = width.checked_mul(height).ok_or(ImportError::TooLarge)?;
    if pixels > MAX_SCREEN_PIXELS {
        return Err(ImportError::TooLarge);
    }
    if pixels != luma.len() {
        return Err(ImportError::InvalidFormat);
    }
    if pixels <= MAX_PIXELS {
        return decode_luma(width, height, luma);
    }
    let mut found: Vec<Zeroizing<String>> = Vec::new();
    let mut tile = Zeroizing::new(Vec::with_capacity(TILE_SIDE * TILE_SIDE));
    for top in tile_starts(height) {
        for left in tile_starts(width) {
            let tile_width = TILE_SIDE.min(width - left);
            let tile_height = TILE_SIDE.min(height - top);
            tile.clear();
            for row in luma.chunks_exact(width).skip(top).take(tile_height) {
                let part = row
                    .get(left..left + tile_width)
                    .ok_or(ImportError::InvalidFormat)?;
                tile.extend_from_slice(part);
            }
            for code in decode_luma(tile_width, tile_height, &tile)? {
                if found.len() < MAX_CODES && !found.contains(&code) {
                    found.push(code);
                }
            }
        }
    }
    Ok(found)
}

/// Posizioni iniziali dei riquadri lungo un lato di `len` pixel; l'ultimo riquadro è
/// allineato al bordo.
fn tile_starts(len: usize) -> impl Iterator<Item = usize> {
    let last = len.saturating_sub(TILE_SIDE);
    (0..last)
        .step_by(TILE_SIDE - TILE_OVERLAP)
        .chain(core::iter::once(last))
}

/// Converte un'immagine RGBA (come `ImageData` del browser) in luminanze.
///
/// # Errors
/// [`ImportError::InvalidFormat`] se la lunghezza non è un multiplo di 4.
pub fn rgba_to_luma(rgba: &[u8]) -> Result<Vec<u8>, ImportError> {
    if !rgba.len().is_multiple_of(4) {
        return Err(ImportError::InvalidFormat);
    }
    Ok(rgba
        .chunks_exact(4)
        .map(|px| match px {
            // Luminanza BT.601 in aritmetica intera; il canale alfa è ignorato.
            [r, g, b, _] => {
                let y = 299 * u32::from(*r) + 587 * u32::from(*g) + 114 * u32::from(*b);
                u8::try_from(y / 1000).unwrap_or(u8::MAX)
            }
            _ => u8::MAX,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Disegna un QR in un'immagine di luminanze, con margine e moduli di `scale` pixel.
    fn render(content: &str, scale: usize) -> (usize, Vec<u8>) {
        let code = qrcode::QrCode::new(content.as_bytes()).unwrap();
        let modules = code.width();
        let colors = code.to_colors();
        let side = (modules + 8) * scale;
        let mut luma = vec![255u8; side * side];
        for (i, color) in colors.iter().enumerate() {
            if *color == qrcode::Color::Dark {
                let (mx, my) = (i % modules + 4, i / modules + 4);
                for dy in 0..scale {
                    for dx in 0..scale {
                        luma[(my * scale + dy) * side + mx * scale + dx] = 0;
                    }
                }
            }
        }
        (side, luma)
    }

    #[test]
    fn decodes_generated_qr() {
        let uri = "otpauth://totp/ACME:mario?secret=JBSWY3DPEHPK3PXP&issuer=ACME";
        let (side, luma) = render(uri, 4);
        let found = decode_luma(side, side, &luma).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].as_str(), uri);
    }

    #[test]
    fn empty_and_invalid_images() {
        assert!(decode_luma(100, 100, &[255; 10_000]).unwrap().is_empty());
        assert!(decode_luma(10, 10, &[0; 100]).unwrap().is_empty());
        assert_eq!(
            decode_luma(100, 100, &[0; 99]),
            Err(ImportError::InvalidFormat)
        );
        assert_eq!(decode_luma(5000, 5000, &[]), Err(ImportError::TooLarge));
        assert_eq!(decode_luma(usize::MAX, 2, &[]), Err(ImportError::TooLarge));
    }

    /// Copia `qr` (quadrato di lato `side`) in una schermata bianca alla posizione data.
    fn screen(width: usize, height: usize, qr: &[(usize, usize, &[u8], usize)]) -> Vec<u8> {
        let mut luma = vec![255u8; width * height];
        for &(x, y, code, side) in qr {
            for row in 0..side {
                let start = (y + row) * width + x;
                luma[start..start + side].copy_from_slice(&code[row * side..(row + 1) * side]);
            }
        }
        luma
    }

    #[test]
    fn tiled_decoding_finds_codes_anywhere_on_large_screens() {
        let first = "otpauth://totp/ACME:mario?secret=JBSWY3DPEHPK3PXP&issuer=ACME";
        let second = "otpauth://totp/Example:anna?secret=KRSXG5CTMVRXEZLU&issuer=Example";
        let (side_a, qr_a) = render(first, 4);
        let (side_b, qr_b) = render(second, 3);
        let (width, height) = (3840, 2160);
        // Il primo QR è a cavallo del bordo tra due riquadri, il secondo in basso a destra.
        let luma = screen(
            width,
            height,
            &[
                (1900, 1000, &qr_a, side_a),
                (width - side_b - 10, height - side_b - 10, &qr_b, side_b),
            ],
        );
        let found = decode_luma_tiled(width, height, &luma).unwrap();
        let mut found: Vec<&str> = found.iter().map(|code| code.as_str()).collect();
        found.sort_unstable();
        assert_eq!(found, vec![first, second]);
    }

    #[test]
    fn tiled_decoding_limits() {
        let uri = "otpauth://totp/ACME:mario?secret=JBSWY3DPEHPK3PXP&issuer=ACME";
        let (side, qr) = render(uri, 4);
        let luma = screen(300, 300, &[(10, 10, &qr, side)]);
        assert_eq!(decode_luma_tiled(300, 300, &luma).unwrap().len(), 1);
        assert_eq!(
            decode_luma_tiled(16_384, 8_192, &[]),
            Err(ImportError::TooLarge)
        );
        assert_eq!(
            decode_luma_tiled(4000, 3000, &[0; 10]),
            Err(ImportError::InvalidFormat)
        );
        assert_eq!(tile_starts(100).collect::<Vec<_>>(), vec![0]);
        assert_eq!(tile_starts(3840).collect::<Vec<_>>(), vec![0, 1536, 1792]);
    }

    #[test]
    fn rgba_conversion() {
        assert_eq!(
            rgba_to_luma(&[255, 255, 255, 255, 0, 0, 0, 255]).unwrap(),
            vec![255, 0]
        );
        assert_eq!(rgba_to_luma(&[1, 2, 3]), Err(ImportError::InvalidFormat));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn random_images_never_panic(side in 21usize..80, seed in any::<u64>()) {
            let mut state = seed;
            let luma: Vec<u8> = (0..side * side)
                .map(|_| {
                    state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    if state >> 63 == 0 { 0 } else { 255 }
                })
                .collect();
            let _ = decode_luma(side, side, &luma);
        }
    }
}
