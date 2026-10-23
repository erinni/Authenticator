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
