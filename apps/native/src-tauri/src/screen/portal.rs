//! Cattura tramite il portale XDG Screenshot (Wayland e X11).
//!
//! Il portale salva la schermata in un file PNG e ne restituisce l'indirizzo: il file
//! viene letto e cancellato subito, e i suoi byte azzerati in memoria.

use std::fs;
use std::io::Read;
use std::path::Path;

use ashpd::desktop::screenshot::Screenshot as Portal;
use authenticator_session::Screenshot;
use zeroize::Zeroizing;

use super::super::text;

/// Errore di cattura annullata dall'utente (la UI non lo mostra come un problema).
const CANCELLED: &str = "screen:cancelled";

/// Dimensione massima del file PNG letto.
const MAX_FILE: u64 = 256 * 1024 * 1024;
/// Byte massimi dell'immagine decodificata (64 megapixel RGBA).
const MAX_IMAGE: usize = 64 * 1024 * 1024 * 4;

pub(super) async fn capture() -> Result<Vec<Screenshot>, String> {
    let request = Portal::request()
        .interactive(false)
        .modal(true)
        .send()
        .await
        .map_err(portal_error)?;
    let response = request.response().map_err(portal_error)?;
    let path = url::Url::parse(response.uri().as_str())
        .ok()
        .filter(|uri| uri.scheme() == "file")
        .and_then(|uri| uri.to_file_path().ok())
        .ok_or("indirizzo della schermata non valido")?;
    let png = read_and_remove(&path)?;
    Ok(vec![decode(&png)?])
}

fn portal_error(e: ashpd::Error) -> String {
    match e {
        ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled) => CANCELLED.into(),
        e => format!("cattura dello schermo non disponibile: {e}"),
    }
}

/// Legge il file della schermata e lo cancella, anche se la lettura non riesce.
fn read_and_remove(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let read = || -> std::io::Result<Zeroizing<Vec<u8>>> {
        let file = fs::File::open(path)?;
        // Capacità preallocata: la lettura non lascia copie parziali non azzerate.
        let len = usize::try_from(file.metadata()?.len().min(MAX_FILE)).unwrap_or(0);
        let mut data = Zeroizing::new(Vec::with_capacity(len.saturating_add(1)));
        file.take(MAX_FILE).read_to_end(&mut data)?;
        Ok(data)
    };
    let data = read();
    let removed = fs::remove_file(path);
    let data = data.map_err(text)?;
    removed.map_err(|e| format!("schermata non cancellata ({}): {e}", path.display()))?;
    Ok(data)
}

/// Decodifica il PNG in RGBA a 8 bit.
fn decode(png: &[u8]) -> Result<Screenshot, String> {
    let mut decoder =
        png::Decoder::new_with_limits(std::io::Cursor::new(png), png::Limits { bytes: MAX_IMAGE });
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(text)?;
    let size = reader
        .output_buffer_size()
        .ok_or("schermata troppo grande")?;
    let mut pixels = Zeroizing::new(vec![0; size]);
    let info = reader.next_frame(&mut pixels).map_err(text)?;
    let pixels = pixels
        .get(..info.buffer_size())
        .ok_or("schermata non valida")?;
    let channels = match info.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::Rgb => 3,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Grayscale => 1,
        png::ColorType::Indexed => return Err("formato della schermata non supportato".into()),
    };
    // Capacità esatta: nessuna riallocazione lascia copie non azzerate dei pixel.
    let mut rgba = Zeroizing::new(Vec::with_capacity(pixels.len() / channels * 4));
    for px in pixels.chunks_exact(channels) {
        rgba.extend_from_slice(&match *px {
            [r, g, b, a] => [r, g, b, a],
            [r, g, b] => [r, g, b, 255],
            [y, a] => [y, y, y, a],
            [y] => [y, y, y, 255],
            _ => [0; 4],
        });
    }
    Ok(Screenshot {
        width: info.width,
        height: info.height,
        rgba,
    })
}
