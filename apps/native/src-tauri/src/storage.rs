//! Persistenza del vault cifrato su file, nella cartella dati dell'app.
//!
//! Viene salvato **solo** il file cifrato prodotto dal core: nessun segreto, nome di
//! account o metadato in chiaro tocca il disco. La scrittura è atomica (file
//! temporaneo, `fsync`, `rename`): un'interruzione lascia il vault precedente intatto.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Nome del file del vault nella cartella dati dell'app.
pub(crate) const VAULT_FILE: &str = "vault.authvault";

/// Dimensione massima accettata in lettura (un vault reale è di pochi KiB).
const MAX_SIZE: u64 = 16 * 1024 * 1024;

/// Legge il vault cifrato, o `None` se non esiste ancora.
pub(crate) fn load(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if file.metadata()?.len() > MAX_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file del vault troppo grande",
        ));
    }
    let mut data = Vec::new();
    io::Read::read_to_end(&mut io::Read::take(file, MAX_SIZE), &mut data)?;
    Ok(Some(data))
}

/// Salva il vault cifrato sostituendo atomicamente il precedente.
pub(crate) fn save(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "percorso senza cartella"))?;
    fs::create_dir_all(dir)?;
    let temp = temp_path(path);
    let written = write_synced(&temp, data).and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        // Il temporaneo non serve più: errore di rimozione irrilevante rispetto al primo.
        let _ = fs::remove_file(&temp);
    }
    written?;
    sync_dir(dir)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

fn write_synced(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // Leggibile solo dall'utente: il contenuto è cifrato, ma non serve ad altri.
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

/// Rende persistente il `rename` (su Windows non serve e non è supportato).
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "authenticator-native-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn missing_vault_is_none() {
        let dir = temp_dir("missing");
        assert_eq!(load(&dir.join(VAULT_FILE)).unwrap(), None);
    }

    #[test]
    fn save_creates_dir_and_replaces() {
        let dir = temp_dir("replace");
        let path = dir.join("nested").join(VAULT_FILE);
        save(&path, b"first").unwrap();
        save(&path, b"second").unwrap();
        assert_eq!(load(&path).unwrap().as_deref(), Some(&b"second"[..]));
        assert!(!temp_path(&path).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
