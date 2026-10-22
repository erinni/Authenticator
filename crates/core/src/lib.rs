//! Core crittografico di Authenticator.
//!
//! Questo crate non esegue I/O: riceve e restituisce byte, così da poter essere
//! compilato sia in nativo (Tauri) sia in WebAssembly (PWA).
//!
//! Le primitive e la gerarchia delle chiavi sono descritte in
//! `docs/adr/0002-primitive-crittografiche.md`.

/// Versione del formato del vault supportata da questa build.
pub const VAULT_FORMAT_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_format_version_is_set() {
        assert_eq!(VAULT_FORMAT_VERSION, 1);
    }
}
