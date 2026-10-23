//! Core crittografico di Authenticator.
//!
//! Questo crate non esegue I/O: riceve e restituisce byte, così da poter essere
//! compilato sia in nativo (Tauri) sia in WebAssembly (PWA).
//!
//! Le primitive e la gerarchia delle chiavi sono descritte in
//! `docs/adr/0002-primitive-crittografiche.md`.

pub mod account;
pub mod aead;
pub mod backup;
pub mod base32;
mod codec;
pub mod error;
pub mod otp;
pub mod secret;
pub mod store;
pub mod vault;

pub use account::{OtpAccount, OtpKind};
pub use error::{Error, Result};
pub use secret::{Key256, SecretBytes};
pub use store::{Entry, EntryId, MergeReport, Store};
pub use vault::{Credential, KdfParams, RecoveryKey, Vault};
