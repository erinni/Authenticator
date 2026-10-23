# Authenticator

App di autenticazione a due fattori (TOTP/HOTP) open source, multipiattaforma — **Web (PWA)**, **iOS/Android**, **Windows/macOS/Linux** — con vault cifrato *zero-knowledge* e sincronizzazione end-to-end opzionale.

> 🚧 In sviluppo: fase 2 (PWA) in corso. Vedi il [Piano di progetto](docs/PIANO-DI-PROGETTO.md).

## Punti chiave
- Codici TOTP (RFC 6238) e HOTP (RFC 4226), import da Google Authenticator, Aegis, 2FAS e andOTP (anche backup cifrati); backup cifrato.
- Core in Rust condiviso da tutte le piattaforme (nativo + WebAssembly).
- Crittografia: Argon2id, XChaCha20-Poly1305, HKDF, Ed25519, scambio chiavi ibrido post-quantistico X25519 + ML-KEM-768, autenticazione OPAQUE + passkey.
- Chiavi protette da Secure Enclave / StrongBox / TPM / WebAuthn PRF.
- Funziona offline; nessuna telemetria.

## Struttura
| Percorso | Contenuto |
|---|---|
| `crates/core` | Core crittografico (OTP, vault, chiavi) — senza I/O, compilabile in WASM |
| `crates/import` | Import da altri authenticator |
| `crates/wasm` | Binding WebAssembly per la PWA (i segreti restano nella memoria WASM) |
| `crates/sync-proto` | Protocollo di sincronizzazione zero-knowledge |
| `apps/web` | PWA (Vite + Svelte 5 + TypeScript) |
| `fuzz/` | Target di fuzzing (`cargo +nightly fuzz`) |
| `docs/` | Piano, [threat model](docs/threat-model.md), [ADR](docs/adr/) |

## Sviluppo
Vedi [CONTRIBUTING.md](CONTRIBUTING.md).

## Sicurezza
Per segnalare vulnerabilità consulta [SECURITY.md](SECURITY.md).

## Licenza
[GPL-3.0-only](LICENSE). Il futuro server di sincronizzazione sarà rilasciato con licenza AGPL-3.0-only.
