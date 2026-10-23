# ADR-0002 — Primitive crittografiche

- **Stato:** accettato
- **Data:** 2026-10-22

## Contesto
Servono primitive moderne, standardizzate, con implementazioni mature in Rust (anche per WebAssembly),
resistenti a uso improprio (es. riuso del nonce) e con un percorso verso la crittografia post-quantistica.

## Decisione

| Scopo | Primitiva | Parametri / note |
|---|---|---|
| KDF da password/PIN | Argon2id (RFC 9106) | m = 64 MiB, t = 3, p = 1 (web) / 4 (nativo); salt 16 byte; parametri salvati nell'header. |
| Cifratura vault e record | XChaCha20-Poly1305 | Chiave 256 bit, nonce 192 bit casuale per ogni cifratura, AD = header/id/versione. |
| Cifratura con chiavi hardware | AES-256-GCM | Solo dove l'hardware non supporta altro (Secure Enclave, Keystore, TPM). |
| Sottochiavi | HKDF-SHA-256 (RFC 5869) | `info` = `"authenticator/v1/<scopo>"`, una chiave per scopo. |
| Scambio chiavi | HPKE (RFC 9180) con KEM ibrido X25519 + ML-KEM-768 (FIPS 203) | Pairing dispositivi e condivisione della DEK. |
| Firme | Ed25519 | ML-DSA-65 (FIPS 204) da aggiungere in modalità ibrida in una fase successiva. |
| Autenticazione server | OPAQUE (RFC 9807) + WebAuthn/passkey | Ristretto255 + Argon2id come KSF. |
| OTP | HMAC-SHA-1/256/512 (RFC 4226, 6238) | SHA-1 richiesto per compatibilità con i servizi esistenti: sicuro in HMAC. |
| Random | `getrandom` / `crypto.getRandomValues` | Mai PRNG applicativi; `Math.random` vietato dal linter. |

**Librerie:** RustCrypto (`chacha20poly1305`, `aes-gcm`, `argon2`, `hkdf`, `hmac`, `sha1`, `sha2`, `ml-kem`),
`x25519-dalek`, `ed25519-dalek`, `opaque-ke`, `hpke`, `zeroize`, `secrecy`, `subtle` (confronti a tempo costante).
`openssl` è vietato da `deny.toml`.

### Primitive usate solo per l'import
Per leggere i backup cifrati di altre app servono le loro primitive, usate **solo in
lettura** e mai per i dati di Authenticator: AES-256-GCM (Aegis, andOTP, 2FAS),
scrypt (Aegis), PBKDF2-HMAC-SHA1 (andOTP) e PBKDF2-HMAC-SHA256 (2FAS). I parametri letti
dai file sono limitati (scrypt ≤ 256 MiB, PBKDF2 ≤ 10 milioni di iterazioni) per evitare DoS.

### Crypto-agility
Ogni struttura cifrata inizia con un header versionato (`magic | versione | kdf_id | alg_id | …`)
autenticato come AD. Cambiare algoritmo = nuova versione + migrazione al primo sblocco.

### Regole
1. Nessuna primitiva implementata in proprio: solo composizione di primitive standard.
2. Ogni primitiva è coperta da test vector ufficiali (RFC, NIST, Wycheproof).
3. Confronti di segreti solo a tempo costante (`subtle`).
4. Nessun segreto in tipi che implementano `Debug`/`Display` in chiaro.

## Alternative considerate
- **AES-256-GCM ovunque**: nonce a 96 bit, rischio di collisione con nonce casuali su molti messaggi; lento senza AES-NI (alcuni Android, WASM).
- **scrypt / PBKDF2**: meno resistenti ad attacchi GPU/ASIC rispetto ad Argon2id.
- **Solo X25519**: vulnerabile a *harvest now, decrypt later*.
- **Solo ML-KEM**: algoritmo giovane; l'ibrido resta sicuro se uno dei due cede.

## Conseguenze
- Argon2id con 64 MiB in WASM richiede ~0,5–1 s sui dispositivi lenti: accettabile allo sblocco con password; lo sblocco quotidiano avviene con biometria/passkey.
- Le versioni di `ml-kem`, `opaque-ke` e `hpke` vanno rivalutate prima della fase 5 (maturità, audit).
