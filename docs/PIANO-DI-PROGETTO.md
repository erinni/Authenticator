# Authenticator — Piano di progetto

> Stato: **v0.2** · Ultimo aggiornamento: 2026-10-22
> Obiettivo: un'app di autenticazione a due fattori (TOTP/HOTP) in stile Google/Microsoft Authenticator,
> disponibile su **browser (PWA)**, **smartphone (iOS/Android)** e **desktop (Windows/macOS/Linux)**,
> progettata con un modello **zero-knowledge** e crittografia moderna, inclusa protezione post-quantistica dove ha senso.

---

## 1. Obiettivi e non-obiettivi

### Obiettivi
1. Generare codici **TOTP (RFC 6238)** e **HOTP (RFC 4226)** — SHA-1/SHA-256/SHA-512, 6–8 cifre, periodo configurabile.
2. Aggiungere account tramite **scansione QR** (`otpauth://`), inserimento manuale e **import** da Google Authenticator (`otpauth-migration://`), Aegis, 2FAS, andOTP, Bitwarden, Microsoft Authenticator (dove esportabile).
3. **Vault cifrato localmente**: nessun segreto è mai salvato in chiaro, su nessuna piattaforma.
4. Sblocco con **biometria / passkey / PIN**, legato all'hardware sicuro del dispositivo (Secure Enclave, Android StrongBox/TEE, TPM, Windows Hello, WebAuthn PRF).
5. **Sincronizzazione opzionale end-to-end cifrata** tra dispositivi: il server vede solo ciphertext e metadati minimi.
6. **Backup/export cifrato** e recupero tramite *recovery key* offline.
7. Funzionamento **completamente offline** (la sincronizzazione è un'aggiunta, non un requisito).
8. Codice open source, build riproducibili, release firmate, audit esterno prima della 1.0.

### Non-obiettivi (per la v1)
- Notifiche push di approvazione stile *Microsoft Authenticator* (richiedono integrazione lato servizio: valutate in fase futura).
- Gestore di password generico.
- Gestione passkey/FIDO2 come authenticator (possibile evoluzione futura).

---

## 2. Architettura generale

```
┌──────────────────────────────────────────────────────────────────────┐
│                    UI condivisa (TypeScript + Svelte 5)              │
│        stesso codice per Web PWA, Desktop e Mobile                   │
└───────────────┬───────────────────────────┬──────────────────────────┘
                │                           │
      ┌─────────▼─────────┐       ┌─────────▼──────────────────────┐
      │  Web (PWA)        │       │  Tauri 2 (Desktop + Mobile)    │
      │  core → WASM      │       │  core → Rust nativo            │
      │  WebCrypto/PRF    │       │  plugin: keychain, biometria   │
      └─────────┬─────────┘       └─────────┬──────────────────────┘
                │                           │
      ┌─────────▼───────────────────────────▼──────────────────────┐
      │        authenticator-core  (Rust, #![forbid(unsafe_code)]) │
      │  OTP · Vault · Key hierarchy · Formato file · Sync client  │
      │  Import/Export · Zeroize memoria                           │
      └─────────────────────────────┬──────────────────────────────┘
                                    │ HTTPS (TLS 1.3) + payload E2EE
                          ┌─────────▼─────────┐
                          │  Sync server      │  Rust (axum) + PostgreSQL
                          │  zero-knowledge   │  self-hostable (Docker)
                          └───────────────────┘
```

### Scelte tecnologiche (raccomandate)

| Area | Scelta | Motivazione |
|---|---|---|
| Core crittografico | **Rust** | Memory safety, librerie crittografiche mature (RustCrypto), `zeroize`, compilazione verso WASM e nativo da un'unica base di codice. |
| Desktop + Mobile | **Tauri 2** | Un'unica app per Windows/macOS/Linux/iOS/Android, binari piccoli, modello di permessi *capability-based*, backend Rust. |
| Web | **PWA** con core in **WASM** | Installabile, offline via Service Worker, stessa UI. |
| UI | **Svelte 5 + TypeScript** (strict) | Bundle piccolo → superficie di attacco ridotta e meno dipendenze. |
| Server sync | **Rust + axum + PostgreSQL** | Stesso linguaggio del core, tipi condivisi. |
| Monorepo | **pnpm workspaces + Cargo workspace** | Una sola repo, CI unica. |

> Alternativa valutata: app native separate (Swift/Kotlin) per massima integrazione con l'hardware.
> Scartata per la v1 a causa del costo di 3 codebase; Tauri consente plugin nativi Swift/Kotlin dove servono (biometria, Keystore).

---

## 3. Architettura di sicurezza

### 3.1 Modello delle minacce (sintesi)

| Minaccia | Mitigazione |
|---|---|
| Furto/accesso fisico al dispositivo | Vault cifrato a riposo, auto-lock, chiavi legate all'hardware sicuro, biometria. |
| Malware che legge il disco | Nessun segreto in chiaro; DEK protetta da chiave non esportabile dell'hardware. |
| Compromissione del server di sync | Zero-knowledge: il server non possiede mai chiavi né password (OPAQUE + E2EE). |
| Attacco offline sul backup / database rubato | Argon2id con parametri elevati + chiave a 256 bit; AEAD autenticata. |
| *Harvest now, decrypt later* (quantistico) | Scambio chiavi ibrido **X25519 + ML-KEM-768** per pairing/condivisione chiavi tra dispositivi. |
| Man-in-the-middle durante il pairing | QR code con chiave effimera + verifica codice SAS a 6 cifre. |
| Supply chain (dipendenze malevole) | Dipendenze minime, `cargo-vet`, `cargo-deny`, lockfile, build riproducibili, SBOM, firme Sigstore. |
| XSS / iniezione codice nella versione Web | CSP rigorosa, Trusted Types, nessuno script di terze parti, SRI. |
| Shoulder-surfing / screenshot | Codici nascosti di default (opzionale), blocco screenshot su mobile (`FLAG_SECURE`), clipboard auto-pulita. |

### 3.2 Primitive crittografiche

| Scopo | Algoritmo | Note |
|---|---|---|
| Derivazione chiave da password/PIN | **Argon2id** (RFC 9106) | Default: m = 64 MiB, t = 3, p = 1 (web) / p = 4 (nativo). Parametri versionati e aggiornabili. |
| Cifratura simmetrica | **XChaCha20-Poly1305** | Nonce a 192 bit casuali (nessun rischio di riuso), veloce anche senza AES-NI. |
| Cifratura con chiavi hardware | **AES-256-GCM** | Quando la chiave vive in Secure Enclave/Keystore/TPM che supportano solo AES. |
| Derivazione sottochiavi | **HKDF-SHA-256** (RFC 5869) | Separazione di dominio con `info` esplicito per ogni uso. |
| Scambio chiavi tra dispositivi | **X25519 + ML-KEM-768** (ibrido, FIPS 203) via **HPKE** (RFC 9180) | Sicuro anche se uno dei due algoritmi venisse rotto. |
| Firme (identità dispositivo) | **Ed25519** (+ ML-DSA-65 come fase successiva) | Firma dei record di sync e degli eventi di gestione dispositivi. |
| Autenticazione al server | **OPAQUE** (RFC 9807) + **Passkey (WebAuthn)** | La password non lascia mai il dispositivo, nemmeno sotto forma di hash. |
| Trasporto | **TLS 1.3** only, HSTS, certificate pinning sulle app native | Difesa in profondità: i payload sono già E2EE. |
| Casualità | CSPRNG del sistema (`getrandom` / `crypto.getRandomValues`) | Mai PRNG applicativi. |

Librerie: crate **RustCrypto** (`chacha20poly1305`, `aes-gcm`, `argon2`, `hkdf`, `ed25519-dalek`, `x25519-dalek`, `ml-kem`), `opaque-ke`, `hpke`, `zeroize`, `secrecy`.
**Nessuna crittografia "fatta in casa"**: solo composizione di primitive standard, con test vector ufficiali.

### 3.3 Gerarchia delle chiavi

```
Password principale ──Argon2id(salt)──► KEK_password ─┐
Recovery key (256 bit, offline) ──HKDF──► KEK_recovery ┤
Biometria/Passkey ──► chiave hardware (non esportabile) ──► KEK_device ┤
                                                       │  (ognuna "avvolge" la stessa DEK)
                                                       ▼
                                  Vault Key (DEK, 256 bit casuali)
                                                       │ HKDF(info)
                         ┌─────────────────────────────┼──────────────────────┐
                         ▼                             ▼                      ▼
                  Item key (per account)     Chiave indice/metadati   Chiave sync/backup
```

- La **DEK** è generata casualmente, mai derivata dalla password → cambiare password = ri-avvolgere solo la DEK.
- Ogni **account OTP è cifrato singolarmente** (AEAD con *associated data* = id account + versione), così una sync tocca solo il record modificato.
- **Web**: sblocco con **WebAuthn PRF extension** (passkey → segreto deterministico → KEK); chiavi WebCrypto `extractable: false` in IndexedDB.
- **iOS**: chiave in **Secure Enclave** con `kSecAccessControlBiometryCurrentSet`.
- **Android**: **StrongBox/TEE** Keystore con `setUserAuthenticationRequired(true)` e `BiometricPrompt` con `CryptoObject`.
- **Windows**: **Windows Hello / TPM** (CNG). **macOS**: Secure Enclave + Touch ID. **Linux**: Secret Service / TPM2 dove disponibile, altrimenti solo password.

### 3.4 Igiene della memoria e runtime
- Segreti in tipi `Secret<…>`/`Zeroizing<…>`: azzerati al drop; mai loggati (`Debug` redatto).
- Il segreto OTP **non attraversa mai il confine verso la UI**: la UI riceve solo il codice a 6–8 cifre e il tempo residuo.
- Auto-lock configurabile (default 5 min / al passaggio in background), blocco dopo N tentativi PIN con backoff esponenziale.
- Clipboard ripulita dopo 30 s; su Android/iOS uso di flag "sensitive".
- Rilevamento (non bloccante) di root/jailbreak con avviso all'utente.

### 3.5 Sicurezza specifica Web
- **CSP**: `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; require-trusted-types-for 'script'; frame-ancestors 'none'`…
- **COOP/COEP/CORP**, `Referrer-Policy: no-referrer`, `Permissions-Policy` restrittiva.
- Nessuna CDN o analytics di terze parti; **SRI** su tutti gli asset; Service Worker con versioni firmate.
- Limite intrinseco documentato: nel web il codice è servito dal server → per massima sicurezza si consigliano le app native; possibile in futuro un'estensione browser che verifica l'integrità degli asset.

### 3.6 Sincronizzazione zero-knowledge
1. Registrazione/login con **OPAQUE** (+ passkey come secondo fattore/alternativa).
2. Ogni dispositivo ha una coppia di chiavi d'identità (Ed25519 + X25519/ML-KEM).
3. **Aggiunta nuovo dispositivo**: il dispositivo esistente mostra un QR (chiave effimera + id sessione) → canale HPKE ibrido → confronto codice SAS → la DEK viene trasferita cifrata.
4. Record sul server: `{id opaco, versione, ciphertext, firma}`; nomi servizi, issuer e icone sono **cifrati** anch'essi.
5. Risoluzione conflitti con **Hybrid Logical Clock** + last-writer-wins per record; eliminazioni come *tombstone* firmate.
6. Revoca dispositivo → rotazione della DEK e ri-cifratura.
7. Server **self-hostable** con Docker Compose.

### 3.7 Formato del vault/backup (`.authvault`)
```
magic "AUTHVLT" | versione | kdf_id + parametri | salt | alg_id | nonce | ciphertext+tag
```
Header incluso come *associated data* dell'AEAD; versionamento per migrare algoritmi in futuro (*crypto-agility*).
Export in chiaro (`otpauth://`/QR) consentito solo dopo ri-autenticazione e con avviso esplicito.

---

## 4. Struttura della repository

```
Authenticator/
├── crates/
│   ├── core/            # OTP, vault, key hierarchy, formato file (no I/O)
│   ├── import/          # parser Google/Aegis/2FAS/andOTP/…
│   ├── sync-proto/      # tipi e protocollo condivisi client/server
│   ├── wasm/            # binding wasm-bindgen per la PWA (fase 2)
│   └── server/          # server di sincronizzazione (axum, fase 5)
├── apps/
│   ├── web/             # PWA (Vite + Svelte)
│   └── native/          # Tauri 2 (desktop + iOS + Android) + plugin nativi (fase 3)
├── docs/
│   ├── PIANO-DI-PROGETTO.md
│   ├── threat-model.md
│   └── adr/             # Architecture Decision Records
├── fuzz/                # target cargo-fuzz (fase 1)
├── .github/workflows/   # CI, release firmate, CodeQL, audit
├── SECURITY.md
└── README.md
```

---

## 5. Roadmap per fasi

| Fase | Contenuto | Deliverable | Stima |
|---|---|---|---|
| **0 — Fondamenta** | Monorepo, CI (lint, test, `cargo-deny`, `cargo-audit`, CodeQL), threat model, ADR iniziali, branch protection, commit firmati. | Repo pronta, pipeline verde. | 1 sett. |
| **1 — Core crittografico** | TOTP/HOTP con test vector RFC; vault, gerarchia chiavi, formato `.authvault`; zeroize; parser `otpauth://` e import Google. Fuzzing + property test + vettori Wycheproof. | `crates/core` ≥ 95% coverage. | 3–4 sett. |
| **2 — Web PWA (solo locale)** | Binding WASM, UI Svelte (lista codici, aggiunta via QR da fotocamera/immagine, ricerca, icone), sblocco password + passkey PRF, offline, CSP. | PWA installabile funzionante offline. | 3–4 sett. |
| **3 — Desktop** | Tauri 2 per Win/macOS/Linux; keychain/Windows Hello/Touch ID; auto-update firmato; scansione QR da schermo. | Installer firmati e notarizzati. | 2–3 sett. |
| **4 — Mobile** | Tauri 2 iOS/Android; Secure Enclave / StrongBox + biometria; scanner QR nativo; `FLAG_SECURE`; widget (opz.). | Build TestFlight / Play internal testing. | 4–5 sett. |
| **5 — Sync E2EE** | Server axum + PostgreSQL; OPAQUE + passkey; pairing con HPKE ibrido PQ e SAS; HLC; revoca dispositivi; Docker self-host. | Sync multi-dispositivo funzionante. | 4–6 sett. |
| **6 — Hardening** | Pen-test interno, **audit crittografico esterno**, build riproducibili, SBOM, firme Sigstore/SLSA L3, bug bounty, accessibilità (WCAG 2.2 AA), localizzazione IT/EN. | Report audit, fix applicati. | 3–4 sett. |
| **7 — Release 1.0** | Pubblicazione su App Store, Play Store, Microsoft Store, Mac (notarizzato), Flathub, PWA online. | v1.0 | 1–2 sett. |

**Totale indicativo: ~5–7 mesi** per una persona/piccolo team.
Evoluzioni successive: notifiche push di approvazione, firme ML-DSA, estensione browser con autofill, Apple Watch / Wear OS, gestione passkey.

---

## 6. Qualità e processo

- **Test**: unit, property-based (`proptest`), test vector RFC 4226/6238, Wycheproof, fuzzing continuo, E2E con Playwright (web) e test strumentali mobile.
- **Analisi statica**: `clippy -D warnings`, `#![forbid(unsafe_code)]` nel core, ESLint strict, TypeScript `strict`, CodeQL, Semgrep.
- **Supply chain**: Renovate con revisione manuale, `cargo-vet`, `pnpm audit`, lockfile obbligatori, nessuno script `postinstall` non approvato.
- **Release**: tag firmati, build riproducibili in CI, artefatti firmati (Sigstore + firme di piattaforma), changelog.
- **Processo**: branch protetti, PR con review obbligatoria, Conventional Commits, ADR per ogni decisione architetturale/crittografica, `SECURITY.md` per segnalazione responsabile delle vulnerabilità.
- **Privacy**: nessuna telemetria di default; nessun dato personale oltre a quanto necessario alla sync.

---

## 7. Decisioni prese (2026-10-22)

1. **Nome**: "Authenticator" come nome provvisorio.
2. **Licenza**: GPL-3.0-only per client e core; AGPL-3.0-only per il server di sync.
3. **Sync**: servizio gestito **e** server self-hostable.
4. **Account sync**: password (OPAQUE) **e** passkey.
5. **Framework UI**: Svelte 5 + TypeScript.
6. **Priorità piattaforme**: si parte dalla PWA.
7. Account sviluppatore Apple / Google / Microsoft e certificati di firma: da predisporre prima della fase 3.

Dettagli in `docs/adr/`.

---

## 8. Stato

- [x] **Fase 0 — Fondamenta**: monorepo Cargo + pnpm, lint rigorosi, CI (Rust, Web, cargo-deny, pnpm audit, CodeQL, dependency review), Dependabot, threat model, ADR 0001–0003, CSP + Trusted Types nella PWA.
  Da fare manualmente su GitHub: le impostazioni elencate in `CONTRIBUTING.md`.
- [x] **Fase 1 — Core crittografico** (completata):
  - [x] HOTP/TOTP con test vector RFC 4226 / 6238 (SHA-1/256/512)
  - [x] Base32, parser ed export `otpauth://` con difese anti-spoofing
  - [x] Vault formato v1: DEK casuale, slot password (Argon2id) / recovery key / segreto di piattaforma, header autenticato, rotazione della DEK
  - [x] Serializzazione degli account nel vault (formato binario versionato), merge senza duplicati
  - [x] Import da Google Authenticator, Aegis, 2FAS, andOTP (anche cifrati), verificato su export reali
  - [x] Backup cifrato su file ed export `otpauth://`
  - [x] Fuzzing (6 target) in CI, property test, test di compatibilità del formato, vettori Wycheproof
- [x] **Fase 2 — Web PWA** (completata):
  - [x] Binding WebAssembly (`crates/wasm`): vault e segreti solo nella memoria WASM, la UI riceve solo metadati e codici
  - [x] Vault cifrato in IndexedDB, creazione/sblocco con password, elenco con codici TOTP/HOTP, aggiunta da URI
  - [x] Blocco automatico (inattività e pagina nascosta), pulizia degli appunti, test end-to-end con CSP di produzione
  - [x] Sblocco con passkey (WebAuthn PRF): slot esterno del vault con id = hash dell'id della credenziale, nessun dato aggiuntivo salvato in chiaro; la password resta sempre valida
  - [x] Recovery key e cambio password dalla UI, con ri-autenticazione
  - [x] Scansione QR da fotocamera e immagine (decodifica in Rust/WASM con `rqrr`, fuzzing), import da altre app e backup cifrato dalla UI
  - [x] Test end-to-end Playwright in CI con la CSP di produzione (fotocamera simulata inclusa)
  - [x] Core in un Web Worker (Argon2 non blocca l'interfaccia), policy Trusted Types per gli URL dei worker
  - [x] Service Worker per l'uso offline (cache generata alla build) e manifest per l'installazione
  - [x] Ricerca nell'elenco (senza distinguere maiuscole e accenti) e icone generate in locale (iniziale e colore dall'issuer, nessun download esterno)
- [ ] **Fase 3 — Desktop** (in corso), vedi [ADR-0004](adr/0004-app-desktop.md):
  - [x] App Tauri 2 (`apps/native`) con il core nativo e la UI della PWA; vault su file con scrittura atomica; solo i comandi del core esposti alla webview
  - [x] Sessione condivisa tra PWA e app native (`crates/session`)
  - [x] CI su Linux, Windows e macOS con installer non firmati
  - [x] Sblocco di sistema: Windows Hello (anche con il solo PIN) e portachiavi della sessione su Linux (con avviso: senza biometria)
  - [ ] Touch ID su macOS (richiede la firma Developer ID)
  - [x] Scansione QR dallo schermo (nel processo nativo), blocco alla ripresa dalla sospensione e con la finestra ridotta a icona, appunti nativi esclusi dalla cronologia
  - [x] Aggiornamenti automatici firmati (updater di Tauri, firma legata alla versione) e workflow di release con bozza su GitHub
  - [ ] Installer Windows firmati con SignPath Foundation (workflow pronto, in attesa dell'approvazione del progetto)
  - [ ] Firma e notarizzazione su macOS (richiede il Developer ID)
