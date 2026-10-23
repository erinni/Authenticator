# Threat model

> Versione 0.1 · da aggiornare a ogni modifica che tocca crittografia, storage, rete o gestione chiavi.
> Metodologia: STRIDE sugli asset principali.

## 1. Asset

| ID | Asset | Riservatezza | Integrità | Disponibilità |
|---|---|---|---|---|
| A1 | Segreti OTP (seed TOTP/HOTP) | **Critica** | Critica | Critica (perderli = perdere l'accesso ai servizi) |
| A2 | Vault Key (DEK) e chiavi derivate | **Critica** | Critica | Critica |
| A3 | Password principale / PIN | **Critica** | — | — |
| A4 | Recovery key | **Critica** | Critica | Critica |
| A5 | Metadati account (issuer, nome, icona) | Alta (rivela quali servizi usa l'utente) | Alta | Media |
| A6 | Chiavi d'identità dei dispositivi | Alta | Critica | Media |
| A7 | Codici OTP generati | Media (validi ~30 s) | Alta | Alta |

## 2. Attori malevoli

| ID | Attore | Capacità |
|---|---|---|
| T1 | Ladro del dispositivo | Accesso fisico, dispositivo bloccato o sbloccato. |
| T2 | Malware locale senza privilegi | Legge file dell'utente, clipboard, screenshot. |
| T3 | Malware con privilegi root/admin | Legge memoria dei processi. **Fuori scope** per la protezione completa; mitigazioni best-effort. |
| T4 | Operatore o attaccante del server di sync | Accesso completo a DB, log, traffico applicativo. |
| T5 | Attaccante di rete (MITM) | Intercetta e modifica il traffico. |
| T6 | Attaccante della supply chain | Compromette una dipendenza, una action CI o l'hosting della PWA. |
| T7 | Attaccante con computer quantistico futuro | Decifra traffico registrato oggi (*harvest now, decrypt later*). |
| T8 | Sito/servizio malevolo | Fornisce QR o file di import costruiti ad arte. |

## 3. Analisi STRIDE

| Minaccia | Attore | Asset | Mitigazione | Stato |
|---|---|---|---|---|
| **S** — Impersonare un dispositivo durante il pairing | T5 | A2, A6 | QR con chiave effimera + verifica SAS; HPKE ibrido. | Pianificata (fase 5) |
| **S** — Login al server con password rubata | T4, T5 | A5 | OPAQUE (il server non riceve mai la password) + passkey. | Pianificata (fase 5) |
| **T** — Modifica dei record cifrati sul server | T4 | A1, A5 | AEAD con associated data (id, versione) + firme Ed25519 dei dispositivi. | Pianificata (fase 5) |
| **T** — Rollback a una versione vecchia del vault | T4 | A1 | Contatori di versione monotoni firmati; HLC. | Pianificata (fase 5) |
| **R** — Negare l'aggiunta/revoca di un dispositivo | T4 | A6 | Log degli eventi firmato e verificabile dai client. | Pianificata (fase 5) |
| **I** — Lettura del vault dal disco | T1, T2 | A1, A2 | Cifratura a riposo XChaCha20-Poly1305; DEK avvolta da chiave hardware non esportabile. | **Core implementato (fase 1)**; chiavi hardware in fase 2–4 |
| **I** — Brute force offline su backup/DB rubato | T1, T4 | A3 | Argon2id (default 64 MiB, minimo 19 MiB); DEK a 256 bit casuali; rate limit server-side su OPAQUE. | **Implementata (fase 1)**; rate limit in fase 5 |
| **I** — Server che legge i metadati | T4 | A5 | Anche issuer/nome/icone sono cifrati; id record opachi. | Pianificata (fase 5) |
| **I** — Traffico registrato e decifrato in futuro | T7 | A2 | Scambio chiavi ibrido X25519 + ML-KEM-768. | Pianificata (fase 5) |
| **I** — Clipboard/screenshot | T2 | A7 | Clipboard pulita dopo 30 s (PWA: implementata), flag "sensitive"; `FLAG_SECURE` su Android, oscuramento in app switcher iOS. | **Parziale (fase 2)**; mobile in fase 4 |
| **I** — Segreti nei log o nei crash report | T2, T4 | A1–A4 | `SecretBytes`/`Key256`/`RecoveryKey` con `Debug` redatto; errori senza dati; nessuna telemetria. | **Implementata (fase 1)** |
| **I** — Segreti residui in memoria | T3 | A1–A3 | `zeroize` al drop; nella PWA vault e seed restano nella memoria WebAssembly e la UI riceve solo codici; password convertite subito in byte e azzerate (le stringhe JS non sono azzerabili). Best-effort. | **Implementata (fase 2)** |
| **E** — XSS nella PWA che esfiltra codici | T6, T8 | A1, A7 | CSP `default-src 'none'`, Trusted Types, nessun `{@html}`/`innerHTML` (lint), nessuno script terzo; anche con XSS i seed non sono leggibili da JS (solo i codici correnti). Verificato con test end-to-end. | **Implementata (fase 0, 2)** |
| **I** — Vault lasciato aperto | T1 | A1, A7 | Blocco automatico dopo 5 min di inattività o 60 s con pagina nascosta; blocco manuale; la sessione WASM viene liberata. | **Implementata (fase 2)** |
| **E** — Clickjacking | T8 | A7 | `frame-ancestors 'none'`, `X-Frame-Options: DENY`. | **Implementata (fase 0)** |
| **S** — Nome del servizio falsificato in un QR (es. caratteri bidirezionali) | T8 | A7 | Rifiuto di caratteri di controllo e override bidirezionali in issuer e nome. | **Implementata (fase 1)** |
| **T** — File vault manomesso o con parametri KDF malevoli (DoS / downgrade) | T1, T2, T4 | A1, A3 | Header autenticato come AAD; parametri Argon2id validati entro limiti min/max prima della derivazione. | **Implementata (fase 1)** |
| **E** — Dipendenza compromessa | T6 | tutti | Dipendenze minime, lockfile, `minimumReleaseAge` 7 giorni, `trustPolicy`, nessuno script di install, cargo-deny, CodeQL, action fissate per SHA. | **Implementata (fase 0)** |
| **E** — Parser di import sfruttato da file malevolo | T8 | A1 | Parser in Rust senza `unsafe`, limiti di dimensione, fuzzing in CI (5 target). | **Implementata (fase 1)** |
| **D** — Perdita del dispositivo = perdita dei segreti | T1 | A1 | Recovery key offline (implementata), backup cifrato, sync multi-dispositivo. | **Parziale (fase 1)**; sync in fase 5 |
| **D** — Codice OTP errato per orologio sbagliato | — | A7 | Avviso se l'orologio di sistema diverge; tolleranza solo lato verificatore. | Pianificata (fase 2) |

## 4. Rischi residui accettati

- **Malware con privilegi elevati (T3)** può leggere i segreti mentre il vault è sbloccato: nessuna app può impedirlo del tutto.
- **PWA**: il codice è servito dal server di hosting a ogni aggiornamento. Una compromissione dell'hosting (T6) potrebbe servire codice malevolo. Mitigazioni: Service Worker che fissa la versione, release firmate e verificabili, raccomandazione delle app native per il massimo livello di sicurezza.
- **Linux senza TPM/Secret Service**: lo sblocco si appoggia solo alla password.
