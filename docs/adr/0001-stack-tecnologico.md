# ADR-0001 — Stack tecnologico

- **Stato:** accettato
- **Data:** 2026-10-22

## Contesto
L'app deve funzionare su browser, iOS, Android, Windows, macOS e Linux, con un livello di sicurezza
elevato e un team ridotto. Mantenere la crittografia in più linguaggi moltiplica la probabilità di errori.

## Decisione
- **Core in Rust** (`crates/core`, `#![forbid(unsafe_code)]`, nessun I/O), compilato:
  - in **WebAssembly** per la PWA;
  - in **nativo** per Tauri.
- **Tauri 2** per desktop e mobile, con plugin nativi (Swift/Kotlin) per Secure Enclave, Keystore e biometria.
- **PWA** con Vite e **Svelte 5 + TypeScript strict** come UI condivisa.
- **Server di sync** in Rust (axum) + PostgreSQL, self-hostable.
- **Monorepo**: Cargo workspace + pnpm workspace.
- **Licenza**: GPL-3.0-only per client e core; AGPL-3.0-only per il server.
- **Priorità**: si parte dalla PWA (fase 2), poi desktop e mobile.

## Alternative considerate
- **App native separate (Swift, Kotlin, C#)**: migliore integrazione, ma 3–4 codebase e crittografia duplicata.
- **Flutter / React Native**: UI condivisa, ma il core crittografico andrebbe comunque in un linguaggio diverso o via FFI; ecosistema crittografico meno maturo.
- **Electron**: binari pesanti e superficie di attacco maggiore (Chromium + Node.js completi).
- **React** al posto di Svelte: ecosistema più ampio, ma bundle più grande e più dipendenze transitive.

## Conseguenze
- Un'unica implementazione crittografica da auditare.
- Tauri mobile è più giovane delle soluzioni native: possibili plugin nativi da scrivere in proprio.
- Il core non deve dipendere da API di sistema: le capacità della piattaforma (keychain, biometria, RNG hardware) vengono iniettate tramite trait.

## Aggiornamento (fase 2): architettura della PWA
- Il core WebAssembly gira in un **Web Worker dedicato**: Argon2id non blocca l'interfaccia e la sessione sbloccata vive in un contesto separato dalla pagina, che comunica solo tramite messaggi (metadati e codici in uscita, password come buffer trasferiti e azzerati).
- Un **Service Worker** generato alla build mette in cache l'intera app (file con hash) e la serve offline; una nuova versione si attiva solo quando tutte le schede della precedente sono chiuse.
- L'hosting di produzione deve applicare gli header di `apps/web/security-headers.ts` a **tutte** le risposte, incluso `sw.js`.
