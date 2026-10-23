# ADR-0004 — Architettura dell'app desktop

- **Stato:** accettato
- **Data:** 2026-10-23

## Contesto
La fase 3 porta l'app su Windows, macOS e Linux con Tauri 2 (ADR-0001). Vanno decisi dove gira il
core, come si condivide la UI con la PWA e quali API di sistema sono raggiungibili dalla webview.

## Decisione
- **Core nativo**: il vault sbloccato vive nel processo Rust dell'app (`apps/native`), non nella
  webview. La webview non carica WebAssembly e riceve solo metadati e codici, come dal Web Worker
  nella PWA. Questo permette di collegare lo sblocco al keychain di sistema (fase 3, PR successive).
- **Una sola implementazione della sessione**: `crates/session` contiene le operazioni sul vault
  sbloccato; `crates/wasm` (PWA) e `apps/native` (desktop) si limitano a convertire tipi ed errori.
- **Stessa UI**: `apps/web` compilata con `--mode desktop`. Un plugin Vite sostituisce i moduli
  `x.ts` con `x.desktop.ts` dove esistono (trasporto verso il core, salvataggio del vault, passkey,
  Service Worker). Le varianti sono tipizzate con `typeof import("./x")`, quindi non possono divergere.
- **Comandi minimi**: un comando Tauri per ogni operazione di `CoreApi`, più lettura e scrittura del
  file del vault. Ogni comando richiede un permesso esplicito; la capability concede solo quelli,
  senza plugin di sistema. ACL statica (feature `dynamic-acl` disattivata).
- **Persistenza**: il vault cifrato è il file `vault.authvault` nella cartella dati dell'app, scritto
  in modo atomico. Il formato è lo stesso della PWA.
- **Argon2id**: parametri `KdfParams::NATIVE` (4 lane) per le password create su desktop.
- **Passkey**: non disponibili su desktop (WebAuthn PRF non uniforme nelle webview di sistema e
  origine non web). Al loro posto c'è lo sblocco di sistema.
- **Sblocco di sistema** (aggiornato il 2026-10-23): usa lo stesso tipo di slot "esterno" delle
  passkey, con un id casuale, e il segreto non lascia mai il processo nativo.
  - *Windows Hello* (`KeyCredentialManager`): la chiave RSA dello slot, non esportabile e nel TPM
    se presente, firma una sfida fissa; la firma PKCS#1 v1.5 è deterministica ed è il segreto.
    Su disco non si salva nulla e ogni sblocco chiede PIN, impronta o volto.
  - *Linux* (Secret Service): segreto casuale di 32 byte nel portachiavi della sessione. Senza
    biometria vale quanto la sessione utente: la UI lo dice prima dell'attivazione.
  - *macOS*: rimandato. Il Keychain con Touch ID richiede l'app firmata con un Developer ID.
  - Nessun `unsafe`: le API WinRT del crate `windows` sono sicure.

## Alternative considerate
- **Core WebAssembly anche nella webview**: zero codice nativo, ma i segreti resterebbero nel
  processo della webview e lo sblocco hardware richiederebbe comunque un ponte nativo.
- **Selezione della piattaforma a runtime** (`if (isTauri)`): il bundle desktop includerebbe worker,
  WebAssembly e Service Worker inutilizzati, e viceversa.
- **Isolation pattern di Tauri**: cifra l'IPC tra webview e core; utile contro script iniettati in
  pagine con contenuti di terzi, che l'app non carica. Da rivalutare in fase 6.

## Conseguenze
- Le API esposte dal core restano una sola (`CoreApi`); un test verifica che ogni metodo abbia il
  comando e il permesso corrispondenti nell'app Tauri.
- Su Linux la build richiede WebKitGTK 4.1; la CI compila e impacchetta l'app su tutti e tre i sistemi.
- Firma e notarizzazione degli installer richiedono i certificati di piattaforma (fase 3, release).
