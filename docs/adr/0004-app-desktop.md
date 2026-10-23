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
- **QR dallo schermo** (aggiornato il 2026-10-23): la schermata è catturata e analizzata nel
  processo nativo e azzerata subito dopo; alla webview arriva solo il riepilogo (quanti account).
  - *Windows e macOS*: `xcap` cattura tutti i monitor (su macOS serve il permesso "Registrazione
    schermo").
  - *Linux*: portale XDG Screenshot (`ashpd`), valido su Wayland e X11, che chiede il consenso
    a ogni cattura. Il portale consegna un file PNG: viene letto e cancellato subito.
  - Le schermate oltre i 4 megapixel (4K, 8K) sono analizzate a riquadri sovrapposti di
    2048 pixel, con gli stessi limiti di memoria e tempo della scansione da immagine.
- **Blocco automatico nativo**: un thread controlla ogni 5 secondi l'orologio di sistema; un salto
  di oltre 30 secondi indica sospensione o ibernazione e blocca il vault. Lo stesso thread blocca
  dopo 60 secondi con la finestra ridotta a icona. La sessione è azzerata nel processo nativo
  (anche se la webview è sospesa) e la UI è avvisata su un canale IPC (`watch_lock`). Nessuna API
  specifica del sistema operativo.
- **Appunti nativi** (`arboard`): accettano solo codici (lettere e cifre, massimo 10 caratteri).
  Su Windows il codice è escluso dalla cronologia degli appunti e dalla sincronizzazione cloud;
  su macOS e Linux è segnalato ai gestori di appunti come dato da non conservare. Dopo 30 secondi
  gli appunti sono svuotati solo se contengono ancora quel codice. Se gli appunti di sistema non
  sono raggiungibili si usa l'API web, come nella PWA.

- **Aggiornamenti e release** (aggiornato il 2026-10-23): plugin updater di Tauri, usato solo
  dal processo nativo (nessun permesso alla webview). Il manifesto `latest.json` sta
  nell'ultima release pubblicata su GitHub; i pacchetti sono firmati con una chiave minisign
  del progetto e la firma lega la versione (`requireSignedVersion`). Controllo all'avvio,
  disattivabile; installazione solo su conferma. La chiave pubblica è incorporata dalla build
  di release: le build di sviluppo non si aggiornano. Il crate `zip` del plugin è escluso
  (gli installer di Tauri 2 non sono archivi).
  - *Firma Windows*: SignPath Foundation, gratuita per i progetti open source. Due richieste
    per release: prima l'eseguibile, poi gli installer che lo contengono; le firme dell'updater
    si calcolano sui file finali. Il disinstallatore NSIS, generato durante l'installazione, non
    è firmato.
  - *macOS*: non firmato finché non c'è un Developer ID.

## Alternative considerate
- **Core WebAssembly anche nella webview**: zero codice nativo, ma i segreti resterebbero nel
  processo della webview e lo sblocco hardware richiederebbe comunque un ponte nativo.
- **Selezione della piattaforma a runtime** (`if (isTauri)`): il bundle desktop includerebbe worker,
  WebAssembly e Service Worker inutilizzati, e viceversa.
- **`xcap` anche su Linux**: richiede PipeWire (per la registrazione video, non usata) e, su
  GNOME, scrive la schermata in un file temporaneo con i permessi predefiniti; il portale chiede
  invece il consenso esplicito.
- **Eventi di sospensione del sistema** (`WM_POWERBROADCAST`, `NSWorkspace`, logind): tre
  implementazioni da mantenere al posto di un controllo portabile.
- **`tauri-action` per le release**: comodo, ma firma gli aggiornamenti prima che SignPath
  firmi gli installer, e le firme dell'updater non corrisponderebbero ai file pubblicati.
- **Isolation pattern di Tauri**: cifra l'IPC tra webview e core; utile contro script iniettati in
  pagine con contenuti di terzi, che l'app non carica. Da rivalutare in fase 6.

## Conseguenze
- Le API esposte dal core restano una sola (`CoreApi`); un test verifica che ogni metodo abbia il
  comando e il permesso corrispondenti nell'app Tauri.
- Su Linux la build richiede WebKitGTK 4.1 e, per la cattura dello schermo, un portale XDG attivo
  (presente in GNOME, KDE e nei desktop basati su wlroots); la CI compila e impacchetta l'app su tutti e tre i sistemi.
- Firma e notarizzazione degli installer richiedono i certificati di piattaforma: Windows con
  SignPath Foundation (in attesa di approvazione), macOS con un Developer ID. La procedura di
  release è in [docs/release.md](../release.md).
