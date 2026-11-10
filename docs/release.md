# Release dell'app desktop

Il workflow [`release.yml`](../.github/workflows/release.yml) parte con un tag `vX.Y.Z` e
crea una **bozza** di release con gli installer per Windows, macOS e Linux e il manifesto
degli aggiornamenti (`latest.json`). Gli utenti, e gli aggiornamenti automatici, la vedono solo
quando la bozza viene pubblicata.

## Configurazione (una volta sola)

### 1. Chiave dell'updater
Firma i pacchetti degli aggiornamenti: l'app installa solo quelli firmati con questa chiave.
Generala sul tuo computer, non in CI:

```sh
pnpm --filter @authenticator/native tauri signer generate -w ~/.tauri/authenticator.key
```

Scegli una password robusta e conserva chiave e password in un posto sicuro (es. password
manager): **se le perdi, le app installate non potranno più aggiornarsi da sole**. Poi, in
GitHub → Settings → Secrets and variables → Actions:

| Tipo | Nome | Valore |
|---|---|---|
| Secret | `TAURI_SIGNING_PRIVATE_KEY` | contenuto di `~/.tauri/authenticator.key` |
| Secret | `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | la password scelta |
| Variable | `TAURI_UPDATER_PUBKEY` | contenuto di `~/.tauri/authenticator.key.pub` |

### 2. SignPath Foundation (firma Windows)
Finché non è configurata, gli installer Windows escono non firmati (con l'avviso di
SmartScreen); il resto funziona.

1. Pubblica almeno una release (anche non firmata): SignPath lo richiede.
2. Fai domanda su [signpath.org/apply](https://signpath.org/apply) indicando questo repository
   e la [politica di firma](../CODE_SIGNING.md).
3. Dopo l'approvazione, in SignPath:
   - collega il repository come *Trusted Build System* GitHub;
   - crea le configurazioni degli artefatti `executable` e `installers` copiando i file in
     [`.signpath/artifact-configurations/`](../.signpath/artifact-configurations/);
   - usa la policy di firma `release-signing`;
   - crea un utente CI e il suo API token.
4. In GitHub → Settings → Secrets and variables → Actions:

| Tipo | Nome | Valore |
|---|---|---|
| Secret | `SIGNPATH_API_TOKEN` | API token dell'utente CI |
| Variable | `SIGNPATH_ORGANIZATION_ID` | id dell'organizzazione SignPath |
| Variable | `SIGNPATH_PROJECT_SLUG` | slug del progetto (es. `Authenticator`) |

## Pubblicare una versione
1. Aggiorna `version` in `apps/native/src-tauri/tauri.conf.json` con una PR.
2. Dopo il merge, crea il tag sul commit di `main` e pubblicalo:
   ```sh
   git tag v0.2.0 && git push origin v0.2.0
   ```
3. Con SignPath attivo, approva le due richieste di firma (eseguibile, poi installer) sul sito
   di SignPath quando il workflow le invia.
4. Controlla la bozza di release (file, note) e pubblicala. Da quel momento le app installate
   la trovano al controllo successivo.

## Cosa contiene la release
| Sistema | File | Aggiornamento automatico |
|---|---|---|
| Windows | `Authenticator_X.Y.Z_x64-setup.exe` (NSIS), `Authenticator_X.Y.Z_x64_en-US.msi` | sì |
| macOS (Apple Silicon) | `Authenticator_X.Y.Z_aarch64.dmg`, `Authenticator.app.tar.gz` | sì (app non firmata: vedi sotto) |
| Linux | `.AppImage`, `.deb`, `.rpm` | sì |

Ogni pacchetto aggiornabile ha la sua firma `.sig`, legata alla versione: un manifesto
alterato non può far installare una versione diversa da quella firmata.

**macOS**: senza Developer ID l'app non è firmata né notarizzata; al primo avvio va aperta con
clic destro → Apri. La firma richiede l'Apple Developer Program.
