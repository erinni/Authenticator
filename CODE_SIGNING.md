# Politica di firma del codice

Firma del codice gratuita fornita da [SignPath.io](https://about.signpath.io/), certificato
di [SignPath Foundation](https://signpath.org/).

## Cosa viene firmato
- **Windows**: l'eseguibile dell'app e gli installer (NSIS `.exe` e `.msi`) di ogni release,
  con firma Authenticode di SignPath Foundation.
- **Tutte le piattaforme**: i pacchetti usati dagli aggiornamenti automatici sono firmati con
  la chiave dell'updater del progetto (minisign); l'app installa un aggiornamento solo se la
  firma è valida e corrisponde alla versione annunciata.

I file vengono firmati solo se prodotti dal workflow
[`release.yml`](.github/workflows/release.yml), sui runner di GitHub, dal codice di questo
repository al tag della release. Nessun binario compilato altrove viene firmato.

## Ruoli
| Ruolo | Persone |
|---|---|
| Autori (committer) e revisori | [erinni](https://github.com/erinni) |
| Approvatori delle richieste di firma | [erinni](https://github.com/erinni) |

Ogni modifica entra in `main` tramite pull request, con i controlli della CI (test, analisi
statica, audit delle dipendenze). Ogni richiesta di firma di una release è approvata a mano.

## Privacy
L'app non trasferisce informazioni ad altri sistemi in rete, salvo quando l'utente lo
richiede. L'unica eccezione predefinita è il controllo degli aggiornamenti all'avvio: l'app
scarica il file `latest.json` dall'ultima release su GitHub, senza inviare alcun dato del
vault o dell'utente. Il controllo si disattiva in **Impostazioni → Aggiornamenti**.
