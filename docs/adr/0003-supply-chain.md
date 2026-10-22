# ADR-0003 — Sicurezza della supply chain

- **Stato:** accettato
- **Data:** 2026-10-22

## Contesto
Una dipendenza o una action CI compromessa può esfiltrare i segreti di tutti gli utenti.
Per un authenticator questo è il rischio più probabile tra quelli ad alto impatto.

## Decisione

### Dipendenze
- **Minime per principio**: ogni nuova dipendenza va motivata nella PR (licenza, manutenzione, alternative).
- **Lockfile obbligatori** (`Cargo.lock`, `pnpm-lock.yaml`); la CI usa `--locked` / `--frozen-lockfile`.
- **pnpm**:
  - `minimumReleaseAge: 10080`: nessuna versione pubblicata da meno di 7 giorni;
  - `trustPolicy: no-downgrade`: rifiuta versioni con meno garanzie di provenance delle precedenti; ogni eccezione in `trustPolicyExclude` va verificata e motivata;
  - `strictDepBuilds` + `onlyBuiltDependencies: []`: nessuno script di install eseguito.
- **cargo-deny**: advisories RustSec, licenze compatibili con GPL-3.0, crate vietati (es. `openssl`), solo crates.io come sorgente.
- **Dependabot** con `cooldown` di 7 giorni, review manuale obbligatoria.

### CI
- Ogni action è **fissata per SHA del commit** (commento con la versione).
- `permissions: contents: read` di default; permessi aggiuntivi solo per job che li richiedono.
- `persist-credentials: false` su ogni checkout.
- Analisi **CodeQL** (Rust, TypeScript, workflow) e **dependency review** sulle PR.
- Audit giornaliero programmato.

### Repository (impostazioni GitHub da applicare manualmente)
Vedi `CONTRIBUTING.md` → *Impostazioni della repository*.

### Release (fase 6)
Build riproducibili, SBOM (CycloneDX), provenance SLSA, firma Sigstore, firme di piattaforma.

## Conseguenze
- Gli aggiornamenti di sicurezza urgenti di una dipendenza richiedono un override esplicito di `minimumReleaseAge` (documentato nella PR).
- Più attrito nell'aggiungere dipendenze: voluto.
