# Contribuire

## Requisiti
- Rust (la versione è fissata in `rust-toolchain.toml`: `rustup` la installa da solo)
- Node.js ≥ 22.12 e pnpm 10.28 (`corepack enable`)

## Comandi
```sh
# Rust
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check            # richiede: cargo install --locked cargo-deny

# Fuzzing (richiede: rustup toolchain install nightly && cargo install --locked cargo-fuzz)
cargo +nightly fuzz list --fuzz-dir fuzz
cargo +nightly fuzz run --fuzz-dir fuzz vault_open -- -max_total_time=300

# Web (richiede: cargo install --locked wasm-bindgen-cli --version 0.2.129)
pnpm install
pnpm --filter @authenticator/web wasm   # compila il core in WebAssembly
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm --filter @authenticator/web dev
```

## Regole
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `security:`).
- **Commit firmati** (SSH o GPG): `git config commit.gpgsign true`.
- Ogni modifica passa da una **pull request** con review e CI verde.
- Le decisioni architetturali o crittografiche richiedono un **ADR** in `docs/adr/`.
- Le modifiche che toccano crittografia, storage, rete o gestione chiavi aggiornano `docs/threat-model.md`.
- Nel codice Rust di produzione sono vietati `unsafe`, `unwrap`, `expect`, `panic!` e indicizzazioni non controllate (lint di workspace).
- Nella UI sono vietati `{@html}`, `innerHTML`, `eval`, `localStorage` e `Math.random` (lint ESLint).
- Mai segreti, seed OTP reali o dati personali in test, log o issue.

## Vulnerabilità
Non aprire issue pubbliche: vedi [SECURITY.md](SECURITY.md).

## Impostazioni della repository
Da applicare su GitHub (*Settings*), non configurabili da file:

1. **Branch protection / Ruleset su `main`**:
   - richiedere pull request con almeno 1 approvazione e review dei CODEOWNERS;
   - richiedere i check di stato: `Rust (fmt, clippy, test)`, `Web (lint, typecheck, test, build)`, `cargo-deny …`, `pnpm audit`, `CodeQL (…)`;
   - richiedere **commit firmati** e cronologia lineare;
   - bloccare force push e cancellazione.
2. **Security → Code security**: attivare *Private vulnerability reporting*, *Dependabot alerts*, *Dependabot security updates*, *Secret scanning* e *Push protection*.
3. **Actions → General**: *Workflow permissions* = "Read repository contents"; consentire solo action fissate per SHA (*Require actions to be pinned to a full-length commit SHA*).
