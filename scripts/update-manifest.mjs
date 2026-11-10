#!/usr/bin/env node
/**
 * Genera il manifesto `latest.json` dell'updater di Tauri dagli artefatti di release.
 *
 * Uso: node scripts/update-manifest.mjs <cartella> <tag> <repository>
 *
 * Per ogni pacchetto con la sua firma (`.sig`) nella cartella aggiunge la piattaforma
 * corrispondente (`{os}-{arch}-{installer}`, più `{os}-{arch}` come predefinita), con
 * l'indirizzo del file tra gli asset della release.
 */
import { readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";

/** Tipo di pacchetto → chiavi del manifesto (la prima è quella predefinita del sistema). */
const KINDS = [
  { suffix: "-setup.exe", keys: ["windows-x86_64-nsis", "windows-x86_64"] },
  { suffix: ".msi", keys: ["windows-x86_64-msi"] },
  { suffix: ".AppImage", keys: ["linux-x86_64-appimage", "linux-x86_64"] },
  { suffix: ".deb", keys: ["linux-x86_64-deb"] },
  { suffix: ".rpm", keys: ["linux-x86_64-rpm"] },
  { suffix: ".app.tar.gz", keys: ["darwin-aarch64-app", "darwin-aarch64"] },
];

function files(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? files(join(dir, entry.name)) : [join(dir, entry.name)],
  );
}

export function manifest(dir, tag, repository, now = new Date()) {
  const version = tag.replace(/^v/, "");
  const platforms = {};
  for (const sig of files(dir).filter((file) => file.endsWith(".sig"))) {
    const file = basename(sig, ".sig");
    const kind = KINDS.find(({ suffix }) => file.endsWith(suffix));
    if (!kind) {
      continue;
    }
    const entry = {
      signature: readFileSync(sig, "utf8").trim(),
      url: `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(file)}`,
    };
    for (const key of kind.keys) {
      if (key in platforms) {
        throw new Error(`piattaforma duplicata: ${key}`);
      }
      platforms[key] = entry;
    }
  }
  if (Object.keys(platforms).length === 0) {
    throw new Error("nessun pacchetto firmato trovato");
  }
  return {
    version,
    notes: `Novità: https://github.com/${repository}/releases/tag/${tag}`,
    pub_date: now.toISOString(),
    platforms,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [dir, tag, repository] = process.argv.slice(2);
  if (!dir || !tag || !repository) {
    console.error("uso: update-manifest.mjs <cartella> <tag> <repository>");
    process.exit(2);
  }
  console.log(JSON.stringify(manifest(dir, tag, repository), null, 2));
}
