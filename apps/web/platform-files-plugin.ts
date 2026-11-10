/**
 * Plugin Vite per le varianti di piattaforma dei moduli.
 *
 * Nella build per una piattaforma (es. `vite build --mode desktop`), un import
 * relativo di `x.ts` viene risolto in `x.desktop.ts` quando quel file esiste.
 * Il codice condiviso importa sempre `x.ts`; i tipi della variante sono vincolati a
 * quelli di `x.ts` (`typeof import("./x")`), così le due versioni non divergono.
 */
import { existsSync } from "node:fs";
import type { Plugin } from "vite";

/** Percorso della variante di `id` per `platform`, o `null` se `id` non è un modulo TS. */
export function variantPath(id: string, platform: string): string | null {
  return /\.ts$/.test(id) && !id.endsWith(`.${platform}.ts`)
    ? id.replace(/\.ts$/, `.${platform}.ts`)
    : null;
}

export function platformFiles(platform: string, exists = existsSync): Plugin {
  return {
    name: "platform-files",
    enforce: "pre",
    async resolveId(source, importer, options) {
      // Una variante può importare il modulo che sostituisce (es. per riesportarne parti).
      if (!importer || !source.startsWith(".") || importer.endsWith(`.${platform}.ts`)) {
        return null;
      }
      const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
      if (!resolved || resolved.external) {
        return null;
      }
      const variant = variantPath(resolved.id, platform);
      return variant && exists(variant) ? variant : null;
    },
  };
}
