/**
 * Icone degli account generate in locale: iniziale e colore ricavati dall'issuer.
 *
 * Nessuna icona viene scaricata da servizi esterni: rivelerebbe quali account
 * possiede l'utente e richiederebbe di allentare la CSP.
 */

/** Numero di colori della palette (classi CSS `hue-0` … `hue-7`). */
export const HUES = 8;

/** Prima lettera o cifra in maiuscolo, oppure "?". */
export function initial(label: string): string {
  const match = /[\p{L}\p{N}]/u.exec(label.normalize("NFC"));
  return match ? match[0].toLocaleUpperCase() : "?";
}

/** Indice di colore stabile per un'etichetta (FNV-1a, senza distinguere maiuscole). */
export function hue(label: string): number {
  let hash = 0x811c9dc5;
  for (const ch of label.trim().toLocaleLowerCase()) {
    hash ^= ch.codePointAt(0) ?? 0;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash % HUES;
}
