/**
 * Ricerca nell'elenco degli account, solo lato UI (i metadati sono già in chiaro
 * nella pagina mentre il vault è sbloccato).
 */
import type { AccountView } from "./protocol";

/** Minuscole e senza diacritici, per confronti tolleranti ("Città" ≈ "citta"). */
export function normalize(text: string): string {
  return text.normalize("NFD").replace(/\p{M}/gu, "").toLocaleLowerCase();
}

/** `true` se ogni parola della query compare nell'issuer o nel nome. */
export function matches(account: Pick<AccountView, "issuer" | "name">, query: string): boolean {
  const haystack = normalize(`${account.issuer ?? ""} ${account.name}`);
  return normalize(query)
    .split(/\s+/)
    .filter(Boolean)
    .every((word) => haystack.includes(word));
}
