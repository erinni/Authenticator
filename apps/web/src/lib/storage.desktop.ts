/**
 * Persistenza desktop: il vault cifrato è un file nella cartella dati dell'app,
 * letto e scritto dal processo nativo (scrittura atomica). Come nella PWA, viene
 * salvato **solo** il file cifrato prodotto dal core.
 */
import { invoke } from "@tauri-apps/api/core";
import type * as Web from "./storage";

export const loadVault: typeof Web.loadVault = async () => {
  const data = new Uint8Array(await invoke<ArrayBuffer>("load_vault"));
  // File assente: il comando restituisce un buffer vuoto (un vault reale non lo è mai).
  return data.length > 0 ? data : null;
};

export const saveVault: typeof Web.saveVault = async (sealed) => {
  // Il chiamante conserva `sealed`: si invia una copia.
  await invoke("save_vault", sealed.slice());
};

export const requestPersistence: typeof Web.requestPersistence = () =>
  // Un file nella cartella dati dell'app non viene rimosso dal sistema per fare spazio.
  Promise.resolve(true);
