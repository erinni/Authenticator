/**
 * Client del core: inoltra le chiamate al trasporto della piattaforma (Web Worker
 * nella PWA, comandi Tauri nell'app desktop) e ne restituisce le risposte.
 */
import type { Core, Method } from "./protocol";
import { call, start } from "./transport";

export type { AccountView, Core, ImportView, ScanView, TotpView } from "./protocol";

/** Core asincrono: ogni metodo corrisponde a un'operazione di `CoreApi`. */
export const core = new Proxy({} as Core, {
  get: (_, method: string) =>
    // `then` assente: il proxy non deve sembrare una Promise se finisce in un `await`.
    method === "then" ? undefined : (...args: unknown[]) => call(method as Method, args),
});

/** Avvia il core in background (nella PWA compila il modulo WebAssembly). */
export function initCore(): void {
  start();
}

/** Messaggio di un errore lanciato dal core o da altro codice. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
