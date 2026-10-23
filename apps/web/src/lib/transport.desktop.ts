/**
 * Trasporto desktop: le chiamate al core diventano comandi Tauri, eseguiti dal core
 * Rust nativo nel processo dell'app (`apps/native`). Come nella PWA, la UI riceve solo
 * metadati e codici; i `Uint8Array` passati vengono azzerati dopo l'invio.
 */
import { invoke } from "@tauri-apps/api/core";
import type { Method } from "./protocol";
import type * as Web from "./transport";

/** Nomi degli argomenti dei comandi Tauri, nell'ordine di `CoreApi`. */
export const PARAMS: Readonly<Record<Method, readonly string[]>> = {
  create: ["password"],
  open: ["file", "password"],
  openRecovery: ["file", "recoveryKey"],
  openExternal: ["file", "slotId", "secret"],
  externalSlots: ["file"],
  verify: ["file", "password"],
  lock: [],
  seal: [],
  accounts: [],
  codes: ["now"],
  nextHotp: ["id"],
  addUri: ["uri", "now"],
  remove: ["id"],
  importData: ["format", "data", "password", "now"],
  scanQr: ["width", "height", "rgba", "now"],
  changePassword: ["password"],
  createRecoveryKey: [],
  setExternal: ["slotId", "secret"],
  removeExternal: ["slotId"],
  exportBackup: ["password"],
  restoreBackup: ["data", "password", "now"],
};

/** Nome del comando Rust: `openRecovery` → `open_recovery`. */
export function commandName(method: Method): string {
  return method.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
}

/** Argomenti come oggetto per `invoke`; i byte diventano array di numeri (JSON). */
export function commandArgs(method: Method, args: readonly unknown[]): Record<string, unknown> {
  const names = PARAMS[method];
  if (args.length > names.length) {
    throw new Error(`argomenti in eccesso per ${method}`);
  }
  return Object.fromEntries(
    names.map((name, i) => {
      const value = args[i];
      return [name, value instanceof Uint8Array ? Array.from(value) : (value ?? null)];
    }),
  );
}

function wipe(args: readonly unknown[]): void {
  for (const arg of args) {
    if (arg instanceof Uint8Array) {
      arg.fill(0);
    }
  }
}

function send(method: Method, args: readonly unknown[]): Promise<unknown> {
  if (method === "scanQr") {
    // Il fotogramma (fino a 4 MiB) viaggia come corpo binario, non come JSON.
    const [width, height, rgba, now] = args as [number, number, Uint8Array, number];
    return invoke("scan_qr", rgba, {
      headers: { width: String(width), height: String(height), now: String(now) },
    });
  }
  return invoke(commandName(method), commandArgs(method, args));
}

export const start: typeof Web.start = () => {
  // Il core nativo è già pronto nel processo dell'app: nulla da avviare.
};

export const call: typeof Web.call = async (method, args) => {
  try {
    const value = await send(method, args);
    // I byte (vault, backup) arrivano come `ArrayBuffer` grezzo.
    return value instanceof ArrayBuffer ? new Uint8Array(value) : value;
  } catch (e) {
    // I comandi rifiutano con il messaggio (stringa), come i codici del core WASM.
    throw e instanceof Error ? e : new Error(String(e));
  } finally {
    wipe(args);
  }
};
