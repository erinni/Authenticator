/**
 * Protocollo tra la pagina e il Web Worker che ospita il core WebAssembly.
 *
 * Il vault sbloccato vive solo nel worker: la pagina riceve metadati e codici.
 * I `Uint8Array` negli argomenti vengono **trasferiti** (non copiati) al worker,
 * che li azzera dopo l'uso: chi deve conservare un buffer passi una copia.
 */

export interface AccountView {
  id: string;
  issuer: string | null;
  name: string;
  kind: "totp" | "hotp";
  digits: number;
  period: number | null;
}

export interface TotpView {
  code: string;
  remaining: number;
  period: number;
}

export interface ImportView {
  added: number;
  duplicates: number;
  skipped: number;
}

export interface ScanView extends ImportView {
  found: number;
  unsupported: number;
}

export type ImportFormat = "google" | "aegis" | "andotp" | "2fas";

/** Operazioni esposte dal worker (versione sincrona, come implementata lì). */
export interface CoreApi {
  create: (password: Uint8Array) => void;
  open: (file: Uint8Array, password: Uint8Array) => void;
  openRecovery: (file: Uint8Array, recoveryKey: string) => void;
  /** Apre con il segreto di una passkey (PRF) e l'id del suo slot. */
  openExternal: (file: Uint8Array, slotId: Uint8Array, secret: Uint8Array) => void;
  /** Id (hex) degli slot esterni di un vault salvato, letti senza sbloccarlo. */
  externalSlots: (file: Uint8Array) => string[];
  /** Verifica la password su un vault salvato senza toccare la sessione corrente. */
  verify: (file: Uint8Array, password: Uint8Array) => boolean;
  lock: () => void;
  seal: () => Uint8Array;
  accounts: () => AccountView[];
  codes: (now: number) => Record<string, TotpView>;
  nextHotp: (id: string) => string;
  addUri: (uri: string, now: number) => string;
  remove: (id: string) => boolean;
  importData(
    format: ImportFormat,
    data: Uint8Array,
    password: Uint8Array | null,
    now: number,
  ): ImportView;
  scanQr: (width: number, height: number, rgba: Uint8Array, now: number) => ScanView;
  changePassword: (password: Uint8Array) => void;
  createRecoveryKey: () => string;
  setExternal: (slotId: Uint8Array, secret: Uint8Array) => void;
  removeExternal: (slotId: Uint8Array) => void;
  exportBackup: (password: Uint8Array) => Uint8Array;
  restoreBackup: (data: Uint8Array, password: Uint8Array, now: number) => ImportView;
}

export type Method = keyof CoreApi;

export interface Request {
  id: number;
  method: Method;
  args: unknown[];
}

export type Response =
  { id: number; ok: true; value: unknown } | { id: number; ok: false; error: string };

/** Versione asincrona vista dalla pagina. */
export type Core = {
  [K in Method]: (...args: Parameters<CoreApi[K]>) => Promise<ReturnType<CoreApi[K]>>;
};

/** Buffer da trasferire al worker (tutti gli `Uint8Array` degli argomenti, senza duplicati). */
export function transferables(args: readonly unknown[]): ArrayBuffer[] {
  const buffers = new Set<ArrayBuffer>();
  for (const arg of args) {
    if (arg instanceof Uint8Array && arg.buffer instanceof ArrayBuffer) {
      buffers.add(arg.buffer);
    }
  }
  return [...buffers];
}
