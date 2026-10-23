/// <reference lib="webworker" />
/**
 * Web Worker che ospita il core WebAssembly e la sessione sbloccata.
 *
 * Tenere il core qui evita che Argon2id (centinaia di millisecondi, anche secondi
 * sui telefoni lenti) blocchi l'interfaccia, e separa la memoria dei segreti dal
 * contesto della pagina.
 */
import init, { Session } from "../wasm/authenticator_wasm.js";
import type {
  AccountView,
  CoreApi,
  ImportView,
  Request,
  Response,
  ScanView,
  TotpView,
} from "../lib/protocol";
import { transferables } from "../lib/protocol";

declare const self: DedicatedWorkerGlobalScope;

let session: Session | null = null;
const ready = init();

function current(): Session {
  if (!session) {
    throw new Error("vault bloccato");
  }
  return session;
}

function replace(next: Session): void {
  session?.free();
  session = next;
}

const api: CoreApi = {
  create: (password) => {
    replace(Session.create(password));
  },
  open: (file, password) => {
    replace(Session.open(file, password));
  },
  openRecovery: (file, recoveryKey) => {
    replace(Session.open_recovery(file, recoveryKey));
  },
  verify: (file, password) => {
    try {
      Session.open(file, password).free();
      return true;
    } catch {
      return false;
    }
  },
  lock: () => {
    // `free()` libera la memoria WebAssembly: il core azzera le chiavi al drop.
    session?.free();
    session = null;
  },
  seal: () => current().seal(),
  accounts: () => JSON.parse(current().accounts()) as AccountView[],
  codes: (now) => JSON.parse(current().totp_all(now)) as Record<string, TotpView>,
  nextHotp: (id) => current().next_hotp(id),
  addUri: (uri, now) => current().add_uri(uri, now),
  remove: (id) => current().remove(id),
  importData: (format, data, password, now) =>
    JSON.parse(current().import(format, data, password ?? undefined, now)) as ImportView,
  scanQr: (width, height, rgba, now) =>
    JSON.parse(current().scan_qr(width, height, rgba, now)) as ScanView,
  changePassword: (password) => {
    current().change_password(password);
  },
  createRecoveryKey: () => current().create_recovery_key(),
  exportBackup: (password) => current().export_backup(password),
  restoreBackup: (data, password, now) =>
    JSON.parse(current().restore_backup(data, password, now)) as ImportView,
};

/** Vista non tipizzata di `api` per l'invocazione dinamica dei metodi. */
const handlers = api as unknown as Record<Request["method"], (...args: unknown[]) => unknown>;

self.onmessage = async (event: MessageEvent<Request>) => {
  const { id, method, args } = event.data;
  let response: Response;
  try {
    await ready;
    const value = handlers[method](...args);
    response = { id, ok: true, value };
  } catch (e) {
    response = { id, ok: false, error: e instanceof Error ? e.message : String(e) };
  } finally {
    // Password, file e immagini ricevuti non servono più: li azzeriamo.
    for (const arg of args) {
      if (arg instanceof Uint8Array) {
        arg.fill(0);
      }
    }
  }
  self.postMessage(response, transferables(response.ok ? [response.value] : []));
};
