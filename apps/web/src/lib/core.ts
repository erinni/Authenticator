/**
 * Client del core: inoltra le chiamate al Web Worker e ne restituisce le risposte.
 */
import workerUrl from "../worker/core.worker.ts?worker&url";
import type { Core, Method, Request, Response } from "./protocol";
import { transferables } from "./protocol";
import { scriptUrl } from "./trusted-urls";

export type { AccountView, Core, ImportView, ScanView, TotpView } from "./protocol";

let worker: Worker | null = null;
let nextId = 1;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

function start(): Worker {
  if (worker) {
    return worker;
  }
  const created = new Worker(scriptUrl(workerUrl), { type: "module", name: "core" });
  created.onmessage = (event: MessageEvent<Response>) => {
    const reply = event.data;
    const waiting = pending.get(reply.id);
    pending.delete(reply.id);
    if (reply.ok) {
      waiting?.resolve(reply.value);
    } else {
      waiting?.reject(new Error(reply.error));
    }
  };
  created.onerror = (event) => {
    for (const waiting of pending.values()) {
      waiting.reject(new Error(event.message || "errore del worker"));
    }
    pending.clear();
  };
  worker = created;
  return created;
}

function call(method: Method, args: unknown[]): Promise<unknown> {
  const target = start();
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    const request: Request = { id, method, args };
    target.postMessage(request, transferables(args));
  });
}

/** Core asincrono: ogni metodo corrisponde a un'operazione del worker. */
export const core = new Proxy({} as Core, {
  get: (_, method: string) =>
    // `then` assente: il proxy non deve sembrare una Promise se finisce in un `await`.
    method === "then" ? undefined : (...args: unknown[]) => call(method as Method, args),
});

/** Avvia il worker (che compila il modulo WebAssembly in background). */
export function initCore(): void {
  start();
}

/** Messaggio di un errore lanciato dal core o da altro codice. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
