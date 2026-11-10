/**
 * Trasporto web: le chiamate al core vanno al Web Worker che ospita il WebAssembly.
 * Nell'app desktop è sostituito da `transport.desktop.ts`.
 */
import workerUrl from "../worker/core.worker.ts?worker&url";
import type { Method, Request, Response } from "./protocol";
import { transferables } from "./protocol";
import { scriptUrl } from "./trusted-urls";

let worker: Worker | null = null;
let nextId = 1;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

function ensureWorker(): Worker {
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

/** Avvia il worker (che compila il modulo WebAssembly in background). */
export function start(): void {
  ensureWorker();
}

/** Invoca un'operazione del core; i `Uint8Array` degli argomenti vengono trasferiti e azzerati. */
export function call(method: Method, args: unknown[]): Promise<unknown> {
  const target = ensureWorker();
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    const request: Request = { id, method, args };
    target.postMessage(request, transferables(args));
  });
}
