/**
 * Accesso tipizzato al core WebAssembly.
 *
 * Il modulo viene inizializzato una sola volta. I metodi della `Session` che
 * restituiscono strutture usano JSON: qui lo interpretiamo con tipi espliciti.
 */
import init, { Session } from "../wasm/authenticator_wasm.js";

export { Session };

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

let ready: Promise<unknown> | null = null;

/** Carica e compila il modulo WebAssembly (idempotente). */
export function initCore(): Promise<unknown> {
  ready ??= init();
  return ready;
}

export function accounts(session: Session): AccountView[] {
  return JSON.parse(session.accounts()) as AccountView[];
}

export function totp(session: Session, id: string, unixTime: number): TotpView {
  return JSON.parse(session.totp(id, unixTime)) as TotpView;
}

export function parseImport(json: string): ImportView {
  return JSON.parse(json) as ImportView;
}

/** Messaggio di un errore lanciato dal core (JsError) o da altro codice. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
