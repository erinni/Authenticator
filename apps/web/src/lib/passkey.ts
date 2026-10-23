/**
 * Sblocco con passkey tramite l'estensione WebAuthn PRF.
 *
 * La passkey restituisce un segreto di 32 byte, deterministico per credenziale e
 * `salt`, che diventa la credenziale di uno slot "esterno" del vault. Lo slot è
 * identificato da un hash dell'id della credenziale: così non serve salvare nulla
 * in chiaro oltre al vault, e allo sblocco basta una passkey *discoverable*.
 *
 * Il segreto passa dalla pagina solo per essere trasferito (e azzerato) nel worker.
 */

/** Input PRF fisso: l'output dipende comunque dalla singola credenziale. */
const PRF_SALT = new TextEncoder().encode("authenticator/v1/prf/vault-unlock");
const SLOT_ID_DOMAIN = new TextEncoder().encode("authenticator/v1/passkey-slot");
const SECRET_LEN = 32;

export interface PasskeySecret {
  /** Id dello slot del vault (16 byte). */
  slotId: Uint8Array;
  /** Output PRF (32 byte): da trasferire subito al worker. */
  secret: Uint8Array;
}

/** Errore con un messaggio già pronto per l'utente. */
export class PasskeyError extends Error {}

/** `true` se il browser espone WebAuthn e (quando lo dichiara) l'estensione PRF. */
export async function passkeySupported(): Promise<boolean> {
  if (typeof PublicKeyCredential === "undefined" || !("credentials" in navigator)) {
    return false;
  }
  if (typeof PublicKeyCredential.getClientCapabilities !== "function") {
    // Capacità non dichiarate: lo scopriamo alla registrazione.
    return true;
  }
  try {
    const capabilities = await PublicKeyCredential.getClientCapabilities();
    return capabilities["extension:prf"] !== false;
  } catch {
    return true;
  }
}

/** Id dello slot per una credenziale: primi 16 byte di SHA-256(dominio ‖ rawId). */
export async function slotIdFor(rawId: ArrayBuffer): Promise<Uint8Array> {
  const input = new Uint8Array(SLOT_ID_DOMAIN.length + rawId.byteLength);
  input.set(SLOT_ID_DOMAIN);
  input.set(new Uint8Array(rawId), SLOT_ID_DOMAIN.length);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(digest, 0, 16).slice();
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  const pairs = hex.match(/[0-9a-f]{2}/g) ?? [];
  return Uint8Array.from(pairs, (pair) => parseInt(pair, 16));
}

function prfOutput(credential: PublicKeyCredential): Uint8Array | null {
  const first = credential.getClientExtensionResults().prf?.results?.first;
  if (!first) {
    return null;
  }
  const bytes = ArrayBuffer.isView(first)
    ? new Uint8Array(first.buffer, first.byteOffset, first.byteLength)
    : new Uint8Array(first);
  // Copia in un buffer proprio (trasferibile), poi azzeriamo l'originale.
  const secret = bytes.slice();
  bytes.fill(0);
  return secret.length >= SECRET_LEN ? secret : null;
}

function cancelled(error: unknown): boolean {
  return error instanceof DOMException && error.name === "NotAllowedError";
}

async function assertion(allow?: ArrayBuffer): Promise<PublicKeyCredential> {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        userVerification: "required",
        allowCredentials: allow ? [{ type: "public-key", id: allow }] : [],
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
  } catch (e) {
    throw new PasskeyError(
      cancelled(e) ? "Operazione annullata." : "La passkey non ha risposto correttamente.",
    );
  }
  if (!(credential instanceof PublicKeyCredential)) {
    throw new PasskeyError("Nessuna passkey selezionata.");
  }
  return credential;
}

/** Crea una nuova passkey per il vault e ne ricava il segreto di sblocco. */
export async function registerPasskey(): Promise<PasskeySecret> {
  let created: Credential | null;
  try {
    created = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Authenticator" },
        // Id utente casuale: non collega la passkey a nessuna identità.
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: "Vault Authenticator",
          displayName: "Vault Authenticator",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -8 }, // Ed25519
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 }, // RS256
        ],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        attestation: "none",
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
  } catch (e) {
    throw new PasskeyError(
      cancelled(e) ? "Operazione annullata." : "Impossibile creare la passkey.",
    );
  }
  if (!(created instanceof PublicKeyCredential)) {
    throw new PasskeyError("Impossibile creare la passkey.");
  }
  if (created.getClientExtensionResults().prf?.enabled === false) {
    throw new PasskeyError(
      "Questa passkey non supporta l'estensione PRF: non può sbloccare il vault.",
    );
  }
  // Alcuni autenticatori restituiscono l'output PRF solo in fase di autenticazione.
  const secret = prfOutput(created) ?? prfOutput(await assertion(created.rawId));
  if (!secret) {
    throw new PasskeyError(
      "Questa passkey non supporta l'estensione PRF: non può sbloccare il vault.",
    );
  }
  return { slotId: await slotIdFor(created.rawId), secret };
}

/** Chiede una passkey registrata per il vault e ne ricava il segreto di sblocco. */
export async function unlockSecret(registered: readonly string[]): Promise<PasskeySecret> {
  const credential = await assertion();
  const slotId = await slotIdFor(credential.rawId);
  const secret = prfOutput(credential);
  if (!registered.includes(toHex(slotId)) || !secret) {
    secret?.fill(0);
    throw new PasskeyError("Questa passkey non è registrata per questo vault.");
  }
  return { slotId, secret };
}
