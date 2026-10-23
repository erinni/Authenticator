/**
 * Sblocco alternativo alla password tramite uno slot "esterno" del vault.
 *
 * Nella PWA è la passkey (WebAuthn PRF, vedi `passkey.ts`); nell'app desktop
 * `external-unlock.desktop.ts` usa il sistema (Windows Hello, portachiavi di Linux).
 * La password resta sempre valida.
 */
import { core } from "./core";
import { fromHex, passkeySupported, registerPasskey, unlockSecret } from "./passkey";

/** Testi dell'interfaccia per il metodo della piattaforma. */
export interface UnlockTexts {
  title: string;
  /** Pulsante nella schermata di sblocco. */
  unlock: string;
  /** Pulsante per attivarlo nelle impostazioni. */
  add: string;
  added: string;
  /** Nome di ogni slot nell'elenco (seguito dal numero). */
  item: string;
  hint: string;
  /** Avvertenza da mostrare prima dell'attivazione, se il metodo ha limiti di sicurezza. */
  warning: string | null;
  removeConfirm: string;
  removed: string;
  unavailable: string;
  /** Messaggio per un errore inatteso durante lo sblocco. */
  failed: string;
}

export interface UnlockOption {
  available: boolean;
  texts: UnlockTexts;
}

const PASSKEY: UnlockTexts = {
  title: "Passkey",
  unlock: "Sblocca con passkey",
  add: "Aggiungi passkey",
  added: "Passkey aggiunta: ora puoi sbloccare il vault anche con questa passkey.",
  item: "Passkey",
  hint: "Sblocca il vault con impronta, volto o PIN del dispositivo. La password resta sempre valida. Serve una passkey con l'estensione PRF.",
  warning: null,
  removeConfirm:
    "Rimuovere questa passkey? Non potrà più sbloccare il vault. La passkey resta salvata nel dispositivo: puoi eliminarla dalle sue impostazioni.",
  removed: "Passkey rimossa.",
  unavailable: "Questo browser non supporta lo sblocco con passkey.",
  failed: "Passkey non valida o vault danneggiato.",
};

/** Metodo disponibile e relativi testi. */
export async function unlockOption(): Promise<UnlockOption> {
  return { available: await passkeySupported(), texts: PASSKEY };
}

/** Aggiunge uno slot al vault sbloccato (il chiamante poi salva il vault). */
export async function enroll(): Promise<void> {
  const { slotId, secret } = await registerPasskey();
  await core.setExternal(slotId, secret);
}

/** Apre il vault salvato `file` con uno degli slot `registered` (id esadecimali). */
export async function unlockVault(file: Uint8Array, registered: readonly string[]): Promise<void> {
  const { slotId, secret } = await unlockSecret(registered);
  await core.openExternal(file, slotId, secret);
}

/** Rimuove uno slot dal vault sbloccato (il chiamante poi salva il vault). */
export async function removeSlot(id: string): Promise<void> {
  await core.removeExternal(fromHex(id));
}
