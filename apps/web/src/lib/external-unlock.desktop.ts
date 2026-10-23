/**
 * Sblocco con il sistema nell'app desktop: Windows Hello o il portachiavi della sessione
 * su Linux. Il segreto dello slot resta nel processo nativo e non arriva mai alla webview.
 */
import { invoke } from "@tauri-apps/api/core";
import type * as Web from "./external-unlock";
import { UnlockError } from "./unlock-error";

type Method = "windows-hello" | "secret-service";

const WINDOWS_HELLO: Web.UnlockTexts = {
  title: "Windows Hello",
  unlock: "Sblocca con Windows Hello",
  add: "Attiva Windows Hello",
  added: "Windows Hello attivato: ora puoi sbloccare il vault con il PIN, l'impronta o il volto.",
  item: "Windows Hello",
  hint: "Sblocca il vault con il PIN, l'impronta o il volto di Windows Hello. La chiave resta in questo PC (nel TPM, se presente). La password resta sempre valida.",
  warning: null,
  removeConfirm: "Disattivare Windows Hello per questo vault? Servirà di nuovo la password.",
  removed: "Windows Hello disattivato.",
  unavailable:
    "Windows Hello non è configurato: imposta un PIN nelle impostazioni di Windows (Account → Opzioni di accesso).",
  failed: "Sblocco con Windows Hello non riuscito.",
};

const SECRET_SERVICE: Web.UnlockTexts = {
  title: "Portachiavi di sistema",
  unlock: "Sblocca con il portachiavi",
  add: "Ricorda su questo computer",
  added: "Fatto: su questo computer il vault si apre con il portachiavi della sessione.",
  item: "Portachiavi di sistema",
  hint: "Salva una chiave di sblocco nel portachiavi della tua sessione (GNOME Keyring, KWallet). La password resta sempre valida.",
  warning:
    "Nessuna biometria: chiunque usi la tua sessione già aperta potrà sbloccare il vault senza password. Attivalo solo su un computer personale protetto da password.",
  removeConfirm:
    "Disattivare lo sblocco con il portachiavi? La chiave verrà eliminata dal portachiavi e servirà di nuovo la password.",
  removed: "Sblocco con il portachiavi disattivato.",
  unavailable:
    "Nessun portachiavi di sistema disponibile (serve un servizio Secret Service, come GNOME Keyring o KWallet).",
  failed: "Sblocco con il portachiavi non riuscito.",
};

const UNAVAILABLE: Web.UnlockTexts = {
  ...WINDOWS_HELLO,
  title: "Sblocco di sistema",
  unavailable: "Lo sblocco di sistema non è ancora disponibile su questo sistema operativo.",
};

/** I comandi rifiutano con un messaggio per l'utente. */
async function run(command: string, args?: Record<string, unknown>): Promise<void> {
  try {
    await invoke(command, args);
  } catch (e) {
    throw new UnlockError(e instanceof Error ? e.message : String(e));
  }
}

export const unlockOption: typeof Web.unlockOption = async () => {
  const method = await invoke<Method | null>("platform_unlock");
  switch (method) {
    case "windows-hello":
      return { available: true, texts: WINDOWS_HELLO };
    case "secret-service":
      return { available: true, texts: SECRET_SERVICE };
    default:
      return { available: false, texts: UNAVAILABLE };
  }
};

export const enroll: typeof Web.enroll = () => run("enable_platform_unlock");

export const unlockVault: typeof Web.unlockVault = async (file) => {
  try {
    // Gli slot da provare li legge il processo nativo dal file stesso.
    await run("unlock_with_platform", { file: Array.from(file) });
  } finally {
    file.fill(0);
  }
};

export const removeSlot: typeof Web.removeSlot = (id) =>
  run("disable_platform_unlock", { slotId: id });
