/**
 * Aggiornamenti nell'app desktop: il processo nativo legge il manifesto dell'ultima
 * release, verifica la firma del pacchetto e lo installa solo su richiesta.
 */
import { Channel, invoke } from "@tauri-apps/api/core";
import * as Web from "./updates";

export const UPDATES_UNAVAILABLE = Web.UPDATES_UNAVAILABLE;

function asError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

export const updates: typeof Web.updates = {
  autoCheck: () => invoke<boolean>("update_auto_check"),
  setAutoCheck: (enabled) => invoke("set_update_auto_check", { enabled }),
  check: () =>
    invoke<Web.UpdateCheck>("check_update").catch((e: unknown) => Promise.reject(asError(e))),
  install: async (onprogress) => {
    const channel = new Channel<{ downloaded: number; total: number | null }>();
    channel.onmessage = ({ downloaded, total }) => {
      onprogress(downloaded, total);
    };
    try {
      await invoke("install_update", { onProgress: channel });
    } catch (e) {
      throw asError(e);
    }
  },
};
