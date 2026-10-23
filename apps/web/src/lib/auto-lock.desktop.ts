/**
 * Blocco automatico nell'app desktop: oltre ai controlli della PWA (inattività, finestra
 * nascosta), il processo nativo blocca il vault dopo la sospensione del computer o con
 * la finestra ridotta a icona e lo comunica su un canale.
 */
import { Channel, invoke } from "@tauri-apps/api/core";
import * as Web from "./auto-lock";

export const IDLE_LOCK_MS = Web.IDLE_LOCK_MS;
export const HIDDEN_LOCK_MS = Web.HIDDEN_LOCK_MS;

export const startAutoLock: typeof Web.startAutoLock = (lock) => {
  const stop = Web.startAutoLock(lock);
  let active = true;
  const channel = new Channel<null>();
  channel.onmessage = () => {
    if (active) {
      lock();
    }
  };
  void invoke("watch_lock", { onLock: channel });
  return () => {
    active = false;
    stop();
  };
};
