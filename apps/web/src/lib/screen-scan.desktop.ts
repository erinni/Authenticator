/**
 * Scansione dello schermo nell'app desktop: cattura e analisi avvengono nel processo
 * nativo; alla UI arriva solo il riepilogo (quanti QR e account), mai l'immagine.
 */
import { invoke } from "@tauri-apps/api/core";
import type { ScanView } from "./protocol";
import * as Web from "./screen-scan";

export const SCREEN_CANCELLED = Web.SCREEN_CANCELLED;

export const scanScreen: typeof Web.scanScreen = async (now) => {
  try {
    return await invoke<ScanView>("scan_screen", { now });
  } catch (e) {
    throw e instanceof Error ? e : new Error(String(e));
  }
};
