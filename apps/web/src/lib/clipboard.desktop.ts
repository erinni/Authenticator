/**
 * Appunti nell'app desktop: il codice è copiato dal processo nativo, che lo esclude
 * dalla cronologia degli appunti (e su Windows dalla sincronizzazione cloud) e lo
 * rimuove dopo {@link CLIPBOARD_CLEAR_MS} solo se gli appunti lo contengono ancora.
 */
import { invoke } from "@tauri-apps/api/core";
import * as Web from "./clipboard";

export const CLIPBOARD_CLEAR_MS = Web.CLIPBOARD_CLEAR_MS;

export const copyCode: typeof Web.copyCode = async (code) => {
  try {
    await invoke("copy_code", { code });
  } catch {
    // Appunti di sistema non raggiungibili (es. Wayland senza XWayland): come nella PWA.
    await Web.copyCode(code);
  }
};
