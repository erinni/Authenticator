/**
 * Scansione dei QR visibili sullo schermo: disponibile solo nell'app desktop
 * (`screen-scan.desktop.ts`), dove la schermata resta nel processo nativo.
 */
import type { ScanView } from "./protocol";

/** Cattura lo schermo e aggiunge gli account trovati; `null` se non disponibile. */
export const scanScreen: ((now: number) => Promise<ScanView>) | null = null;

/** Errore restituito quando l'utente annulla la cattura. */
export const SCREEN_CANCELLED = "screen:cancelled";
