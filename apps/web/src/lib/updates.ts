/**
 * Aggiornamenti dell'app: disponibili solo nell'app desktop (`updates.desktop.ts`).
 * La PWA si aggiorna da sola con il Service Worker.
 */

export interface UpdateCheck {
  /** Versione installata. */
  current: string;
  /** Versione più recente disponibile, se c'è. */
  available: string | null;
  notes: string | null;
}

export interface Updates {
  check: () => Promise<UpdateCheck>;
  /** `true` se il controllo all'avvio è attivo (preferenza salvata dall'app). */
  autoCheck: () => Promise<boolean>;
  setAutoCheck: (enabled: boolean) => Promise<void>;
  /** Scarica, verifica la firma, installa e riavvia l'app. */
  install: (onprogress: (downloaded: number, total: number | null) => void) => Promise<void>;
}

export const updates: Updates | null = null;

/** Errore delle build senza chiave dell'updater (sviluppo). */
export const UPDATES_UNAVAILABLE = "updates:unavailable";
