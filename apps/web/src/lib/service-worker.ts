/**
 * Registrazione del Service Worker per l'uso offline della PWA.
 * Nell'app desktop è sostituita da `service-worker.desktop.ts` (i file sono già locali).
 */
import { scriptUrl } from "./trusted-urls";

export function registerServiceWorker(): void {
  // Solo nella build di produzione (in sviluppo interferirebbe con l'HMR).
  if (import.meta.env.PROD && "serviceWorker" in navigator) {
    void navigator.serviceWorker
      .register(scriptUrl("./sw.js"), { scope: "./", updateViaCache: "none" })
      .catch((error: unknown) => {
        console.warn("Service Worker non registrato:", error);
      });
  }
}
