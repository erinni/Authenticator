import type * as Web from "./service-worker";

export const registerServiceWorker: typeof Web.registerServiceWorker = () => {
  // L'app desktop serve i file dal bundle locale: nessun Service Worker.
};
