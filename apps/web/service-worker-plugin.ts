/**
 * Plugin Vite che genera `sw.js` alla build, con l'elenco esatto dei file prodotti
 * (nomi con hash) e una versione derivata da quell'elenco.
 *
 * Strategia: tutta l'app viene messa in cache all'installazione e servita dalla cache
 * (funziona offline). Una nuova versione si installa in background e si attiva quando
 * tutte le schede della versione precedente sono chiuse, così una pagina aperta non
 * mescola mai codice di versioni diverse.
 */
import { createHash } from "node:crypto";
import type { Plugin } from "vite";

/** File di `public/` da includere nella cache, oltre a quelli generati dalla build. */
const PUBLIC_FILES = ["favicon.svg", "manifest.webmanifest"];

export function serviceWorkerSource(version: string, assets: readonly string[]): string {
  return `// Generato dalla build: non modificare.
const VERSION = ${JSON.stringify(version)};
const CACHE = "authenticator-" + VERSION;
const ASSETS = ${JSON.stringify(assets)};

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key.startsWith("authenticator-") && key !== CACHE)
            .map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  // Solo GET della stessa origine: nient'altro passa dal Service Worker.
  if (request.method !== "GET" || new URL(request.url).origin !== self.location.origin) {
    return;
  }
  // Le navigazioni ricevono sempre la pagina dell'app in cache.
  const lookup = request.mode === "navigate" ? new Request("./") : request;
  event.respondWith(
    caches.open(CACHE).then((cache) =>
      // ignoreVary: i file hanno nomi con hash e non cambiano; senza, le richieste con
      // header Origin (script modulo "crossorigin") non troverebbero la copia in cache.
      cache.match(lookup, { ignoreVary: true }).then((cached) => cached || fetch(request)),
    ),
  );
});
`;
}

export function serviceWorker(): Plugin {
  return {
    name: "authenticator-service-worker",
    apply: "build",
    generateBundle(_options, bundle) {
      const files = Object.keys(bundle)
        .filter((name) => !name.endsWith(".map") && name !== "index.html")
        .concat(PUBLIC_FILES)
        .sort();
      const assets = ["./", ...files.map((name) => `./${name}`)];
      const version = createHash("sha256").update(assets.join("\n")).digest("hex").slice(0, 16);
      this.emitFile({
        type: "asset",
        fileName: "sw.js",
        source: serviceWorkerSource(version, assets),
      });
    },
  };
}
