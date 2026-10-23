import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";
import { scriptUrl } from "./lib/trusted-urls";

const target = document.getElementById("app");
if (!target) {
  throw new Error("Elemento #app mancante");
}

export default mount(App, { target });

// Service Worker solo nella build di produzione (in sviluppo interferirebbe con l'HMR).
if (import.meta.env.PROD && "serviceWorker" in navigator) {
  void navigator.serviceWorker
    .register(scriptUrl("./sw.js"), { scope: "./", updateViaCache: "none" })
    .catch((error: unknown) => {
      console.warn("Service Worker non registrato:", error);
    });
}
