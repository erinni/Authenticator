import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";
import { registerServiceWorker } from "./lib/service-worker";

const target = document.getElementById("app");
if (!target) {
  throw new Error("Elemento #app mancante");
}

export default mount(App, { target });

registerServiceWorker();
