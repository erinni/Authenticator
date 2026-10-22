import { mount } from "svelte";
import App from "./App.svelte";

const target = document.getElementById("app");
if (!target) {
  throw new Error("Elemento #app mancante");
}

export default mount(App, { target });
