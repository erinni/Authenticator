import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";
import { securityHeaders } from "./security-headers.ts";

export default defineConfig({
  plugins: [svelte()],
  build: {
    target: "es2022",
    sourcemap: false,
    // Nessun asset inline: tutto servito da 'self', compatibile con la CSP.
    assetsInlineLimit: 0,
  },
  preview: {
    headers: securityHeaders,
  },
});
