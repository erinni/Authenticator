import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";
import { securityHeaders } from "./security-headers.ts";

export default defineConfig({
  plugins: [svelte()],
  build: {
    target: "es2022",
    sourcemap: false,
    // Nessun asset inline: tutto servito da 'self', compatibile con la CSP.
    assetsInlineLimit: 0,
  },
  test: {
    // I test end-to-end (e2e/) sono eseguiti da Playwright, non da Vitest.
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
  },
  preview: {
    headers: securityHeaders,
  },
});
