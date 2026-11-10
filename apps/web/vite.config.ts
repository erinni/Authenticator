import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";
import { platformFiles } from "./platform-files-plugin.ts";
import { securityHeaders } from "./security-headers.ts";
import { serviceWorker } from "./service-worker-plugin.ts";

// `--mode desktop`: UI per l'app Tauri (apps/native). Il core è nativo, quindi niente
// worker WebAssembly né Service Worker; i moduli `*.desktop.ts` sostituiscono quelli web.
export default defineConfig(({ mode }) => {
  const desktop = mode === "desktop";
  return {
    plugins: [svelte(), desktop ? platformFiles("desktop") : serviceWorker()],
    build: {
      outDir: desktop ? "dist-desktop" : "dist",
      target: "es2022",
      sourcemap: false,
      // Nessun asset inline: tutto servito da 'self', compatibile con la CSP.
      assetsInlineLimit: 0,
    },
    server: {
      // Porta fissa: è il `devUrl` dell'app Tauri.
      port: 5173,
      strictPort: desktop,
    },
    test: {
      // I test end-to-end (e2e/) sono eseguiti da Playwright, non da Vitest.
      exclude: ["e2e/**", "node_modules/**", "dist/**", "dist-desktop/**"],
    },
    preview: {
      headers: securityHeaders,
    },
  };
});
