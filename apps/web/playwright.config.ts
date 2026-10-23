import { defineConfig, devices } from "@playwright/test";

/**
 * Test end-to-end sulla build di produzione servita da `vite preview`, che applica
 * gli stessi header di sicurezza (CSP, Trusted Types, COOP/COEP) della produzione.
 *
 * `CHROMIUM_PATH` permette di usare un Chromium già installato (es. in sviluppo locale).
 */
export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  forbidOnly: !!process.env["CI"],
  retries: 0,
  reporter: process.env["CI"] ? "github" : "list",
  use: {
    baseURL: "http://localhost:4173",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: process.env["CHROMIUM_PATH"]
          ? { executablePath: process.env["CHROMIUM_PATH"] }
          : {},
      },
    },
  ],
  webServer: {
    command: "pnpm preview --port 4173 --strictPort",
    url: "http://localhost:4173",
    reuseExistingServer: !process.env["CI"],
  },
});
