import { expect, test } from "@playwright/test";
import { PASSWORD, RFC_SECRET, addUri, createVault, watchViolations } from "./helpers";

test("dopo la prima visita funziona offline", async ({ page, context }) => {
  const problems = await watchViolations(page);
  await createVault(page);
  await addUri(page, `otpauth://totp/Offline:anna@example.com?secret=${RFC_SECRET}&issuer=Offline`);
  await expect(page.getByText("anna@example.com")).toBeVisible();

  // Il Service Worker è installato e controlla la pagina.
  await page.evaluate(async () => {
    await navigator.serviceWorker.ready;
  });
  await page.reload();
  expect(await page.evaluate(() => navigator.serviceWorker.controller !== null)).toBe(true);

  await context.setOffline(true);
  await page.reload();
  await page.getByLabel("Password principale").fill(PASSWORD);
  await page.getByRole("button", { name: "Sblocca" }).click();
  await expect(page.getByText("anna@example.com")).toBeVisible();
  await expect(page.locator(".code").first()).toHaveText(/^\d{3} \d{3}$/);
  await context.setOffline(false);

  // Anche le risposte servite dalla cache mantengono la CSP.
  expect(problems).toEqual([]);
});

test("manifest e header di sicurezza", async ({ request }) => {
  const manifest = await request.get("/manifest.webmanifest");
  expect(manifest.ok()).toBe(true);
  const body = (await manifest.json()) as { display: string; icons: unknown[] };
  expect(body.display).toBe("standalone");
  expect(body.icons.length).toBeGreaterThan(0);

  const sw = await request.get("/sw.js");
  expect(sw.ok()).toBe(true);
  expect(await sw.text()).toContain("authenticator-");

  const page = await request.get("/");
  const csp = page.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("trusted-types svelte-trusted-html authenticator-script-url");
  expect(csp).toContain("worker-src 'self'");
});
