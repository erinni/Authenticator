import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import {
  PASSWORD,
  RFC_SECRET,
  addUri,
  createVault,
  storedVault,
  totp,
  watchViolations,
} from "./helpers";

const ACME = `otpauth://totp/ACME:mario@example.com?secret=${RFC_SECRET}&issuer=ACME`;
const fixture = (name: string) => new URL(`fixtures/${name}`, import.meta.url).pathname;

let problems: string[] = [];

test.beforeEach(async ({ page }) => {
  problems = await watchViolations(page);
});

test.afterEach(() => {
  // Nessuna violazione CSP/Trusted Types né errore JavaScript durante il test.
  expect(problems).toEqual([]);
});

test("crea, usa, blocca e riapre il vault", async ({ page, context }) => {
  await page.goto("/");
  await page.getByLabel("Password principale").fill("corta");
  await page.getByLabel("Conferma password").fill("corta");
  await page.getByRole("button", { name: "Crea vault" }).click();
  await expect(page.getByText("almeno 10 caratteri")).toBeVisible();

  await createVault(page);
  await addUri(page, ACME);
  await expect(page.getByText("mario@example.com")).toBeVisible();

  const shown = ((await page.locator(".code").first().textContent()) ?? "").replace(/\s/g, "");
  const now = Date.now() / 1000;
  expect([totp("12345678901234567890", now), totp("12345678901234567890", now - 1)]).toContain(
    shown,
  );

  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.locator(".code").first().click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(shown);

  await addUri(page, ACME);
  await expect(page.getByText("già presente")).toBeVisible();

  const stored = (await storedVault(page)).toString("latin1");
  expect(stored.startsWith("AUTHVLT")).toBe(true);
  for (const plaintext of ["ACME", "mario", "1234567890", RFC_SECRET]) {
    expect(stored).not.toContain(plaintext);
  }

  await page.reload();
  await page.getByLabel("Password principale").fill("password sbagliata!!");
  await page.getByRole("button", { name: "Sblocca" }).click();
  await expect(page.getByText("Password errata")).toBeVisible();

  await page.getByLabel("Password principale").fill(PASSWORD);
  await page.getByRole("button", { name: "Sblocca" }).click();
  await expect(page.getByText("mario@example.com")).toBeVisible();

  await page.getByRole("button", { name: "Blocca" }).click();
  await expect(page.getByRole("heading", { name: "Vault bloccato" })).toBeVisible();
  await expect(page.getByText("mario@example.com")).toHaveCount(0);
});

test("aggiunge un account scansionando un QR da immagine", async ({ page }) => {
  await createVault(page);
  await page.getByRole("button", { name: "Aggiungi", exact: true }).first().click();
  await page.locator('input[type="file"][accept="image/*"]').setInputFiles(fixture("totp-qr.bmp"));
  await expect(page.getByText("1 aggiunti")).toBeVisible();
  await page.getByRole("button", { name: "Codici" }).click();
  await expect(page.getByText("lucia@example.com")).toBeVisible();
});

test("importa un export cifrato di Aegis", async ({ page }) => {
  await createVault(page);
  await page.getByRole("button", { name: "Aggiungi", exact: true }).first().click();
  await page.getByLabel("App di provenienza").selectOption("aegis");
  await page.getByLabel("File di esportazione").setInputFiles(fixture("aegis_encrypted.json"));
  await page.getByRole("button", { name: "Importa" }).click();
  await expect(
    page.getByText("serve la password").or(page.getByText("inserisci la sua password")),
  ).toBeVisible();

  await page.getByLabel(/Password del file/).fill("test");
  await page.getByRole("button", { name: "Importa" }).click();
  await expect(page.getByText("6 aggiunti, 1 non supportati")).toBeVisible();
  await page.getByRole("button", { name: "Codici" }).click();
  await expect(page.locator(".account")).toHaveCount(6);
});

test("recovery key: generazione e sblocco senza password", async ({ page }) => {
  await createVault(page);
  await addUri(page, ACME);
  await page.getByRole("button", { name: "Impostazioni" }).click();
  page.on("dialog", (dialog) => void dialog.accept());
  const recoveryForm = page.locator("form").filter({ hasText: "Genera recovery key" });
  await recoveryForm.getByLabel("Password attuale").fill(PASSWORD);
  await recoveryForm.getByRole("button", { name: "Genera recovery key" }).click();
  const key = (await page.locator(".recovery .key").textContent()) ?? "";
  expect(key).toMatch(/^([A-Z2-7]{4}-){12}[A-Z2-7]{4}$/);
  await page.getByRole("button", { name: "L'ho trascritta" }).click();

  await page.getByRole("button", { name: "Blocca" }).click();
  await page.getByRole("button", { name: /usa la recovery key/ }).click();
  await page.getByLabel("Recovery key").fill(key.toLowerCase().replaceAll("-", " "));
  await page.getByRole("button", { name: "Sblocca" }).click();
  await expect(page.getByText("Hai aperto il vault con la recovery key")).toBeVisible();
  await page.getByRole("button", { name: "Codici" }).click();
  await expect(page.getByText("mario@example.com")).toBeVisible();
});

test("backup cifrato: export e ripristino su un nuovo vault", async ({ page, browser }) => {
  await createVault(page);
  await addUri(page, ACME);
  await page.getByRole("button", { name: "Impostazioni" }).click();
  const exportForm = page.locator("form").filter({ hasText: "Scarica backup cifrato" });
  await exportForm.getByLabel("Password del backup", { exact: true }).fill("password del backup");
  await exportForm.getByLabel("Conferma password del backup").fill("password del backup");
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    exportForm.getByRole("button", { name: "Scarica backup cifrato" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^authenticator-\d{4}-\d{2}-\d{2}\.authbackup$/);
  const file = await download.path();
  const contents = (await readFile(file)).toString("latin1");
  expect(contents).not.toContain("mario");

  // Dispositivo "nuovo": contesto separato, storage vuoto.
  const other = await browser.newContext();
  const fresh = await other.newPage();
  await createVault(fresh, "altra password lunga");
  await fresh.getByRole("button", { name: "Impostazioni" }).click();
  await fresh.locator('input[accept=".authbackup"]').setInputFiles(file);
  const restoreForm = fresh.locator("form").filter({ hasText: "Ripristina da backup" });
  await restoreForm.getByLabel("Password del backup").fill("password del backup");
  await restoreForm.getByRole("button", { name: "Ripristina" }).click();
  await expect(fresh.getByText("Ripristino completato: 1 aggiunti")).toBeVisible();
  await fresh.getByRole("button", { name: "Codici" }).click();
  await expect(fresh.getByText("mario@example.com")).toBeVisible();
  await other.close();
});
