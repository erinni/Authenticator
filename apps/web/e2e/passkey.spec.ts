import { generateKeyPairSync, randomBytes } from "node:crypto";
import { expect, test, type CDPSession, type Page } from "@playwright/test";
import { PASSWORD, RFC_SECRET, addUri, createVault, watchViolations } from "./helpers";

const ACME = `otpauth://totp/ACME:mario@example.com?secret=${RFC_SECRET}&issuer=ACME`;

let problems: string[] = [];

test.beforeEach(async ({ page }) => {
  problems = await watchViolations(page);
});

test.afterEach(() => {
  expect(problems).toEqual([]);
});

/** Autenticatore virtuale di Chromium con PRF e verifica utente sempre riuscita. */
const authenticators = new WeakMap<CDPSession, string>();

function authenticatorOf(cdp: CDPSession): { authenticatorId: string } {
  const authenticatorId = authenticators.get(cdp);
  if (!authenticatorId) {
    throw new Error("autenticatore virtuale mancante");
  }
  return { authenticatorId };
}

async function virtualAuthenticator(page: Page): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  authenticators.set(cdp, authenticatorId);
  return cdp;
}

async function addPasskey(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Impostazioni" }).click();
  const form = page.locator("form").filter({ hasText: "Aggiungi passkey" });
  await form.getByLabel("Password attuale").fill(PASSWORD);
  await form.getByRole("button", { name: "Aggiungi passkey" }).click();
  await expect(page.getByText("Passkey aggiunta")).toBeVisible();
}

test("passkey: registrazione, sblocco e rimozione", async ({ page }) => {
  await virtualAuthenticator(page);
  await createVault(page);
  await addUri(page, ACME);

  // Senza passkey registrate il pulsante non compare.
  await page.getByRole("button", { name: "Blocca" }).click();
  await expect(page.getByRole("button", { name: "Sblocca con passkey" })).toHaveCount(0);
  await page.getByLabel("Password principale").fill(PASSWORD);
  await page.getByRole("button", { name: "Sblocca", exact: true }).click();

  await addPasskey(page);
  await expect(page.getByText("Passkey 1")).toBeVisible();

  await page.reload();
  await page.getByRole("button", { name: "Sblocca con passkey" }).click();
  await expect(page.getByText("mario@example.com")).toBeVisible();

  // La password resta valida.
  await page.getByRole("button", { name: "Blocca" }).click();
  await page.getByLabel("Password principale").fill(PASSWORD);
  await page.getByRole("button", { name: "Sblocca", exact: true }).click();
  await expect(page.getByText("mario@example.com")).toBeVisible();

  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Impostazioni" }).click();
  await page.locator(".passkeys").getByRole("button", { name: "Rimuovi" }).click();
  await expect(page.getByText("Passkey rimossa")).toBeVisible();
  await page.getByRole("button", { name: "Blocca" }).click();
  await expect(page.getByRole("button", { name: "Sblocca con passkey" })).toHaveCount(0);
});

test("passkey non registrata per il vault rifiutata", async ({ page }) => {
  const cdp = await virtualAuthenticator(page);
  await createVault(page);
  await addPasskey(page);

  // Sostituiamo la passkey registrata con un'altra della stessa origine.
  const { authenticatorId } = authenticatorOf(cdp);
  await cdp.send("WebAuthn.clearCredentials", { authenticatorId });
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: randomBytes(16).toString("base64"),
      isResidentCredential: true,
      rpId: "localhost",
      userHandle: randomBytes(16).toString("base64"),
      privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      signCount: 0,
    },
  });

  await page.getByRole("button", { name: "Blocca" }).click();
  await page.getByRole("button", { name: "Sblocca con passkey" }).click();
  await expect(page.getByText("non è registrata per questo vault")).toBeVisible();
});

test("ricerca e icone degli account", async ({ page }) => {
  await createVault(page);
  await addUri(page, ACME);
  await addUri(
    page,
    `otpauth://totp/Citt%C3%A0:luigi@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Citt%C3%A0`,
  );
  await page.getByRole("button", { name: "Codici" }).click();

  await expect(page.locator(".account .avatar")).toHaveText(["A", "C"]);
  await page.getByLabel("Cerca account").fill("citta");
  await expect(page.getByText("luigi@example.com")).toBeVisible();
  await expect(page.getByText("mario@example.com")).toBeHidden();
  await page.getByLabel("Cerca account").fill("nessuno");
  await expect(page.getByText("Nessun account corrisponde")).toBeVisible();
});
