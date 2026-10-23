import { createHmac } from "node:crypto";
import { expect, type Page } from "@playwright/test";

export const PASSWORD = "una password molto lunga";
/** Seed del test vector RFC 6238 ("12345678901234567890" in Base32). */
export const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/** TOTP (SHA-1, 6 cifre, 30 s) calcolato indipendentemente dal core. */
export function totp(seed: string, unixSeconds: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const digest = createHmac("sha1", seed).update(message).digest();
  const offset = (digest.at(-1) ?? 0) & 0x0f;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** Registra violazioni CSP/Trusted Types ed errori di pagina, da verificare a fine test. */
export async function watchViolations(page: Page): Promise<string[]> {
  const problems: string[] = [];
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  page.on("console", (m) => {
    if (m.type() === "error") {
      problems.push(m.text());
    }
  });
  page.on("pageerror", (e) => problems.push(e.message));
  return problems;
}

export async function createVault(page: Page, password = PASSWORD): Promise<void> {
  await page.goto("/");
  await page.getByLabel("Password principale").fill(password);
  await page.getByLabel("Conferma password").fill(password);
  await page.getByRole("button", { name: "Crea vault" }).click();
  await expect(page.getByRole("button", { name: "Blocca" })).toBeVisible();
}

export async function addUri(page: Page, uri: string): Promise<void> {
  await page.getByRole("button", { name: "Aggiungi", exact: true }).first().click();
  await page.getByLabel(/Aggiungi account/).fill(uri);
  await page.locator("form.add").getByRole("button", { name: "Aggiungi" }).click();
}

/** Contenuto grezzo del vault salvato in IndexedDB. */
export async function storedVault(page: Page): Promise<Buffer> {
  const bytes = await page.evaluate(
    () =>
      new Promise<number[]>((resolve, reject) => {
        const open = indexedDB.open("authenticator");
        open.onerror = () => {
          reject(new Error("IndexedDB"));
        };
        open.onsuccess = () => {
          const get = open.result.transaction("vault").objectStore("vault").get("current");
          get.onsuccess = () => {
            resolve(Array.from(get.result as Uint8Array));
          };
        };
      }),
  );
  return Buffer.from(bytes);
}
