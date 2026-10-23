import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { createVault, watchViolations } from "./helpers";

/**
 * Converte il QR di test (BMP 24 bit, righe dal basso) in un video Y4M di un solo
 * fotogramma, usato da Chromium come fotocamera finta.
 */
function bmpToY4m(bmpPath: string): string {
  const bmp = readFileSync(bmpPath);
  const offset = bmp.readUInt32LE(10);
  const width = bmp.readInt32LE(18);
  const height = bmp.readInt32LE(22);
  const stride = Math.ceil((width * 3) / 4) * 4;
  const luma = Buffer.alloc(width * height);
  for (let y = 0; y < height; y++) {
    const row = offset + (height - 1 - y) * stride;
    for (let x = 0; x < width; x++) {
      luma[y * width + x] = bmp[row + x * 3] ?? 255;
    }
  }
  const chroma = Buffer.alloc((width / 2) * (height / 2), 128);
  const header = `YUV4MPEG2 W${String(width)} H${String(height)} F1:1 Ip A1:1 C420jpeg\nFRAME\n`;
  // Cartella temporanea con nome casuale e permessi 0700: nessun percorso prevedibile.
  const path = join(mkdtempSync(join(tmpdir(), "authenticator-e2e-")), "qr.y4m");
  writeFileSync(path, Buffer.concat([Buffer.from(header), luma, chroma, chroma]));
  return path;
}

const video = bmpToY4m(new URL("fixtures/totp-qr.bmp", import.meta.url).pathname);
const executablePath = process.env["CHROMIUM_PATH"];

test.use({
  permissions: ["camera"],
  launchOptions: {
    ...(executablePath ? { executablePath } : {}),
    args: [
      "--use-fake-ui-for-media-stream",
      "--use-fake-device-for-media-stream",
      `--use-file-for-fake-video-capture=${video}`,
    ],
  },
});

test("aggiunge un account inquadrando il QR con la fotocamera", async ({ page }) => {
  const problems = await watchViolations(page);
  await createVault(page);
  await page.getByRole("button", { name: "Aggiungi", exact: true }).first().click();
  await page.getByRole("button", { name: "Usa la fotocamera" }).click();
  await expect(page.getByText("1 aggiunti")).toBeVisible({ timeout: 15_000 });
  // La fotocamera si spegne da sola dopo la lettura.
  await expect(page.getByRole("button", { name: "Usa la fotocamera" })).toBeVisible();
  await page.getByRole("button", { name: "Codici" }).click();
  await expect(page.getByText("lucia@example.com")).toBeVisible();
  expect(problems).toEqual([]);
});
