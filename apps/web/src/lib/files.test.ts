import { describe, expect, it } from "vitest";
import { today } from "./files";
import { fitWithin } from "./qr-frame";
import { friendlyError, importSummary } from "./messages";

describe("today", () => {
  it("formatta la data per i nomi dei file", () => {
    expect(today(new Date(2026, 0, 5))).toBe("2026-01-05");
  });
});

describe("fitWithin", () => {
  it("riduce mantenendo le proporzioni e non ingrandisce", () => {
    expect(fitWithin(4000, 3000)).toEqual([1024, 768]);
    expect(fitWithin(640, 480)).toEqual([640, 480]);
  });
});

describe("messaggi", () => {
  it("traduce i codici del core e riassume gli import", () => {
    expect(friendlyError("import:decryption")).toBe("Password errata o file danneggiato.");
    expect(friendlyError("altro")).toBe("altro");
    expect(importSummary({ added: 3, duplicates: 1, skipped: 1 })).toBe(
      "3 aggiunti, 1 già presenti, 1 non supportati (es. Steam)",
    );
  });
});
