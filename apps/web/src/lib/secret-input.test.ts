import { describe, expect, it } from "vitest";
import { checkNewPassword, passwordBytes, withPassword } from "./secret-input";

describe("passwordBytes", () => {
  it("normalizza in NFC: la stessa password produce gli stessi byte", () => {
    const composed = "caffè"; // è precomposta
    const decomposed = "caffè"; // e + accento combinante
    expect(passwordBytes(composed)).toEqual(passwordBytes(decomposed));
  });
});

describe("withPassword", () => {
  it("azzera i byte dopo l'uso, anche in caso di errore", () => {
    let seen: Uint8Array | undefined;
    expect(() =>
      withPassword("segreto123", (bytes) => {
        seen = bytes;
        throw new Error("fallito");
      }),
    ).toThrow("fallito");
    expect(seen?.every((b) => b === 0)).toBe(true);
  });
});

describe("checkNewPassword", () => {
  it("richiede lunghezza minima e conferma", () => {
    expect(checkNewPassword("corta", "corta")).not.toBeNull();
    expect(checkNewPassword("abbastanza lunga", "diversa lunga")).not.toBeNull();
    expect(checkNewPassword("abbastanza lunga", "abbastanza lunga")).toBeNull();
  });
});
