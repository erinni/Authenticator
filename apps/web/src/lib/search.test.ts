import { describe, expect, it } from "vitest";
import { matches, normalize } from "./search";

describe("ricerca", () => {
  const acme = { issuer: "ACME Città", name: "mario@example.com" };

  it("ignora maiuscole e diacritici", () => {
    expect(normalize("Città ÀÉ")).toBe("citta ae");
    expect(matches(acme, "citta")).toBe(true);
    expect(matches(acme, "acme")).toBe(true);
  });

  it("richiede tutte le parole, in issuer o nome", () => {
    expect(matches(acme, "acme mario")).toBe(true);
    expect(matches(acme, "acme luigi")).toBe(false);
    expect(matches({ issuer: null, name: "luigi" }, "LUI")).toBe(true);
  });

  it("query vuota: tutto", () => {
    expect(matches(acme, "   ")).toBe(true);
  });
});
