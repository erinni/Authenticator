import { describe, expect, it } from "vitest";
import { HUES, hue, initial } from "./avatar";

describe("icone", () => {
  it("usa la prima lettera o cifra", () => {
    expect(initial("acme")).toBe("A");
    expect(initial("  @école")).toBe("É");
    expect(initial("1Password")).toBe("1");
    expect(initial("---")).toBe("?");
  });

  it("colore stabile e indipendente dalle maiuscole", () => {
    expect(hue("GitHub")).toBe(hue("github"));
    for (const label of ["a", "Google", "Microsoft", ""]) {
      expect(hue(label)).toBeGreaterThanOrEqual(0);
      expect(hue(label)).toBeLessThan(HUES);
    }
  });
});
