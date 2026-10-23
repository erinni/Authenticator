import { describe, expect, it } from "vitest";
import { groupCode, nowSeconds } from "./format";

describe("groupCode", () => {
  it("raggruppa i codici per lunghezza", () => {
    expect(groupCode("123456")).toBe("123 456");
    expect(groupCode("1234567")).toBe("1234 567");
    expect(groupCode("12345678")).toBe("1234 5678");
    expect(groupCode("12345")).toBe("12345");
  });
});

describe("nowSeconds", () => {
  it("tronca i millisecondi", () => {
    expect(nowSeconds(1_700_000_000_999)).toBe(1_700_000_000);
  });
});
