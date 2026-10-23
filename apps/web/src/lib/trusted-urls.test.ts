import { describe, expect, it } from "vitest";
import { sameOriginOnly } from "./trusted-urls";

describe("sameOriginOnly", () => {
  const base = "https://app.example/";

  it("accetta percorsi della stessa origine e li normalizza", () => {
    expect(sameOriginOnly("/assets/core.worker.js", base)).toBe(
      "https://app.example/assets/core.worker.js",
    );
    expect(sameOriginOnly("sw.js", base)).toBe("https://app.example/sw.js");
  });

  it("rifiuta altre origini, anche camuffate", () => {
    expect(() => sameOriginOnly("https://evil.example/x.js", base)).toThrow();
    expect(() => sameOriginOnly("//evil.example/x.js", base)).toThrow();
    expect(() => sameOriginOnly("data:text/javascript,alert(1)", base)).toThrow();
    expect(() => sameOriginOnly("blob:https://evil.example/1", base)).toThrow();
  });
});
