import { describe, expect, it } from "vitest";
import { securityHeaders } from "./security-headers.ts";

const csp = securityHeaders["Content-Security-Policy"] ?? "";
const directives = new Map(
  csp.split(";").map((d) => {
    const [name = "", ...values] = d.trim().split(/\s+/);
    return [name, values] as const;
  }),
);

describe("Content-Security-Policy", () => {
  it("nega tutto per default", () => {
    expect(directives.get("default-src")).toEqual(["'none'"]);
  });

  it("non consente script inline né eval JavaScript", () => {
    const scriptSrc = directives.get("script-src") ?? [];
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
  });

  it("non contiene sorgenti esterne o wildcard", () => {
    expect(csp).not.toMatch(/https?:|\*/);
  });

  it("impone Trusted Types e vieta l'embedding", () => {
    expect(directives.get("require-trusted-types-for")).toEqual(["'script'"]);
    expect(directives.get("frame-ancestors")).toEqual(["'none'"]);
  });
});

describe("isolamento cross-origin", () => {
  it("abilita COOP e COEP", () => {
    expect(securityHeaders["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(securityHeaders["Cross-Origin-Embedder-Policy"]).toBe("require-corp");
  });
});
