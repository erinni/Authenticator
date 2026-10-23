import { Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { serviceWorkerSource } from "./service-worker-plugin";

describe("serviceWorkerSource", () => {
  const source = serviceWorkerSource("abc123", ["./", "./assets/index-1.js"]);

  it("include versione ed elenco dei file da mettere in cache", () => {
    expect(source).toContain('const VERSION = "abc123";');
    expect(source).toContain('["./","./assets/index-1.js"]');
  });

  it("intercetta solo GET della stessa origine", () => {
    expect(source).toContain('request.method !== "GET"');
    expect(source).toContain("origin !== self.location.origin");
  });

  it("trova in cache anche le richieste con header Origin", () => {
    expect(source).toContain("ignoreVary: true");
  });

  it("è JavaScript sintatticamente valido", () => {
    // Compila senza eseguire.
    expect(() => new Script(source)).not.toThrow();
  });
});
