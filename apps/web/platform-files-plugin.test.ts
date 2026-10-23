import { describe, expect, it } from "vitest";
import { platformFiles, variantPath } from "./platform-files-plugin";

describe("variantPath", () => {
  it("aggiunge il suffisso della piattaforma ai moduli TypeScript", () => {
    expect(variantPath("/app/src/lib/storage.ts", "desktop")).toBe(
      "/app/src/lib/storage.desktop.ts",
    );
  });

  it("ignora altri file, query e varianti già risolte", () => {
    expect(variantPath("/app/src/App.svelte", "desktop")).toBeNull();
    expect(variantPath("/app/src/worker.ts?worker&url", "desktop")).toBeNull();
    expect(variantPath("/app/src/lib/storage.desktop.ts", "desktop")).toBeNull();
  });
});

describe("platformFiles", () => {
  type Resolve = (source: string, importer: string | undefined) => Promise<unknown>;

  function resolver(existing: readonly string[]): Resolve {
    const plugin = platformFiles("desktop", (path) => existing.includes(String(path)));
    const hook = plugin.resolveId as unknown as (
      this: unknown,
      source: string,
      importer: string | undefined,
      options: object,
    ) => Promise<unknown>;
    const context = {
      resolve: (source: string) => Promise.resolve({ id: `/src/lib/${source.slice(2)}.ts` }),
    };
    return (source, importer) => hook.call(context, source, importer, {});
  }

  it("sostituisce un modulo con la sua variante, se esiste", async () => {
    const resolve = resolver(["/src/lib/storage.desktop.ts"]);
    await expect(resolve("./storage", "/src/App.svelte")).resolves.toBe(
      "/src/lib/storage.desktop.ts",
    );
    await expect(resolve("./format", "/src/App.svelte")).resolves.toBeNull();
  });

  it("lascia alla variante l'accesso al modulo originale", async () => {
    const resolve = resolver(["/src/lib/passkey.desktop.ts"]);
    await expect(resolve("./passkey", "/src/lib/passkey.desktop.ts")).resolves.toBeNull();
  });

  it("non tocca i pacchetti", async () => {
    const resolve = resolver(["/src/lib/svelte.desktop.ts"]);
    await expect(resolve("svelte", "/src/App.svelte")).resolves.toBeNull();
  });
});
