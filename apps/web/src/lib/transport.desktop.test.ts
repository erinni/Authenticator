import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Method } from "./protocol";
import { PARAMS, commandArgs, commandName } from "./transport.desktop";

describe("trasporto desktop", () => {
  it("usa i nomi dei comandi Rust", () => {
    expect(commandName("openRecovery")).toBe("open_recovery");
    expect(commandName("createRecoveryKey")).toBe("create_recovery_key");
    expect(commandName("seal")).toBe("seal");
  });

  it("nomina gli argomenti e converte i byte", () => {
    expect(commandArgs("open", [Uint8Array.of(1, 2), Uint8Array.of(3)])).toEqual({
      file: [1, 2],
      password: [3],
    });
    expect(commandArgs("importData", ["aegis", Uint8Array.of(9), null, 10])).toEqual({
      format: "aegis",
      data: [9],
      password: null,
      now: 10,
    });
  });

  it("rifiuta argomenti in eccesso", () => {
    expect(() => commandArgs("lock", [1])).toThrow();
  });

  it("ogni metodo corrisponde a un comando con permesso nell'app Tauri", () => {
    const tauri = new URL("../../../native/src-tauri/", import.meta.url);
    const build = readFileSync(new URL("build.rs", tauri), "utf8");
    const capability = readFileSync(new URL("capabilities/default.json", tauri), "utf8");
    for (const method of Object.keys(PARAMS) as Method[]) {
      const command = commandName(method);
      expect(build).toContain(`"${command}"`);
      expect(capability).toContain(`"allow-${command.replaceAll("_", "-")}"`);
    }
  });
});
