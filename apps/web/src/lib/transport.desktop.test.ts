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
    // Metodi di CoreApi, più i comandi usati dagli altri moduli `*.desktop.ts`.
    const commands = [
      ...(Object.keys(PARAMS) as Method[]).map(commandName),
      "load_vault",
      "save_vault",
      "platform_unlock",
      "enable_platform_unlock",
      "unlock_with_platform",
      "disable_platform_unlock",
      "scan_screen",
      "copy_code",
      "watch_lock",
      "check_update",
      "install_update",
      "update_auto_check",
      "set_update_auto_check",
    ];
    for (const command of commands) {
      expect(build).toContain(`"${command}"`);
      expect(capability).toContain(`"allow-${command.replaceAll("_", "-")}"`);
    }
  });
});
