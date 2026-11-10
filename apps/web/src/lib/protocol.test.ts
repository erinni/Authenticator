import { describe, expect, it } from "vitest";
import { parseRequest, transferables } from "./protocol";

const api = { seal: () => new Uint8Array(), lock: () => undefined };

describe("parseRequest", () => {
  it("accetta solo richieste ben formate verso metodi propri dell'api", () => {
    expect(parseRequest({ id: 1, method: "seal", args: [] }, api)).toEqual({
      id: 1,
      method: "seal",
      args: [],
    });
  });

  it("rifiuta metodi ereditati o inesistenti", () => {
    for (const method of ["constructor", "toString", "__proto__", "hasOwnProperty", "nope"]) {
      expect(parseRequest({ id: 1, method, args: [] }, api)).toBeNull();
    }
  });

  it("rifiuta messaggi malformati", () => {
    for (const data of [
      null,
      undefined,
      "seal",
      42,
      { method: "seal", args: [] },
      { id: "1", method: "seal", args: [] },
      { id: 1.5, method: "seal", args: [] },
      { id: 1, method: "seal" },
      { id: 1, method: "seal", args: "x" },
      { id: 1, method: 7, args: [] },
    ]) {
      expect(parseRequest(data, api)).toBeNull();
    }
  });
});

describe("transferables", () => {
  it("raccoglie i buffer degli Uint8Array senza duplicati", () => {
    const a = new Uint8Array(4);
    const view = new Uint8Array(a.buffer, 1, 2);
    expect(transferables([a, view, "x", 3])).toEqual([a.buffer]);
  });
});
