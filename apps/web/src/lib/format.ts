/** Raggruppa le cifre per la lettura: "123456" → "123 456", "12345678" → "1234 5678". */
export function groupCode(code: string): string {
  if (code.length < 6) {
    return code;
  }
  const split = code.length === 7 ? 4 : Math.ceil(code.length / 2);
  return `${code.slice(0, split)} ${code.slice(split)}`;
}

/** Secondi Unix correnti, come atteso dal core. */
export function nowSeconds(now: number = Date.now()): number {
  return Math.floor(now / 1000);
}
