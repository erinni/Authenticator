/**
 * Conversione delle password in byte per il core WebAssembly.
 *
 * Le stringhe JavaScript sono immutabili e non possono essere azzerate: le
 * convertiamo subito in `Uint8Array`, che il chiamante azzera dopo l'uso con
 * {@link wipe}. La normalizzazione NFC garantisce che la stessa password
 * digitata su dispositivi diversi produca gli stessi byte.
 */
export function passwordBytes(password: string): Uint8Array {
  return new TextEncoder().encode(password.normalize("NFC"));
}

/** Sovrascrive con zeri un buffer che conteneva dati sensibili. */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}

/** Esegue `fn` con i byte della password e li azzera in ogni caso al termine. */
export function withPassword<T>(password: string, fn: (bytes: Uint8Array) => T): T {
  const bytes = passwordBytes(password);
  try {
    return fn(bytes);
  } finally {
    wipe(bytes);
  }
}

/** Requisiti minimi della password principale. Restituisce un messaggio d'errore o `null`. */
export function checkNewPassword(password: string, confirmation: string): string | null {
  // Conta i caratteri percepiti (grafemi), non le unità UTF-16.
  const graphemes = [...new Intl.Segmenter().segment(password.normalize("NFC"))].length;
  if (graphemes < 10) {
    return "La password deve avere almeno 10 caratteri.";
  }
  if (password !== confirmation) {
    return "Le due password non coincidono.";
  }
  return null;
}
