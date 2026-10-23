/** Messaggi in italiano per gli errori stabili del core (`import:*`, ecc.). */
const MESSAGES: Record<string, string> = {
  "import:password-required": "Il file è cifrato: inserisci la sua password.",
  "import:decryption": "Password errata o file danneggiato.",
  "import:unsupported-version": "Versione del file non supportata.",
  "import:too-large": "Il file è troppo grande.",
  "import:invalid-format": "Formato del file non riconosciuto.",
  "import:unknown-format": "Formato di import sconosciuto.",
  duplicate: "Questo account è già presente.",
  "decifratura fallita": "Password errata o file danneggiato.",
};

export function friendlyError(message: string): string {
  return MESSAGES[message] ?? message;
}

/** Riepilogo di un import o di una scansione. */
export function importSummary(report: {
  added: number;
  duplicates: number;
  skipped: number;
}): string {
  const parts = [`${String(report.added)} aggiunti`];
  if (report.duplicates > 0) {
    parts.push(`${String(report.duplicates)} già presenti`);
  }
  if (report.skipped > 0) {
    parts.push(`${String(report.skipped)} non supportati (es. Steam)`);
  }
  return parts.join(", ");
}
