/** Legge un file scelto dall'utente come byte. */
export async function readFile(file: File): Promise<Uint8Array> {
  return new Uint8Array(await file.arrayBuffer());
}

/** Avvia il download di dati generati localmente (nessuna richiesta di rete). */
export function download(
  bytes: Uint8Array,
  filename: string,
  type = "application/octet-stream",
): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}

/** Data locale nel formato AAAA-MM-GG, per i nomi dei file. */
export function today(date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${String(date.getFullYear())}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}
