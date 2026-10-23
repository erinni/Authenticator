/** Durata prima che il codice copiato venga rimosso dagli appunti. */
export const CLIPBOARD_CLEAR_MS = 30_000;

let timer: ReturnType<typeof setTimeout> | undefined;

/**
 * Copia un codice negli appunti e lo cancella dopo {@link CLIPBOARD_CLEAR_MS}.
 * Il browser non permette di sapere se nel frattempo l'utente ha copiato altro:
 * come i password manager, svuotiamo comunque gli appunti alla scadenza.
 */
export async function copyCode(code: string): Promise<void> {
  await navigator.clipboard.writeText(code);
  clearTimeout(timer);
  timer = setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => undefined);
  }, CLIPBOARD_CLEAR_MS);
}
