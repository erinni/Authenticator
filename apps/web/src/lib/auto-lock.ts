/** Blocco automatico dopo inattività o quando la pagina resta nascosta. */
export const IDLE_LOCK_MS = 5 * 60_000;
export const HIDDEN_LOCK_MS = 60_000;

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

/** Avvia il controllo; restituisce la funzione che lo ferma. */
export function startAutoLock(lock: () => void): () => void {
  let idle: ReturnType<typeof setTimeout> | undefined;
  let hidden: ReturnType<typeof setTimeout> | undefined;

  const resetIdle = () => {
    clearTimeout(idle);
    idle = setTimeout(lock, IDLE_LOCK_MS);
  };
  const onVisibility = () => {
    clearTimeout(hidden);
    if (document.visibilityState === "hidden") {
      hidden = setTimeout(lock, HIDDEN_LOCK_MS);
    }
  };

  for (const event of ACTIVITY_EVENTS) {
    window.addEventListener(event, resetIdle, { passive: true });
  }
  document.addEventListener("visibilitychange", onVisibility);
  resetIdle();

  return () => {
    clearTimeout(idle);
    clearTimeout(hidden);
    for (const event of ACTIVITY_EVENTS) {
      window.removeEventListener(event, resetIdle);
    }
    document.removeEventListener("visibilitychange", onVisibility);
  };
}
