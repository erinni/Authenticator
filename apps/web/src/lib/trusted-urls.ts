/**
 * Trusted Types per gli URL di script (Web Worker e Service Worker).
 *
 * La CSP impone `require-trusted-types-for 'script'`: `new Worker()` e
 * `serviceWorker.register()` accettano solo URL creati da una policy registrata.
 * Questa policy accetta esclusivamente URL della stessa origine.
 */

export const POLICY_NAME = "authenticator-script-url";

/** Tipi minimi delle Trusted Types (non ancora inclusi nella libreria DOM di TypeScript). */
interface ScriptUrlPolicy {
  createScriptURL(input: string): unknown;
}
interface PolicyFactory {
  createPolicy(
    name: string,
    rules: { createScriptURL: (input: string) => string },
  ): ScriptUrlPolicy;
}

let policy: ScriptUrlPolicy | null = null;
let initialized = false;

function getPolicy(): ScriptUrlPolicy | null {
  if (!initialized) {
    initialized = true;
    const factory = (globalThis as { trustedTypes?: PolicyFactory }).trustedTypes;
    policy =
      factory?.createPolicy(POLICY_NAME, { createScriptURL: (u) => sameOriginOnly(u) }) ?? null;
  }
  return policy;
}

/** Normalizza l'URL e rifiuta qualsiasi origine diversa da quella della pagina. */
export function sameOriginOnly(input: string, base: string = location.href): string {
  const url = new URL(input, base);
  if (url.origin !== new URL(base).origin) {
    throw new TypeError(`URL di script non consentito: ${url.origin}`);
  }
  return url.href;
}

/**
 * URL di script utilizzabile con `new Worker()` e `serviceWorker.register()`.
 * Il valore restituito è un `TrustedScriptURL` dove supportato: va passato così com'è.
 */
export function scriptUrl(input: string): string {
  const trusted = getPolicy();
  // Nei browser senza Trusted Types (es. Firefox, Safari) basta la verifica di origine.
  return trusted ? (trusted.createScriptURL(input) as string) : sameOriginOnly(input);
}
