/**
 * Header di sicurezza HTTP della PWA.
 *
 * Unica fonte di verità: usati da `vite preview` e da replicare identici
 * nella configurazione dell'hosting di produzione.
 */

const csp = [
  "default-src 'none'",
  // 'wasm-unsafe-eval' consente solo la compilazione WebAssembly del core, non eval() JS.
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "media-src 'self' blob:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types svelte-trusted-html",
  "upgrade-insecure-requests",
].join("; ");

export const securityHeaders: Readonly<Record<string, string>> = {
  "Content-Security-Policy": csp,
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  // La fotocamera serve per la scansione dei QR code; tutto il resto è disabilitato.
  "Permissions-Policy":
    "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), serial=()",
};
