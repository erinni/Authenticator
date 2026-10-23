/**
 * Passkey nell'app desktop: non disponibili. Le webview di sistema non offrono in modo
 * uniforme WebAuthn con l'estensione PRF, e l'origine dell'app non è un dominio web:
 * lo sblocco biometrico arriverà dal keychain del sistema (Touch ID, Windows Hello).
 */
import type * as Web from "./passkey";
import { PasskeyError } from "./passkey";

export { PasskeyError, fromHex, slotIdFor, toHex } from "./passkey";
export type { PasskeySecret } from "./passkey";

const unavailable = () => Promise.reject(new PasskeyError("Passkey non disponibili nell'app."));

export const passkeySupported: typeof Web.passkeySupported = () => Promise.resolve(false);
export const registerPasskey: typeof Web.registerPasskey = unavailable;
export const unlockSecret: typeof Web.unlockSecret = unavailable;
