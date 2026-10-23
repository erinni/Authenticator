<script lang="ts">
  import { onMount } from "svelte";
  import Setup from "./components/Setup.svelte";
  import Unlock from "./components/Unlock.svelte";
  import Vault from "./components/Vault.svelte";
  import { startAutoLock } from "./lib/auto-lock";
  import { core, errorMessage, initCore } from "./lib/core";
  import { passwordBytes } from "./lib/secret-input";
  import { loadVault, requestPersistence, saveVault } from "./lib/storage";

  type Screen = "loading" | "setup" | "locked" | "unlocked" | "error";

  let screen = $state<Screen>("loading");
  let fatal = $state("");
  let sealed: Uint8Array | null = null;
  let stopAutoLock: (() => void) | null = null;
  let recovered = $state(false);

  onMount(async () => {
    try {
      initCore();
      sealed = await loadVault();
      screen = sealed ? "locked" : "setup";
    } catch (e) {
      fatal = errorMessage(e);
      screen = "error";
    }
  });

  function savedVault(): Uint8Array {
    if (!sealed) {
      throw new Error("Nessun vault salvato");
    }
    // Copia: il buffer passato al worker viene trasferito e azzerato.
    return sealed.slice();
  }

  async function persist() {
    sealed = await core.seal();
    await saveVault(sealed);
  }

  function enter() {
    screen = "unlocked";
    stopAutoLock = startAutoLock(() => void lock());
  }

  async function create(password: string) {
    await core.create(passwordBytes(password));
    await persist();
    enter();
    void requestPersistence();
  }

  async function unlock(password: string) {
    await core.open(savedVault(), passwordBytes(password));
    enter();
  }

  async function recover(recoveryKey: string) {
    await core.openRecovery(savedVault(), recoveryKey);
    recovered = true;
    enter();
  }

  /** Verifica la password attuale (per operazioni sensibili). */
  function verify(password: string): Promise<boolean> {
    return core.verify(savedVault(), passwordBytes(password));
  }

  async function lock() {
    stopAutoLock?.();
    stopAutoLock = null;
    recovered = false;
    screen = sealed ? "locked" : "setup";
    await core.lock();
  }
</script>

<main>
  <h1>Authenticator</h1>
  {#if screen === "loading"}
    <p class="hint">Caricamento…</p>
  {:else if screen === "error"}
    <p class="error" role="alert">Impossibile avviare l'app: {fatal}</p>
  {:else if screen === "setup"}
    <Setup oncreate={create} />
  {:else if screen === "locked"}
    <Unlock onunlock={unlock} onrecover={recover} />
  {:else}
    {#if recovered}
      <p class="notice" role="alert">
        Hai aperto il vault con la recovery key: imposta subito una nuova password in
        «Impostazioni».
      </p>
    {/if}
    <Vault onchange={persist} onlock={() => void lock()} {verify} />
  {/if}
</main>
