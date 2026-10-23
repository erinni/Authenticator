<script lang="ts">
  import { onMount } from "svelte";
  import Setup from "./components/Setup.svelte";
  import Unlock from "./components/Unlock.svelte";
  import Vault from "./components/Vault.svelte";
  import { startAutoLock } from "./lib/auto-lock";
  import { errorMessage, initCore, Session } from "./lib/core";
  import { withPassword } from "./lib/secret-input";
  import { loadVault, requestPersistence, saveVault } from "./lib/storage";

  type Screen = "loading" | "setup" | "locked" | "unlocked" | "error";

  let screen = $state<Screen>("loading");
  let fatal = $state("");
  let sealed: Uint8Array | null = null;
  let session = $state<Session | null>(null);
  let stopAutoLock: (() => void) | null = null;

  onMount(async () => {
    try {
      await initCore();
      sealed = await loadVault();
      screen = sealed ? "locked" : "setup";
    } catch (e) {
      fatal = errorMessage(e);
      screen = "error";
    }
  });

  /** Lascia al browser il tempo di mostrare "in corso…" prima di Argon2 (sincrono). */
  const paint = () => new Promise((resolve) => setTimeout(resolve, 30));

  async function persist() {
    if (session) {
      sealed = session.seal();
      await saveVault(sealed);
    }
  }

  function enter(opened: Session) {
    session = opened;
    screen = "unlocked";
    stopAutoLock = startAutoLock(lock);
  }

  async function create(password: string) {
    await paint();
    const created = withPassword(password, (bytes) => Session.create(bytes));
    enter(created);
    await persist();
    void requestPersistence();
  }

  async function unlock(password: string) {
    await paint();
    const file = sealed;
    if (!file) {
      throw new Error("Nessun vault salvato");
    }
    enter(withPassword(password, (bytes) => Session.open(file, bytes)));
  }

  function lock() {
    stopAutoLock?.();
    stopAutoLock = null;
    // Libera la memoria WebAssembly: le chiavi vengono azzerate dal core.
    session?.free();
    session = null;
    screen = sealed ? "locked" : "setup";
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
    <Unlock onunlock={unlock} />
  {:else if session}
    <Vault {session} onchange={persist} onlock={lock} />
  {/if}
</main>
