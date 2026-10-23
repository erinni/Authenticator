<script lang="ts">
  import { onMount } from "svelte";
  import { core, errorMessage } from "../lib/core";
  import { PasskeyError, fromHex, passkeySupported, registerPasskey } from "../lib/passkey";
  import { checkNewPassword, passwordBytes } from "../lib/secret-input";

  interface Props {
    verify: (password: string) => Promise<boolean>;
    onchange: () => Promise<void>;
    /** Id degli slot passkey del vault. */
    passkeys: readonly string[];
  }
  const { verify, onchange, passkeys }: Props = $props();

  let passkeyAvailable = $state(false);
  onMount(async () => {
    passkeyAvailable = await passkeySupported();
  });

  let recoveryKey = $state<string | null>(null);
  let current = $state("");
  let next = $state("");
  let confirmation = $state("");
  let message = $state<string | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function reauthenticated(): Promise<boolean> {
    const ok = await verify(current);
    current = "";
    if (!ok) {
      error = "Password attuale errata.";
    }
    return ok;
  }

  async function createRecoveryKey(event: SubmitEvent) {
    event.preventDefault();
    error = message = null;
    if (
      !confirm(
        "Una nuova recovery key sostituisce la precedente, che smetterà di funzionare. Continuare?",
      )
    ) {
      return;
    }
    busy = true;
    try {
      if (await reauthenticated()) {
        recoveryKey = await core.createRecoveryKey();
        await onchange();
      }
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function addPasskey(event: SubmitEvent) {
    event.preventDefault();
    error = message = null;
    busy = true;
    try {
      if (await reauthenticated()) {
        const { slotId, secret } = await registerPasskey();
        await core.setExternal(slotId, secret);
        await onchange();
        message = "Passkey aggiunta: ora puoi sbloccare il vault anche con questa passkey.";
      }
    } catch (e) {
      error = e instanceof PasskeyError ? e.message : errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function removePasskey(id: string) {
    error = message = null;
    if (
      !confirm(
        "Rimuovere questa passkey? Non potrà più sbloccare il vault. La passkey resta salvata nel dispositivo: puoi eliminarla dalle sue impostazioni.",
      )
    ) {
      return;
    }
    busy = true;
    try {
      await core.removeExternal(fromHex(id));
      await onchange();
      message = "Passkey rimossa.";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function changePassword(event: SubmitEvent) {
    event.preventDefault();
    error = message = null;
    const problem = checkNewPassword(next, confirmation);
    if (problem) {
      error = problem;
      return;
    }
    busy = true;
    try {
      if (await reauthenticated()) {
        await core.changePassword(passwordBytes(next));
        await onchange();
        message = "Password cambiata.";
      }
    } catch (e) {
      error = errorMessage(e);
    } finally {
      next = confirmation = "";
      busy = false;
    }
  }
</script>

<section class="card">
  <h3>Sicurezza</h3>

  {#if recoveryKey}
    <div class="recovery" role="alert">
      <p>
        <strong>Trascrivi questa recovery key e conservala offline</strong> (su carta, in un luogo sicuro).
        Permette di aprire il vault se dimentichi la password. Non verrà mostrata di nuovo.
      </p>
      <code class="key">{recoveryKey}</code>
      <button onclick={() => (recoveryKey = null)}>L'ho trascritta</button>
    </div>
  {:else}
    <form class="stack" onsubmit={createRecoveryKey}>
      <p class="hint">
        La recovery key permette di recuperare il vault senza password. Generane una e conservala
        offline.
      </p>
      <label>
        Password attuale
        <input type="password" autocomplete="current-password" bind:value={current} required />
      </label>
      <button type="submit" disabled={busy}>Genera recovery key</button>
    </form>

    <form class="stack" onsubmit={addPasskey}>
      <h4>Passkey</h4>
      {#if passkeyAvailable}
        <p class="hint">
          Sblocca il vault con impronta, volto o PIN del dispositivo. La password resta sempre
          valida. Serve una passkey con l'estensione PRF.
        </p>
        {#if passkeys.length > 0}
          <ul class="passkeys">
            {#each passkeys as id, i (id)}
              <li>
                <span>Passkey {i + 1}</span>
                <button
                  type="button"
                  class="ghost"
                  disabled={busy}
                  onclick={() => void removePasskey(id)}>Rimuovi</button
                >
              </li>
            {/each}
          </ul>
        {/if}
        <label>
          Password attuale
          <input type="password" autocomplete="current-password" bind:value={current} required />
        </label>
        <button type="submit" disabled={busy}>Aggiungi passkey</button>
      {:else}
        <p class="hint">Questo browser non supporta lo sblocco con passkey.</p>
      {/if}
    </form>

    <form class="stack" onsubmit={changePassword}>
      <h4>Cambia password</h4>
      <label>
        Password attuale
        <input type="password" autocomplete="current-password" bind:value={current} required />
      </label>
      <label>
        Nuova password
        <input type="password" autocomplete="new-password" bind:value={next} required />
      </label>
      <label>
        Conferma nuova password
        <input type="password" autocomplete="new-password" bind:value={confirmation} required />
      </label>
      <button type="submit" disabled={busy}>{busy ? "In corso…" : "Cambia password"}</button>
    </form>
  {/if}

  {#if message}<p class="success" role="status">{message}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</section>
