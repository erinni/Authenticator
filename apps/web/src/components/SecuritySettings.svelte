<script lang="ts">
  import { onMount } from "svelte";
  import { core, errorMessage } from "../lib/core";
  import { type UnlockOption, enroll, removeSlot, unlockOption } from "../lib/external-unlock";
  import { UnlockError } from "../lib/unlock-error";
  import { checkNewPassword, passwordBytes } from "../lib/secret-input";

  interface Props {
    verify: (password: string) => Promise<boolean>;
    onchange: () => Promise<void>;
    /** Id degli slot esterni del vault (passkey o sblocco di sistema). */
    externalSlots: readonly string[];
  }
  const { verify, onchange, externalSlots }: Props = $props();

  let option = $state<UnlockOption | null>(null);
  onMount(async () => {
    option = await unlockOption();
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

  async function addExternal(event: SubmitEvent) {
    event.preventDefault();
    if (!option) {
      return;
    }
    error = message = null;
    busy = true;
    try {
      if (await reauthenticated()) {
        await enroll();
        await onchange();
        message = option.texts.added;
      }
    } catch (e) {
      error = e instanceof UnlockError ? e.message : errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function removeExternal(id: string) {
    if (!option) {
      return;
    }
    error = message = null;
    if (!confirm(option.texts.removeConfirm)) {
      return;
    }
    busy = true;
    try {
      await removeSlot(id);
      await onchange();
      message = option.texts.removed;
    } catch (e) {
      error = e instanceof UnlockError ? e.message : errorMessage(e);
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

    {#if option}
      {@const texts = option.texts}
      <form class="stack" onsubmit={addExternal}>
        <h4>{texts.title}</h4>
        {#if option.available}
          <p class="hint">{texts.hint}</p>
          {#if texts.warning}<p class="warning">{texts.warning}</p>{/if}
          {#if externalSlots.length > 0}
            <ul class="passkeys">
              {#each externalSlots as id, i (id)}
                <li>
                  <span>{texts.item} {i + 1}</span>
                  <button
                    type="button"
                    class="ghost"
                    disabled={busy}
                    onclick={() => void removeExternal(id)}>Rimuovi</button
                  >
                </li>
              {/each}
            </ul>
          {/if}
          <label>
            Password attuale
            <input type="password" autocomplete="current-password" bind:value={current} required />
          </label>
          <button type="submit" disabled={busy}>{texts.add}</button>
        {:else}
          <p class="hint">{texts.unavailable}</p>
        {/if}
      </form>
    {/if}

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
