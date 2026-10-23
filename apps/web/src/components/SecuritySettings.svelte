<script lang="ts">
  import type { Session } from "../lib/core";
  import { errorMessage } from "../lib/core";
  import { checkNewPassword, withPassword } from "../lib/secret-input";

  interface Props {
    session: Session;
    verify: (password: string) => Promise<boolean>;
    onchange: () => Promise<void>;
  }
  const { session, verify, onchange }: Props = $props();

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
        recoveryKey = session.create_recovery_key();
        await onchange();
      }
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
        withPassword(next, (bytes) => {
          session.change_password(bytes);
        });
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
