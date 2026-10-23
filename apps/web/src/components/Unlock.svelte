<script lang="ts">
  interface Props {
    onunlock: (password: string) => Promise<void>;
    onrecover: (recoveryKey: string) => Promise<void>;
  }
  const { onunlock, onrecover }: Props = $props();

  let useRecovery = $state(false);
  let secret = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = null;
    try {
      await (useRecovery ? onrecover(secret) : onunlock(secret));
    } catch {
      // Volutamente generico: non distinguiamo credenziale errata e file danneggiato.
      error = useRecovery
        ? "Recovery key errata o vault danneggiato."
        : "Password errata o vault danneggiato.";
    } finally {
      secret = "";
      busy = false;
    }
  }
</script>

<form class="card" onsubmit={submit}>
  <h2>Vault bloccato</h2>
  {#if useRecovery}
    <label>
      Recovery key
      <input type="text" autocomplete="off" spellcheck="false" bind:value={secret} required />
    </label>
  {:else}
    <label>
      Password principale
      <!-- svelte-ignore a11y_autofocus -->
      <input
        type="password"
        autocomplete="current-password"
        bind:value={secret}
        required
        autofocus
      />
    </label>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <button type="submit" disabled={busy}>{busy ? "Sblocco in corso…" : "Sblocca"}</button>
  <button
    type="button"
    class="link"
    onclick={() => {
      useRecovery = !useRecovery;
      error = null;
      secret = "";
    }}
  >
    {useRecovery ? "Usa la password" : "Ho dimenticato la password: usa la recovery key"}
  </button>
</form>
