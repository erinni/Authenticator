<script lang="ts">
  interface Props {
    onunlock: (password: string) => Promise<void>;
  }
  const { onunlock }: Props = $props();

  let password = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = null;
    try {
      await onunlock(password);
    } catch {
      // Volutamente generico: non distinguiamo password errata e file danneggiato.
      error = "Password errata o vault danneggiato.";
    } finally {
      password = "";
      busy = false;
    }
  }
</script>

<form class="card" onsubmit={submit}>
  <h2>Vault bloccato</h2>
  <label>
    Password principale
    <!-- svelte-ignore a11y_autofocus -->
    <input
      type="password"
      autocomplete="current-password"
      bind:value={password}
      required
      autofocus
    />
  </label>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <button type="submit" disabled={busy}>{busy ? "Sblocco in corso…" : "Sblocca"}</button>
</form>
