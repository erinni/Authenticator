<script lang="ts">
  interface Props {
    onadd: (uri: string) => Promise<void>;
  }
  const { onadd }: Props = $props();

  let uri = $state("");
  let error = $state<string | null>(null);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    try {
      await onadd(uri.trim());
      uri = "";
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      error =
        message === "duplicate" ? "Questo account è già presente." : `URI non valido (${message}).`;
    }
  }
</script>

<form class="add" onsubmit={submit}>
  <label>
    Aggiungi account (URI <code>otpauth://</code>)
    <input
      type="text"
      autocomplete="off"
      spellcheck="false"
      placeholder="otpauth://totp/Servizio:nome?secret=…"
      bind:value={uri}
      required
    />
  </label>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <button type="submit">Aggiungi</button>
</form>
