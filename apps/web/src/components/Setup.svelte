<script lang="ts">
  import { checkNewPassword } from "../lib/secret-input";

  interface Props {
    oncreate: (password: string) => Promise<void>;
  }
  const { oncreate }: Props = $props();

  let password = $state("");
  let confirmation = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = checkNewPassword(password, confirmation);
    if (error) {
      return;
    }
    busy = true;
    try {
      await oncreate(password);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      password = "";
      confirmation = "";
      busy = false;
    }
  }
</script>

<form class="card" onsubmit={submit}>
  <h2>Crea il tuo vault</h2>
  <p class="hint">
    La password principale cifra tutti i tuoi account su questo dispositivo. Non viene mai inviata a
    nessun server e <strong>non può essere recuperata</strong>: sceglila lunga e conservala con
    cura.
  </p>
  <label>
    Password principale
    <input type="password" autocomplete="new-password" bind:value={password} required />
  </label>
  <label>
    Conferma password
    <input type="password" autocomplete="new-password" bind:value={confirmation} required />
  </label>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <button type="submit" disabled={busy}>{busy ? "Creazione in corso…" : "Crea vault"}</button>
</form>
