<script lang="ts">
  import type { Session } from "../lib/core";
  import { errorMessage, parseImport } from "../lib/core";
  import { readFile } from "../lib/files";
  import { nowSeconds } from "../lib/format";
  import { friendlyError, importSummary } from "../lib/messages";
  import { passwordBytes, wipe } from "../lib/secret-input";

  interface Props {
    session: Session;
    onchange: () => Promise<void>;
  }
  const { session, onchange }: Props = $props();

  const FORMATS = [
    { id: "aegis", label: "Aegis (.json)", accept: ".json" },
    { id: "2fas", label: "2FAS (.2fas)", accept: ".2fas,.json" },
    { id: "andotp", label: "andOTP (.json, .json.aes)", accept: ".json,.aes" },
    { id: "google", label: "Google Authenticator (link otpauth-migration://)", accept: "" },
  ] as const;
  type Format = (typeof FORMATS)[number]["id"];

  let format = $state<Format>("aegis");
  let file = $state<File | null>(null);
  let link = $state("");
  let password = $state("");
  let needsPassword = $state(false);
  let message = $state<string | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  const selected = $derived(FORMATS.find((f) => f.id === format) ?? FORMATS[0]);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = message = null;
    busy = true;
    await new Promise((resolve) => setTimeout(resolve, 30));
    const secret = password ? passwordBytes(password) : undefined;
    try {
      const data =
        format === "google" ? new TextEncoder().encode(link) : file ? await readFile(file) : null;
      if (!data) {
        return;
      }
      const report = parseImport(session.import(format, data, secret, nowSeconds()));
      message = `Import completato: ${importSummary(report)}.`;
      needsPassword = false;
      link = "";
      await onchange();
    } catch (e) {
      const code = errorMessage(e);
      needsPassword ||= code === "import:password-required";
      error = friendlyError(code);
    } finally {
      if (secret) {
        wipe(secret);
      }
      password = "";
      busy = false;
    }
  }
</script>

<section class="card">
  <h3>Importa da un'altra app</h3>
  <form class="stack" onsubmit={submit}>
    <label>
      App di provenienza
      <select bind:value={format} onchange={() => (needsPassword = false)}>
        {#each FORMATS as f (f.id)}
          <option value={f.id}>{f.label}</option>
        {/each}
      </select>
    </label>
    {#if format === "google"}
      <p class="hint">
        In Google Authenticator: «Trasferisci account» → «Esporta». Scansiona il QR qui sopra oppure
        incolla il link.
      </p>
      <label>
        Link di esportazione
        <input type="text" autocomplete="off" spellcheck="false" bind:value={link} required />
      </label>
    {:else}
      <label>
        File di esportazione
        <input
          type="file"
          accept={selected.accept}
          onchange={(e) => (file = e.currentTarget.files?.[0] ?? null)}
          required
        />
      </label>
    {/if}
    {#if needsPassword || format !== "google"}
      <label>
        Password del file {needsPassword ? "" : "(solo se cifrato)"}
        <input type="password" autocomplete="off" bind:value={password} required={needsPassword} />
      </label>
    {/if}
    <button type="submit" disabled={busy}>{busy ? "Import in corso…" : "Importa"}</button>
  </form>
  {#if message}<p class="success" role="status">{message}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</section>
