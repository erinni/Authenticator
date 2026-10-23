<script lang="ts">
  import type { Session } from "../lib/core";
  import { errorMessage, parseImport } from "../lib/core";
  import { download, readFile, today } from "../lib/files";
  import { nowSeconds } from "../lib/format";
  import { friendlyError, importSummary } from "../lib/messages";
  import { checkNewPassword, withPassword } from "../lib/secret-input";

  interface Props {
    session: Session;
    onchange: () => Promise<void>;
  }
  const { session, onchange }: Props = $props();

  let password = $state("");
  let confirmation = $state("");
  let restorePassword = $state("");
  let restoreFile = $state<File | null>(null);
  let message = $state<string | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function exportBackup(event: SubmitEvent) {
    event.preventDefault();
    error = message = null;
    const problem = checkNewPassword(password, confirmation);
    if (problem) {
      error = problem;
      return;
    }
    busy = true;
    await new Promise((resolve) => setTimeout(resolve, 30));
    try {
      const file = withPassword(password, (bytes) => session.export_backup(bytes));
      download(file, `authenticator-${today()}.authbackup`);
      message =
        "Backup cifrato scaricato. Conservalo insieme alla sua password, in luoghi diversi.";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      password = confirmation = "";
      busy = false;
    }
  }

  async function restore(event: SubmitEvent) {
    event.preventDefault();
    error = message = null;
    if (!restoreFile) {
      return;
    }
    busy = true;
    try {
      const data = await readFile(restoreFile);
      const report = parseImport(
        withPassword(restorePassword, (bytes) => session.restore_backup(data, bytes, nowSeconds())),
      );
      message = `Ripristino completato: ${importSummary(report)}.`;
      await onchange();
    } catch (e) {
      error = friendlyError(errorMessage(e));
    } finally {
      restorePassword = "";
      busy = false;
    }
  }
</script>

<section class="card">
  <h3>Backup</h3>
  <form class="stack" onsubmit={exportBackup}>
    <p class="hint">
      Il backup è cifrato con una password dedicata, diversa da quella del vault, e si può
      ripristinare su un altro dispositivo.
    </p>
    <label>
      Password del backup
      <input type="password" autocomplete="new-password" bind:value={password} required />
    </label>
    <label>
      Conferma password del backup
      <input type="password" autocomplete="new-password" bind:value={confirmation} required />
    </label>
    <button type="submit" disabled={busy}>{busy ? "In corso…" : "Scarica backup cifrato"}</button>
  </form>

  <form class="stack" onsubmit={restore}>
    <h4>Ripristina da backup</h4>
    <label>
      File <code>.authbackup</code>
      <input
        type="file"
        accept=".authbackup"
        onchange={(e) => (restoreFile = e.currentTarget.files?.[0] ?? null)}
        required
      />
    </label>
    <label>
      Password del backup
      <input type="password" autocomplete="off" bind:value={restorePassword} required />
    </label>
    <button type="submit" disabled={busy || !restoreFile}>Ripristina</button>
  </form>

  {#if message}<p class="success" role="status">{message}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</section>
