<script lang="ts">
  import { onMount } from "svelte";
  import { errorMessage } from "../lib/core";
  import { UPDATES_UNAVAILABLE, type UpdateCheck, updates } from "../lib/updates";

  interface Props {
    /** `banner`: controllo all'avvio, visibile solo se c'è una versione nuova. */
    mode: "banner" | "settings";
  }
  const { mode }: Props = $props();

  let result = $state<UpdateCheck | null>(null);
  let auto = $state(true);
  let checking = $state(false);
  let progress = $state<string | null>(null);
  let error = $state<string | null>(null);
  let dismissed = $state(false);

  async function check(quiet: boolean) {
    if (!updates) {
      return;
    }
    checking = true;
    error = null;
    try {
      result = await updates.check();
    } catch (e) {
      const message = errorMessage(e);
      if (!quiet) {
        error =
          message === UPDATES_UNAVAILABLE
            ? "Gli aggiornamenti non sono disponibili in questa build (sviluppo)."
            : `Controllo non riuscito: ${message}`;
      }
    } finally {
      checking = false;
    }
  }

  async function install() {
    if (!updates) {
      return;
    }
    error = null;
    progress = "Download…";
    try {
      await updates.install((downloaded, total) => {
        progress = total
          ? `Download: ${String(Math.round((downloaded / total) * 100))}%`
          : `Download: ${String(Math.round(downloaded / 1024))} KiB`;
      });
      progress = "Installazione…";
    } catch (e) {
      progress = null;
      error = `Aggiornamento non riuscito: ${errorMessage(e)}`;
    }
  }

  async function toggle(event: Event) {
    const enabled = (event.currentTarget as HTMLInputElement).checked;
    try {
      await updates?.setAutoCheck(enabled);
      auto = enabled;
    } catch (e) {
      error = `Preferenza non salvata: ${errorMessage(e)}`;
    }
  }

  function checkNow() {
    void check(false);
  }

  function dismiss() {
    dismissed = true;
  }

  onMount(async () => {
    auto = (await updates?.autoCheck().catch(() => true)) ?? false;
    if (mode === "banner" && auto) {
      await check(true);
    }
  });
</script>

{#if updates && (mode === "settings" || (result?.available && !dismissed))}
  <section class="card" class:update={mode === "banner"} role={mode === "banner" ? "status" : null}>
    {#if mode === "settings"}
      <h3>Aggiornamenti</h3>
      <p class="hint">
        Gli aggiornamenti arrivano dalle release su GitHub e vengono installati solo se firmati
        dallo sviluppatore. Il controllo non invia alcun dato del vault.
      </p>
      <label class="check">
        <input type="checkbox" checked={auto} onchange={toggle} />
        <span>Cerca aggiornamenti all'avvio</span>
      </label>
      <div class="row">
        <button class="ghost" onclick={checkNow} disabled={checking || progress !== null}>
          {checking ? "Controllo in corso…" : "Cerca aggiornamenti"}
        </button>
      </div>
    {/if}
    {#if result?.available}
      <p>È disponibile la versione <strong>{result.available}</strong>.</p>
      {#if result.notes}<p class="hint">{result.notes}</p>{/if}
      {#if progress}
        <p role="status">{progress}</p>
      {:else}
        <div class="row">
          <button onclick={install}>Installa e riavvia</button>
          {#if mode === "banner"}
            <button class="ghost" onclick={dismiss}>Più tardi</button>
          {/if}
        </div>
      {/if}
    {:else if result}
      <p class="success" role="status">Hai la versione più recente ({result.current}).</p>
    {/if}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
  </section>
{/if}

<style>
  .update {
    margin-bottom: 1rem;
  }
  .update p {
    margin: 0;
  }
  label.check {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    font-weight: 400;
  }
  label.check input {
    width: auto;
  }
</style>
