<script lang="ts">
  import { copyCode } from "../lib/clipboard";
  import { groupCode } from "../lib/format";
  import type { AccountView, TotpView } from "../lib/core";

  interface Props {
    account: AccountView;
    current: TotpView | null;
    onhotp: (id: string) => Promise<string>;
    onremove: (account: AccountView) => Promise<void>;
  }
  const { account, current, onhotp, onremove }: Props = $props();

  let hotpCode = $state<string | null>(null);
  let copied = $state(false);

  const code = $derived(current?.code ?? hotpCode);

  async function copy() {
    if (code) {
      await copyCode(code);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    }
  }
</script>

<li class="account">
  <div class="labels">
    <span class="issuer">{account.issuer ?? account.name}</span>
    {#if account.issuer}<span class="name">{account.name}</span>{/if}
  </div>

  {#if code}
    <button class="code" onclick={copy} title="Copia il codice" aria-label="Copia il codice">
      {groupCode(code)}
    </button>
  {:else}
    <span class="code placeholder" aria-hidden="true">{"•".repeat(account.digits)}</span>
  {/if}

  <div class="actions">
    {#if current}
      <progress
        max={current.period}
        value={current.remaining}
        aria-label="Secondi rimanenti: {current.remaining}"
        class:expiring={current.remaining <= 5}
      ></progress>
    {:else if account.kind === "hotp"}
      <button
        onclick={async () => {
          hotpCode = await onhotp(account.id);
        }}>Genera</button
      >
    {/if}
    {#if copied}<span class="copied" role="status">Copiato</span>{/if}
    <button
      class="ghost"
      onclick={() => void onremove(account)}
      aria-label="Rimuovi {account.issuer ?? account.name}"
    >
      ✕
    </button>
  </div>
</li>
