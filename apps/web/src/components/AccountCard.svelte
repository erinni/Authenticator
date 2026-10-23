<script lang="ts">
  import { copyCode } from "../lib/clipboard";
  import { groupCode } from "../lib/format";
  import type { AccountView, Session } from "../lib/core";
  import { totp } from "../lib/core";

  interface Props {
    session: Session;
    account: AccountView;
    now: number;
    onhotp: (id: string) => string;
    onremove: (account: AccountView) => void;
  }
  const { session, account, now, onhotp, onremove }: Props = $props();

  let hotpCode = $state<string | null>(null);
  let copied = $state(false);

  const current = $derived(account.kind === "totp" ? totp(session, account.id, now) : null);
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
    {:else}
      <button
        onclick={() => {
          hotpCode = onhotp(account.id);
        }}>Genera</button
      >
    {/if}
    {#if copied}<span class="copied" role="status">Copiato</span>{/if}
    <button
      class="ghost"
      onclick={() => {
        onremove(account);
      }}
      aria-label="Rimuovi {account.issuer ?? account.name}"
    >
      ✕
    </button>
  </div>
</li>
