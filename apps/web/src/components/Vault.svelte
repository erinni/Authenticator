<script lang="ts">
  import { onDestroy } from "svelte";
  import AccountCard from "./AccountCard.svelte";
  import AddAccount from "./AddAccount.svelte";
  import BackupPanel from "./BackupPanel.svelte";
  import ImportPanel from "./ImportPanel.svelte";
  import ScanQr from "./ScanQr.svelte";
  import SecuritySettings from "./SecuritySettings.svelte";
  import { accounts, type AccountView, type Session } from "../lib/core";
  import { nowSeconds } from "../lib/format";

  interface Props {
    session: Session;
    onchange: () => Promise<void>;
    onlock: () => void;
    verify: (password: string) => Promise<boolean>;
  }
  const { session, onchange, onlock, verify }: Props = $props();

  const TABS = [
    { id: "codes", label: "Codici" },
    { id: "add", label: "Aggiungi" },
    { id: "settings", label: "Impostazioni" },
  ] as const;
  let tab = $state<(typeof TABS)[number]["id"]>("codes");

  let list = $state<AccountView[]>([]);
  let now = $state(nowSeconds());

  function refresh() {
    list = accounts(session);
  }
  $effect.pre(refresh);

  const tick = setInterval(() => (now = nowSeconds()), 1000);
  onDestroy(() => {
    clearInterval(tick);
  });

  async function changed() {
    refresh();
    await onchange();
  }

  function add(uri: string) {
    session.add_uri(uri, nowSeconds());
    void changed();
    tab = "codes";
  }

  function hotp(id: string): string {
    const code = session.next_hotp(id);
    void changed();
    return code;
  }

  function remove(account: AccountView) {
    const label = account.issuer ? `${account.issuer} (${account.name})` : account.name;
    if (confirm(`Rimuovere ${label}? Senza un backup non potrai più generare i suoi codici.`)) {
      session.remove(account.id);
      void changed();
    }
  }
</script>

<section>
  <header class="toolbar">
    <nav class="tabs" aria-label="Sezioni">
      {#each TABS as t (t.id)}
        <button
          class:active={tab === t.id}
          aria-current={tab === t.id ? "page" : undefined}
          onclick={() => (tab = t.id)}
        >
          {t.label}
        </button>
      {/each}
    </nav>
    <button class="ghost" onclick={onlock}>Blocca</button>
  </header>

  {#if tab === "codes"}
    {#if list.length === 0}
      <p class="hint">Nessun account. Aggiungine uno dalla scheda «Aggiungi».</p>
    {:else}
      <ul class="accounts">
        {#each list as account (account.id)}
          <AccountCard {session} {account} {now} onhotp={hotp} onremove={remove} />
        {/each}
      </ul>
    {/if}
  {:else if tab === "add"}
    <div class="panels">
      <ScanQr {session} onchange={changed} />
      <AddAccount onadd={add} />
      <ImportPanel {session} onchange={changed} />
    </div>
  {:else}
    <div class="panels">
      <SecuritySettings {session} {verify} onchange={changed} />
      <BackupPanel {session} onchange={changed} />
    </div>
  {/if}
</section>
