<script lang="ts">
  import { onDestroy } from "svelte";
  import AccountCard from "./AccountCard.svelte";
  import AddAccount from "./AddAccount.svelte";
  import BackupPanel from "./BackupPanel.svelte";
  import ImportPanel from "./ImportPanel.svelte";
  import ScanQr from "./ScanQr.svelte";
  import SecuritySettings from "./SecuritySettings.svelte";
  import { core, type AccountView, type TotpView } from "../lib/core";
  import { nowSeconds } from "../lib/format";
  import { matches } from "../lib/search";

  interface Props {
    onchange: () => Promise<void>;
    onlock: () => void;
    verify: (password: string) => Promise<boolean>;
    passkeys: readonly string[];
  }
  const { onchange, onlock, verify, passkeys }: Props = $props();

  const TABS = [
    { id: "codes", label: "Codici" },
    { id: "add", label: "Aggiungi" },
    { id: "settings", label: "Impostazioni" },
  ] as const;
  let tab = $state<(typeof TABS)[number]["id"]>("codes");

  let list = $state<AccountView[]>([]);
  let codes = $state<Record<string, TotpView>>({});
  let query = $state("");
  const visible = $derived(list.filter((account) => matches(account, query)));

  async function refresh() {
    list = await core.accounts();
    codes = await core.codes(nowSeconds());
  }
  void refresh();

  const tick = setInterval(() => {
    void core.codes(nowSeconds()).then((next) => (codes = next));
  }, 1000);
  onDestroy(() => {
    clearInterval(tick);
  });

  async function changed() {
    await refresh();
    await onchange();
  }

  async function add(uri: string) {
    await core.addUri(uri, nowSeconds());
    await changed();
    tab = "codes";
  }

  async function hotp(id: string): Promise<string> {
    const code = await core.nextHotp(id);
    await changed();
    return code;
  }

  async function remove(account: AccountView) {
    const label = account.issuer ? `${account.issuer} (${account.name})` : account.name;
    if (confirm(`Rimuovere ${label}? Senza un backup non potrai più generare i suoi codici.`)) {
      await core.remove(account.id);
      await changed();
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
      <input
        class="search"
        type="search"
        placeholder="Cerca"
        aria-label="Cerca account"
        autocomplete="off"
        spellcheck="false"
        bind:value={query}
      />
      {#if visible.length === 0}
        <p class="hint" role="status">Nessun account corrisponde a «{query}».</p>
      {/if}
      <ul class="accounts">
        {#each visible as account (account.id)}
          <AccountCard
            {account}
            current={codes[account.id] ?? null}
            onhotp={hotp}
            onremove={remove}
          />
        {/each}
      </ul>
    {/if}
  {:else if tab === "add"}
    <div class="panels">
      <ScanQr onchange={changed} />
      <AddAccount onadd={add} />
      <ImportPanel onchange={changed} />
    </div>
  {:else}
    <div class="panels">
      <SecuritySettings {verify} onchange={changed} {passkeys} />
      <BackupPanel onchange={changed} />
    </div>
  {/if}
</section>
