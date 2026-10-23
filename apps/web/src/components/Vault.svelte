<script lang="ts">
  import { onDestroy } from "svelte";
  import AccountCard from "./AccountCard.svelte";
  import AddAccount from "./AddAccount.svelte";
  import { accounts, type AccountView, type Session } from "../lib/core";
  import { nowSeconds } from "../lib/format";

  interface Props {
    session: Session;
    onchange: () => Promise<void>;
    onlock: () => void;
  }
  const { session, onchange, onlock }: Props = $props();

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
    <h2>I tuoi account</h2>
    <button class="ghost" onclick={onlock}>Blocca</button>
  </header>

  {#if list.length === 0}
    <p class="hint">
      Nessun account. Aggiungine uno incollando il suo URI <code>otpauth://</code>.
    </p>
  {:else}
    <ul class="accounts">
      {#each list as account (account.id)}
        <AccountCard {session} {account} {now} onhotp={hotp} onremove={remove} />
      {/each}
    </ul>
  {/if}

  <AddAccount onadd={add} />
</section>
