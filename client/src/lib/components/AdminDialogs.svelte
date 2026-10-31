<script lang="ts">
  import { backdrop, dialog } from "../actions/dialog.js";
  // Admin token login, and the list of active bans.
  //
  // Mounted once by App.svelte. Both layouts have a shield button somewhere —
  // the classic status bar, the modern layout's voice panel — and both open these.

  import {
    adminToken,
    banAccount,
    bans,
    expiry,
    showAdminLogin,
    showAdminPanel,
    submitAdminLogin,
    unban,
  } from "../stores/admin-ui.js";
  import { relayAccounts } from "../stores/account.js";
  import { emoteLimits, pendingImport } from "../stores/emotes.js";
  import EmoteManager from "./EmoteManager.svelte";
  import type { BanInfo } from "../types.js";

  let tab = $state<"bans" | "emotes">("bans");
  // A chat picture's "Make an emote or sticker…": straight to the importer
  $effect(() => {
    if ($pendingImport) tab = "emotes";
  });
  /** A server without emotes has the bans only, whatever was picked before. */
  const shown = $derived($emoteLimits ? tab : "bans");
  let emoteManager = $state<{ mayClose: () => Promise<boolean> } | null>(null);
  /** Leave the emotes tab, after it asked about an import not added yet. */
  async function leaveEmotes(then: () => void) {
    if (shown !== "emotes" || !emoteManager || (await emoteManager.mayClose())) then();
  }
  const closePanel = () => leaveEmotes(() => showAdminPanel.set(false));
  let accountBans = $derived($bans.filter((b) => b.account));
  let addressBans = $derived($bans.filter((b) => !b.account));
  // Banning an account that is not here (admins only, as the list is)
  let banName = $state("");
  let banReason = $state("");
  let banDays = $state(0);

  async function submitBan() {
    if (!banName.trim()) return;
    await banAccount(banName, banReason, banDays * 86_400);
    banName = "";
    banReason = "";
  }
</script>

{#snippet banRow(ban: BanInfo)}
  <li>
    <div class="ban-what">
      <span class="ban-label">{ban.label}</span>
      <span class="ban-reason">{ban.reason} · by {ban.by}</span>
    </div>
    <span class="ban-expiry">{expiry(ban)}</span>
    <button class="admin-cancel" onclick={() => unban(ban.id)}>Unban</button>
  </li>
{/snippet}

{#if $showAdminLogin}
  <div class="admin-overlay" role="presentation" onclick={backdrop(() => showAdminLogin.set(false))}>
    <form
      class="admin-dialog"
      onsubmit={(e) => { e.preventDefault(); submitAdminLogin(); }}
      aria-label="Admin login"
      use:dialog={{ onclose: () => showAdminLogin.set(false) }}
    >
      <div class="admin-title">Admin login</div>
      <div class="admin-hint">The admin token is in the server's config (<code>admin_token</code>) or, if none is set, in the server log at startup.</div>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="admin-input" type="password" placeholder="Admin token" bind:value={$adminToken} autofocus />
      <div class="admin-actions">
        <button type="button" class="admin-cancel" onclick={() => showAdminLogin.set(false)}>Cancel</button>
        <button type="submit" class="admin-ok" disabled={!$adminToken.trim()}>Log in</button>
      </div>
    </form>
  </div>
{/if}

{#if $showAdminPanel}
  <div class="admin-overlay" role="presentation" onclick={backdrop(closePanel)}>
    <div
      class="admin-dialog"
      class:wide={shown === "emotes"}
      aria-label={shown === "emotes" ? "Server admin: emotes and stickers" : "Server admin: bans"}
      use:dialog={{ onclose: closePanel }}
    >
      {#if $emoteLimits}
        <div class="admin-tabs" role="tablist" aria-label="Admin">
          <button type="button" role="tab" aria-selected={shown === "bans"} class:active={shown === "bans"} onclick={() => leaveEmotes(() => (tab = "bans"))}>Bans</button>
          <button type="button" role="tab" aria-selected={shown === "emotes"} class:active={shown === "emotes"} onclick={() => (tab = "emotes")}>Emotes and stickers</button>
        </div>
      {/if}
      {#if shown === "emotes"}
        <EmoteManager bind:this={emoteManager} />
      {:else}
      <div class="admin-title">Active bans</div>
      {#if $relayAccounts}
        <form class="ban-add" onsubmit={(e) => { e.preventDefault(); submitBan(); }}>
          <input class="admin-input" placeholder="Account name" aria-label="Account to ban" bind:value={banName} />
          <input class="admin-input" placeholder="Reason" aria-label="Reason" bind:value={banReason} maxlength="200" />
          <select aria-label="How long" bind:value={banDays}>
            <option value={0}>Permanent</option>
            <option value={1}>1 day</option>
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
          </select>
          <button type="submit" class="admin-ok" disabled={!banName.trim()}>Ban account</button>
        </form>
      {/if}
      {#if $bans.length === 0}
        <div class="admin-hint">No active bans. Right-click a user to kick or ban.</div>
      {:else}
        {#if accountBans.length}
          <div class="ban-heading">Accounts</div>
          <ul class="ban-list">
            {#each accountBans as ban (ban.id)}{@render banRow(ban)}{/each}
          </ul>
        {/if}
        {#if addressBans.length}
          <div class="ban-heading">Addresses <span class="admin-hint">(by the name used from there)</span></div>
          <ul class="ban-list">
            {#each addressBans as ban (ban.id)}{@render banRow(ban)}{/each}
          </ul>
        {/if}
      {/if}
      {/if}
      <div class="admin-actions">
        <button type="button" class="admin-cancel" onclick={closePanel}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .admin-overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-dialog-over);
  }

  .admin-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    width: min(380px, 92vw);
    display: flex;
    flex-direction: column;
    gap: 10px;
    font-size: var(--fs-body);
    color: var(--text-primary);
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
  }

  .admin-dialog.wide {
    width: min(640px, 92vw);
  }

  .admin-tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
  }

  .admin-tabs button {
    min-height: var(--hit);
    padding: 6px 12px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
  }

  .admin-tabs button.active {
    color: var(--text-primary);
    border-bottom-color: var(--text-primary);
  }

  .admin-title {
    font-weight: 600;
    color: var(--text-primary);
  }

  .admin-hint {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .admin-input {
    width: 100%;
    box-sizing: border-box;
  }

  .admin-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  .admin-cancel,
  .admin-ok {
    min-height: var(--hit);
  }

  .admin-cancel {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 10px;
    font-size: var(--fs-sm);
  }

  .admin-ok {
    padding: 4px 12px;
    font-size: var(--fs-sm);
  }

  .ban-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 40vh;
    overflow-y: auto;
  }

  .ban-list li {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .ban-heading {
    font-weight: 600;
    font-size: var(--fs-sm);
  }

  .ban-add {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .ban-add .admin-input {
    flex: 1 1 140px;
  }

  .ban-what {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .ban-label {
    font-weight: 600;
  }

  .ban-reason {
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ban-expiry {
    margin-left: auto;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }
</style>
