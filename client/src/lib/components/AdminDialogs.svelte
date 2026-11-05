<script lang="ts">
  import { adminOps, community, moderation, moves } from "../relay-rules.js";
  import { removalHint, removalReachesAccount, removalWindows } from "../modlog-rules.js";
  import { backdrop, dialog } from "../actions/dialog.js";
  import { roving } from "../actions/roving.js";
  // Admin token login, and the server admin panel: bans, emotes, and on a
  // relay with accounts (1.7) its users and groups.
  //
  // Mounted once by App.svelte. Each layout has its way in (the modern one's
  // server menu, for one), and all of them open these.
  //
  // The panel's look is Settings': a title with its close button, the tabs,
  // and only the body below them scrolls. Its pieces (sections, fields, rows,
  // check lists) are styled here for the tabs' own components as well, so the
  // three read as one panel. `admin-ok`, `admin-cancel`, `admin-input` and the
  // `ban-*` classes are what test-ui.mjs finds them by.

  import {
    adminError,
    adminOp,
    adminToken,
    clearShown,
    banAccount,
    bans,
    banSearch,
    banTotal,
    expiry,
    moreBans,
    searchBans,
    showAdminLogin,
    showAdminPanel,
    stepUp,
    stepUpSays,
    submitAdminLogin,
    submitStepUp,
    unban,
  } from "../stores/admin-ui.js";
  import { account, relayAccounts } from "../stores/account.js";
  import { can } from "../stores/powers.js";
  import { emoteLimits, pendingImport } from "../stores/emotes.js";
  import { olderRelay } from "../stores/relay.js";
  import { serverAddress } from "../stores/connection.js";
  import EmoteManager from "./EmoteManager.svelte";
  import AdminUsers from "./AdminUsers.svelte";
  import AdminGroups from "./AdminGroups.svelte";
  import AdminServer from "./AdminServer.svelte";
  import AdminChannels from "./AdminChannels.svelte";
  import AdminModLog from "./AdminModLog.svelte";
  import AdminMove from "./AdminMove.svelte";
  import Icon from "./Icons.svelte";
  import type { BanInfo } from "../types.js";

  type Tab = "bans" | "emotes" | "users" | "groups" | "channels" | "modlog" | "server" | "move";
  let tab = $state<Tab>("bans");
  // A chat picture's "Make an emote or sticker…": straight to the importer
  $effect(() => {
    if ($pendingImport) tab = "emotes";
  });
  /** The tabs this account's privileges open; users and groups need a relay
   *  with accounts of 1.7 or later. */
  const tabs = $derived.by(() => {
    const groups = !!$relayAccounts && adminOps($olderRelay?.protocol ?? null);
    const t: [Tab, string][] = [];
    if ($can("voipc:bans")) t.push(["bans", "Bans"]);
    if ($emoteLimits && $can("voipc:emotes")) t.push(["emotes", "Emotes and stickers"]);
    if (groups && $can("users:read")) t.push(["users", "Users"]);
    if (groups && ($can("roles:admin") || $can("users:read"))) t.push(["groups", "Groups"]);
    if ($relayAccounts && community($olderRelay?.protocol ?? null) && $can("voipc:channels")) t.push(["channels", "Channels"]);
    if ($relayAccounts && moderation($olderRelay?.protocol ?? null) && $can("voipc:modlog")) t.push(["modlog", "Moderation log"]);
    if ($relayAccounts && community($olderRelay?.protocol ?? null) && $can("*")) t.push(["server", "Server"]);
    // Asked as the account: a token admin has none to ask as
    if ($relayAccounts && $account && moves($olderRelay?.protocol ?? null) && $can("*")) t.push(["move", "Discord move"]);
    return t;
  });
  /** What was picked, or the first tab still open to us. */
  const shown = $derived(tabs.some(([t]) => t === tab) ? tab : (tabs[0]?.[0] ?? "bans"));
  let stepCode = $state("");
  let emoteManager = $state<{ mayClose: () => Promise<boolean> } | null>(null);
  /** Leave the emotes tab, after it asked about an import not added yet. */
  async function leaveEmotes(then: () => void) {
    if (shown !== "emotes" || !emoteManager || (await emoteManager.mayClose())) then();
  }
  const closePanel = () => leaveEmotes(() => showAdminPanel.set(false));
  let body = $state<HTMLDivElement | undefined>(undefined);
  // The code is asked for at the top: a Save at the bottom of a long form
  // must not leave the question out of sight
  $effect(() => {
    if ($stepUp) body?.scrollTo({ top: 0, behavior: "smooth" });
  });
  function pick(t: Tab) {
    void leaveEmotes(() => {
      tab = t;
      body?.scrollTo({ top: 0 });
    });
  }
  let accountBans = $derived($bans.filter((b) => b.account));
  let addressBans = $derived($bans.filter((b) => !b.account));
  // The box holds what is typed until it is asked for, and follows what the list is of
  let banQuery = $state("");
  $effect(() => {
    banQuery = $banSearch;
  });
  // Banning an account that is not here (admins only, as the list is)
  let banName = $state("");
  let banReason = $state("");
  let banDays = $state(0);
  let banRemoval = $state<number | null>(null);
  // Asked of the account: a token admin has none to ask as
  const mayRemove = $derived(!!$account && !!$relayAccounts && moderation($olderRelay?.protocol ?? null));

  async function submitBan() {
    if (!banName.trim()) return;
    await banAccount(banName, banReason, banDays * 86_400, mayRemove ? banRemoval : null);
    banName = "";
    banReason = "";
    banRemoval = null;
  }

  // Removing the posts of someone on the list, who may have been banned a while ago
  let removing = $state<BanInfo | null>(null);
  let removingWindow = $state(86_400);
  function submitRemoval() {
    if (removing) void adminOp({ RemovePosts: { name: removing.label, window_secs: removingWindow } });
    removing = null;
  }
</script>

{#snippet banRow(ban: BanInfo)}
  <li class="list-item">
    <div class="ban-what">
      <span class="ban-label row-name">{ban.label}</span>
      <span class="ban-reason row-meta">{ban.reason ? `${ban.reason} · ` : ""}by {ban.by} · {expiry(ban)}</span>
    </div>
    {#if mayRemove}
      <button type="button" class="btn btn-secondary ban-remove" onclick={() => { removing = ban; removingWindow = 86_400; }}>Remove posts</button>
    {/if}
    <button type="button" class="btn btn-secondary admin-cancel" onclick={() => unban(ban.id)}>Unban</button>
  </li>
{/snippet}

{#if $showAdminLogin}
  <div class="admin-overlay" role="presentation" onclick={backdrop(() => showAdminLogin.set(false))}>
    <form
      class="admin-dialog login"
      onsubmit={(e) => { e.preventDefault(); submitAdminLogin(); }}
      aria-label="Admin login"
      use:dialog={{ onclose: () => showAdminLogin.set(false) }}
    >
      <h2 class="admin-heading">Admin login</h2>
      <p class="admin-hint">The admin token is in the server's config (<code>admin_token</code>) or, if none is set, in the server log at startup.</p>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="admin-input" type="password" placeholder="Admin token" aria-label="Admin token" bind:value={$adminToken} autofocus />
      <div class="form-actions">
        <button type="button" class="btn btn-secondary admin-cancel" onclick={() => showAdminLogin.set(false)}>Cancel</button>
        <button type="submit" class="btn btn-primary admin-ok" disabled={!$adminToken.trim()}>Log in</button>
      </div>
    </form>
  </div>
{/if}

{#if $showAdminPanel}
  <div class="admin-overlay" role="presentation" onclick={backdrop(closePanel)}>
    <div
      class="admin-dialog panel"
      aria-label={`Server admin: ${tabs.find(([t]) => t === shown)?.[1] ?? "bans"}`}
      use:dialog={{ onclose: closePanel }}
    >
      <div class="panel-head">
        <h2 class="admin-heading">Server admin</h2>
        <button type="button" class="icon-btn admin-close" title="Close" aria-label="Close server admin" onclick={closePanel}>
          <Icon name="close" size={18} />
        </button>
      </div>
      {#if tabs.length > 1}
        <div class="admin-tabs" role="tablist" aria-label="Server admin" use:roving>
          {#each tabs as [t, name] (t)}
            <button type="button" role="tab" aria-selected={shown === t} class:active={shown === t} onclick={() => pick(t)}>{name}</button>
          {/each}
        </div>
      {/if}
      <div class="panel-body" bind:this={body}>
        {#if $stepUp}
          <form class="callout" onsubmit={(e) => { e.preventDefault(); submitStepUp(stepCode); stepCode = ""; }}>
            <div class="section-title">Confirm with a code</div>
            <p class="admin-hint">{stepUpSays($stepUp)} Enter a code from your authenticator app; it holds for ten minutes.</p>
            <div class="inline-form">
              <!-- svelte-ignore a11y_autofocus -->
              <input class="admin-input code-input" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" aria-label="Two-factor code" bind:value={stepCode} autofocus />
              <button type="button" class="btn btn-secondary admin-cancel" onclick={() => { clearShown(stepUp); adminError.of($serverAddress).set("Not done: that takes a code."); stepCode = ""; }}>Cancel</button>
              <button type="submit" class="btn btn-primary admin-ok" disabled={!stepCode.trim()}>Confirm</button>
            </div>
          </form>
        {/if}
        {#if $adminError}
          <div class="admin-error" role="alert">{$adminError}</div>
        {/if}
        {#if shown === "emotes"}
          <EmoteManager bind:this={emoteManager} />
        {:else if shown === "users"}
          <AdminUsers />
        {:else if shown === "groups"}
          <AdminGroups />
        {:else if shown === "channels"}
          <AdminChannels />
        {:else if shown === "modlog"}
          <AdminModLog />
        {:else if shown === "server"}
          <AdminServer />
        {:else if shown === "move"}
          <AdminMove />
        {:else}
          {#if $relayAccounts}
            <section class="section">
              <div class="section-title">Ban an account</div>
              <form class="ban-add inline-form" onsubmit={(e) => { e.preventDefault(); submitBan(); }}>
                <input class="admin-input grow" placeholder="Account name" aria-label="Account to ban" bind:value={banName} />
                <input class="admin-input grow" placeholder="Reason (optional)" aria-label="Reason" bind:value={banReason} maxlength="200" />
                <select class="admin-select" aria-label="How long" bind:value={banDays}>
                  <option value={0}>Permanent</option>
                  <option value={1}>1 day</option>
                  <option value={7}>7 days</option>
                  <option value={30}>30 days</option>
                </select>
                {#if mayRemove}
                  <select class="admin-select ban-add-removal" aria-label="Also remove their posts" bind:value={banRemoval}>
                    <option value={null}>Keep their posts</option>
                    {#each removalWindows($can("*")) as [secs, label] (secs)}
                      <option value={secs}>Remove posts: {label.toLowerCase()}</option>
                    {/each}
                  </select>
                {/if}
                <button type="submit" class="btn btn-danger admin-ok" disabled={!banName.trim()}>Ban account</button>
              </form>
              {#if mayRemove && banRemoval !== null}
                <p class="admin-hint">{removalHint(true, moves($olderRelay?.protocol ?? null))}</p>
              {/if}
            </section>
          {/if}
          <section class="section">
            <div class="section-title">Active bans</div>
            {#if removing}
              <form class="callout ban-removal" onsubmit={(e) => { e.preventDefault(); submitRemoval(); }}>
                <div class="section-title">Remove the posts of {removing.label}</div>
                <p class="admin-hint">{removalHint(removalReachesAccount(removing, $bans), moves($olderRelay?.protocol ?? null))}</p>
                <div class="inline-form">
                  <select class="admin-select" aria-label="How far back" bind:value={removingWindow}>
                    {#each removalWindows($can("*")) as [secs, label] (secs)}
                      <option value={secs}>{label}</option>
                    {/each}
                  </select>
                  <button type="button" class="btn btn-secondary admin-cancel" onclick={() => (removing = null)}>Cancel</button>
                  <button type="submit" class="btn btn-danger admin-ok">Remove posts</button>
                </div>
              </form>
            {/if}
            {#if moves($olderRelay?.protocol ?? null) && ($banTotal > 0 || $banSearch)}
              <form class="inline-form ban-search" role="search" onsubmit={(e) => { e.preventDefault(); searchBans(banQuery.trim()); }}>
                <input class="admin-input grow" type="search" placeholder="Search by name" aria-label="Search bans" maxlength="64" bind:value={banQuery} />
                <button type="submit" class="btn btn-secondary"><Icon name="search" size={16} /> Search</button>
              </form>
            {/if}
            {#if $bans.length === 0}
              {#if $banSearch}
                <p class="admin-hint empty">No active ban matches “{$banSearch}”.</p>
              {:else}
                <p class="admin-hint empty">No active bans. Right-click someone in the member list to kick or ban them.</p>
              {/if}
            {:else}
              {#if accountBans.length}
                <div class="sub-title">Accounts</div>
                <ul class="ban-list list">
                  {#each accountBans as ban (ban.id)}{@render banRow(ban)}{/each}
                </ul>
              {/if}
              {#if addressBans.length}
                <div class="sub-title">Addresses <span class="admin-hint">by the name used from there</span></div>
                <ul class="ban-list list">
                  {#each addressBans as ban (ban.id)}{@render banRow(ban)}{/each}
                </ul>
              {/if}
              {#if $bans.length < $banTotal}
                <button type="button" class="btn btn-secondary ban-more" onclick={moreBans}>Show more ({$banTotal - $bans.length} left)</button>
              {/if}
            {/if}
          </section>
        {/if}
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
    border-radius: var(--r-lg, 8px);
    box-shadow: var(--shadow-dialog);
    width: min(420px, 92vw);
    display: flex;
    flex-direction: column;
    font-size: var(--fs-body);
    color: var(--text-primary);
    /* The window can be 640×480: the dialog fits, its body scrolls */
    max-height: calc(100dvh - 32px);
  }

  .admin-dialog.login {
    padding: var(--sp-5, 20px);
    gap: var(--sp-3, 12px);
  }

  /* One size for every tab, so switching does not make it jump */
  .admin-dialog.panel {
    width: min(640px, 92vw);
    height: min(660px, calc(100dvh - 32px));
  }

  .admin-heading {
    margin: 0;
    font-size: var(--fs-lg);
    font-weight: 700;
    color: var(--text-primary);
  }

  .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--sp-4, 16px) var(--sp-5, 20px) var(--sp-2, 8px);
    flex-shrink: 0;
  }

  .admin-tabs {
    display: flex;
    flex-wrap: wrap;
    padding: 0 var(--sp-5, 20px);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .admin-tabs button {
    min-height: var(--hit);
    padding: 8px 12px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    /* The underline is the tab's: square, not the buttons' 6px */
    border-radius: 0;
    color: var(--text-secondary);
    font-size: var(--fs-body);
    white-space: nowrap;
    transition: color var(--dur-fast), border-color var(--dur-fast);
  }

  .admin-tabs button:hover {
    color: var(--text-primary);
  }

  .admin-tabs button.active {
    color: var(--text-primary);
    border-bottom-color: var(--text-primary);
  }

  .admin-tabs button:focus-visible {
    outline-offset: -2px;
  }

  .panel-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: var(--sp-4, 16px) var(--sp-5, 20px) var(--sp-5, 20px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-4, 16px);
  }

  .callout {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2, 8px);
    padding: var(--sp-3, 12px);
    border: 1px solid var(--border);
    border-radius: var(--r-md, 6px);
    background: var(--bg-tertiary);
  }

  .admin-dialog .callout :global(.code-input) {
    width: 12ch;
    flex: 0 0 auto;
    font-variant-numeric: tabular-nums;
    letter-spacing: 0.1em;
  }

  .admin-error {
    color: var(--danger);
    font-size: var(--fs-sm);
  }

  .admin-hint.empty {
    margin: 0;
  }

  /* ── Shared by the tabs (AdminUsers, AdminGroups) ─────────────────────── */

  .admin-dialog :global(.form-actions) {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: var(--sp-2, 8px);
  }

  /* A destroying action keeps to the left, away from Save */
  .admin-dialog :global(.form-actions .push-left) {
    margin-right: auto;
  }

  .admin-dialog :global(.section) {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2, 8px);
    margin: 0;
  }

  .admin-dialog :global(.section-head) {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-3, 12px);
  }

  .admin-dialog :global(.section-title) {
    font-size: var(--fs-md, 14px);
    font-weight: 600;
    color: var(--text-primary);
  }

  .admin-dialog :global(.sub-title) {
    font-size: var(--fs-sm);
    font-weight: 600;
    color: var(--text-secondary);
    margin-top: var(--sp-1, 4px);
  }

  .admin-dialog :global(.admin-hint) {
    margin: 0;
    font-size: var(--fs-sm);
    font-weight: 400;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .admin-dialog :global(.admin-input) {
    width: 100%;
    box-sizing: border-box;
    min-height: var(--hit);
  }

  /* Colour only: app.css draws the chevron as the background image */
  .admin-dialog :global(.admin-select) {
    min-height: var(--hit);
    background-color: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm, 4px);
  }

  .admin-dialog :global(.inline-form) {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--sp-2, 8px);
  }

  .admin-dialog :global(.inline-form .grow) {
    flex: 1 1 160px;
    width: auto;
  }

  /* A labelled field: its name above it, its hint below */
  .admin-dialog :global(.field) {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--fs-sm);
    font-weight: 600;
    color: var(--text-secondary);
  }

  /* Lists: rows on the panel's surface, a hairline between them */
  .admin-dialog :global(.list) {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: var(--r-md, 6px);
    overflow: hidden;
  }

  .admin-dialog :global(.list > li + li) {
    border-top: 1px solid var(--border);
  }

  .admin-dialog :global(.list-item) {
    display: flex;
    align-items: center;
    gap: var(--sp-3, 12px);
    padding: 6px var(--sp-3, 12px);
    min-height: var(--hit);
  }

  .admin-dialog :global(.list-row) {
    display: flex;
    align-items: center;
    gap: var(--sp-3, 12px);
    width: 100%;
    min-height: var(--hit);
    padding: 6px var(--sp-3, 12px);
    background: transparent;
    border: none;
    border-radius: 0;
    color: var(--text-primary);
    text-align: left;
  }

  .admin-dialog :global(.list-row:hover) {
    background: var(--bg-hover);
  }

  .admin-dialog :global(.list-row:focus-visible) {
    outline-offset: -2px;
  }

  .admin-dialog :global(.ban-what),
  .admin-dialog :global(.row-text) {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }

  .admin-dialog :global(.row-name) {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .admin-dialog :global(.row-meta) {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .admin-dialog :global(.row-chevron) {
    display: inline-flex;
    color: var(--text-secondary);
    transform: rotate(-90deg);
    flex-shrink: 0;
  }

  /* Ticks: the box beside the first line, a hint under the name */
  .admin-dialog :global(.check-list) {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: var(--sp-1, 4px) var(--sp-4, 16px);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .admin-dialog :global(.check-row) {
    display: grid;
    grid-template-columns: auto 1fr;
    align-items: start;
    column-gap: var(--sp-2, 8px);
    padding: 6px 0;
    min-height: var(--hit);
    box-sizing: border-box;
    cursor: pointer;
    font-weight: 400;
    color: var(--text-primary);
  }

  .admin-dialog :global(.check-row input) {
    width: 16px;
    height: 16px;
    margin: 1px 0 0;
  }

  .admin-dialog :global(.check-row.disabled) {
    cursor: default;
  }

  .admin-dialog :global(.check-text) {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .admin-dialog :global(.check-hint) {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    line-height: 1.35;
  }

  /* A group's badge, as the member list draws it */
  .admin-dialog :global(.pill) {
    display: inline-block;
    margin-left: 6px;
    padding: 0 6px;
    border-radius: var(--r-pill);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--fs-micro);
    font-weight: 500;
    line-height: 1.6;
    vertical-align: middle;
  }

  .admin-dialog :global(.btn-back) {
    align-self: flex-start;
    padding-left: 8px;
  }

  /* Wrapped onto a row of its own, the submit keeps to the right edge */
  .ban-add .admin-ok {
    flex: 0 0 auto;
    margin-left: auto;
  }
</style>
