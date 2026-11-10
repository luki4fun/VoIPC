<script lang="ts">
  // The admin panel's Users tab (1.7): the relay's accounts, one account's
  // groups and history, and sign-up invites. Each step is an
  // `AccountRequest::Admin`; the relay checks the privilege behind it.
  // Its look (sections, fields, lists, check lists) is AdminDialogs.svelte's.

  import { noPowerOverAnyone } from "../scopes.js";
  import { onMount, untrack } from "svelte";
  import {
    adminGroups,
    adminInvites,
    adminInviteLinks,
    inviteLinkCode,
    adminOp,
    adminRead,
    adminUser,
    adminUsers,
    banAccount,
    clearShown,
    inviteCode,
  } from "../stores/admin-ui.js";
  import { account, relayAccounts } from "../stores/account.js";
  import { profiles } from "../stores/profiles.js";
  import { clearProfile } from "../stores/user-menu.js";
  import { can } from "../stores/powers.js";
  import { confirmAction } from "../stores/confirm.js";
  import { olderRelay } from "../stores/relay.js";
  import { serverAddress } from "../stores/scoped.js";
  import { community, moves } from "../relay-rules.js";
  import { canLiftBan, expiryText, moveAccountKey, moveAccounts as cleanAccounts, moveChip, moveFiltersFor, ownPage } from "../move-rules.js";
  import { excludeOne, importerAsking, moveAccountsPage, moveWizard } from "../stores/move.js";
  import { buildJoinLink, splitAddress } from "../invite.js";
  import { addNotification } from "../stores/notifications.js";
  import { toHex } from "../hex.js";
  import Icon from "./Icons.svelte";
  import MemberName from "./MemberName.svelte";
  import type { AdminUser, MoveAccount, MoveFilter } from "../types.js";

  const PAGE = 50;
  let search = $state("");
  let filter = $state<MoveFilter>("All");
  let inviteFor = $state("");
  let inviteDays = $state(7);

  const day = (secs: number) => new Date(secs * 1000).toLocaleDateString();
  const when = (secs: number) => new Date(secs * 1000).toLocaleString();
  /** What a history line says, in words. */
  const EVENTS: Record<string, string> = {
    register: "Account made",
    role_grant: "Given group",
    role_revoke: "Group taken away",
    totp_on: "Two-factor codes on",
    totp_off: "Two-factor codes off",
    totp_reset: "Two-factor codes reset",
    password_change: "Password changed",
    recovery_new: "New recovery key",
    devkey_add: "Device remembered",
    devkey_revoke: "Device forgotten",
    invite_create: "Invite made",
    invite_revoke: "Invite revoked",
    disable: "Suspended",
    enable: "Unsuspended",
    account_delete: "Account deleted",
    rename: "Name changed",
    profile_reset: "Display name or picture cleared",
  };

  /** With what the move knows of each account; on an older relay, and while the importer
   *  asks for the same list of its own, the plain one. */
  const paged = $derived(moves($olderRelay?.protocol ?? null) && !importerAsking($moveWizard.step));

  const own = ownPage<{ search: string; offset: number; filter: MoveFilter }>();

  function list(offset = 0) {
    const ask = { search: search.trim(), offset, filter };
    own.asking(paged ? ask : null);
    void adminOp(paged ? { MoveAccounts: ask } : { Users: { search: ask.search, offset } });
  }

  /** What is listed, whichever way it was asked for. */
  const page = $derived.by<{ search: string; offset: number; total: number; rows: MoveAccount[] } | null>(() => {
    if (paged) return $moveAccountsPage?.filter === filter ? $moveAccountsPage : null;
    const u = $adminUsers;
    if (!u) return null;
    return {
      ...u,
      rows: cleanAccounts(u.users.map((user) => ({ user, state: "NotImported" as const, dc_id: "", expires_at: 0 }))),
    };
  });

  // On mount, and when a run begins or ends: what was asked for before is not what `page` reads now
  $effect(() => {
    void paged;
    untrack(() => list());
  });

  // The dashboard's refresh answers in the same store, with its own filter: a ban lifted, a run
  // or an undo ended. A read, so a code being asked for and a refusal shown stay as they are
  $effect(() => {
    const again = $moveAccountsPage && own.page($moveAccountsPage.filter);
    if (again) adminRead({ MoveAccounts: again });
  });

  async function liftBan(r: MoveAccount) {
    const ok = await confirmAction({
      title: `Lift the ban on ${r.user.name}?`,
      body: "That Discord id is no longer shut out: they can come in the way anyone new can, and what they wrote stays. No later import bans them again or makes them an account, until you let them back in under Discord move, Left out.",
      confirm: "Lift ban",
    });
    if (!ok) return;
    excludeOne($serverAddress, r.dc_id, true, false);
  }

  onMount(() => {
    if (!$adminGroups) void adminOp("Groups");
    if ($can("users:admin")) void adminOp("Invites");
  });

  function open(u: AdminUser) {
    void adminOp({ User: { id: u.id } });
  }

  function toggle(group: string, on: boolean) {
    const d = $adminUser;
    if (!d) return;
    void adminOp(on ? { Grant: { id: d.user.id, group } } : { Revoke: { id: d.user.id, group } });
  }

  async function reset2fa() {
    const d = $adminUser;
    if (!d) return;
    const ok = await confirmAction({
      title: `Reset ${d.user.name}'s two-factor codes?`,
      body: "Their codes, recovery codes and remembered devices go, and they are signed out. They sign in with their password next, and set up codes again.",
      confirm: "Reset codes",
      danger: true,
    });
    if (ok) void adminOp({ Reset2fa: { id: d.user.id } });
  }

  async function ban() {
    const d = $adminUser;
    if (!d) return;
    const ok = await confirmAction({
      title: `Ban ${d.user.name}?`,
      body: "The account is signed out and cannot sign in again until the ban is lifted on the Bans tab.",
      confirm: "Ban for good",
      danger: true,
    });
    if (ok) await banAccount(d.user.name, "", 0);
  }

  // The menu's own conditions, less the live row, plus something to clear: someone who has
  // gone has no row to open that menu on. The relay refuses who holds more, as it does a Grant here
  const shownProfile = $derived($adminUser ? $profiles.get(toHex($adminUser.user.id)) : undefined);
  const mayClear = $derived(
    $can("voipc:profiles") && !!$account && community($olderRelay?.protocol ?? null) && !!(shownProfile?.name || shownProfile?.picture),
  );

  async function clearName() {
    const d = $adminUser;
    if (!d) return;
    const server = $serverAddress;
    // Requests on a connection are answered in order: this read brings the new history line
    if (await clearProfile(d.user.id, server)) adminRead({ User: { id: d.user.id } }, server);
  }

  function newInvite() {
    void adminOp({ InviteNew: { name: inviteFor.trim() || null, days: inviteDays } });
    inviteFor = "";
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      addNotification("Invite code copied", "info");
    } catch {
      addNotification("Could not copy; select the code instead", "warning");
    }
  }

  // A new code also changes the list
  $effect(() => {
    if ($inviteCode) void adminOp("Invites");
  });

  /** Every group but `user`, which every account is in. */
  const groups = $derived(($adminGroups ?? []).filter((g) => g.name !== "user"));
  const closed = $derived($relayAccounts?.registration === "Closed");

  /** How a new link is made. Its group holds no power over anyone: the relay checks. */
  let linkUses = $state(1000);
  let linkDays = $state(30);
  let linkGroup = $state<string | null>(null);
  const showsLinks = $derived(community($olderRelay?.protocol ?? null) && !closed);
  const startGroups = $derived(groups.filter((g) => noPowerOverAnyone(g.scopes)));
  const linkShown = $derived.by(() => {
    const at = splitAddress($serverAddress);
    return $inviteLinkCode && at ? buildJoinLink(at.host, at.port, $inviteLinkCode) : null;
  });

  $effect(() => {
    if (showsLinks && $can("users:admin")) void adminOp("InviteLinks");
  });
  // A new code also changes the list
  $effect(() => {
    if ($inviteLinkCode) void adminOp("InviteLinks");
  });
</script>

{#if $adminUser}
  {@const d = $adminUser}
  <button type="button" class="btn btn-ghost btn-back" onclick={() => clearShown(adminUser)}>
    <Icon name="arrow-left" size={16} /> All accounts
  </button>
  <section class="section">
    <div class="section-title"><MemberName username={d.user.name} account={d.user.id} /></div>
    <p class="admin-hint">
      Account since {day(d.user.created_at)} · two-factor codes {d.user.totp ? "on" : "off"}
    </p>
  </section>
  <section class="section">
    <div class="section-title">Groups</div>
    <ul class="check-list">
      {#each groups as g (g.name)}
        <li>
          <label class="check-row" class:disabled={!$can("users:admin")}>
            <input
              type="checkbox"
              data-group={g.name}
              checked={d.groups.includes(g.name)}
              disabled={!$can("users:admin")}
              onchange={(e) => toggle(g.name, e.currentTarget.checked)}
            />
            <span class="check-text">
              <span>{g.name}{#if g.badge}<span class="pill">{g.badge}</span>{/if}</span>
              <span class="check-hint">
                {!g.scopes.length
                  ? "No privileges"
                  : noPowerOverAnyone(g.scopes)
                    ? "Can share history, if they turn it on"
                    : d.groups.includes(g.name) && !d.user.totp
                    ? "Its privileges wait for two-factor codes"
                    : "Hands out privileges"}
              </span>
            </span>
          </label>
        </li>
      {/each}
    </ul>
    <p class="admin-hint">Taking away a group with privileges signs the account out; a remembered device signs it in again.</p>
  </section>
  {#if $can("users:admin") || $can("voipc:bans") || mayClear}
    <div class="form-actions account-actions">
      {#if mayClear}
        <button type="button" class="btn btn-danger-outline clear-profile" onclick={clearName}>Clear display name and picture</button>
      {/if}
      {#if $can("users:admin")}
        <button type="button" class="btn btn-danger-outline" onclick={reset2fa}>Reset two-factor codes</button>
      {/if}
      {#if $can("voipc:bans")}
        <button type="button" class="btn btn-danger-outline" onclick={ban}>Ban account</button>
      {/if}
    </div>
  {/if}
  <section class="section">
    <div class="section-title">History</div>
    {#if d.audit.length === 0}
      <p class="admin-hint">Nothing yet.</p>
    {:else}
      <ul class="list history">
        {#each d.audit as e, i (i)}
          <li class="list-item">
            <span class="row-text">
              <span>{EVENTS[e.event] ?? e.event}{e.detail ? `: ${e.detail}` : ""}</span>
              <span class="row-meta">{when(e.at)}{e.actor ? ` · by ${e.actor}` : ""}</span>
            </span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{:else}
  <section class="section">
    <form class="inline-form" role="search" onsubmit={(e) => { e.preventDefault(); list(); }}>
      <input class="admin-input grow" type="search" placeholder="Search by name" aria-label="Search accounts" bind:value={search} />
      {#if paged}
        <select class="admin-select move-filter" aria-label="Which accounts" bind:value={filter} onchange={() => list()}>
          {#each moveFiltersFor($can("*")) as [value, label] (value)}
            <option {value}>{label}</option>
          {/each}
        </select>
      {/if}
      <button type="submit" class="btn btn-secondary">
        <Icon name="search" size={16} /> Search
      </button>
    </form>
    {#if page}
      {#if page.rows.length === 0}
        <p class="admin-hint">No accounts{page.search ? ` match “${page.search}”` : ""}.</p>
      {:else}
        <ul class="list">
          {#each page.rows as r (moveAccountKey(r))}
            {@const u = r.user}
            {@const chip = moveChip(r.state)}
            {@const liftable = canLiftBan(r)}
            <li class:liftable>
              <button type="button" class="list-row" onclick={() => open(u)}>
                <span class="row-text">
                  <span class="row-name">{u.name}{#if chip}<span class="pill move-chip" data-state={r.state}>{chip}</span>{/if}</span>
                  <span class="row-meta">
                    since {day(u.created_at)}{u.totp ? " · codes on" : ""}{r.state === "Waiting" ? ` · ${expiryText(r.expires_at)}` : ""}{r.dc_id ? ` · Discord ${r.dc_id}` : ""}
                  </span>
                </span>
                <span class="row-chevron"><Icon name="chevron-down" size={16} /></span>
              </button>
              {#if liftable}
                <button type="button" class="btn btn-secondary move-lift" onclick={() => liftBan(r)}>Lift ban</button>
              {/if}
            </li>
          {/each}
        </ul>
        <div class="form-actions">
          <span class="admin-hint push-left">
            {page.total <= PAGE
              ? `${page.total} account${page.total === 1 ? "" : "s"}`
              : `${page.offset + 1}–${page.offset + page.rows.length} of ${page.total} accounts`}
          </span>
          {#if page.total > PAGE}
            <button type="button" class="btn btn-secondary" disabled={page.offset === 0} onclick={() => list(Math.max(0, page.offset - PAGE))}>Newer</button>
            <button type="button" class="btn btn-secondary" disabled={page.offset + PAGE >= page.total} onclick={() => list(page.offset + PAGE)}>Older</button>
          {/if}
        </div>
      {/if}
    {:else}
      <p class="admin-hint">Loading…</p>
    {/if}
  </section>

  {#if $can("users:admin")}
    <section class="section">
      <div class="section-title">Invites</div>
      <p class="admin-hint">
        {closed
          ? "Sign-up is closed: an invite makes the one account it names."
          : "Each code makes one account. It goes in Create account → Invite code."}
      </p>
      <form class="inline-form" onsubmit={(e) => { e.preventDefault(); newInvite(); }}>
        <input
          class="admin-input grow"
          placeholder={closed ? "Account name" : "Account name (optional)"}
          aria-label="Invite for account name"
          bind:value={inviteFor}
        />
        <select class="admin-select" aria-label="Valid for" bind:value={inviteDays}>
          <option value={1}>1 day</option>
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
        </select>
        <button type="submit" class="btn btn-secondary" disabled={closed && !inviteFor.trim()}>Make invite</button>
      </form>
      {#if $inviteCode}
        {@const code = $inviteCode}
        <div class="code-box" role="status">
          <span class="admin-hint">New invite code, shown once:</span>
          <code class="code">{code}</code>
          <div class="form-actions">
            <button type="button" class="btn btn-ghost" onclick={() => clearShown(inviteCode)}>Done</button>
            <button type="button" class="btn btn-secondary" onclick={() => copyCode(code)}>
              <Icon name="copy" size={16} /> Copy
            </button>
          </div>
        </div>
      {/if}
      {#if $adminInvites?.length}
        <ul class="list">
          {#each $adminInvites as inv (inv.id)}
            <li class="list-item">
              <span class="row-text">
                <span class="row-name">{inv.used_by ? `Used by ${inv.used_by}` : inv.name ? `For ${inv.name}` : "Anyone"}</span>
                <span class="row-meta">until {when(inv.expires_at)}{inv.created_by ? ` · by ${inv.created_by}` : ""}</span>
              </span>
              {#if !inv.used_by}
                <button type="button" class="btn btn-secondary" onclick={() => adminOp({ InviteRevoke: { id: inv.id } })}>Revoke</button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>
    {#if showsLinks}
      <section class="section">
        <div class="section-title">Invite links</div>
        <p class="admin-hint">
          One link for many people, for a post or a website. Each sign-up with it still solves the proof of work and counts against the sign-up limits. Revoke it the moment it leaks.
        </p>
        <form class="inline-form" onsubmit={(e) => { e.preventDefault(); void adminOp({ InviteLinkNew: { max_uses: linkUses, days: linkDays, group: linkGroup } }); }}>
          <select class="admin-select" aria-label="How many people" bind:value={linkUses}>
            <option value={10}>10 people</option>
            <option value={100}>100 people</option>
            <option value={1000}>1,000 people</option>
            <option value={100000}>100,000 people</option>
          </select>
          <select class="admin-select" aria-label="Link valid for" bind:value={linkDays}>
            <option value={1}>1 day</option>
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={365}>A year</option>
            <option value={0}>Until revoked</option>
          </select>
          <select class="admin-select" aria-label="Starting group" bind:value={linkGroup}>
            <option value={null}>No starting group</option>
            {#each startGroups as g (g.name)}
              <option value={g.name}>{g.name}</option>
            {/each}
          </select>
          <button type="submit" class="btn btn-secondary">Make link</button>
        </form>
        {#if linkShown}
          {@const link = linkShown}
          <div class="code-box" role="status">
            <span class="admin-hint">New invite link, shown once:</span>
            <code class="code">{link}</code>
            <div class="form-actions">
              <button type="button" class="btn btn-ghost" onclick={() => clearShown(inviteLinkCode)}>Done</button>
              <button type="button" class="btn btn-secondary" onclick={() => copyCode(link)}>
                <Icon name="copy" size={16} /> Copy
              </button>
            </div>
          </div>
        {/if}
        {#if $adminInviteLinks?.length}
          <ul class="list">
            {#each $adminInviteLinks as link (link.id)}
              <li class="list-item">
                <span class="row-text">
                  <span class="row-name">{link.uses} of {link.max_uses} used</span>
                  <span class="row-meta">
                    {link.expires_at ? `until ${when(link.expires_at)}` : "until revoked"}{link.group ? ` · starts in ${link.group}` : ""}
                  </span>
                </span>
                <button type="button" class="btn btn-secondary" onclick={() => adminOp({ InviteLinkRevoke: { id: link.id } })}>Revoke</button>
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    {/if}
  {/if}
{/if}

<style>
  /* Three long buttons do not fit a phone */
  .account-actions {
    flex-wrap: wrap;
  }

  .liftable {
    display: flex;
    align-items: center;
    gap: var(--sp-2, 8px);
  }

  .liftable .list-row {
    flex: 1;
    min-width: 0;
  }

  .move-lift {
    flex: none;
  }

  .code-box {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2, 8px);
    padding: var(--sp-3, 12px);
    border: 1px solid var(--border);
    border-radius: var(--r-md, 6px);
    background: var(--bg-tertiary);
  }

  .code {
    font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
    font-size: var(--fs-md, 14px);
    user-select: all;
    word-break: break-all;
  }
</style>
