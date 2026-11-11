<script lang="ts">
  import { backdrop, dialog } from "../actions/dialog.js";
  import { menu as menuAction } from "../actions/menu.js";
  // The member context menu, the poke dialog and the admin kick/ban dialog.
  //
  // Mounted once in App.svelte, outside either layout. Both member lists open it
  // through stores/user-menu.ts, so there is one copy of "what you can do to a
  // person" however many lists exist — and, more to the point, one copy of the
  // admin actions.
  //
  // The class names are load-bearing: test-ui.mjs drives .ctx-overlay, .ctx-menu,
  // .ctx-item and .ctx-vol-slider by hand. They came across unchanged.

  import { openDm } from "../stores/chat.js";
  import { channels, viewingVoice } from "../stores/channels.js";
  import { blockedMember, toggleBlock } from "../stores/blocks.js";
  import { isAdmin, serverAddress } from "../stores/connection.js";
  import { showChatPane } from "../stores/platform.js";
  import { centreView } from "../stores/room.js";
  import { canInvite, canKick, canSummon, isCurrentChannelCreator, isPreviewing } from "../stores/roster.js";
  import { users } from "../stores/users.js";
  import { can } from "../stores/powers.js";
  import { selectedStrip, setUserVolume, toggleUserMute, userVolumes } from "../stores/mixer.js";
  import {
    adminAction,
    adminBanAccount,
    adminDuration,
    adminReason,
    adminRemovePosts,
    cancelAdminAction,
    cancelPoke,
    clearProfile,
    closeUserMenu,
    confirmAdminAction,
    inviteUser,
    kickUser,
    liftRestriction,
    openAdminAction,
    openPokeDialog,
    pokeMessage,
    pokeTarget,
    repositionUserMenu,
    sendPoke,
    userMenu,
    watchUser,
  } from "../stores/user-menu.js";
  import Icon from "./Icons.svelte";
  import MemberName from "./MemberName.svelte";
  import { adminError, stepUp, stepUpCancelled, stepUpSays } from "../stores/admin-ops.js";
  import { showAdminPanel, submitStepUp } from "../stores/admin-ui.js";
  import { account, relayAccounts } from "../stores/account.js";
  import { olderRelay } from "../stores/relay.js";
  import { community, moderation, moves } from "../relay-rules.js";
  import { removalHint, removalWindows } from "../modlog-rules.js";
  import { restrictions } from "../stores/restrictions.js";
  import { markTitle } from "../restrict-rules.js";
  import { splitName, shortName } from "../username.js";
  import { invoke } from "@tauri-apps/api/core";
  import { account as ownAccount, showPrompt } from "../stores/account.js";
  import { addNotification } from "../stores/notifications.js";

  /** Both of us have accounts here: the number to compare with them. */
  async function verifyIdentity(userId: number, name: string) {
    const server = $serverAddress;
    try {
      const number = await invoke<string>("safety_number", { server, userId });
      showPrompt({ kind: "safety", server, name: shortName(name), number });
    } catch (e) {
      addNotification(String(e), "warning");
    }
  }

  const menu = $derived($userMenu);
  let menuEl: HTMLDivElement | undefined = $state(undefined);
  // Only an admin acts on admins and on those who hold privileges (the server
  // holds to that, for any privilege; the roster shows `voipc:channels`); in
  // their own channel a creator still kicks.
  const spared = $derived(!!menu && !$isAdmin && !!(menu.user.is_admin || menu.user.is_moderator));
  // Only an admin here: the roster shows `voipc:channels` only, and a holder of that
  // may well hold no more than we do (restrict.rs). The relay answers the rest with an error
  const canRestrict = $derived(!!menu && ($isAdmin || !menu.user.is_admin) && $can("voipc:restrict") && moderation($olderRelay?.protocol ?? null));
  // Not behind a pseudonym: a block there would say who it is
  const canBlock = $derived(!!menu && !$channels.find((c) => c.channel_id === menu.user.channel_id)?.anonymous);
  // Whoever stands in the room with us needs no invite; `users` is that room's roster
  const summonable = $derived(!!menu && $canSummon && !$users.some((u) => u.user_id === menu.user.user_id));

  // Per-user volume lives in one store, shared with the mixer: this used to be
  // a component-local record, so the same person had two different volumes
  // depending on which control you were looking at.
  function getUserVolume(uid: number): number {
    return $userVolumes.get(uid) ?? 1.0;
  }

  function handleUserVolumeInput(targetUserId: number, e: Event) {
    setUserVolume(targetUserId, parseFloat((e.target as HTMLInputElement).value));
  }

  // Nudge the menu back on screen once it has a size
  $effect(() => {
    if (menu && menuEl) {
      const rect = menuEl.getBoundingClientRect();
      repositionUserMenu(rect.width, rect.height);
    }
  });

  function handleContextMenuKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") closeUserMenu();
  }

  function handlePokeKeydown(e: KeyboardEvent) {
    // Escape is the dialog's (actions/dialog.ts)
    if (e.key === "Enter") {
      e.preventDefault();
      sendPoke();
    }
  }

  function handleAdminKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      confirmAdminAction();
    }
  }

  // The panel asks for itself; from the ban dialog it may be shut, and for a moderator
  // with no panel to open, the step would otherwise silently never happen.
  let stepCode = $state("");
  function confirmStep() {
    submitStepUp(stepCode);
    stepCode = "";
  }
  function cancelStep() {
    const server = $serverAddress;
    const said = stepUpCancelled($stepUp);
    stepUp.of(server).set(null);
    adminError.of(server).set(null);
    stepCode = "";
    addNotification(said, "warning");
  }
</script>

<svelte:window onkeydown={menu ? handleContextMenuKeydown : undefined} />

<!-- Context menu -->
{#if menu}
  {@const who = splitName(menu.user.username)}
  <div class="ctx-overlay" role="presentation" onclick={backdrop(closeUserMenu)}>
    <div
      class="ctx-menu"
      style="left: {menu.x}px; top: {menu.y}px;"
      bind:this={menuEl}
      use:menuAction={{ onclose: closeUserMenu, label: shortName(menu.user.username) }}
    >
      <!-- Who exactly: the one place a name's tag is spelled out -->
      <div class="ctx-title"><MemberName username={menu.user.username} account={menu.user.account} />{#if who.tag}<span class="ctx-tag">#{who.tag}</span>{/if}</div>
      <!-- The mark's words, for a touch screen that has no hover (W3-13) -->
      {#if $restrictions.has(menu.user.user_id)}
        <div class="ctx-note">{markTitle($restrictions.get(menu.user.user_id)!, Date.now())}</div>
      {/if}
      <div class="ctx-separator"></div>
      <!-- Watching, the mixer and the volume are the call's, so only for
           somebody on the server carrying it: an id on another server is a
           different person to the backend's voice connection. -->
      {#if !$isPreviewing && $viewingVoice && menu.user.is_screen_sharing}
        <button class="ctx-item" onclick={() => { watchUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="play" size={16} />
          <span>Watch screen</span>
        </button>
      {/if}
      <!-- And show it: from a phone's Users tab or a Stage tile the chat is
           not on screen, and a tap that changes nothing looks like it failed -->
      <button class="ctx-item" onclick={() => { openDm($serverAddress, menu.user.user_id, menu.user.username); showChatPane(); closeUserMenu(); }}>
        <Icon name="direct-message" size={16} />
        <span>Direct message</span>
      </button>
      <button class="ctx-item" onclick={() => { openPokeDialog(menu.user.user_id, menu.user.username); closeUserMenu(); }}>
        <Icon name="poke" size={16} />
        <span>Poke</span>
      </button>
      {#if menu.user.account && $ownAccount}
        <button class="ctx-item" onclick={() => { void verifyIdentity(menu.user.user_id, menu.user.username); closeUserMenu(); }}>
          <Icon name="lock" size={16} />
          <span>Verify identity</span>
        </button>
      {/if}
      {#if !$isPreviewing && $viewingVoice}
        <button
          class="ctx-item"
          onclick={() => {
            selectedStrip.set(menu.user.user_id);
            centreView.set("mixer");
            closeUserMenu();
          }}
        >
          <Icon name="music-note" size={16} />
          <span>Mixer…</span>
        </button>
      {/if}
      {#if $canInvite || (menu.idle && $isCurrentChannelCreator) || summonable}
        <button class="ctx-item" onclick={() => { inviteUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="invite" size={16} />
          <span>Invite to Channel</span>
        </button>
      {/if}
      {#if canBlock}
        <button class="ctx-item" onclick={() => { void toggleBlock($serverAddress, menu.user); closeUserMenu(); }}>
          <Icon name="ban" size={16} />
          <span>{$blockedMember(menu.user) ? "Unblock" : "Block"}</span>
        </button>
      {/if}
      {#if $canKick && !menu.idle && !(spared && !$isCurrentChannelCreator)}
        <div class="ctx-separator"></div>
        <button class="ctx-item danger" onclick={() => { void kickUser(menu.user.user_id, shortName(menu.user.username)); closeUserMenu(); }}>
          <Icon name="kick" size={16} />
          <span>Kick from channel</span>
        </button>
      {/if}
      {#if $can("voipc:profiles") && $account && community($olderRelay?.protocol ?? null) && menu.user.account && !spared}
        <button class="ctx-item danger" onclick={() => { const id = menu.user.account!; closeUserMenu(); void clearProfile(id); }}>
          <Icon name="close" size={16} />
          <span>Clear display name and picture</span>
        </button>
      {/if}
      {#if canRestrict || (($can("voipc:kick") || $can("voipc:ban")) && !spared)}
        <div class="ctx-separator"></div>
      {/if}
      {#if canRestrict}
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "mute", 3600, "Mute voice"); closeUserMenu(); }}>
          <Icon name="mic-off" size={16} />
          <span>Mute voice…</span>
        </button>
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "timeout", 3600, "Time out"); closeUserMenu(); }}>
          <Icon name="hourglass" size={16} />
          <span>Time out…</span>
        </button>
        {#if $restrictions.get(menu.user.user_id)?.by}
          <button class="ctx-item" onclick={() => { void liftRestriction(menu.user.user_id); closeUserMenu(); }}>
            <Icon name="mic-on" size={16} />
            <span>Lift mute or timeout</span>
          </button>
        {/if}
      {/if}
      {#if $can("voipc:kick") && !spared}
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "kick", 0, "Kick from server"); closeUserMenu(); }}>
          <Icon name="shield" size={16} />
          <span>Kick from server</span>
        </button>
      {/if}
      {#if $can("voipc:ban") && !spared}
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "ban", 3600, "Ban for 1 hour"); closeUserMenu(); }}>
          <Icon name="ban" size={16} />
          <span>Ban 1 hour</span>
        </button>
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "ban", 86400, "Ban for 24 hours"); closeUserMenu(); }}>
          <Icon name="ban" size={16} />
          <span>Ban 24 hours</span>
        </button>
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "ban", 0, "Ban for good"); closeUserMenu(); }}>
          <Icon name="ban" size={16} />
          <span>Ban for good</span>
        </button>
      {/if}
      {#if !$isPreviewing && $viewingVoice}
        <div class="ctx-separator"></div>
        <div class="ctx-volume">
          <button
            class="ctx-mute-btn"
            class:muted={getUserVolume(menu.user.user_id) === 0}
            title={getUserVolume(menu.user.user_id) === 0 ? "Unmute user" : "Mute user"}
            onclick={() => toggleUserMute(menu.user.user_id)}
          >
            <Icon name={getUserVolume(menu.user.user_id) === 0 ? "volume-off" : "volume"} size={16} />
          </button>
          <input
            type="range"
            class="ctx-vol-slider"
            min="0"
            max="2"
            step="0.05"
            value={getUserVolume(menu.user.user_id)}
            oninput={(e) => handleUserVolumeInput(menu.user.user_id, e)}
            title="Volume: {Math.round(getUserVolume(menu.user.user_id) * 100)}%"
          />
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if $pokeTarget}
  <div class="poke-overlay" onclick={backdrop(cancelPoke)} role="presentation">
    <div class="poke-dialog" use:dialog={{ onclose: cancelPoke }}>
      <div class="poke-dialog-header dialog-title">Poke {shortName($pokeTarget.username)}</div>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="poke-input"
        type="text"
        placeholder="Message (optional)"
        aria-label="Poke message (optional)"
        bind:value={$pokeMessage}
        onkeydown={handlePokeKeydown}
        maxlength="200"
        autofocus
      />
      <div class="poke-dialog-actions">
        <button class="poke-cancel-btn" onclick={cancelPoke}>Cancel</button>
        <button class="poke-send-btn btn btn-primary" onclick={sendPoke}>Poke</button>
      </div>
    </div>
  </div>
{/if}

{#if $adminAction}
  <div class="poke-overlay" onclick={backdrop(cancelAdminAction)} role="presentation">
    <div class="poke-dialog" use:dialog={{ onclose: cancelAdminAction }}>
      <div class="poke-dialog-header dialog-title">{$adminAction.label}: {$adminAction.username}</div>
      {#if $adminAction.kind === "ban"}
        <div class="admin-hint">
          Bans the address they connect from, so everyone behind it is kept out too, except people who hold a
          role here. The ban outlasts a server restart; admins can lift it under Active bans.
        </div>
        {#if $adminAction.hasAccount}
          <label class="admin-check">
            <input type="checkbox" bind:checked={$adminBanAccount} disabled={$adminRemovePosts !== null} />
            <span>Ban the account too, from any address</span>
          </label>
        {/if}
        {#if $account && $relayAccounts && moderation($olderRelay?.protocol ?? null)}
          <label class="admin-check">
            <span>Also remove their posts</span>
            <select
              class="remove-posts"
              bind:value={$adminRemovePosts}
              onchange={() => { if ($adminRemovePosts !== null) adminBanAccount.set(true); }}
            >
              <option value={null}>No</option>
              {#each removalWindows($can("*")) as [secs, label] (secs)}
                <option value={secs}>{label}</option>
              {/each}
            </select>
          </label>
          {#if $adminRemovePosts !== null}
            <div class="admin-hint remove-posts-hint">{removalHint($adminAction.hasAccount, moves($olderRelay?.protocol ?? null))}</div>
          {/if}
        {/if}
      {/if}
      {#if $adminAction.kind === "mute" || $adminAction.kind === "timeout"}
        <div class="admin-hint">
          {$adminAction.kind === "mute"
            ? "They can read and write, and nobody hears them."
            : "They can read, and cannot speak, post, poke, invite or set a name or picture."} They can still write
          direct messages. Everyone sees that they are held, by whom and until when; only they and moderators see why.
          {#if !$adminAction.hasAccount}
            Someone with no account goes by address, for every guest there, for a day at most.
          {/if}
        </div>
        <label class="admin-check">
          <span>For</span>
          <select class="restrict-duration" bind:value={$adminDuration} aria-label="How long">
            <option value={600}>10 minutes</option>
            <option value={3600}>1 hour</option>
            <option value={86400}>24 hours</option>
            {#if $adminAction.hasAccount}
              <option value={604800}>7 days</option>
              <option value={0}>Until someone lifts it</option>
            {/if}
          </select>
        </label>
      {/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="poke-input"
        type="text"
        placeholder="Reason (shown to the user)"
        aria-label="Reason, shown to the user"
        bind:value={$adminReason}
        onkeydown={handleAdminKeydown}
        maxlength="200"
        autofocus
      />
      <div class="poke-dialog-actions">
        <button class="poke-cancel-btn" onclick={cancelAdminAction}>Cancel</button>
        <button class="poke-send-btn btn btn-danger" onclick={confirmAdminAction}>{{ kick: "Kick", ban: "Ban", mute: "Mute", timeout: "Time out" }[$adminAction.kind]}</button>
      </div>
    </div>
  </div>
{/if}

{#if $stepUp && !$showAdminPanel}
  <div class="poke-overlay" onclick={backdrop(cancelStep)} role="presentation">
    <form class="poke-dialog step-up-dialog" onsubmit={(e) => { e.preventDefault(); confirmStep(); }} use:dialog={{ onclose: cancelStep }}>
      <div class="poke-dialog-header dialog-title">Confirm with a code</div>
      <div class="admin-hint">{stepUpSays($stepUp)} Enter a code from your authenticator app; it holds for ten minutes.</div>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="poke-input" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" aria-label="Two-factor code" bind:value={stepCode} autofocus />
      <div class="poke-dialog-actions">
        <button type="button" class="poke-cancel-btn" onclick={cancelStep}>Cancel</button>
        <button type="submit" class="poke-send-btn btn btn-primary" disabled={!stepCode.trim()}>Confirm</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .admin-hint {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    line-height: 1.4;
    margin-bottom: 8px;
  }

  .admin-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    margin-bottom: 8px;
  }

  .ctx-overlay {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
  }

  .ctx-menu {
    position: fixed;
    min-width: 180px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 4px;
    box-shadow: var(--shadow-menu);
    z-index: var(--z-menu);
    max-height: calc(100dvh - 16px);
    overflow-y: auto;
  }

  .ctx-title {
    padding: 6px 12px 4px;
    font-size: var(--fs-body);
    font-weight: 600;
    color: var(--text-primary);
    overflow-wrap: anywhere;
  }

  .ctx-tag {
    font-weight: 400;
    color: var(--text-secondary);
  }

  .ctx-note {
    padding: 2px 12px 6px;
    font-size: 12px;
    color: var(--text-secondary);
    overflow-wrap: anywhere;
  }

  .ctx-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 12px;
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-body);
    border: none;
    border-radius: 4px;
    cursor: pointer;
    text-align: left;
  }

  .ctx-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .ctx-item.danger:hover {
    background: rgba(231, 76, 60, 0.15);
    color: var(--danger);
  }

  .ctx-separator {
    height: 1px;
    background: var(--border);
    margin: 4px 0;
  }

  .ctx-volume {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
  }

  .ctx-mute-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .ctx-mute-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .ctx-mute-btn.muted {
    color: var(--danger);
  }

  .ctx-vol-slider {
    flex: 1;
    height: 4px;
    accent-color: var(--control-fill);
    background: transparent;
    border: none;
    padding: 0;
    min-width: 0;
  }

  /* Poke dialog */
  .poke-overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-dialog);
  }

  .poke-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    width: 300px;
    box-shadow: var(--shadow-menu);
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
  }

  .poke-dialog-header {
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 12px;
  }

  .poke-input {
    width: 100%;
    padding: 8px 10px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: var(--fs-body);
    outline: none;
    box-sizing: border-box;
  }

  .poke-input:focus {
    border-color: var(--focus-ring);
  }

  .poke-dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 12px;
  }

  .poke-cancel-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 6px 14px;
    font-size: var(--fs-sm);
    border-radius: 4px;
    cursor: pointer;
  }

  .poke-cancel-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .poke-send-btn {
    padding: 6px 14px;
    font-size: var(--fs-sm);
  }
</style>
