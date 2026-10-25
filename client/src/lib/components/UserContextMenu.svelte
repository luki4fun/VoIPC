<script lang="ts">
  import { backdrop, dialog } from "../actions/dialog.js";
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
  import { viewingVoice } from "../stores/channels.js";
  import { isAdmin, serverAddress } from "../stores/connection.js";
  import { isMobile, mobileTab } from "../stores/platform.js";
  import { centreView } from "../stores/room.js";
  import { canInvite, canKick, isCurrentChannelCreator, isModerator, isPreviewing } from "../stores/roster.js";
  import { selectedStrip, setUserVolume, toggleUserMute, userVolumes } from "../stores/mixer.js";
  import {
    adminAction,
    adminBanAccount,
    adminReason,
    cancelAdminAction,
    cancelPoke,
    closeUserMenu,
    confirmAdminAction,
    inviteUser,
    kickUser,
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
  // A moderator acts on people, not on admins or other moderators (the server
  // holds to that too); in their own channel they still kick as its creator.
  const spared = $derived(!!menu && !$isAdmin && !!(menu.user.is_admin || menu.user.is_moderator));

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
    >
      <!-- Who exactly: the one place a name's tag is spelled out -->
      <div class="ctx-title">{who.name}{#if who.tag}<span class="ctx-tag">#{who.tag}</span>{/if}</div>
      <div class="ctx-separator"></div>
      <!-- Watching, the mixer and the volume are the call's, so only for
           somebody on the server carrying it: an id on another server is a
           different person to the backend's voice connection. -->
      {#if !$isPreviewing && $viewingVoice && menu.user.is_screen_sharing}
        <button class="ctx-item" onclick={() => { watchUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="play" size={16} />
          <span>Watch Screen</span>
        </button>
      {/if}
      <button class="ctx-item" onclick={() => { openDm($serverAddress, menu.user.user_id, menu.user.username); closeUserMenu(); }}>
        <Icon name="direct-message" size={16} />
        <span>Direct Message</span>
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
            if ($isMobile) mobileTab.set("mixer");
            else centreView.set("mixer");
            closeUserMenu();
          }}
        >
          <Icon name="music-note" size={16} />
          <span>Mixer…</span>
        </button>
      {/if}
      {#if $canInvite || (menu.idle && $isCurrentChannelCreator)}
        <button class="ctx-item" onclick={() => { inviteUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="invite" size={16} />
          <span>Invite to Channel</span>
        </button>
      {/if}
      {#if $canKick && !menu.idle && !(spared && !$isCurrentChannelCreator)}
        <div class="ctx-separator"></div>
        <button class="ctx-item danger" onclick={() => { kickUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="kick" size={16} />
          <span>Kick from channel</span>
        </button>
      {/if}
      {#if $isAdmin || ($isModerator && !spared)}
        <div class="ctx-separator"></div>
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "kick", 0, "Kick from server"); closeUserMenu(); }}>
          <Icon name="shield" size={16} />
          <span>Kick from server</span>
        </button>
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
      <div class="poke-dialog-header">Poke {shortName($pokeTarget.username)}</div>
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="poke-input"
        type="text"
        placeholder="Message (optional)"
        bind:value={$pokeMessage}
        onkeydown={handlePokeKeydown}
        maxlength="200"
        autofocus
      />
      <div class="poke-dialog-actions">
        <button class="poke-cancel-btn" onclick={cancelPoke}>Cancel</button>
        <button class="poke-send-btn" onclick={sendPoke}>Poke</button>
      </div>
    </div>
  </div>
{/if}

{#if $adminAction}
  <div class="poke-overlay" onclick={backdrop(cancelAdminAction)} role="presentation">
    <div class="poke-dialog" use:dialog={{ onclose: cancelAdminAction }}>
      <div class="poke-dialog-header">{$adminAction.label}: {$adminAction.username}</div>
      {#if $adminAction.kind === "ban"}
        <div class="admin-hint">
          Bans the address they connect from, so everyone behind it is kept out too, except people who hold a
          role here. The ban outlasts a server restart; admins can lift it under Active bans.
        </div>
        {#if $adminAction.hasAccount}
          <label class="admin-check">
            <input type="checkbox" bind:checked={$adminBanAccount} />
            <span>Ban the account too, from any address</span>
          </label>
        {/if}
      {/if}
      <!-- svelte-ignore a11y_autofocus -->
      <input
        class="poke-input"
        type="text"
        placeholder="Reason (shown to the user)"
        bind:value={$adminReason}
        onkeydown={handleAdminKeydown}
        maxlength="200"
        autofocus
      />
      <div class="poke-dialog-actions">
        <button class="poke-cancel-btn" onclick={cancelAdminAction}>Cancel</button>
        <button class="poke-send-btn danger" onclick={confirmAdminAction}>{$adminAction.kind === "kick" ? "Kick" : "Ban"}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .admin-hint {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.4;
    margin-bottom: 8px;
  }

  .admin-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    margin-bottom: 8px;
  }

  .poke-send-btn.danger {
    background: var(--danger);
  }

  .ctx-overlay {
    position: fixed;
    inset: 0;
    z-index: 200;
  }

  .ctx-menu {
    position: fixed;
    min-width: 180px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 4px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    z-index: 201;
  }

  .ctx-title {
    padding: 6px 12px 4px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    overflow-wrap: anywhere;
  }

  .ctx-tag {
    font-weight: 400;
    color: var(--text-secondary);
  }

  .ctx-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 12px;
    background: transparent;
    color: var(--text-secondary);
    font-size: 13px;
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
    accent-color: var(--accent);
    background: transparent;
    border: none;
    padding: 0;
    min-width: 0;
  }

  /* Poke dialog */
  .poke-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .poke-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    width: 300px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
  }

  .poke-dialog-header {
    font-size: 14px;
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
    font-size: 13px;
    outline: none;
    box-sizing: border-box;
  }

  .poke-input:focus {
    border-color: var(--accent);
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
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
  }

  .poke-cancel-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .poke-send-btn {
    background: var(--accent);
    color: white;
    border: none;
    padding: 6px 14px;
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
  }

  .poke-send-btn:hover {
    opacity: 0.9;
  }
</style>
