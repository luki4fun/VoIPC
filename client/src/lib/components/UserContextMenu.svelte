<script lang="ts">
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
  import { userId, isAdmin } from "../stores/connection.js";
  import { isMobile, mobileTab } from "../stores/platform.js";
  import { centreView } from "../stores/room.js";
  import { canInvite, canKick, isPreviewing } from "../stores/roster.js";
  import { selectedStrip, setUserVolume, toggleUserMute, userVolumes } from "../stores/mixer.js";
  import {
    adminAction,
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

  const menu = $derived($userMenu);
  let menuEl: HTMLDivElement | undefined = $state(undefined);

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
    if (e.key === "Enter") {
      e.preventDefault();
      sendPoke();
    } else if (e.key === "Escape") {
      cancelPoke();
    }
  }

  function handleAdminKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      confirmAdminAction();
    } else if (e.key === "Escape") {
      cancelAdminAction();
    }
  }
</script>

<svelte:window onkeydown={menu ? handleContextMenuKeydown : undefined} />

<!-- Context menu -->
{#if menu}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="ctx-overlay" onclick={closeUserMenu}>
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div
      class="ctx-menu"
      style="left: {menu.x}px; top: {menu.y}px;"
      onclick={(e) => e.stopPropagation()}
      bind:this={menuEl}
    >
      {#if !$isPreviewing && menu.user.is_screen_sharing}
        <button class="ctx-item" onclick={() => { watchUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="play" size={16} />
          <span>Watch Screen</span>
        </button>
      {/if}
      <button class="ctx-item" onclick={() => { openDm(menu.user.user_id, menu.user.username, $userId); closeUserMenu(); }}>
        <Icon name="direct-message" size={16} />
        <span>Direct Message</span>
      </button>
      <button class="ctx-item" onclick={() => { openPokeDialog(menu.user.user_id, menu.user.username); closeUserMenu(); }}>
        <Icon name="poke" size={16} />
        <span>Poke</span>
      </button>
      {#if !$isPreviewing}
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
      {#if $canInvite}
        <button class="ctx-item" onclick={() => { inviteUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="invite" size={16} />
          <span>Invite to Channel</span>
        </button>
      {/if}
      {#if $canKick}
        <div class="ctx-separator"></div>
        <button class="ctx-item danger" onclick={() => { kickUser(menu.user.user_id); closeUserMenu(); }}>
          <Icon name="kick" size={16} />
          <span>Kick from channel</span>
        </button>
      {/if}
      {#if $isAdmin}
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
        <button class="ctx-item danger" onclick={() => { openAdminAction(menu.user, "ban", 0, "Ban until server restart"); closeUserMenu(); }}>
          <Icon name="ban" size={16} />
          <span>Ban until restart</span>
        </button>
      {/if}
      {#if !$isPreviewing}
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
  <div class="poke-overlay" onclick={cancelPoke} onkeydown={() => {}} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="poke-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="poke-dialog-header">Poke {$pokeTarget.username}</div>
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
  <div class="poke-overlay" onclick={cancelAdminAction} onkeydown={() => {}} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="poke-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="poke-dialog-header">{$adminAction.label}: {$adminAction.username}</div>
      {#if $adminAction.kind === "ban"}
        <div class="admin-hint">
          Bans the user's IP address, so everyone behind the same address is affected.
          Bans live in server memory until they expire or the server restarts.
        </div>
      {/if}
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
