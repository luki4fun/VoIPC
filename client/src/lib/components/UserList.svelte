<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "../stores/channels.js";
  import { users, speakingUsers } from "../stores/users.js";
  import { userId } from "../stores/connection.js";
  import { openDm } from "../stores/chat.js";
  import { watchingUserId, currentFrame } from "../stores/screenshare.js";
  import { addNotification } from "../stores/notifications.js";
  import Icon from "./Icons.svelte";
  import type { UserInfo } from "../types.js";

  // Are we previewing a different channel?
  let isPreviewing = $derived(
    $previewChannelId !== null && $previewChannelId !== $currentChannelId
  );

  // Which channel's info to show
  let displayChannelId = $derived(
    isPreviewing ? $previewChannelId! : $currentChannelId
  );

  let displayUsers = $derived(
    isPreviewing ? $previewUsers : $users
  );

  let channelName = $derived(
    $channels.find((c) => c.channel_id === displayChannelId)?.name ?? ""
  );

  // Creator info for the displayed channel
  let displayChannelCreatorId = $derived(
    $channels.find((c) => c.channel_id === displayChannelId)?.created_by ?? null
  );

  // Creator of the user's CURRENT channel (for invite permissions)
  let currentChannelCreatorId = $derived(
    $channels.find((c) => c.channel_id === $currentChannelId)?.created_by ?? null
  );

  let isCurrentChannelCreator = $derived(
    currentChannelCreatorId === $userId && $currentChannelId !== 0
  );

  // Kick is only available when viewing own channel (not previewing)
  let canKick = $derived(
    !isPreviewing && displayChannelCreatorId === $userId && $currentChannelId !== 0
  );

  // Invite is available when previewing another channel and you're creator of your current channel
  let canInvite = $derived(
    isPreviewing && isCurrentChannelCreator
  );

  async function kickUser(targetUserId: number) {
    try {
      await invoke("kick_user", {
        channelId: $currentChannelId,
        userId: targetUserId,
      });
    } catch (e) {
      console.error("Failed to kick user:", e);
    }
  }

  async function inviteUser(targetUserId: number) {
    try {
      await invoke("send_invite", {
        channelId: $currentChannelId,
        targetUserId,
      });
    } catch (e) {
      console.error("Failed to invite user:", e);
    }
  }

  // Poke dialog state
  let pokeTarget = $state<{ userId: number; username: string } | null>(null);
  let pokeMessage = $state("");

  function openPokeDialog(targetUserId: number, targetUsername: string) {
    pokeTarget = { userId: targetUserId, username: targetUsername };
    pokeMessage = "";
  }

  function cancelPoke() {
    pokeTarget = null;
    pokeMessage = "";
  }

  async function sendPoke() {
    if (!pokeTarget) return;
    const { userId: targetUserId } = pokeTarget;
    const message = pokeMessage;
    pokeTarget = null;
    pokeMessage = "";
    try {
      await invoke("send_poke", { targetUserId, message });
    } catch (e) {
      console.error("Failed to poke user:", e);
    }
  }

  function handlePokeKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") {
      e.preventDefault();
      sendPoke();
    } else if (e.key === "Escape") {
      cancelPoke();
    }
  }

  async function watchUser(targetUserId: number) {
    try {
      await invoke("watch_screen_share", { sharerUserId: targetUserId });
      watchingUserId.set(targetUserId);
      currentFrame.set(null);
    } catch (e: any) {
      addNotification(e.toString(), "error");
    }
  }

  // Per-user volume state: user_id → volume (0.0 - 2.0, default 1.0)
  let userVolumes: Record<number, number> = $state({});

  async function setUserVolume(targetUserId: number, vol: number) {
    userVolumes[targetUserId] = vol;
    try {
      await invoke("set_user_volume", { userId: targetUserId, volume: vol });
    } catch (e) {
      console.error("Failed to set user volume:", e);
    }
  }

  function handleUserVolumeInput(targetUserId: number, e: Event) {
    const vol = parseFloat((e.target as HTMLInputElement).value);
    setUserVolume(targetUserId, vol);
  }

  function toggleUserMute(targetUserId: number) {
    const current = userVolumes[targetUserId] ?? 1.0;
    if (current > 0) {
      setUserVolume(targetUserId, 0);
    } else {
      setUserVolume(targetUserId, 1.0);
    }
  }

  function getUserVolume(uid: number): number {
    return userVolumes[uid] ?? 1.0;
  }

  // Context menu state
  let contextMenu = $state<{ user: UserInfo; x: number; y: number } | null>(null);
  let contextMenuEl: HTMLDivElement | undefined = $state(undefined);

  function showContextMenu(user: UserInfo, e: MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (user.user_id === $userId) return;
    contextMenu = { user, x: e.clientX, y: e.clientY };
  }

  function closeContextMenu() {
    contextMenu = null;
  }

  // Reposition context menu if it overflows viewport
  $effect(() => {
    if (contextMenu && contextMenuEl) {
      const rect = contextMenuEl.getBoundingClientRect();
      let { x, y } = contextMenu;
      if (rect.right > window.innerWidth) {
        x = window.innerWidth - rect.width - 8;
      }
      if (rect.bottom > window.innerHeight) {
        y = window.innerHeight - rect.height - 8;
      }
      if (x !== contextMenu.x || y !== contextMenu.y) {
        contextMenu = { ...contextMenu, x, y };
      }
    }
  });

  function handleContextMenuKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") closeContextMenu();
  }
</script>

<svelte:window onkeydown={contextMenu ? handleContextMenuKeydown : undefined} />

<div class="user-list">
  <div class="header">
    {#if isPreviewing}
      Previewing #{channelName}
    {:else}
      Users in #{channelName}
    {/if}
  </div>
  <div class="users">
    {#each displayUsers as user (user.user_id)}
      <div
        class="user"
        class:speaking={!isPreviewing && $speakingUsers.has(user.user_id)}
        oncontextmenu={(e) => showContextMenu(user, e)}
      >
        <div
          class="indicator"
          class:speaking={!isPreviewing && $speakingUsers.has(user.user_id)}
          class:muted={user.is_muted}
          class:deafened={user.is_deafened}
        ></div>
        <span class="name">
          {user.username}
          {#if user.user_id === displayChannelCreatorId && displayChannelId !== 0}
            <span class="crown" title="Channel creator"><Icon name="crown" size={12} /></span>
          {/if}
          {#if user.user_id === $userId}
            <span class="you">(you)</span>
          {/if}
        </span>
        {#if user.is_muted}
          <span class="status-icon muted" title="Muted">
            <Icon name="mic-off" size={14} />
          </span>
        {/if}
        {#if user.is_deafened}
          <span class="status-icon deafened" title="Deafened">
            <Icon name="headphones-off" size={14} />
          </span>
        {/if}
        {#if user.is_screen_sharing}
          <span class="status-icon sharing" title="Sharing screen">
            <Icon name="monitor" size={14} />
          </span>
        {/if}
        {#if user.user_id !== $userId}
          <button
            class="more-btn"
            title="Actions"
            onclick={(e) => { e.stopPropagation(); showContextMenu(user, e); }}
          >
            <Icon name="more-vertical" size={16} />
          </button>
        {/if}
      </div>
    {/each}
  </div>
  {#if isPreviewing}
    <div class="preview-hint">Double-click channel to join</div>
  {/if}
</div>

<!-- Context menu -->
{#if contextMenu}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="ctx-overlay" onclick={closeContextMenu}>
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div
      class="ctx-menu"
      style="left: {contextMenu.x}px; top: {contextMenu.y}px;"
      onclick={(e) => e.stopPropagation()}
      bind:this={contextMenuEl}
    >
      {#if !isPreviewing && contextMenu.user.is_screen_sharing}
        <button class="ctx-item" onclick={() => { watchUser(contextMenu!.user.user_id); closeContextMenu(); }}>
          <Icon name="play" size={16} />
          <span>Watch Screen</span>
        </button>
      {/if}
      <button class="ctx-item" onclick={() => { openDm(contextMenu!.user.user_id, contextMenu!.user.username, $userId); closeContextMenu(); }}>
        <Icon name="direct-message" size={16} />
        <span>Direct Message</span>
      </button>
      <button class="ctx-item" onclick={() => { openPokeDialog(contextMenu!.user.user_id, contextMenu!.user.username); closeContextMenu(); }}>
        <Icon name="poke" size={16} />
        <span>Poke</span>
      </button>
      {#if canInvite}
        <button class="ctx-item" onclick={() => { inviteUser(contextMenu!.user.user_id); closeContextMenu(); }}>
          <Icon name="invite" size={16} />
          <span>Invite to Channel</span>
        </button>
      {/if}
      {#if canKick}
        <div class="ctx-separator"></div>
        <button class="ctx-item danger" onclick={() => { kickUser(contextMenu!.user.user_id); closeContextMenu(); }}>
          <Icon name="kick" size={16} />
          <span>Kick</span>
        </button>
      {/if}
      {#if !isPreviewing}
        <div class="ctx-separator"></div>
        <div class="ctx-volume">
          <button
            class="ctx-mute-btn"
            class:muted={getUserVolume(contextMenu.user.user_id) === 0}
            title={getUserVolume(contextMenu.user.user_id) === 0 ? "Unmute user" : "Mute user"}
            onclick={() => toggleUserMute(contextMenu!.user.user_id)}
          >
            <Icon name={getUserVolume(contextMenu.user.user_id) === 0 ? "volume-off" : "volume"} size={16} />
          </button>
          <input
            type="range"
            class="ctx-vol-slider"
            min="0"
            max="2"
            step="0.05"
            value={getUserVolume(contextMenu.user.user_id)}
            oninput={(e) => handleUserVolumeInput(contextMenu!.user.user_id, e)}
            title="Volume: {Math.round(getUserVolume(contextMenu!.user.user_id) * 100)}%"
          />
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if pokeTarget}
  <div class="poke-overlay" onclick={cancelPoke} onkeydown={() => {}} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="poke-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="poke-dialog-header">Poke {pokeTarget.username}</div>
      <input
        class="poke-input"
        type="text"
        placeholder="Message (optional)"
        bind:value={pokeMessage}
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

<style>
  .user-list {
    display: flex;
    flex-direction: column;
    height: 100%;
    width: 180px;
    min-width: 140px;
    flex-shrink: 1;
    border-left: 1px solid var(--border);
  }

  .header {
    padding: 12px 16px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
  }

  .users {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
  }

  .user {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    border-radius: 4px;
    transition: background-color 0.15s;
    position: relative;
  }

  .user:hover {
    background: var(--bg-hover);
  }

  .user.speaking {
    background: rgba(76, 175, 80, 0.1);
  }

  .indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-secondary);
    flex-shrink: 0;
  }

  .indicator.speaking {
    background: var(--speaking);
    box-shadow: 0 0 6px var(--speaking);
  }

  .indicator.muted {
    background: var(--danger);
  }

  .indicator.deafened {
    background: #ffa726;
  }

  .name {
    flex: 1;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .crown {
    color: #ffc107;
    margin-left: 1px;
    display: inline-flex;
    vertical-align: middle;
  }

  .you {
    color: var(--text-secondary);
    font-size: 11px;
  }

  .status-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .status-icon.muted {
    color: var(--danger);
  }

  .status-icon.deafened {
    color: #ffa726;
  }

  .status-icon.sharing {
    color: var(--success);
  }

  .more-btn {
    display: none;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .user:hover .more-btn {
    display: flex;
  }

  .more-btn:hover {
    background: rgba(255, 255, 255, 0.1);
    color: var(--text-primary);
  }

  .preview-hint {
    padding: 8px 16px;
    font-size: 11px;
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
    font-style: italic;
  }

  /* Context menu */
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
    background: rgba(255, 255, 255, 0.1);
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
