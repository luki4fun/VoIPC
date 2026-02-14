<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "../stores/channels.js";
  import { users, speakingUsers } from "../stores/users.js";
  import { userId } from "../stores/connection.js";
  import { openDm } from "../stores/chat.js";
  import { watchingUserId, currentFrame } from "../stores/screenshare.js";
  import { addNotification } from "../stores/notifications.js";

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
</script>

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
      <div class="user" class:speaking={!isPreviewing && $speakingUsers.has(user.user_id)}>
        <div
          class="indicator"
          class:speaking={!isPreviewing && $speakingUsers.has(user.user_id)}
          class:muted={user.is_muted}
          class:deafened={user.is_deafened}
        ></div>
        <span class="name">
          {user.username}
          {#if user.user_id === displayChannelCreatorId && displayChannelId !== 0}
            <span class="crown" title="Channel creator">&#9819;</span>
          {/if}
          {#if user.user_id === $userId}
            <span class="you">(you)</span>
          {/if}
        </span>
        {#if user.is_muted}
          <span class="muted-icon" title="Muted">M</span>
        {/if}
        {#if user.is_deafened}
          <span class="deafened-icon" title="Deafened">D</span>
        {/if}
        {#if user.is_screen_sharing}
          <span class="share-icon" title="Sharing screen">S</span>
        {/if}
        <div class="user-actions">
          {#if !isPreviewing && user.is_screen_sharing && user.user_id !== $userId}
            <button
              class="action-btn watch-btn"
              title="Watch screen share"
              onclick={() => watchUser(user.user_id)}
            >&#9654;</button>
          {/if}
          {#if canKick && user.user_id !== $userId}
            <button
              class="action-btn kick-btn"
              title="Kick user"
              onclick={() => kickUser(user.user_id)}
            >&#10005;</button>
          {/if}
          {#if canInvite && user.user_id !== $userId}
            <button
              class="action-btn invite-btn"
              title="Invite to your channel"
              onclick={() => inviteUser(user.user_id)}
            >&#8594;</button>
          {/if}
          {#if user.user_id !== $userId}
            <button
              class="action-btn dm-btn"
              title="Direct message"
              onclick={() => openDm(user.user_id, user.username, $userId)}
            >&#9993;</button>
          {/if}
        </div>
        {#if !isPreviewing && user.user_id !== $userId}
          <div class="user-volume-popup">
            <button
              class="mute-user-btn"
              class:muted={getUserVolume(user.user_id) === 0}
              title={getUserVolume(user.user_id) === 0 ? "Unmute user" : "Mute user"}
              onclick={() => toggleUserMute(user.user_id)}
            >{getUserVolume(user.user_id) === 0 ? "X" : "V"}</button>
            <input
              type="range"
              class="user-vol-slider"
              min="0"
              max="2"
              step="0.05"
              value={getUserVolume(user.user_id)}
              oninput={(e) => handleUserVolumeInput(user.user_id, e)}
              title="Volume: {Math.round(getUserVolume(user.user_id) * 100)}%"
            />
          </div>
        {/if}
      </div>
    {/each}
  </div>
  {#if isPreviewing}
    <div class="preview-hint">Double-click channel to join</div>
  {/if}
</div>

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
    font-size: 12px;
    margin-left: 1px;
  }

  .you {
    color: var(--text-secondary);
    font-size: 11px;
  }

  .muted-icon {
    font-size: 10px;
    color: var(--danger);
    font-weight: bold;
    flex-shrink: 0;
  }

  .deafened-icon {
    font-size: 10px;
    color: #ffa726;
    font-weight: bold;
    flex-shrink: 0;
  }

  .share-icon {
    font-size: 9px;
    color: var(--success);
    font-weight: bold;
    background: rgba(76, 175, 80, 0.15);
    padding: 1px 3px;
    border-radius: 3px;
    flex-shrink: 0;
  }

  .user-actions {
    display: none;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }

  .user:hover .user-actions {
    display: flex;
  }

  .action-btn {
    background: transparent;
    color: var(--text-secondary);
    border: none;
    font-size: 11px;
    cursor: pointer;
    padding: 1px 3px;
    border-radius: 3px;
    line-height: 1;
    flex-shrink: 0;
  }

  .action-btn:hover {
    color: var(--text-primary);
  }

  .kick-btn:hover {
    color: var(--danger);
    background: rgba(244, 67, 54, 0.1);
  }

  .invite-btn:hover,
  .watch-btn:hover,
  .dm-btn:hover {
    color: var(--accent);
    background: rgba(74, 158, 255, 0.1);
  }

  .preview-hint {
    padding: 8px 16px;
    font-size: 11px;
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
    font-style: italic;
  }

  /* Volume popup — appears below user row on hover */
  .user-volume-popup {
    display: none;
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    align-items: center;
    gap: 4px;
    padding: 4px 8px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    z-index: 10;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3);
  }

  .user:hover .user-volume-popup {
    display: flex;
  }

  .user-vol-slider {
    flex: 1;
    height: 4px;
    accent-color: var(--accent);
    background: transparent;
    border: none;
    padding: 0;
    min-width: 0;
  }

  .mute-user-btn {
    background: transparent;
    color: var(--text-secondary);
    border: none;
    font-size: 10px;
    font-weight: bold;
    cursor: pointer;
    padding: 1px 3px;
    border-radius: 2px;
    min-width: 14px;
    flex-shrink: 0;
  }

  .mute-user-btn:hover {
    color: var(--text-primary);
  }

  .mute-user-btn.muted {
    color: var(--danger);
  }
</style>
