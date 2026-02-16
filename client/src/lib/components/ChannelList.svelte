<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "../stores/channels.js";
  import { userId } from "../stores/connection.js";
  import { dmConversations, activeDmUserId, openDm, closeDm, unreadPerChannel, clearChannelUnread } from "../stores/chat.js";
  import Icon from "./Icons.svelte";

  let showCreateForm = $state(false);
  let newChannelName = $state("");
  let newChannelPassword = $state("");

  // Password prompt state (for joining)
  let passwordPromptChannelId = $state<number | null>(null);
  let passwordPromptInput = $state("");

  // Password change dialog state (for channel creators)
  let passwordEditChannelId = $state<number | null>(null);
  let passwordEditInput = $state("");

  // Deterministic avatar color from username
  const AVATAR_COLORS = [
    "#5865F2", "#57F287", "#FEE75C", "#EB459E",
    "#ED4245", "#3498db", "#e67e22", "#1abc9c",
  ];

  function avatarColor(name: string): string {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
  }

  function previewChannel(channelId: number) {
    // Always exit DM mode when clicking a channel
    if ($activeDmUserId !== null) {
      closeDm();
    }

    if (channelId === $currentChannelId) {
      // Clicking own channel clears preview, shows own channel chat
      previewChannelId.set(null);
      previewUsers.set([]);
      return;
    }
    previewChannelId.set(channelId);
    const chName = $channels.find((c) => c.channel_id === channelId)?.name;
    if (chName) clearChannelUnread(chName);
    invoke("request_channel_users", { channelId }).catch((e: unknown) =>
      console.error("Failed to request channel users:", e),
    );
  }

  async function joinChannel(channelId: number, hasPassword: boolean) {
    if (hasPassword && channelId !== $currentChannelId) {
      passwordPromptChannelId = channelId;
      passwordPromptInput = "";
      return;
    }
    try {
      await invoke("join_channel", { channelId, password: null });
    } catch (e) {
      console.error("Failed to join channel:", e);
    }
  }

  async function submitPasswordJoin() {
    if (passwordPromptChannelId === null) return;
    try {
      await invoke("join_channel", {
        channelId: passwordPromptChannelId,
        password: passwordPromptInput || null,
      });
      passwordPromptChannelId = null;
      passwordPromptInput = "";
    } catch (e) {
      console.error("Failed to join channel:", e);
    }
  }

  function cancelPasswordPrompt() {
    passwordPromptChannelId = null;
    passwordPromptInput = "";
  }

  async function createChannel() {
    const name = newChannelName.trim();
    if (!name) return;
    try {
      await invoke("create_channel", {
        name,
        password: newChannelPassword || null,
      });
      newChannelName = "";
      newChannelPassword = "";
      showCreateForm = false;
    } catch (e) {
      console.error("Failed to create channel:", e);
    }
  }

  function cancelCreate() {
    newChannelName = "";
    newChannelPassword = "";
    showCreateForm = false;
  }

  function openPasswordEdit(channelId: number, e: Event) {
    e.stopPropagation();
    passwordEditChannelId = channelId;
    // Leave input empty — user sets a new password (or submits empty to remove)
    passwordEditInput = "";
  }

  async function submitPasswordEdit() {
    if (passwordEditChannelId === null) return;
    try {
      await invoke("set_channel_password", {
        channelId: passwordEditChannelId,
        password: passwordEditInput || null,
      });
      passwordEditChannelId = null;
      passwordEditInput = "";
    } catch (e) {
      console.error("Failed to change password:", e);
    }
  }

  function cancelPasswordEdit() {
    passwordEditChannelId = null;
    passwordEditInput = "";
  }
</script>

<div class="channel-list">
  <div class="header">
    <span>Channels</span>
    <button class="add-btn" onclick={() => (showCreateForm = !showCreateForm)} title="Create channel">
      <Icon name="plus" size={18} />
    </button>
  </div>

  {#if showCreateForm}
    <form class="create-form" onsubmit={(e) => { e.preventDefault(); createChannel(); }}>
      <input
        class="create-input"
        type="text"
        placeholder="Channel name"
        bind:value={newChannelName}
        maxlength="32"
      />
      <input
        class="create-input"
        type="password"
        placeholder="Password (optional)"
        bind:value={newChannelPassword}
      />
      <div class="create-actions">
        <button class="create-btn" type="submit">Create</button>
        <button class="cancel-btn" type="button" onclick={cancelCreate}>Cancel</button>
      </div>
    </form>
  {/if}

  <div class="channels">
    {#each $channels as channel (channel.channel_id)}
      <button
        class="channel"
        class:active={channel.channel_id === $currentChannelId}
        class:previewing={channel.channel_id === $previewChannelId && channel.channel_id !== $currentChannelId}
        onclick={() => previewChannel(channel.channel_id)}
        ondblclick={() => joinChannel(channel.channel_id, channel.has_password)}
      >
        <span class="channel-icon">
          {#if channel.channel_id === 0}
            <Icon name="lobby" size={16} />
          {:else if channel.has_password}
            <Icon name="lock" size={16} />
          {:else}
            <Icon name="hash" size={16} />
          {/if}
        </span>
        <span class="channel-name">{channel.name}</span>
        <span class="user-count">({channel.user_count})</span>
        {#if ($unreadPerChannel.get(channel.name) ?? 0) > 0}
          <span class="channel-unread">{$unreadPerChannel.get(channel.name)}</span>
        {/if}
        {#if channel.created_by === $userId && channel.channel_id !== 0}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <span
            class="settings-icon"
            title="Channel settings"
            role="button"
            tabindex="-1"
            onclick={(e) => openPasswordEdit(channel.channel_id, e)}
          ><Icon name="channel-settings" size={14} /></span>
        {/if}
      </button>
    {/each}
  </div>

  {#if $dmConversations.length > 0}
    <div class="dm-section">
      <div class="header dm-header">
        <span class="dm-header-icon"><Icon name="direct-message" size={14} /></span>
        <span>Direct Messages</span>
      </div>
      <div class="dm-list">
        {#each $dmConversations as convo (convo.user_id)}
          <button
            class="dm-entry"
            class:active={$activeDmUserId === convo.user_id}
            onclick={() => openDm(convo.user_id, convo.username, $userId)}
          >
            <span class="dm-avatar" style="background: {avatarColor(convo.username)}">
              {convo.username.charAt(0).toUpperCase()}
            </span>
            <span class="dm-name">{convo.username}</span>
            {#if convo.unread > 0}
              <span class="dm-unread">{convo.unread}</span>
            {/if}
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

{#if passwordPromptChannelId !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={cancelPasswordPrompt} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_to_interactive_role a11y_no_noninteractive_element_interactions -->
    <form
      class="password-dialog"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cancelPasswordPrompt(); }}
      onsubmit={(e) => { e.preventDefault(); submitPasswordJoin(); }}
    >
      <div class="dialog-title">Enter Password</div>
      <input
        class="dialog-input"
        type="password"
        placeholder="Channel password"
        bind:value={passwordPromptInput}
      />
      <div class="dialog-actions">
        <button class="create-btn" type="submit">Join</button>
        <button class="cancel-btn" type="button" onclick={cancelPasswordPrompt}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

{#if passwordEditChannelId !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={cancelPasswordEdit} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_to_interactive_role a11y_no_noninteractive_element_interactions -->
    <form
      class="password-dialog"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cancelPasswordEdit(); }}
      onsubmit={(e) => { e.preventDefault(); submitPasswordEdit(); }}
    >
      <div class="dialog-title">Change Channel Password</div>
      <input
        class="dialog-input"
        type="password"
        placeholder="New password (empty to remove)"
        bind:value={passwordEditInput}
      />
      <div class="dialog-actions">
        <button class="create-btn" type="submit">Save</button>
        <button class="cancel-btn" type="button" onclick={cancelPasswordEdit}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .channel-list {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    width: 220px;
    min-width: 160px;
    flex-shrink: 1;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
  }

  .add-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: var(--icon-btn-size-sm);
    height: var(--icon-btn-size-sm);
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 6px;
    cursor: pointer;
  }

  .add-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .create-form {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 8px;
    border-bottom: 1px solid var(--border);
  }

  .create-input {
    padding: 6px 8px;
    font-size: 13px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
  }

  .create-input:focus {
    border-color: var(--accent);
  }

  .create-actions {
    display: flex;
    gap: 6px;
  }

  .create-btn {
    flex: 1;
    padding: 4px 8px;
    font-size: 12px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .create-btn:hover {
    opacity: 0.9;
  }

  .cancel-btn {
    flex: 1;
    padding: 4px 8px;
    font-size: 12px;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
  }

  .cancel-btn:hover {
    color: var(--text-primary);
  }

  .channels {
    flex: 1;
    overflow-y: auto;
    padding: 4px;
  }

  .channel {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 8px 12px;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    font-size: 14px;
    border-radius: 4px;
  }

  .channel:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .channel.active {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .channel.previewing {
    background: var(--bg-hover);
    color: var(--text-primary);
    border: 1px dashed var(--accent);
  }

  .channel-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-secondary);
    width: 18px;
    flex-shrink: 0;
  }

  .channel-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .user-count {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .channel-unread {
    background: var(--accent);
    color: white;
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 600;
    margin-left: auto;
  }

  .settings-icon {
    display: none;
    align-items: center;
    color: var(--text-secondary);
    cursor: pointer;
  }

  .channel:hover .settings-icon {
    display: flex;
  }

  .settings-icon:hover {
    color: var(--text-primary);
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .password-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    min-width: 280px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .dialog-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .dialog-input {
    padding: 8px 10px;
    font-size: 14px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
  }

  .dialog-input:focus {
    border-color: var(--accent);
  }

  .dialog-actions {
    display: flex;
    gap: 8px;
  }

  .dm-section {
    border-top: 1px solid var(--border);
  }

  .dm-header {
    display: flex;
    align-items: center;
    gap: 6px;
    background: rgba(74, 158, 255, 0.05);
  }

  .dm-header-icon {
    display: flex;
    align-items: center;
    color: var(--accent);
    opacity: 0.7;
  }

  .dm-list {
    padding: 4px;
  }

  .dm-entry {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 12px;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    font-size: 13px;
    border-radius: 4px;
  }

  .dm-entry:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dm-entry.active {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .dm-avatar {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    font-weight: 600;
    color: white;
    flex-shrink: 0;
  }

  .dm-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .dm-unread {
    background: var(--accent);
    color: white;
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 600;
  }
</style>
