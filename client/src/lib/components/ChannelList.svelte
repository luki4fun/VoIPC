<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "../stores/channels.js";
  import { userId, serverAddress, channelPasswords } from "../stores/connection.js";
  import { addNotification } from "../stores/notifications.js";
  import { dmConversations, activeDmUserId, openDm, closeDm, unreadPerChannel, clearChannelUnread } from "../stores/chat.js";
  import { buildInviteLink, splitAddress } from "../invite.js";
  import { avatarColor } from "../avatar.js";
  import { isAdmin } from "../stores/connection.js";
  import Icon from "./Icons.svelte";
  import type { ProximityMode } from "../spatial.js";
  import type { ChannelInfo } from "../types.js";

  let currentChannelName = $derived(
    $channels.find((c) => c.channel_id === $currentChannelId)?.name ?? ""
  );

  // Invite link for the current channel; the password rides along only when
  // this session knows it (created the channel or joined with it)
  let inviteLinkPopup = $state<string | null>(null);

  async function copyInviteLink() {
    const ch = $channels.find((c) => c.channel_id === $currentChannelId);
    if (!ch || ch.channel_id === 0) return;
    const { host, port } = splitAddress($serverAddress);
    const password = ch.has_password ? ($channelPasswords.get(ch.name) ?? null) : null;
    const link = buildInviteLink(host, port, ch.name, password);
    if (ch.has_password && !password) {
      addNotification("This session does not know the channel password — the link will ask the joiner for it", "warning");
    }
    try {
      await navigator.clipboard.writeText(link);
      addNotification("Invite link copied", "info", 2500);
    } catch {
      inviteLinkPopup = link; // clipboard blocked: show it for manual copy
    }
  }

  let showCreateForm = $state(false);
  let newChannelName = $state("");
  let newChannelPassword = $state("");
  let newChannelProximity = $state<ProximityMode>("off");
  let newChannelAnonymous = $state(false);

  // A hidden channel is not listed, unless you are an admin or standing in it
  let visibleChannels = $derived(
    $channels.filter(
      (c) => !c.hidden || $isAdmin || c.channel_id === $currentChannelId,
    ),
  );

  // Password prompt state (for joining)
  let passwordPromptChannelId = $state<number | null>(null);
  let passwordPromptInput = $state("");

  // Password change dialog state (for channel creators)
  let passwordEditChannelId = $state<number | null>(null);
  let passwordEditInput = $state("");


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
      addNotification(`Failed to join channel: ${e}`, "error");
    }
  }

  async function submitPasswordJoin() {
    if (passwordPromptChannelId === null) return;
    try {
      await invoke("join_channel", {
        channelId: passwordPromptChannelId,
        password: passwordPromptInput || null,
      });
      const chName = $channels.find((c) => c.channel_id === passwordPromptChannelId)?.name;
      if (chName && passwordPromptInput) {
        const pw = passwordPromptInput;
        channelPasswords.update((m) => new Map(m).set(chName, pw));
      }
      passwordPromptChannelId = null;
      passwordPromptInput = "";
    } catch (e) {
      console.error("Failed to join channel:", e);
      addNotification(`Failed to join channel: ${e}`, "error");
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
        proximity: newChannelProximity,
        anonymous: newChannelAnonymous,
      });
      if (newChannelPassword) {
        const pw = newChannelPassword;
        channelPasswords.update((m) => new Map(m).set(name, pw));
      }
      newChannelName = "";
      newChannelPassword = "";
      newChannelProximity = "off";
      newChannelAnonymous = false;
      showCreateForm = false;
    } catch (e) {
      console.error("Failed to create channel:", e);
      addNotification(`Failed to create channel: ${e}`, "error");
    }
  }

  function cancelCreate() {
    newChannelName = "";
    newChannelPassword = "";
    newChannelProximity = "off";
    newChannelAnonymous = false;
    showCreateForm = false;
  }

  // Channel settings: password and proximity mode. The server lets the
  // creator (or any admin) change these; channels from channels.json have no
  // creator, so those are admin-only.
  let settingsProximity = $state<ProximityMode>("off");

  function canEditChannel(channel: { channel_id: number; created_by: number | null }): boolean {
    return channel.channel_id !== 0 && (channel.created_by === $userId || $isAdmin);
  }

  /** Does the edited channel have a password right now? */
  let passwordEditHasPassword = $state(false);
  /** Explicit "remove the password" choice; an empty field alone means "leave it". */
  let passwordEditRemove = $state(false);
  // The other options, seeded from the channel so only real changes are sent
  let settingsHidden = $state(false);
  let settingsAnonymous = $state(false);
  let settingsScreenShare = $state(true);
  let settingsHideMembers = $state(false);
  let settingsBefore: ChannelInfo | null = null;

  function openPasswordEdit(channelId: number, e: Event) {
    e.stopPropagation();
    const channel = $channels.find((c) => c.channel_id === channelId);
    passwordEditChannelId = channelId;
    // Leave input empty — an empty field keeps the current password
    passwordEditInput = "";
    passwordEditRemove = false;
    passwordEditHasPassword = channel?.has_password ?? false;
    settingsProximity = channel?.proximity ?? "off";
    settingsHidden = channel?.hidden ?? false;
    settingsAnonymous = channel?.anonymous ?? false;
    settingsScreenShare = channel?.screen_share ?? true;
    settingsHideMembers = channel?.hide_members ?? false;
    settingsBefore = channel ?? null;
  }

  async function submitPasswordEdit() {
    if (passwordEditChannelId === null) return;
    const channelId = passwordEditChannelId;
    const before = $channels.find((c) => c.channel_id === channelId)?.proximity ?? "off";
    try {
      // Only touch the password when the user actually asked to: saving this
      // dialog to change the proximity mode must not drop it
      if (passwordEditRemove || passwordEditInput) {
        await invoke("set_channel_password", {
          channelId,
          password: passwordEditRemove ? null : passwordEditInput,
        });
        const chName = $channels.find((c) => c.channel_id === channelId)?.name;
        if (chName) {
          channelPasswords.update((m) => {
            const next = new Map(m);
            if (passwordEditRemove) next.delete(chName);
            else next.set(chName, passwordEditInput);
            return next;
          });
        }
      }
      if (settingsProximity !== before) {
        await invoke("set_channel_proximity", { channelId, proximity: settingsProximity });
      }
      // Only what actually changed; null leaves an option alone
      const was = settingsBefore;
      const changed = <T>(now: T, then: T | undefined) => (now === then ? null : now);
      if (
        was &&
        (settingsHidden !== was.hidden ||
          settingsAnonymous !== was.anonymous ||
          settingsScreenShare !== was.screen_share ||
          settingsHideMembers !== was.hide_members)
      ) {
        await invoke("set_channel_options", {
          channelId,
          hidden: changed(settingsHidden, was.hidden),
          anonymous: changed(settingsAnonymous, was.anonymous),
          screenShare: changed(settingsScreenShare, was.screen_share),
          hideMembers: changed(settingsHideMembers, was.hide_members),
        });
      }
      passwordEditChannelId = null;
      passwordEditInput = "";
      passwordEditRemove = false;
    } catch (e) {
      console.error("Failed to change channel settings:", e);
      addNotification(`Failed to change channel settings: ${e}`, "error");
    }
  }

  function cancelPasswordEdit() {
    passwordEditChannelId = null;
    passwordEditInput = "";
    passwordEditRemove = false;
  }
</script>

<div class="channel-list">
  <div class="header">
    <span>Channels</span>
    <span class="header-actions">
      {#if $currentChannelId !== 0}
        <button class="add-btn" onclick={copyInviteLink} title="Copy invite link for #{currentChannelName}">
          <Icon name="link" size={16} />
        </button>
      {/if}
      <button class="add-btn" onclick={() => (showCreateForm = !showCreateForm)} title="Create channel">
        <Icon name="plus" size={18} />
      </button>
    </span>
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
      <label class="create-label">
        Proximity chat
        <select class="create-input" bind:value={newChannelProximity}>
          <option value="off">Off — everyone equally loud</option>
          <option value="2d">2D — on a floor plan</option>
          <option value="3d">3D — height counts too</option>
        </select>
      </label>
      <label class="dialog-check">
        <input type="checkbox" bind:checked={newChannelAnonymous} />
        Anonymous (everyone gets a random name)
      </label>
      <div class="create-actions">
        <button class="create-btn" type="submit">Create</button>
        <button class="cancel-btn" type="button" onclick={cancelCreate}>Cancel</button>
      </div>
    </form>
  {/if}

  <div class="channels">
    {#each visibleChannels as channel (channel.channel_id)}
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
        <span class="channel-name-col">
          <span class="channel-name">{channel.name}</span>
          {#if channel.description}
            <span class="channel-desc">{channel.description}</span>
          {/if}
        </span>
        {#if channel.proximity !== "off"}
          <span class="proximity-tag" title="Proximity chat: you hear people where they stand">
            {channel.proximity.toUpperCase()}
          </span>
        {/if}
        {#if channel.anonymous}
          <span class="proximity-tag" title="Anonymous: members see each other under random names">?</span>
        {/if}
        {#if channel.hidden}
          <span class="proximity-tag" title="Hidden: only admins see this channel in the list">H</span>
        {/if}
        {#if !(channel.hide_members && !$isAdmin)}
          <span class="user-count">({channel.user_count}{#if channel.max_users > 0}/{channel.max_users}{/if})</span>
        {/if}
        {#if ($unreadPerChannel.get(channel.name) ?? 0) > 0}
          <span class="channel-unread">{$unreadPerChannel.get(channel.name)}</span>
        {/if}
        {#if canEditChannel(channel)}
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

{#if inviteLinkPopup !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={() => (inviteLinkPopup = null)} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="password-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="dialog-title">Invite link</div>
      <input class="dialog-input" readonly value={inviteLinkPopup} onfocus={(e) => e.currentTarget.select()} />
      <div class="dialog-actions">
        <button class="cancel-btn" type="button" onclick={() => (inviteLinkPopup = null)}>Close</button>
      </div>
    </div>
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
      <div class="dialog-title">Channel Settings</div>
      <input
        class="dialog-input"
        type="password"
        placeholder={passwordEditHasPassword ? "New password (empty: keep current)" : "Set a password (optional)"}
        bind:value={passwordEditInput}
        disabled={passwordEditRemove}
      />
      {#if passwordEditHasPassword}
        <label class="dialog-check">
          <input type="checkbox" bind:checked={passwordEditRemove} />
          Remove the password
        </label>
      {/if}
      <label class="dialog-label">
        Proximity chat
        <select class="dialog-input" bind:value={settingsProximity}>
          <option value="off">Off — everyone equally loud</option>
          <option value="2d">2D — on a floor plan</option>
          <option value="3d">3D — height counts too</option>
        </select>
      </label>
      <label class="dialog-check">
        <input type="checkbox" bind:checked={settingsHidden} />
        Hidden — not listed for anyone but admins
      </label>
      <label class="dialog-check">
        <input type="checkbox" bind:checked={settingsAnonymous} />
        Anonymous — random names instead of real ones
      </label>
      <label class="dialog-check">
        <input type="checkbox" bind:checked={settingsHideMembers} />
        Hide members — non-admins see only who is speaking
      </label>
      <label class="dialog-check">
        <input type="checkbox" bind:checked={settingsScreenShare} />
        Allow screen sharing
      </label>
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
    /* Joining is a double click. Without this the page is zoomable, so a
       double tap on a touchscreen is double-tap-to-zoom and the browser never
       delivers dblclick — which made it impossible to join a channel on
       Android at all. */
    touch-action: manipulation;
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

  .channel-name-col {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-width: 0;
  }

  .channel-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .channel-desc {
    font-size: 11px;
    color: var(--text-secondary);
    opacity: 0.7;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .user-count {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .proximity-tag {
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 0.05em;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid var(--border);
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .create-label,
  .dialog-label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .dialog-check {
    display: flex;
    align-items: center;
    gap: 6px;
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

  .header-actions {
    display: flex;
    gap: 4px;
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
