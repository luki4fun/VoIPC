<script lang="ts">
  // The channel sidebar of the classic layout: rows, and the direct-message
  // list underneath them.
  //
  // Click looks — at a channel's members and its chat — and the way in is a
  // button in the pane that click just opened. A double click still joins a
  // voice row, for the hands that have always done it that way; a phone has no
  // such gesture, which is why it cannot be the only way in. The modern sidebar
  // does the same, through the same functions in stores/channel-ui.ts.
  //
  // The class names here are driven by test-ui.mjs (`.channel`, `.channel-name`,
  // `.proximity-tag`, `.settings-icon`, `.channel-list`) and the modern sidebar
  // keeps them too, so the same checks can run against either layout.

  import { channels, currentChannelId, previewChannelId } from "../stores/channels.js";
  import { userId, isAdmin } from "../stores/connection.js";
  import {
    activeTextChannelId,
    channelUnread,
    dmConversations,
    activeDmUserId,
    joinedTextChannelIds,
    openDm,
    unreadPerChannel,
  } from "../stores/chat.js";
  import {
    canEditChannel,
    copyInviteLink,
    joinChannel,
    leaveTextChannel,
    leftTextChannelNames,
    openChannelSettings,
    selectChannel,
    showCreateForm,
  } from "../stores/channel-ui.js";
  import { avatarColor } from "../avatar.js";
  import ChannelCreateForm from "./ChannelCreateForm.svelte";
  import Icon from "./Icons.svelte";

  let currentChannelName = $derived(
    $channels.find((c) => c.channel_id === $currentChannelId)?.name ?? ""
  );

  // A hidden channel is not listed, unless you are an admin or standing in it
  let visibleChannels = $derived(
    $channels.filter(
      (c) => !c.hidden || $isAdmin || c.channel_id === $currentChannelId,
    ),
  );
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
      <button class="add-btn" onclick={() => showCreateForm.update((v) => !v)} title="Create channel">
        <Icon name="plus" size={18} />
      </button>
    </span>
  </div>
  <ChannelCreateForm />


  <div class="channels">
    {#each visibleChannels as channel (channel.channel_id)}
      {@const subscribed = channel.text && $joinedTextChannelIds.has(channel.channel_id)}
      {@const left = channel.text && !subscribed && $leftTextChannelNames.has(channel.name)}
      {@const unread = channelUnread($unreadPerChannel, channel.name)}
      <button
        class="channel"
        class:active={channel.text
          ? $activeTextChannelId === channel.channel_id
          : channel.channel_id === $currentChannelId}
        class:unjoined={channel.text && !subscribed}
        class:left
        title={channel.channel_id === $currentChannelId || subscribed
          ? undefined
          : "Click to look; joining is a button in the chat pane"}
        class:previewing={!channel.text &&
          channel.channel_id === $previewChannelId &&
          channel.channel_id !== $currentChannelId}
        onclick={() => selectChannel(channel)}
        ondblclick={() =>
          channel.text ? undefined : joinChannel(channel.channel_id, channel.has_password)}
      >
        <span class="channel-icon">
          {#if channel.channel_id === 0}
            <Icon name="lobby" size={16} />
          {:else if channel.has_password}
            <Icon name="lock" size={16} />
          {:else if channel.text}
            <Icon name="hash" size={16} />
          {:else}
            <Icon name="speaker" size={16} />
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
        {#if left}
          <span class="proximity-tag" title="You left this channel — click to read, rejoin to write">left</span>
        {/if}
        {#if channel.routed}
          <span
            class="proximity-tag"
            title="Routed: the server is told which members you want to hear, and forwards only their voice"
            >R</span
          >
        {/if}
        {#if !(channel.hide_members && !$isAdmin)}
          <span class="user-count">({channel.user_count}{#if channel.max_users > 0}/{channel.max_users}{/if})</span>
        {/if}
        {#if unread > 0}
          <span class="channel-unread">{unread}</span>
        {/if}
        {#if subscribed}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <span
            class="settings-icon"
            title="Leave this channel"
            role="button"
            tabindex="-1"
            onclick={(e) => { e.stopPropagation(); leaveTextChannel(channel.channel_id); }}
          ><Icon name="close" size={14} /></span>
        {/if}
        {#if canEditChannel(channel)}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <span
            class="settings-icon"
            title="Channel settings"
            role="button"
            tabindex="-1"
            onclick={(e) => openChannelSettings(channel.channel_id, e)}
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

<style>
  .channel-list {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    /* Set by whichever shell is on screen, so a width dragged in one layout is
       not the width the other one gets. The fallback is the value this was
       before it became a variable. */
    width: var(--sidebar-width, 220px);
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

  /* A text channel you are not in: still listed, still readable once joined. */
  .channel.unjoined {
    opacity: 0.6;
  }

  /* One you walked out of, which the tag beside it says in words. Dimmer
     than merely unjoined, because the difference is a decision you made. */
  .channel.left {
    opacity: 0.45;
    font-style: italic;
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

  /* A touch screen has no hover: without this the leave ✕ and the settings
     gear exist only while a finger is held on the row, which is not a gesture
     anybody finds. */
  @media (hover: none) {
    .settings-icon {
      display: flex;
    }
  }

  .settings-icon:hover {
    color: var(--text-primary);
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
