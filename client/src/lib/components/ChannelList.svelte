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
  import { visibleChannels } from "../stores/roster.js";
  import { isAdmin, serverAddress } from "../stores/connection.js";
  import { account } from "../stores/account.js";
  import { showChatPane } from "../stores/platform.js";
  import {
    activeTextChannelId,
    channelUnread,
    closeDmRow,
    dmList,
    activeDmUserId,
    activeDmUsername,
    joinedTextChannelIds,
    openDm,
    unreadPerChannel,
  } from "../stores/chat.js";
  import { users } from "../stores/users.js";
  import { channelRosters } from "../stores/rosters.js";
  import { uiPrefs } from "../stores/ui-prefs.js";
  import { ago, awayHint, liveIdOf, reach } from "../dm-rules.js";
  import { notificationBody } from "../chat-rules.js";
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
  import { avatarStyle } from "../avatar.js";
  import { shortName } from "../username.js";
  import ChannelCreateForm from "./ChannelCreateForm.svelte";
  import Icon from "./Icons.svelte";
  import { closeRow } from "../actions/focus.js";
  import ChannelTags from "./ChannelTags.svelte";

  let currentChannelName = $derived(
    $channels.find((c) => c.channel_id === $currentChannelId)?.name ?? ""
  );

  // What a direct conversation's "3h" is counted from, while previews show it
  let now = $state(Date.now());
  $effect(() => {
    if (!$uiPrefs.dm_previews) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 60_000);
    return () => clearInterval(timer);
  });
</script>

<div class="channel-list">
  <div class="header">
    <span>Channels</span>
    <span class="header-actions">
      {#if $currentChannelId !== 0}
        <button aria-label="Copy invite link for #{currentChannelName}" class="add-btn" onclick={copyInviteLink} title="Copy invite link for #{currentChannelName}">
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
    {#each $visibleChannels as channel (channel.channel_id)}
      {@const subscribed = channel.text && $joinedTextChannelIds.has(channel.channel_id)}
      {@const left = channel.text && !subscribed && $leftTextChannelNames.has(channel.name)}
      {@const unread = channelUnread($unreadPerChannel, $serverAddress, channel.name)}
      <div class="channel-row">
      <button
        class="channel"
        class:has-actions={subscribed || canEditChannel(channel)}
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
          {#if channel.has_password}
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
        {#if left}
          <span class="proximity-tag" title="You left this channel — click to read, rejoin to write">left</span>
        {/if}
        <ChannelTags {channel} />
        {#if !(channel.hide_members && !$isAdmin)}
          <span class="user-count">({channel.user_count}{#if channel.max_users > 0}/{channel.max_users}{/if})</span>
        {/if}
        {#if unread > 0}
          <span class="channel-unread">{unread}</span>
        {/if}
      </button>
      {#if subscribed || canEditChannel(channel)}
        <span class="row-actions">
          {#if subscribed}
            <button
              class="settings-icon"
              title={channel.log && $account?.cloud ? "Leave this channel: its kept messages stop coming to you; what you have stays" : "Leave this channel"}
              aria-label={channel.log && $account?.cloud ? "Leave this channel: its kept messages stop coming to you; what you have stays" : "Leave this channel"}
              onclick={() => leaveTextChannel(channel.channel_id)}
            ><Icon name="close" size={14} /></button>
          {/if}
          {#if canEditChannel(channel)}
            <button
              class="settings-icon"
              title="Channel settings"
              aria-label="Channel settings"
              onclick={(e) => openChannelSettings(channel.channel_id, e)}
            ><Icon name="channel-settings" size={14} /></button>
          {/if}
        </span>
      {/if}
      </div>
    {/each}
  </div>

  {#if $dmList.length > 0}
    <div class="dm-section">
      <div class="header dm-header">
        <span class="dm-header-icon"><Icon name="direct-message" size={14} /></span>
        <span>Direct messages</span>
      </div>
      <!-- Keyed by name: a person coming back gets a new id, and the row (and
           the focus on it) must stay the same one -->
      <div class="dm-list" role="group" aria-label="Direct messages">
        {#each $dmList as { convo, last } (convo.username)}
          {@const seen = convo.user_id > 0 ? convo.user_id : liveIdOf(convo.username, $users, $channelRosters)}
          {@const r = reach(convo.user_id, seen, convo.account, !!$account?.cloud)}
          {@const who = shortName(convo.username)}
          {@const open = $activeDmUserId !== null && $activeDmUsername === convo.username}
          {@const preview = $uiPrefs.dm_previews && last ? notificationBody(last) : ""}
          <div class="channel-row">
            <button
              class="dm-entry"
              class:active={open}
              class:away={r !== "live"}
              aria-current={open ? "true" : undefined}
              aria-label={[who, r !== "live" && "away", convo.unread > 0 && `${convo.unread} unread`, preview].filter(Boolean).join(", ")}
              title={r !== "live" ? awayHint(who, r) : undefined}
              onclick={() => {
                openDm($serverAddress, seen ?? convo.user_id, convo.username);
                // On a phone this list is a tab or a drawer over the chat
                showChatPane();
              }}
            >
              <span class="dm-avatar" aria-hidden="true" style={avatarStyle(convo.username)}>
                {convo.username.charAt(0).toUpperCase()}
              </span>
              <span class="dm-text">
                <span class="dm-name" title={convo.username}>{who}</span>
                {#if preview}<span class="dm-preview">{preview}</span>{/if}
              </span>
              {#if r !== "live"}<span class="proximity-tag">away</span>{/if}
              {#if $uiPrefs.dm_previews && last}<span class="dm-ago">{ago(last.timestamp, now)}</span>{/if}
              {#if convo.unread > 0}
                <span class="dm-unread">{convo.unread}</span>
              {/if}
            </button>
            <span class="row-actions">
              <button
                class="settings-icon"
                title="Close — the messages are kept"
                aria-label="Close conversation with {who}"
                onclick={(e) => closeRow(e, () => closeDmRow($serverAddress, convo.username))}
              ><Icon name="close" size={14} /></button>
            </span>
          </div>
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
    font-size: var(--fs-micro);
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
    overflow-x: hidden;
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
    font-size: var(--fs-md);
    border-radius: 4px;
    /* Joining is a double click. Without this the page is zoomable, so a
       double tap on a touchscreen is double-tap-to-zoom and the browser never
       delivers dblclick — which made it impossible to join a channel on
       Android at all. */
    touch-action: manipulation;
  }

  .channel:hover,
  .channel-row:hover > .channel {
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
    border: 1px dashed var(--text-muted);
  }

  /* A text channel you are not in: still listed, still readable once joined. */
  .channel.unjoined {
    color: var(--text-muted);
  }

  /* One you walked out of, which the tag beside it says in words. Dimmer
     than merely unjoined, because the difference is a decision you made. */
  .channel.left {
    color: var(--text-muted);
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
    font-size: var(--fs-micro);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .user-count {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .proximity-tag,
  .channel :global(.proximity-tag) {
    font-size: var(--fs-micro);
    font-weight: 600;
    letter-spacing: 0.05em;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid var(--border);
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .channel-unread {
    background: var(--text-primary);
    color: var(--bg-primary);
    font-size: var(--fs-micro);
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 600;
    margin-left: auto;
  }

  /* The row's own controls are buttons beside the row's button, not spans
     inside it: a button in a button is invalid, and Tab never reached them
     (H5-04). They sit over the row's right edge, as they did. */
  .channel-row {
    position: relative;
  }

  .row-actions {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    display: flex;
    gap: 4px;
  }

  .settings-icon {
    display: none;
    align-items: center;
    padding: 2px;
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
  }

  .channel-row:hover .settings-icon,
  .channel-row:focus-within .settings-icon {
    display: flex;
  }

  .channel-row:hover > .channel.has-actions,
  .channel-row:focus-within > .channel.has-actions {
    padding-right: 52px;
  }

  /* A touch screen has no hover: without this the leave ✕ and the settings
     gear exist only while a finger is held on the row, which is not a gesture
     anybody finds. */
  @media (hover: none) {
    .settings-icon {
      display: flex;
    }
    .channel.has-actions {
      padding-right: 52px;
    }
    .dm-entry {
      padding-right: 32px;
    }
  }

  .settings-icon:hover {
    color: var(--text-primary);
  }

  /* Archived conversations make the list long: it scrolls on its own rather
     than squeezing the channels out of the column */
  .dm-section {
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    max-height: 40%;
    min-height: 0;
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
    color: var(--text-secondary);
    opacity: 0.7;
  }

  .dm-list {
    padding: 4px;
    overflow-y: auto;
    overflow-x: hidden;
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
    font-size: var(--fs-body);
    border-radius: 4px;
  }

  .dm-entry:hover,
  .channel-row:hover > .dm-entry {
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
    font-size: var(--fs-body);
    font-weight: 600;
    flex-shrink: 0;
  }

  .dm-text {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }

  .dm-name,
  .dm-preview {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .dm-preview,
  .dm-ago {
    font-size: var(--fs-sm);
    color: var(--text-muted);
  }

  .dm-ago {
    flex-shrink: 0;
  }

  /* Archived, and their person is on no list we see */
  .dm-entry.away .dm-name {
    color: var(--text-muted);
  }

  .dm-entry.away .dm-avatar {
    opacity: 0.5;
  }

  .channel-row:hover > .dm-entry,
  .channel-row:focus-within > .dm-entry {
    padding-right: 32px;
  }

  .dm-unread {
    background: var(--text-primary);
    color: var(--bg-primary);
    font-size: var(--fs-micro);
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 600;
  }
</style>
