<script lang="ts">
  // The modern layout's channel list: a flat list of rows with the people in
  // each channel nested under it.
  //
  // The names are *asked* for rather than pushed. A `UserJoined` broadcast goes
  // to every session — it doubles as the user-count update — but it carries an
  // empty username to anyone outside the channel it names, so that moving
  // between an anonymous channel and an ordinary one cannot hand outsiders both
  // names for the same person. stores/rosters.ts does the asking, through the
  // one query the server already answers carefully: a channel that hides its
  // members or carries a password is refused to anyone not in it, and an
  // anonymous one answers with its pseudonyms unless the asker is an admin.
  //
  // So a row shows what this client is *allowed* to know, which for most rows is
  // everybody and for some is nobody. That decision stays on the server.
  //
  // A click previews a channel and a double click joins it, the same as the
  // classic sidebar: both go through the same functions in
  // stores/channel-ui.ts, so the two layouts cannot drift on what a click does.

  import { channels, currentChannelId, previewChannelId } from "../../stores/channels.js";
  import { channelRosters } from "../../stores/rosters.js";
  import { rosterForRow } from "../../roster-rules.js";
  import { userId, isAdmin } from "../../stores/connection.js";
  import {
    activeDmUserId,
    activeTextChannelId,
    channelUnread,
    dmConversations,
    joinedTextChannelIds,
    openDm,
    unreadPerChannel,
  } from "../../stores/chat.js";
  import {
    canEditChannel,
    joinChannel,
    leaveTextChannel,
    leftTextChannelNames,
    openChannelSettings,
    selectChannel,
    showCreateForm,
  } from "../../stores/channel-ui.js";
  import { users, speakingUsers } from "../../stores/users.js";
  import { audibleIds } from "../../stores/room.js";
  import { isCulled } from "../../stores/roster.js";
  import { openUserMenu } from "../../stores/user-menu.js";
  import { avatarColor } from "../../avatar.js";
  import ChannelCreateForm from "../ChannelCreateForm.svelte";
  import Icon from "../Icons.svelte";
  import type { ChannelInfo, UserInfo } from "../../types.js";

  // A hidden channel is not listed, unless you are an admin or standing in it
  const visibleChannels = $derived(
    $channels.filter((c) => !c.hidden || $isAdmin || c.channel_id === $currentChannelId),
  );

  // Text above voice, the way Discord groups them. A text channel has no
  // members nested under it: its subscribers are in voice channels of their
  // own, and listing them twice would say they are in two places at once.
  const textChannels = $derived(visibleChannels.filter((c) => c.text));
  const voiceChannels = $derived(visibleChannels.filter((c) => !c.text));

  /** The members this client is allowed to show under a row. */
  function membersOf(channel: ChannelInfo): UserInfo[] {
    // Per row, with that row's own hide-members rule — see roster-rules.ts.
    // The panel-wide `hideMembers` belongs to whichever channel the member list
    // is showing, which follows the text channel the user opened, and applying
    // it here emptied the voice room they are standing in.
    return rosterForRow(channel, $channelRosters, $currentChannelId, $users, $isAdmin);
  }
</script>

<div class="channel-list modern">
  <div class="sidebar-head">
    <span class="sidebar-title">Channels</span>
    <button
      class="add-btn"
      onclick={() => showCreateForm.update((v) => !v)}
      title="Create channel"
    >
      <Icon name="plus" size={18} />
    </button>
  </div>

  <ChannelCreateForm />

  {#if textChannels.length > 0}
    <div class="sidebar-head">
      <span class="sidebar-title">Text channels</span>
    </div>
    <!-- `text`/`voice` name the two groups for test-ui.mjs, which has to click
         a voice row and a text row and mean different things by each. -->
    <div class="channels text">
      {#each textChannels as channel (channel.channel_id)}
        {@const subscribed = $joinedTextChannelIds.has(channel.channel_id)}
        {@const left = !subscribed && $leftTextChannelNames.has(channel.name)}
        {@const unread = channelUnread($unreadPerChannel, channel.name)}
        <button
          class="channel"
          class:active={$activeTextChannelId === channel.channel_id}
          class:unjoined={!subscribed}
          class:left
          onclick={() => selectChannel(channel)}
          title={subscribed ? undefined : "Click to read it; joining is a button in the chat pane"}
        >
          <span class="channel-icon"><Icon name="hash" size={18} /></span>
          <span class="channel-name">{channel.name}</span>

          {#if left}
            <span class="proximity-tag" title="You left this channel — click to read, rejoin to write">left</span>
          {/if}
          {#if !(channel.hide_members && !$isAdmin)}
            <span class="user-count">{channel.user_count}</span>
          {/if}
          {#if channel.has_password}
            <span class="channel-icon"><Icon name="lock" size={14} /></span>
          {/if}
          {#if channel.anonymous}
            <span class="proximity-tag" title="Anonymous: members see each other under random names">?</span>
          {/if}
          {#if channel.hidden}
            <span class="proximity-tag" title="Hidden: only admins see this channel in the list">H</span>
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
              ><Icon name="close" size={14} /></span
            >
          {/if}
          {#if canEditChannel(channel)}
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <span
              class="settings-icon"
              title="Channel settings"
              role="button"
              tabindex="-1"
              onclick={(e) => openChannelSettings(channel.channel_id, e)}
              ><Icon name="channel-settings" size={14} /></span
            >
          {/if}
        </button>
      {/each}
    </div>

    <div class="sidebar-head">
      <span class="sidebar-title">Voice channels</span>
    </div>
  {/if}

  <div class="channels voice">
    {#each voiceChannels as channel (channel.channel_id)}
      {@const joined = channel.channel_id === $currentChannelId}
      {@const members = membersOf(channel)}
      {@const unread = channelUnread($unreadPerChannel, channel.name)}
      <button
        class="channel"
        class:active={joined}
        class:previewing={channel.channel_id === $previewChannelId && !joined}
        onclick={() => selectChannel(channel)}
        ondblclick={() => joinChannel(channel.channel_id, channel.has_password)}
        title={joined ? "Click to show its chat" : "Click to look, double click to join"}
      >
        <span class="channel-icon">
          {#if channel.channel_id === 0}
            <Icon name="lobby" size={18} />
          {:else if channel.has_password}
            <Icon name="lock" size={18} />
          {:else}
            <Icon name="speaker" size={18} />
          {/if}
        </span>
        <span class="channel-name">{channel.name}</span>

        {#if channel.proximity !== "off"}
          <span class="proximity-tag" title="Proximity chat: you hear people where they stand"
            >{channel.proximity.toUpperCase()}</span
          >
        {/if}
        {#if channel.anonymous}
          <span class="proximity-tag" title="Anonymous: members see each other under random names">?</span>
        {/if}
        {#if channel.hidden}
          <span class="proximity-tag" title="Hidden: only admins see this channel in the list">H</span>
        {/if}
        {#if channel.routed}
          <span
            class="proximity-tag"
            title="Routed: the server is told which members you want to hear, and forwards only their voice"
            >R</span
          >
        {/if}

        {#if unread > 0}
          <span class="channel-unread">{unread}</span>
        {/if}
        {#if !(channel.hide_members && !$isAdmin)}
          <span class="user-count">{channel.user_count}</span>
        {/if}
        {#if canEditChannel(channel)}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <span
            class="settings-icon"
            title="Channel settings"
            role="button"
            tabindex="-1"
            onclick={(e) => openChannelSettings(channel.channel_id, e)}><Icon name="channel-settings" size={14} /></span
          >
        {/if}
      </button>

      {#if members.length > 0}
        <div class="nested">
          {#each members as member (member.user_id)}
            <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
            <div
              class="nested-member"
              class:speaking={joined && $speakingUsers.has(member.user_id)}
              class:culled={isCulled(member.user_id, $audibleIds, $userId, !joined)}
              oncontextmenu={(e) => {
                e.preventDefault();
                e.stopPropagation();
                openUserMenu(member, e.clientX, e.clientY);
              }}
            >
              <span class="nested-avatar" style="background: {avatarColor(member.username)}"
                >{member.username.charAt(0).toUpperCase()}</span
              >
              <span class="nested-name">{member.username}</span>
              {#if member.is_muted}
                <span class="status-icon muted" title="Muted"><Icon name="mic-off" size={12} /></span>
              {/if}
              {#if member.is_deafened}
                <span class="status-icon deafened" title="Deafened"><Icon name="headphones-off" size={12} /></span>
              {/if}
              {#if member.is_screen_sharing}
                <span class="live-tag" title="Sharing screen">LIVE</span>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    {/each}
  </div>

  {#if $dmConversations.length > 0}
    <div class="dm-section">
      <div class="sidebar-head">
        <span class="sidebar-title">Direct Messages</span>
      </div>
      <div class="dm-list">
        {#each $dmConversations as convo (convo.user_id)}
          <button
            class="dm-entry"
            class:active={$activeDmUserId === convo.user_id}
            onclick={() => openDm(convo.user_id, convo.username, $userId)}
          >
            <span class="dm-avatar" style="background: {avatarColor(convo.username)}"
              >{convo.username.charAt(0).toUpperCase()}</span
            >
            <span class="dm-name">{convo.username}</span>
            {#if convo.unread > 0}<span class="dm-unread">{convo.unread}</span>{/if}
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .channel-list.modern {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
    width: 100%;
    background: var(--bg-secondary);
    overflow-y: auto;
    padding-bottom: 8px;
  }

  .sidebar-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 8px 4px 16px;
  }

  .sidebar-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text-secondary);
  }

  .add-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
  }

  .add-btn:hover {
    color: var(--text-primary);
  }

  .channels {
    display: flex;
    flex-direction: column;
    padding: 0 8px;
  }

  .channel {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 6px 8px;
    margin-top: 1px;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    font-size: 15px;
    border-radius: 4px;
    /* `manipulation` keeps the double click that joins while dropping the
       300ms double-tap-to-zoom delay a tap would otherwise pay. */
    touch-action: manipulation;
  }

  .channel:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .channel.active {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .channel.previewing {
    color: var(--text-primary);
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
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .channel-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .proximity-tag {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 1px 4px;
    border-radius: 4px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .user-count {
    font-size: 12px;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .channel-unread {
    min-width: 16px;
    padding: 0 5px;
    border-radius: 8px;
    background: var(--danger);
    color: #fff;
    font-size: 11px;
    font-weight: 700;
    text-align: center;
    flex-shrink: 0;
  }

  .settings-icon {
    display: none;
    align-items: center;
    color: var(--text-secondary);
    flex-shrink: 0;
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

  .nested {
    display: flex;
    flex-direction: column;
    padding-left: 22px;
  }

  .nested-member {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 14px;
    color: var(--text-secondary);
  }

  .nested-member:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* A game says who is in earshot by leaving everyone else out — shown rather
     than hidden, for the same reason as in the classic member list. */
  .nested-member.culled {
    opacity: 0.45;
  }

  .nested-avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    color: #fff;
    font-size: 11px;
    font-weight: 600;
    flex-shrink: 0;
    transition: box-shadow 0.1s;
  }

  .nested-member.speaking .nested-avatar {
    box-shadow: 0 0 0 2px var(--speaking);
  }

  .nested-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .status-icon {
    display: flex;
    flex-shrink: 0;
  }

  .status-icon.muted {
    color: var(--danger);
  }

  .status-icon.deafened {
    color: var(--warning);
  }

  .live-tag {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 1px 4px;
    border-radius: 4px;
    border: 1px solid var(--danger);
    color: var(--danger);
    flex-shrink: 0;
  }

  .dm-section {
    border-top: 1px solid var(--border);
    margin-top: 8px;
  }

  .dm-list {
    display: flex;
    flex-direction: column;
    padding: 0 8px;
  }

  .dm-entry {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 8px;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    font-size: 15px;
    border-radius: 4px;
  }

  .dm-entry:hover,
  .dm-entry.active {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dm-avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    color: #fff;
    font-size: 11px;
    font-weight: 600;
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
    min-width: 16px;
    padding: 0 5px;
    border-radius: 8px;
    background: var(--danger);
    color: #fff;
    font-size: 11px;
    font-weight: 700;
    text-align: center;
  }
</style>
