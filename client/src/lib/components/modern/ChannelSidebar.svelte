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
  // A click previews a channel; the way in is a button in the pane it opens,
  // with a double click on the row as the desktop shortcut. The classic sidebar
  // behaves the same, through the same functions in stores/channel-ui.ts, so
  // the two layouts cannot drift on what a click does.

  import {
    currentChannelId,
    previewChannelId,
    viewingVoice,
  } from "../../stores/channels.js";
  import { channelRosters } from "../../stores/rosters.js";
  import { rosterForRow } from "../../roster-rules.js";
  import { userId, isAdmin, serverAddress } from "../../stores/connection.js";
  import { account } from "../../stores/account.js";
  import { showChatPane } from "../../stores/platform.js";
  import {
    activeDmUserId,
    activeDmUsername,
    activeTextChannelId,
    channelUnread,
    closeDmRow,
    dmList,
    joinedTextChannelIds,
    openDm,
    unreadPerChannel,
  } from "../../stores/chat.js";
  import { ago, awayHint, liveIdOf, reach } from "../../dm-rules.js";
  import { notificationBody } from "../../chat-rules.js";
  import { uiPrefs } from "../../stores/ui-prefs.js";
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
  import { isCulled, visibleChannels } from "../../stores/roster.js";
  import { openShare } from "../../stores/user-menu.js";
  import { memberMenu } from "../../actions/member-menu.js";
  import { avatarStyle } from "../../avatar.js";
  import { shortName } from "../../username.js";
  import ChannelCreateForm from "../ChannelCreateForm.svelte";
  import Icon from "../Icons.svelte";
  import ChannelTags from "../ChannelTags.svelte";
  import type { ChannelInfo, UserInfo } from "../../types.js";


  // Text above voice, the way Discord groups them. A text channel has no
  // members nested under it: its subscribers are in voice channels of their
  // own, and listing them twice would say they are in two places at once.
  // Which channels are listed at all: stores/roster.ts `visibleChannels`
  const textChannels = $derived($visibleChannels.filter((c) => c.text));
  const voiceChannels = $derived($visibleChannels.filter((c) => !c.text));

  // What a direct conversation's "3h" is counted from, while previews show it
  let now = $state(Date.now());
  $effect(() => {
    if (!$uiPrefs.dm_previews) return;
    now = Date.now();
    const timer = setInterval(() => (now = Date.now()), 60_000);
    return () => clearInterval(timer);
  });

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
        {@const unread = channelUnread($unreadPerChannel, $serverAddress, channel.name)}
        <div class="channel-row">
        <button
          class="channel"
          class:has-actions={subscribed || canEditChannel(channel)}
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
          <ChannelTags {channel} />
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

    <div class="sidebar-head">
      <span class="sidebar-title">Voice channels</span>
    </div>
  {/if}

  <div class="channels voice">
    {#each voiceChannels as channel (channel.channel_id)}
      {@const joined = channel.channel_id === $currentChannelId}
      {@const members = membersOf(channel)}
      {@const unread = channelUnread($unreadPerChannel, $serverAddress, channel.name)}
      <div class="channel-row">
      <button
        class="channel"
        class:has-actions={canEditChannel(channel)}
        class:active={joined}
        class:previewing={channel.channel_id === $previewChannelId && !joined}
        onclick={() => selectChannel(channel)}
        ondblclick={() => joinChannel(channel.channel_id, channel.has_password)}
        title={joined ? "Click to show its chat" : "Click to look; joining is a button in the chat pane"}
      >
        <span class="channel-icon">
          {#if channel.has_password}
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
        <ChannelTags {channel} />

        {#if unread > 0}
          <span class="channel-unread">{unread}</span>
        {/if}
        {#if !(channel.hide_members && !$isAdmin)}
          <span class="user-count">{channel.user_count}</span>
        {/if}
      </button>
      {#if canEditChannel(channel)}
        <span class="row-actions">
          <button
            class="settings-icon"
            title="Channel settings"
            aria-label="Channel settings"
            onclick={(e) => openChannelSettings(channel.channel_id, e)}
          ><Icon name="channel-settings" size={14} /></button>
        </span>
      {/if}
      </div>

      {#if members.length > 0}
        <div class="nested">
          {#each members as member (member.user_id)}
            <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
            <div
              class="nested-member"
              class:speaking={joined && $viewingVoice && $speakingUsers.has(member.user_id)}
              class:culled={isCulled(member.user_id, $audibleIds, $userId, !joined || !$viewingVoice)}
              use:memberMenu={{ user: member, self: member.user_id === $userId }}
            >
              <span class="nested-avatar" style={avatarStyle(member.username)}
                >{member.username.charAt(0).toUpperCase()}</span
              >
              <span class="nested-name" title={member.username}>{shortName(member.username)}</span>
              {#if member.is_muted}
                <span class="status-icon muted" title="Muted"><Icon name="mic-off" size={12} /></span>
              {/if}
              {#if member.is_deafened}
                <span class="status-icon deafened" title="Deafened"><Icon name="headphones-off" size={12} /></span>
              {/if}
              {#if member.is_screen_sharing}
                <!-- One click watches, in the call we are in; elsewhere a marker -->
                {#if joined && $viewingVoice}
                  <button
                    class="live-tag watch"
                    title={member.user_id === $userId ? "Show what you are sharing" : "Watch the stream"}
                    onclick={(e) => {
                      e.stopPropagation();
                      openShare(member.user_id);
                    }}>LIVE</button
                  >
                {:else}
                  <span class="live-tag" title="Sharing screen">LIVE</span>
                {/if}
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    {/each}
  </div>

  {#if $dmList.length > 0}
    <div class="dm-section">
      <div class="sidebar-head">
        <span class="sidebar-title">Direct messages</span>
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
                // On a phone this list is a drawer over the chat
                showChatPane();
              }}
            >
              <span class="dm-avatar" aria-hidden="true" style={avatarStyle(convo.username)}
                >{convo.username.charAt(0).toUpperCase()}</span
              >
              <span class="dm-text">
                <span class="dm-name" title={convo.username}>{who}</span>
                {#if preview}<span class="dm-preview">{preview}</span>{/if}
              </span>
              {#if r !== "live"}<span class="proximity-tag">away</span>{/if}
              {#if $uiPrefs.dm_previews && last}<span class="dm-ago">{ago(last.timestamp, now)}</span>{/if}
              {#if convo.unread > 0}<span class="dm-unread">{convo.unread}</span>{/if}
            </button>
            <span class="row-actions">
              <button
                class="settings-icon"
                title="Close — the messages are kept"
                aria-label="Close conversation with {who}"
                onclick={() => closeDmRow($serverAddress, convo.username)}
              ><Icon name="close" size={14} /></button>
            </span>
          </div>
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
    /* overflow-y alone makes x scroll too: a long name is cut, not panned */
    overflow-x: hidden;
    padding-bottom: 8px;
  }

  .sidebar-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 8px 4px 16px;
  }

  .sidebar-title {
    font-size: var(--fs-micro);
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

  .channel:hover,
  .channel-row:hover > .channel {
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

  .proximity-tag,
  .channel :global(.proximity-tag) {
    font-size: var(--fs-micro);
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 1px 4px;
    border-radius: 4px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .user-count {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .channel-unread {
    min-width: 16px;
    padding: 0 5px;
    border-radius: 8px;
    background: var(--danger);
    color: var(--on-danger);
    font-size: var(--fs-micro);
    font-weight: 700;
    text-align: center;
    flex-shrink: 0;
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
    font-size: var(--fs-md);
    color: var(--text-secondary);
  }

  .nested-member:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* A game says who is in earshot by leaving everyone else out — shown rather
     than hidden, for the same reason as in the classic member list. */
  .nested-member.culled {
    color: var(--text-muted);
  }

  .nested-member.culled .nested-avatar {
    opacity: 0.5;
  }

  .nested-avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    font-size: var(--fs-micro);
    font-weight: 600;
    flex-shrink: 0;
    transition: box-shadow var(--dur-fast);
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

  /* A share going out is live, so mint, filled: the same pill as Stage's
     Watch button, and the on-accent pair is the one tested at 4.5:1 on every
     palette (accent as bare text is only held to 3:1) */
  .live-tag {
    font-size: var(--fs-micro);
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 1px 5px;
    border-radius: 4px;
    border: none;
    background: var(--accent);
    color: var(--on-accent);
    flex-shrink: 0;
  }

  button.live-tag {
    line-height: inherit;
  }

  button.live-tag:hover {
    background: var(--accent-hover);
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
  .channel-row:hover > .dm-entry,
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
    font-size: var(--fs-micro);
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

  /* Archived, and their person is on no list we see: as "out of earshot" is */
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
    min-width: 16px;
    padding: 0 5px;
    border-radius: 8px;
    background: var(--danger);
    color: var(--on-danger);
    font-size: var(--fs-micro);
    font-weight: 700;
    text-align: center;
  }

  /* ── Touch ── 44px to aim at (--hit). The rows grow rather than their icons
     growing over each other: a list row on a phone is 44-48px anyway, and a
     taller row gives the leave and settings buttons its full height. */
  @media (pointer: coarse) {
    .add-btn {
      width: var(--hit);
      height: var(--hit);
      margin: -8px -12px -8px 0;
    }
    .channel,
    .dm-entry {
      min-height: var(--hit);
    }
    .nested-member {
      min-height: 40px;
    }
    .settings-icon {
      min-width: 40px;
      min-height: var(--hit);
      justify-content: center;
    }
    .channel.has-actions {
      padding-right: 92px;
    }
    .dm-entry,
    .channel-row:hover > .dm-entry {
      padding-right: 52px;
    }
    button.live-tag {
      position: relative;
      padding: 4px 10px;
    }
    /* The pill stays small to look at; what a finger has to hit is larger */
    button.live-tag::after {
      content: "";
      position: absolute;
      inset: -10px -6px;
    }
  }
</style>
