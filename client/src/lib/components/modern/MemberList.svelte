<script lang="ts">
  // The modern layout's member list, grouped.
  //
  // The sections are by *state*, not by role: `UserInfo` carries
  // user_id/username/channel_id/is_muted/is_deafened/is_screen_sharing/is_admin
  // and there is no role concept in the protocol to group by. Live and everyone
  // else is the honest version of Discord's sections here. Talking only lights
  // the row up: moving talkers into a group of their own made rows jump around.
  //
  // Goes through stores/roster.ts like the classic list, which is what keeps the
  // hide-members rule in one place: in such a channel a non-admin sees only
  // themselves and whoever spoke recently, and a second member list quietly
  // ignoring that would leak the roster the first one hides.
  //
  // Under the channel's members, everyone on the server who is in no voice
  // channel: "Online". In its own box rather than as one more group in
  // `.users`, which test-ui.mjs counts as the channel's members.

  import { avatarStyle } from "../../avatar.js";
  import { userId } from "../../stores/connection.js";
  import { groupStyles, viewingVoice } from "../../stores/channels.js";
  import { speakingUsers } from "../../stores/users.js";
  import { blockedMember } from "../../stores/blocks.js";
  import { restrictions } from "../../stores/restrictions.js";
  import { markTitle } from "../../restrict-rules.js";
  import { audibleIds } from "../../stores/room.js";
  import {
    displayChannelCreatorId,
    displayChannelId,
    displayChannelName,
    displayUsers,
    hideMembers,
    idleUsers,
    isCulled,
    isPreviewing,
    displayChannel,
    openTextHere,
  } from "../../stores/roster.js";
  import { olderRelay } from "../../stores/relay.js";
  import { livePath } from "../../relay-rules.js";
  import { refreshList } from "../../stores/sweep.js";
  import { serverAddress } from "../../stores/scoped.js";
  import { openShare, openUserMenu } from "../../stores/user-menu.js";
  import { memberMenu } from "../../actions/member-menu.js";
  import { badgeStyle, badgesInOrder, sectionsOf } from "../../member-sections.js";
  import Icon from "../Icons.svelte";
  import AvatarPicture from "../AvatarPicture.svelte";
  import MemberName from "../MemberName.svelte";
  import type { UserInfo } from "../../types.js";

  const live = $derived($displayUsers.filter((u) => u.is_screen_sharing));
  const rest = $derived($displayUsers.filter((u) => !u.is_screen_sharing));

  // "In voice" only when that is what the list is: a text channel's members are
  // subscribers, each standing in a voice channel of their own, and the lobby's
  // are in none — the pane shows it when we are in no voice channel here and
  // have no other channel open.
  const restLabel = $derived(
    $displayChannelId === 0 || $openTextHere
      ? "Online"
      : $isPreviewing || $displayChannel?.text
        ? `In #${$displayChannelName}`
        : "In voice",
  );
  const groups = $derived([
    ...(live.length > 0 ? [{ key: "live", label: "Live", members: live }] : []),
    ...sectionsOf(rest, $groupStyles, restLabel),
  ]);
  const idleGroups = $derived(sectionsOf($idleUsers, $groupStyles, "Online"));
  /** A channel whose list comes by the sweep, so it is as old as that. */
  const byList = $derived(!$isPreviewing && !!$displayChannel?.text && !$openTextHere && livePath($olderRelay?.protocol ?? null));

  function menu(user: UserInfo, e: MouseEvent, idle: boolean) {
    e.preventDefault();
    e.stopPropagation();
    openUserMenu(user, e.clientX, e.clientY, idle);
  }
</script>

<aside class="user-list modern">
  {#if $hideMembers && !$isPreviewing}
    <div class="hidden-note">Members are hidden here — people appear while they speak</div>
  {:else if byList}
    <div class="hidden-note">
      Who is here, up to ten minutes ago.
      <button class="refresh-list" title="Asks now, which tells the server this is the channel you are looking at" onclick={() => refreshList($serverAddress, $displayChannelId)}>Refresh</button>
    </div>
  {/if}

  <div class="users">
    {#each groups as group (group.key)}
      <div class="group-label">{group.label} — {group.members.length}</div>
      {#each group.members as user (user.user_id)}
        {@render member(user, !$isPreviewing && $viewingVoice, true)}
      {/each}
    {/each}
  </div>

  {#if $idleUsers.length > 0}
    <div class="idle-users">
      {#each idleGroups as group (group.key)}
        <div class="group-label">{group.label} — {group.members.length}</div>
        {#each group.members as user (user.user_id)}
          {@render member(user, false, false)}
        {/each}
      {/each}
    </div>
  {/if}

  {#if $isPreviewing}
    <div class="preview-hint">Click the channel to join</div>
  {/if}
</aside>

<!-- One row. `inCall` is whether this list is the call's: speaking and the
     game's culling are about the people we hear, and nobody else. `inChannel`
     is whether it is the channel on screen's, which is what the crown is about. -->
{#snippet member(user: UserInfo, inCall: boolean, inChannel: boolean)}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div
    class="user"
    class:speaking={inCall && $speakingUsers.has(user.user_id)}
    class:culled={isCulled(user.user_id, $audibleIds, $userId, !inCall)}
    title={isCulled(user.user_id, $audibleIds, $userId, !inCall)
      ? "Out of earshot in the game — close it to hear everyone again"
      : undefined}
    use:memberMenu={{ user, idle: !inChannel, self: user.user_id === $userId }}
  >
    <span class="avatar" style={avatarStyle(user.username)}
      >{user.username.charAt(0).toUpperCase()}<AvatarPicture account={user.account} /></span
    >
    <span class="name" title={user.username}>
      <MemberName username={user.username} account={user.account} />
      {#if inChannel && user.user_id === $displayChannelCreatorId && $displayChannelId !== 0}
        <span class="crown" title="Channel creator"><Icon name="crown" size={12} /></span>
      {/if}
      {#if user.is_admin}
        <span class="shield" title="Server admin"><Icon name="shield" size={12} /></span>
      {/if}
      {#each badgesInOrder(user.badges ?? [], $groupStyles) as badge (badge)}
        <span class="badge" style={badgeStyle(badge, $groupStyles)} title="A group badge on this server"
          >{badge}</span
        >
      {/each}
      {#if user.shares_history}
        <span class="sharing-history" role="img" title="Shares history with newcomers" aria-label="Shares history with newcomers"><Icon name="history" size={12} /></span>
      {/if}
      {#if $blockedMember(user)}
        <span class="blocked-mark" role="img" title="You blocked this person" aria-label="You blocked this person"><Icon name="ban" size={12} /></span>
      {/if}
      {#if user.user_id === $userId}
        <span class="you">(you)</span>
      {/if}
    </span>
    {#if user.is_muted}
      <span class="status-icon muted" title="Muted"><Icon name="mic-off" size={14} /></span>
    {/if}
    {#if $restrictions.has(user.user_id)}
      {@const held = markTitle($restrictions.get(user.user_id)!, Date.now())}
      <span class="status-icon restricted-mark" role="img" title={held} aria-label={held}><Icon name="hourglass" size={14} /></span>
    {/if}
    {#if user.is_deafened}
      <span class="status-icon deafened" title="Deafened"><Icon name="headphones-off" size={14} /></span>
    {/if}
    <!-- Watching is the call's, as in the menu: one click instead of two -->
    {#if user.is_screen_sharing && inCall}
      <button
        class="watch-btn"
        title={user.user_id === $userId ? "Show what you are sharing" : "Watch the stream"}
        onclick={(e) => {
          e.stopPropagation();
          openShare(user.user_id);
        }}
      >
        <Icon name="play" size={14} />
      </button>
    {/if}
    {#if user.user_id !== $userId}
      <button class="more-btn" title="Actions" onclick={(e) => menu(user, e, !inChannel)}>
        <Icon name="more-vertical" size={16} />
      </button>
    {/if}
  </div>
{/snippet}

<style>
  .user-list.modern {
    display: flex;
    flex-direction: column;
    height: 100%;
    width: var(--memberlist-width, 240px);
    min-width: 140px;
    flex-shrink: 0;
    background: var(--bg-secondary);
  }

  .refresh-list {
    display: block;
    margin-top: 4px;
    padding: 0;
    border: none;
    background: none;
    color: var(--accent);
    font: inherit;
    cursor: pointer;
    text-decoration: underline;
  }

  .hidden-note {
    padding: 12px 16px;
    font-size: var(--fs-micro);
    line-height: 1.4;
    color: var(--text-secondary);
  }

  .users {
    flex: 1;
    overflow-y: auto;
    padding: 12px 8px;
  }

  /* Below the channel's members, capped so a busy lobby cannot push them off
     screen; it scrolls on its own. */
  .idle-users {
    max-height: 40%;
    overflow-y: auto;
    padding: 0 8px 12px;
    border-top: 1px solid var(--border);
  }

  .group-label {
    padding: 14px 8px 4px;
    font-size: var(--fs-micro);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text-secondary);
  }

  .user {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 8px;
    border-radius: 4px;
  }

  .user:hover {
    background: var(--bg-hover);
  }

  .user.culled {
    color: var(--text-muted);
  }

  /* The picture fades; the name stays readable */
  .user.culled .avatar {
    opacity: 0.5;
  }

  .avatar {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    font-size: var(--fs-body);
    font-weight: 600;
    flex-shrink: 0;
    transition: box-shadow var(--dur-fast);
  }

  .user.speaking .avatar {
    box-shadow: 0 0 0 2px var(--speaking);
  }

  /* The name clips, not what stands after it: inline, a display name with its @tag pushed
     the group's badge out of sight (W3-59) */
  .name {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: var(--fs-md);
    color: var(--text-secondary);
    overflow: hidden;
    white-space: nowrap;
    min-width: 0;
  }

  .name :global(.member-name) {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .crown,
  .shield,
  .badge,
  .sharing-history,
  .blocked-mark,
  .you {
    flex-shrink: 0;
  }

  .user:hover .name {
    color: var(--text-primary);
  }

  .crown {
    color: var(--warning);
    display: inline-flex;
    vertical-align: middle;
  }

  .shield {
    color: var(--accent);
    display: inline-flex;
    vertical-align: middle;
  }

  /* A group's badge (1.7): text the server's admins chose */
  .badge {
    display: inline-block;
    max-width: 10ch;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: middle;
    padding: 0 5px;
    border-radius: var(--r-pill);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--fs-micro);
    font-weight: 500;
    line-height: 1.5;
  }

  /* Quieter than the shield: it says what someone offers, not what they are */
  .sharing-history {
    color: var(--text-secondary);
    display: inline-flex;
    vertical-align: middle;
  }

  .blocked-mark {
    display: inline-flex;
    margin-left: 4px;
    color: var(--text-secondary);
  }

  .you {
    color: var(--text-secondary);
    font-size: var(--fs-micro);
  }

  .status-icon {
    display: flex;
    flex-shrink: 0;
  }

  .status-icon.restricted-mark {
    color: var(--warning);
  }

  .status-icon.muted {
    color: var(--danger);
  }

  .status-icon.deafened {
    color: var(--warning);
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
    flex-shrink: 0;
  }

  .user:hover .more-btn {
    display: flex;
  }

  .more-btn:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  .watch-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    padding: 0;
    /* Live: mint, like every other way into a share */
    background: var(--accent);
    color: var(--on-accent);
    border-radius: 4px;
    flex-shrink: 0;
  }

  .watch-btn:hover {
    opacity: 0.85;
  }

  .preview-hint {
    padding: 8px 16px;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
    font-style: italic;
  }

  /* No hover on a touch screen, and keyboard focus is not hover either: the
     ⋮ is there whenever the row could be acted on (as in ChannelSidebar) */
  .user:focus-within .more-btn {
    display: flex;
  }

  @media (hover: none) {
    .more-btn {
      display: flex;
    }
  }

  /* Touch: 44px rows and 44px buttons in them (--hit) */
  @media (pointer: coarse) {
    .user {
      min-height: var(--hit);
    }
    .more-btn,
    .watch-btn {
      width: var(--hit);
      height: var(--hit);
    }
  }
</style>
