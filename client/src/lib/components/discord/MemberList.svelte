<script lang="ts">
  // Discord's member list, grouped.
  //
  // The sections are by *state*, not by role: `UserInfo` carries
  // user_id/username/channel_id/is_muted/is_deafened/is_screen_sharing/is_admin
  // and there is no role concept in the protocol to group by. Live, speaking,
  // and everyone else is the honest version of Discord's sections here.
  //
  // Goes through stores/roster.ts like the classic list, which is what keeps the
  // hide-members rule in one place: in such a channel a non-admin sees only
  // themselves and whoever spoke recently, and a second member list quietly
  // ignoring that would leak the roster the first one hides.

  import { avatarColor } from "../../avatar.js";
  import { userId } from "../../stores/connection.js";
  import { speakingUsers } from "../../stores/users.js";
  import { audibleIds } from "../../stores/room.js";
  import {
    displayChannelCreatorId,
    displayChannelId,
    displayChannelName,
    displayUsers,
    hideMembers,
    isCulled,
    isPreviewing,
  } from "../../stores/roster.js";
  import { openUserMenu } from "../../stores/user-menu.js";
  import Icon from "../Icons.svelte";
  import type { UserInfo } from "../../types.js";

  const live = $derived($displayUsers.filter((u) => u.is_screen_sharing));
  const talking = $derived(
    $displayUsers.filter((u) => !u.is_screen_sharing && !$isPreviewing && $speakingUsers.has(u.user_id)),
  );
  const rest = $derived(
    $displayUsers.filter((u) => !live.includes(u) && !talking.includes(u)),
  );

  const groups = $derived(
    [
      { label: "Live", members: live },
      { label: "Speaking", members: talking },
      { label: $isPreviewing ? `In #${$displayChannelName}` : "In voice", members: rest },
    ].filter((g) => g.members.length > 0),
  );

  function menu(user: UserInfo, e: MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    openUserMenu(user, e.clientX, e.clientY);
  }
</script>

<aside class="user-list discord">
  {#if $hideMembers && !$isPreviewing}
    <div class="hidden-note">Members are hidden here — people appear while they speak</div>
  {/if}

  <div class="users">
    {#each groups as group (group.label)}
      <div class="group-label">{group.label} — {group.members.length}</div>
      {#each group.members as user (user.user_id)}
        <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
        <div
          class="user"
          class:speaking={!$isPreviewing && $speakingUsers.has(user.user_id)}
          class:culled={isCulled(user.user_id, $audibleIds, $userId, $isPreviewing)}
          title={isCulled(user.user_id, $audibleIds, $userId, $isPreviewing)
            ? "Out of earshot in the game — close it to hear everyone again"
            : undefined}
          oncontextmenu={(e) => menu(user, e)}
        >
          <span class="avatar" style="background: {avatarColor(user.username)}"
            >{user.username.charAt(0).toUpperCase()}</span
          >
          <span class="name">
            {user.username}
            {#if user.user_id === $displayChannelCreatorId && $displayChannelId !== 0}
              <span class="crown" title="Channel creator"><Icon name="crown" size={12} /></span>
            {/if}
            {#if user.is_admin}
              <span class="shield" title="Server admin"><Icon name="shield" size={12} /></span>
            {/if}
            {#if user.user_id === $userId}
              <span class="you">(you)</span>
            {/if}
          </span>
          {#if user.is_muted}
            <span class="status-icon muted" title="Muted"><Icon name="mic-off" size={14} /></span>
          {/if}
          {#if user.is_deafened}
            <span class="status-icon deafened" title="Deafened"><Icon name="headphones-off" size={14} /></span>
          {/if}
          {#if user.user_id !== $userId}
            <button class="more-btn" title="Actions" onclick={(e) => menu(user, e)}>
              <Icon name="more-vertical" size={16} />
            </button>
          {/if}
        </div>
      {/each}
    {/each}
  </div>

  {#if $isPreviewing}
    <div class="preview-hint">Click the channel to join</div>
  {/if}
</aside>

<style>
  .user-list.discord {
    display: flex;
    flex-direction: column;
    height: 100%;
    width: var(--memberlist-width, 240px);
    min-width: 140px;
    flex-shrink: 0;
    background: var(--bg-secondary);
  }

  .hidden-note {
    padding: 12px 16px;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-secondary);
  }

  .users {
    flex: 1;
    overflow-y: auto;
    padding: 12px 8px;
  }

  .group-label {
    padding: 14px 8px 4px;
    font-size: 11px;
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
    opacity: 0.45;
  }

  .avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    color: #fff;
    font-size: 13px;
    font-weight: 600;
    flex-shrink: 0;
    transition: box-shadow 0.1s;
  }

  .user.speaking .avatar {
    box-shadow: 0 0 0 2px var(--speaking);
  }

  .name {
    flex: 1;
    font-size: 14px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .user:hover .name {
    color: var(--text-primary);
  }

  .crown {
    color: #ffc107;
    display: inline-flex;
    vertical-align: middle;
  }

  .shield {
    color: var(--accent);
    display: inline-flex;
    vertical-align: middle;
  }

  .you {
    color: var(--text-secondary);
    font-size: 11px;
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

  .preview-hint {
    padding: 8px 16px;
    font-size: 11px;
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
    font-style: italic;
  }
</style>
