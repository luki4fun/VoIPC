<script lang="ts">
  // The member list of the classic layout.
  //
  // Rows only. Who may appear in them, and who may be kicked or invited, are
  // rules rather than styling and live in stores/roster.ts; the right-click menu
  // and its dialogs are UserContextMenu.svelte, mounted once by App.svelte. Both
  // exist because there are two member lists now and neither of those things
  // should be written twice — least of all the hide-members rule.

  import { userId } from "../stores/connection.js";
  import { speakingUsers } from "../stores/users.js";
  import { audibleIds } from "../stores/room.js";
  import {
    displayChannelCreatorId,
    displayChannelId,
    displayChannelName,
    displayUsers,
    hideMembers,
    isCulled,
    isPreviewing,
  } from "../stores/roster.js";
  import { openUserMenu } from "../stores/user-menu.js";
  import Icon from "./Icons.svelte";
</script>

<div class="user-list">
  <div class="header">
    {#if $isPreviewing}
      Previewing #{$displayChannelName}
    {:else}
      Users in #{$displayChannelName}
    {/if}
  </div>
  {#if $hideMembers && !$isPreviewing}
    <div class="hidden-note">Members are hidden here — people appear while they speak</div>
  {/if}
  <div class="users">
    {#each $displayUsers as user (user.user_id)}
      <div
        class="user"
        class:speaking={!$isPreviewing && $speakingUsers.has(user.user_id)}
        class:culled={isCulled(user.user_id, $audibleIds, $userId, $isPreviewing)}
        title={isCulled(user.user_id, $audibleIds, $userId, $isPreviewing)
          ? "Out of earshot in the game — close it to hear everyone again"
          : undefined}
        oncontextmenu={(e) => { e.preventDefault(); e.stopPropagation(); openUserMenu(user, e.clientX, e.clientY); }}
      >
        <div
          class="indicator"
          class:speaking={!$isPreviewing && $speakingUsers.has(user.user_id)}
          class:muted={user.is_muted}
          class:deafened={user.is_deafened}
        ></div>
        <span class="name">
          {user.username}
          {#if user.user_id === $displayChannelCreatorId && $displayChannelId !== 0}
            <span class="crown" title="Channel creator"><Icon name="crown" size={12} /></span>
          {/if}
          {#if user.is_admin}
            <span class="shield" title="Server admin"><Icon name="shield" size={12} /></span>
          {/if}
          {#if user.shares_history}
            <span class="sharing-history" title="Shares recent chat with newcomers"><Icon name="history" size={12} /></span>
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
            onclick={(e) => { e.stopPropagation(); openUserMenu(user, e.clientX, e.clientY); }}
          >
            <Icon name="more-vertical" size={16} />
          </button>
        {/if}
      </div>
    {/each}
  </div>
  {#if $isPreviewing}
    <div class="preview-hint">Double-click channel to join</div>
  {/if}
</div>

<style>
  .user-list {
    display: flex;
    flex-direction: column;
    height: 100%;
    /* Per-shell, like the channel sidebar — see ChannelList. */
    width: var(--memberlist-width, 180px);
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

  .hidden-note {
    padding: 8px 16px;
    font-size: 11px;
    line-height: 1.4;
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

  /* A game says who is in earshot by leaving everyone else out. That is how
     distance culling works, and also how a game could silence one person — so
     it is shown rather than left to be discovered. */
  .user.culled {
    opacity: 0.45;
  }

  .user.speaking {
    background: rgba(76, 175, 80, 0.1);
  }

  .shield {
    display: inline-flex;
    color: var(--accent);
    margin-left: 4px;
    vertical-align: middle;
  }

  /* Quieter than the shield: it says what someone offers, not what they are */
  .sharing-history {
    display: inline-flex;
    color: var(--text-secondary);
    margin-left: 4px;
    vertical-align: middle;
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
    background: var(--bg-hover);
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
