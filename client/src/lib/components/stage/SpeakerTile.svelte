<script lang="ts">
  // One person in the call, as the Stage layout draws them: a large avatar
  // with the mint ring while they talk, their name, and what they are doing
  // to their own audio. A click opens the same member menu as every list
  // (actions/member-menu.ts) — volume, poke, direct message — so nothing a
  // person can do to somebody here is new code.
  //
  // The menu's trigger is the person (`.who`), stretched over the whole tile,
  // and Watch is a button beside it, not inside it: the children of a button
  // are not there for a screen reader, so Watch could not be reached (R5-06).

  import { avatarStyle } from "../../avatar.js";
  import { shortName } from "../../username.js";
  import { userId } from "../../stores/connection.js";
  import { speakingUsers } from "../../stores/users.js";
  import { audibleIds } from "../../stores/room.js";
  import { isCulled } from "../../stores/roster.js";
  import { openShare } from "../../stores/user-menu.js";
  import { watchingUserId } from "../../stores/screenshare.js";
  import { memberMenu } from "../../actions/member-menu.js";
  import Icon from "../Icons.svelte";
  import type { UserInfo } from "../../types.js";

  interface Props {
    user: UserInfo;
    /** The filmstrip under a share: one row of small tiles. */
    small?: boolean;
  }
  let { user, small = false }: Props = $props();

  const self = $derived(user.user_id === $userId);
  const talking = $derived($speakingUsers.has(user.user_id));
  const culled = $derived(isCulled(user.user_id, $audibleIds, $userId, false));
  const watched = $derived($watchingUserId === user.user_id);

  const state = $derived(
    [
      talking ? "talking" : null,
      user.is_muted ? "muted" : null,
      user.is_deafened ? "deafened" : null,
      user.is_screen_sharing ? "sharing their screen" : null,
      culled ? "out of earshot in the game" : null,
    ]
      .filter(Boolean)
      .join(", "),
  );
</script>

<div class="tile" class:small class:talking class:culled data-stage-tile={user.user_id}>
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="who"
    aria-label="{shortName(user.username)}{self ? ' (you)' : ''}{state ? `, ${state}` : ''}"
    use:memberMenu={{ user, idle: false, self }}
  >
    <span class="avatar" style={avatarStyle(user.username)} aria-hidden="true"
      >{user.username.charAt(0).toUpperCase()}</span
    >
    <span class="name" title={user.username}>
      {shortName(user.username)}{#if self}<span class="you">(you)</span>{/if}
    </span>
    <span class="marks" aria-hidden="true">
      {#if user.is_muted}<span class="mark" title="Muted"><Icon name="mic-off" size={small ? 12 : 14} /></span>{/if}
      {#if user.is_deafened}<span class="mark" title="Deafened"><Icon name="headphones-off" size={small ? 12 : 14} /></span>{/if}
    </span>
  </div>
  {#if user.is_screen_sharing && !watched}
    <button
      class="live"
      onclick={(e) => {
        e.stopPropagation();
        openShare(user.user_id);
      }}
      title={self ? "Show what you are sharing" : "Watch the stream"}
    >
      <span class="live-dot" aria-hidden="true"></span>
      {self ? "Your share" : "Watch"}
    </button>
  {/if}
</div>

<style>
  .tile {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--sp-2);
    min-height: 168px;
    padding: var(--sp-4) var(--sp-3);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    color: var(--text-primary);
    cursor: pointer;
    transition: border-color var(--dur-fast), background-color var(--dur-fast);
    /* Its own stacking context, for the trigger's layer below */
    isolation: isolate;
  }

  .tile:hover {
    background: var(--bg-hover);
  }

  .who {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-2);
    min-width: 0;
    max-width: 100%;
  }

  /* The whole tile is the trigger, as it was: a layer over the tile's own
     background and under everything on it, so the name and the marks keep
     their tooltips and Watch its own click */
  .who::after {
    content: "";
    position: absolute;
    inset: 0;
    z-index: -1;
  }

  /* Keyboard focus rings the tile, not the avatar and name inside it */
  .who:focus-visible {
    outline: none;
  }

  .tile:has(> .who:focus-visible) {
    outline: 2px solid var(--focus-ring);
    outline-offset: 2px;
  }

  .avatar {
    display: grid;
    place-items: center;
    width: 72px;
    height: 72px;
    border-radius: 50%;
    font-size: var(--fs-2xl);
    font-weight: 700;
    /* The ring is drawn by the box-shadow, so talking never moves a pixel */
    box-shadow: 0 0 0 0 transparent;
    transition: box-shadow var(--dur-fast);
  }

  /* Mint means live: the ring is the one place the tile uses it */
  .tile.talking .avatar {
    box-shadow:
      0 0 0 3px var(--bg-secondary),
      0 0 0 6px var(--speaking);
  }

  .tile.talking {
    border-color: color-mix(in srgb, var(--speaking) 45%, var(--border));
  }

  .name {
    max-width: 100%;
    font-size: var(--fs-md);
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .you {
    margin-left: 0.3em;
    font-weight: 400;
    color: var(--text-secondary);
  }

  .marks {
    position: absolute;
    top: var(--sp-2);
    right: var(--sp-2);
    display: flex;
    gap: var(--sp-1);
    color: var(--danger);
  }

  .mark {
    display: inline-flex;
  }

  .tile.culled {
    color: var(--text-muted);
  }

  .tile.culled .avatar {
    opacity: 0.5;
  }

  .live {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 28px;
    padding: 2px 10px;
    border-radius: var(--r-pill);
    background: var(--accent);
    color: var(--on-accent);
    font-size: var(--fs-sm);
    font-weight: 600;
  }

  .live-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }

  /* The filmstrip under a share */
  .tile.small {
    flex-direction: row;
    justify-content: flex-start;
    min-height: 0;
    min-width: 140px;
    padding: var(--sp-2) var(--sp-3);
    border-radius: var(--r-md);
  }

  .tile.small .who {
    flex-direction: row;
  }

  .tile.small .avatar {
    width: 32px;
    height: 32px;
    font-size: var(--fs-md);
  }

  .tile.small.talking .avatar {
    box-shadow:
      0 0 0 2px var(--bg-secondary),
      0 0 0 4px var(--speaking);
  }

  .tile.small .marks {
    position: static;
  }

  .tile.small .live {
    min-height: 24px;
  }

  /* A finger's size on a phone, the filmstrip's poster too (it is the
     button for switching to another share while watching one) */
  @media (pointer: coarse) {
    .live,
    .tile.small .live {
      min-height: var(--hit);
    }
  }
</style>
