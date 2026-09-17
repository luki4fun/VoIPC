<script lang="ts">
  // Discord's 72px strip of server icons.
  //
  // Reads stores/servers.ts, which is a *list* today containing the one live
  // connection plus the saved bookmarks — see that file for what is and is not
  // implemented behind it. Nothing here assumes there is only one.

  import { avatarColor } from "../../avatar.js";
  import { connectionState } from "../../stores/connection.js";
  import { serverEntries, type ServerEntry } from "../../stores/servers.js";
  import { requestServerSwitch } from "../../stores/server-switch.js";
  import Icon from "../Icons.svelte";

  interface Props {
    onadd: () => void;
  }
  let { onadd }: Props = $props();

  function initials(name: string): string {
    return name
      .split(/[\s.\-_]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0]!.toUpperCase())
      .join("");
  }

  function pick(entry: ServerEntry) {
    if (entry.active) return;
    requestServerSwitch(entry);
  }
</script>

<nav class="server-rail" aria-label="Servers">
  {#each $serverEntries as entry (entry.id)}
    <button
      class="rail-item"
      class:active={entry.active}
      onclick={() => pick(entry)}
      title={entry.active
        ? `${entry.name} — connected`
        : `${entry.name} (${entry.host}:${entry.port}) — connect`}
    >
      <span class="pill" class:show={entry.active || entry.unread > 0}></span>
      <span class="badge" style="background: {avatarColor(entry.name)}">{initials(entry.name)}</span>
      {#if entry.unread > 0}
        <span class="rail-unread">{entry.unread > 99 ? "99+" : entry.unread}</span>
      {/if}
    </button>
  {/each}

  <button class="rail-item add" onclick={onadd} title="Add a server">
    <span class="badge plus"><Icon name="plus" size={20} /></span>
  </button>

  {#if $connectionState === "reconnecting"}
    <span class="rail-note" title="Reconnecting">…</span>
  {/if}
</nav>

<style>
  .server-rail {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    width: 72px;
    flex-shrink: 0;
    padding: 12px 0;
    overflow-y: auto;
    /* Discord's rail is the darkest surface in the app; --bg-tertiary is the
       role that carries "recessed" in every palette. */
    background: var(--bg-tertiary);
  }

  .rail-item {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    padding: 0;
    background: transparent;
    border: none;
  }

  .pill {
    position: absolute;
    left: 0;
    width: 4px;
    height: 8px;
    border-radius: 0 4px 4px 0;
    background: var(--text-primary);
    opacity: 0;
    transition: height 0.15s, opacity 0.15s;
  }

  .pill.show {
    opacity: 1;
  }

  .rail-item.active .pill {
    height: 32px;
  }

  .badge {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 48px;
    height: 48px;
    border-radius: 16px;
    color: #fff;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 0.5px;
    transition: border-radius 0.15s;
  }

  .rail-item:hover .badge,
  .rail-item.active .badge {
    border-radius: 14px;
  }

  .rail-item:not(.active) .badge {
    opacity: 0.55;
  }

  .rail-item:hover .badge {
    opacity: 1;
  }

  .badge.plus {
    background: var(--bg-secondary);
    color: var(--success);
  }

  .rail-unread {
    position: absolute;
    right: 8px;
    bottom: -2px;
    min-width: 18px;
    padding: 1px 5px;
    border-radius: 10px;
    background: var(--danger);
    color: #fff;
    font-size: 11px;
    font-weight: 700;
    text-align: center;
    border: 3px solid var(--bg-tertiary);
  }

  .rail-note {
    color: var(--text-secondary);
    font-size: 18px;
    line-height: 1;
  }
</style>
