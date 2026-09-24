<script lang="ts">
  // The 72px strip of server icons down the far left, in both layouts.
  //
  // The open servers first, in the order they were opened, then the bookmarks
  // that are not open (stores/servers.ts). A click on an open one looks at it;
  // a click on a bookmark opens it in the background and looks at it once it is
  // up — neither touches any other server, or the call. Right-click, or a long
  // press on a phone, for Disconnect and Remove bookmark.

  import { invoke } from "@tauri-apps/api/core";
  import { avatarColor } from "../../avatar.js";
  import { serverAddress } from "../../stores/connection.js";
  import { addNotification } from "../../stores/notifications.js";
  import { savedServers, type SavedServer } from "../../stores/settings.js";
  import type { ServerEntry } from "../../stores/servers.js";
  import { connectTo, disconnectServer, serverEntries, serverId } from "../../connect.js";
  import { playDisconnectedSound } from "../../sounds.js";
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

  function bookmarkOf(entry: ServerEntry): SavedServer | undefined {
    return $savedServers.find((s) => serverId(s.host, s.port) === entry.id);
  }

  async function pick(entry: ServerEntry) {
    if (entry.open) {
      serverAddress.set(entry.id);
      return;
    }
    const bookmark = bookmarkOf(entry);
    if (!bookmark) return;
    const result = await connectTo({
      host: bookmark.host,
      port: bookmark.port,
      username: bookmark.username,
      acceptSelfSigned: bookmark.accept_self_signed,
    });
    if (!result.ok) addNotification(`${entry.name}: ${result.error}`, "error");
  }

  function stateLabel(entry: ServerEntry): string {
    if (!entry.open) return `${entry.name} (${entry.host}:${entry.port}) — connect`;
    const state =
      entry.state === "connecting"
        ? "connecting…"
        : entry.state === "reconnecting"
          ? "reconnecting…"
          : entry.inVoice
            ? "connected, in voice"
            : "connected";
    return `${entry.name} — ${state}`;
  }

  // ── Context menu ──
  let menu = $state<{ entry: ServerEntry; x: number; y: number } | null>(null);
  let pressTimer: ReturnType<typeof setTimeout> | null = null;

  function openMenu(entry: ServerEntry, x: number, y: number) {
    menu = { entry, x, y };
  }

  // A phone has no right click: hold the icon instead.
  function pressStart(entry: ServerEntry, e: PointerEvent) {
    if (e.pointerType !== "touch") return;
    const { clientX, clientY } = e;
    pressTimer = setTimeout(() => {
      pressTimer = null;
      openMenu(entry, clientX, clientY);
    }, 500);
  }

  function pressEnd() {
    if (pressTimer) clearTimeout(pressTimer);
    pressTimer = null;
  }

  async function disconnect(entry: ServerEntry) {
    menu = null;
    await disconnectServer(entry.id);
    playDisconnectedSound();
  }

  async function removeBookmark(entry: ServerEntry) {
    menu = null;
    const bookmark = bookmarkOf(entry);
    if (!bookmark) return;
    try {
      savedServers.set(
        await invoke<SavedServer[]>("remove_server", { host: bookmark.host, port: bookmark.port }),
      );
    } catch (e) {
      addNotification(`Could not remove the bookmark: ${e}`, "error");
    }
  }
</script>

<nav class="server-rail" aria-label="Servers">
  {#each $serverEntries as entry (entry.id)}
    <button
      class="rail-item"
      class:active={entry.active}
      class:open={entry.open}
      data-server={entry.id}
      onclick={() => {
        // The long press already opened the menu; the click that ends it is not a pick
        if (menu) return;
        void pick(entry);
      }}
      oncontextmenu={(e) => {
        e.preventDefault();
        openMenu(entry, e.clientX, e.clientY);
      }}
      onpointerdown={(e) => pressStart(entry, e)}
      onpointerup={pressEnd}
      onpointerleave={pressEnd}
      onpointercancel={pressEnd}
      title={stateLabel(entry)}
    >
      <span class="pill" class:show={entry.active || entry.unread > 0}></span>
      <span class="badge" style="background: {avatarColor(entry.name)}">{initials(entry.name)}</span>
      {#if entry.state === "connecting" || entry.state === "reconnecting"}
        <span class="rail-state" title={entry.state === "connecting" ? "Connecting" : "Reconnecting"}
          >…</span
        >
      {:else if entry.inVoice}
        <span class="rail-voice" title="In voice here"><Icon name="speaker" size={12} /></span>
      {/if}
      {#if entry.unread > 0}
        <span class="rail-unread">{entry.unread > 99 ? "99+" : entry.unread}</span>
      {/if}
    </button>
  {/each}

  <button class="rail-item add" onclick={onadd} title="Add a server">
    <span class="badge plus"><Icon name="plus" size={20} /></span>
  </button>
</nav>

{#if menu}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div
    class="rail-menu-overlay"
    onclick={() => (menu = null)}
    oncontextmenu={(e) => {
      e.preventDefault();
      menu = null;
    }}
  >
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="rail-menu" style="left: {menu.x}px; top: {menu.y}px;" onclick={(e) => e.stopPropagation()}>
      <div class="rail-menu-title">{menu.entry.name}</div>
      {#if menu.entry.open}
        <button class="rail-menu-item danger" onclick={() => disconnect(menu!.entry)}>
          <Icon name="disconnect" size={16} />
          <span>Disconnect</span>
        </button>
      {/if}
      {#if bookmarkOf(menu.entry)}
        <button class="rail-menu-item" onclick={() => removeBookmark(menu!.entry)}>
          <Icon name="trash" size={16} />
          <span>Remove bookmark</span>
        </button>
      {/if}
    </div>
  </div>
{/if}

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
    /* The rail is the darkest surface in the app; --bg-tertiary is the
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

  /* A bookmark nobody opened: fainter still than an open server in the background */
  .rail-item:not(.open):not(.add) .badge {
    opacity: 0.35;
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

  /* Connecting or reconnecting: the server is in the list, not up yet */
  .rail-state,
  .rail-voice {
    position: absolute;
    left: 8px;
    bottom: -2px;
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 3px;
    border-radius: 10px;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    border: 3px solid var(--bg-tertiary);
  }

  .rail-voice {
    color: var(--success);
  }

  .rail-menu-overlay {
    position: fixed;
    inset: 0;
    z-index: 150;
  }

  .rail-menu {
    position: fixed;
    min-width: 180px;
    padding: 4px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: var(--shadow-dialog);
  }

  .rail-menu-title {
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text-secondary);
  }

  .rail-menu-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 10px;
    background: transparent;
    color: var(--text-primary);
    border: none;
    border-radius: 4px;
    font-size: 13px;
    text-align: left;
  }

  .rail-menu-item:hover {
    background: var(--bg-hover);
  }

  .rail-menu-item.danger {
    color: var(--danger);
  }
</style>
