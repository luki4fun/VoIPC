<script lang="ts">
  // The server name across the top of the sidebar, with its dropdown.

  import { isAdmin, serverAddress } from "../../stores/connection.js";
  import { copyInviteLink } from "../../stores/channel-ui.js";
  import { openAdminPanel, showAdminLogin } from "../../stores/admin-ui.js";
  import { currentChannelId } from "../../stores/channels.js";
  import { serverEntries } from "../../stores/servers.js";
  import { invoke } from "@tauri-apps/api/core";
  import { connectionState } from "../../stores/connection.js";
  import { playDisconnectedSound } from "../../sounds.js";
  import { addNotification } from "../../stores/notifications.js";
  import { updateUiPrefs } from "../../stores/ui-prefs.js";
  import Icon from "../Icons.svelte";

  interface Props {
    /** The shell's own way into Settings. The gear in the user panel is the
     *  other one, and on a phone it is at the very bottom of a drawer — which
     *  is exactly where a system navigation bar sits. */
    onopensettings?: () => void;
  }
  let { onopensettings }: Props = $props();

  let open = $state(false);

  const name = $derived($serverEntries.find((e) => e.active)?.name ?? $serverAddress);

  async function disconnect() {
    open = false;
    try {
      await invoke("disconnect");
      connectionState.set("disconnected");
      playDisconnectedSound();
    } catch (e) {
      addNotification(`Failed to disconnect: ${e}`, "error");
    }
  }
</script>

<svelte:window onclick={() => (open = false)} />

<div class="server-header">
  <button
    class="header-btn"
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}
    title={$serverAddress}
  >
    <span class="server-name">{name}</span>
    <Icon name="chevron-down" size={16} />
  </button>

  {#if open}
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="menu" onclick={(e) => e.stopPropagation()}>
      {#if $currentChannelId !== 0}
        <button
          class="menu-item"
          onclick={() => {
            open = false;
            copyInviteLink();
          }}
        >
          <Icon name="user-plus" size={16} />
          <span>Invite people</span>
        </button>
      {/if}
      <button
        class="menu-item"
        onclick={() => {
          open = false;
          $isAdmin ? openAdminPanel() : showAdminLogin.set(true);
        }}
      >
        <Icon name="shield" size={16} />
        <span>{$isAdmin ? "Active bans" : "Admin login"}</span>
      </button>
      <div class="menu-sep"></div>
      {#if onopensettings}
        <button
          class="menu-item"
          onclick={() => {
            open = false;
            onopensettings?.();
          }}
        >
          <Icon name="settings" size={16} />
          <span>Settings</span>
        </button>
      {/if}
      <button
        class="menu-item"
        onclick={() => {
          open = false;
          updateUiPrefs((p) => (p.layout = "classic"));
        }}
      >
        <Icon name="hamburger" size={16} />
        <span>Switch to the classic layout</span>
      </button>
      <div class="menu-sep"></div>
      <button class="menu-item danger" onclick={disconnect}>
        <Icon name="disconnect" size={16} />
        <span>Disconnect</span>
      </button>
    </div>
  {/if}
</div>

<style>
  .server-header {
    position: relative;
    flex-shrink: 0;
  }

  .header-btn {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    padding: 12px 16px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: none;
    border-radius: 0;
    border-bottom: 1px solid var(--border);
    font-size: 15px;
    font-weight: 600;
  }

  .header-btn:hover {
    background: var(--bg-hover);
  }

  .server-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .menu {
    position: absolute;
    top: 100%;
    left: 8px;
    right: 8px;
    z-index: 60;
    margin-top: 4px;
    padding: 6px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: var(--shadow-menu);
  }

  .menu-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 7px 8px;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    font-size: 13px;
    border-radius: 4px;
  }

  .menu-item:hover {
    background: var(--accent);
    color: #fff;
  }

  .menu-item.danger {
    color: var(--danger);
  }

  .menu-item.danger:hover {
    background: var(--danger);
    color: #fff;
  }

  .menu-sep {
    height: 1px;
    margin: 4px 0;
    background: var(--border);
  }
</style>
