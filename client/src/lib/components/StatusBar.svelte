<script lang="ts">
  // The status bar along the very bottom of the classic layout.
  //
  // Bar only. Packet loss is polled in stores/connection-quality.ts and the two
  // admin dialogs are AdminDialogs.svelte, both because the Discord layout shows
  // the same things somewhere else and neither should be computed twice.

  import { invoke } from "@tauri-apps/api/core";
  import { connectionState, serverAddress, latency, isAdmin } from "../stores/connection.js";
  import { lossPercent, quality } from "../stores/connection-quality.js";
  import { openAdminPanel, showAdminLogin } from "../stores/admin-ui.js";
  import { playDisconnectedSound } from "../sounds.js";
  import { addNotification } from "../stores/notifications.js";
  import Icon from "./Icons.svelte";

  async function disconnect() {
    try {
      await invoke("disconnect");
      connectionState.set("disconnected");
      playDisconnectedSound();
    } catch (e) {
      console.error("Failed to disconnect:", e);
      addNotification(`Failed to disconnect: ${e}`, "error");
    }
  }
</script>

<div class="status-bar">
  <div class="status">
    <div
      class="dot"
      class:connected={$connectionState === "connected"}
      class:connecting={$connectionState === "connecting"}
    ></div>
    {#if $connectionState === "connected"}
      <span>Connected to {$serverAddress}</span>
    {:else if $connectionState === "connecting"}
      <span>Connecting...</span>
    {:else}
      <span>Disconnected</span>
    {/if}
  </div>

  {#if $connectionState === "connected"}
    <span class="latency quality-{$quality}" title="Voice packet loss (2s window)">
      Ping: {$latency}ms{#if $lossPercent > 0}&nbsp;· {$lossPercent}% loss{/if}
    </span>
    <button
      class="admin-btn"
      class:active={$isAdmin}
      title={$isAdmin ? "Server admin — active bans" : "Admin login (server token)"}
      onclick={() => ($isAdmin ? openAdminPanel() : showAdminLogin.set(true))}
    >
      <Icon name="shield" size={14} />
      {#if $isAdmin}Admin{/if}
    </button>
    <button class="disconnect-btn" onclick={disconnect}>
      <Icon name="disconnect" size={14} />
      Disconnect
    </button>
  {/if}
</div>


<style>
  .status-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 16px;
    background: var(--bg-primary);
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-secondary);
  }

  .status {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .quality-warn {
    color: var(--warning);
  }

  .quality-bad {
    color: var(--danger);
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
  }

  .dot.connected {
    background: var(--success);
  }

  .dot.connecting {
    background: var(--warning);
    animation: pulse 1s infinite;
  }

  @keyframes pulse {
    50% {
      opacity: 0.5;
    }
  }

  .latency {
    margin-left: auto;
  }

  .disconnect-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    background: transparent;
    color: var(--danger);
    padding: 4px 10px;
    font-size: 11px;
    border: 1px solid var(--danger);
  }

  .disconnect-btn:hover {
    background: var(--danger);
    color: white;
  }

  .admin-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px 8px;
    font-size: 11px;
    border: 1px solid var(--border);
  }

  .admin-btn:hover,
  .admin-btn.active {
    color: var(--accent);
    border-color: var(--accent);
  }

</style>
