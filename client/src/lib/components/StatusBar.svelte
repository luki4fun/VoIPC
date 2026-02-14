<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    connectionState,
    serverAddress,
    latency,
  } from "../stores/connection.js";

  async function disconnect() {
    try {
      await invoke("disconnect");
      connectionState.set("disconnected");
    } catch (e) {
      console.error("Failed to disconnect:", e);
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
    <span class="latency">Ping: {$latency}ms</span>
    <button class="disconnect-btn" onclick={disconnect}>Disconnect</button>
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
    background: transparent;
    color: var(--danger);
    padding: 2px 8px;
    font-size: 11px;
    border: 1px solid var(--danger);
  }

  .disconnect-btn:hover {
    background: var(--danger);
    color: white;
  }
</style>
