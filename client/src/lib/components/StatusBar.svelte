<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    connectionState,
    serverAddress,
    latency,
  } from "../stores/connection.js";
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

  // Voice loss % over a rolling 2s window (from jitter-buffer conceal counts)
  let lossPercent = $state(0);
  let lastPlayed = 0;
  let lastLost = 0;
  let lossInterval: ReturnType<typeof setInterval> | null = null;

  $effect(() => {
    if ($connectionState === "connected") {
      if (!lossInterval) {
        lastPlayed = 0;
        lastLost = 0;
        lossInterval = setInterval(() => {
          invoke<[number, number]>("get_voice_stats")
            .then(([played, lost]) => {
              const dPlayed = played - lastPlayed;
              const dLost = lost - lastLost;
              lastPlayed = played;
              lastLost = lost;
              const total = dPlayed + dLost;
              lossPercent = total > 0 ? Math.round((dLost / total) * 100) : 0;
            })
            .catch(() => {});
        }, 2000);
      }
    } else if (lossInterval) {
      clearInterval(lossInterval);
      lossInterval = null;
      lossPercent = 0;
    }
    return () => {
      if (lossInterval) {
        clearInterval(lossInterval);
        lossInterval = null;
      }
    };
  });

  let quality = $derived(
    lossPercent >= 5 ? "bad" : lossPercent >= 1 ? "warn" : "good",
  );
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
    <span class="latency quality-{quality}" title="Voice packet loss (2s window)">
      Ping: {$latency}ms{#if lossPercent > 0}&nbsp;· {lossPercent}% loss{/if}
    </span>
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
</style>
