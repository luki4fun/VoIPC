<script lang="ts">
  // Discord's green "Voice Connected" strip above the user panel: where you are,
  // how the line is, and the way out. Same numbers the classic status bar shows.

  import { connectionState, latency } from "../../stores/connection.js";
  import { lossPercent, quality } from "../../stores/connection-quality.js";
  import { channels, currentChannelId } from "../../stores/channels.js";
  import { isMobile } from "../../stores/platform.js";
  import { invoke } from "@tauri-apps/api/core";
  import { addNotification } from "../../stores/notifications.js";
  import ScreenShareControls from "../ScreenShareControls.svelte";
  import Icon from "../Icons.svelte";

  const channelName = $derived(
    $channels.find((c) => c.channel_id === $currentChannelId)?.name ?? "",
  );

  // Voice is off in the lobby, so there is nothing to report there.
  const inVoice = $derived($connectionState === "connected" && $currentChannelId !== 0);

  async function leave() {
    try {
      await invoke("join_channel", { channelId: 0, password: null });
    } catch (e) {
      addNotification(`Could not leave the channel: ${e}`, "error");
    }
  }
</script>

{#if inVoice}
  <div class="voice-panel">
    <div class="voice-line">
      <span class="voice-state quality-{$quality}">
        <Icon name="speaker" size={16} />
        <span>Voice connected</span>
      </span>
      <button class="leave-btn" onclick={leave} title="Leave the channel">
        <Icon name="disconnect" size={16} />
      </button>
    </div>
    <div class="voice-meta">
      <span class="channel">#{channelName}</span>
      <span class="ping quality-{$quality}" title="Voice packet loss (2s window)">
        {$latency}ms{#if $lossPercent > 0}&nbsp;· {$lossPercent}%{/if}
      </span>
    </div>
    {#if !$isMobile}
      <div class="share-row"><ScreenShareControls /></div>
    {/if}
  </div>
{/if}

<style>
  .voice-panel {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 10px;
    background: var(--bg-secondary);
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  .voice-line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .voice-state {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    font-weight: 600;
    color: var(--success);
  }

  .voice-state.quality-warn {
    color: var(--warning);
  }

  .voice-state.quality-bad {
    color: var(--danger);
  }

  .leave-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
  }

  .leave-btn:hover {
    background: var(--bg-hover);
    color: var(--danger);
  }

  .voice-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: 11px;
    color: var(--text-secondary);
  }

  .channel {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ping.quality-warn {
    color: var(--warning);
  }

  .ping.quality-bad {
    color: var(--danger);
  }

  .share-row {
    display: flex;
    min-width: 0;
  }

  /* ScreenShareControls renders a fragment, not a wrapper element — it starts
     with its own `.divider`, which belongs in a wide bar and not in a panel. */
  .share-row {
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }

  .share-row > :global(.divider) {
    display: none;
  }

  .share-row > :global(.share-btn) {
    flex: 1;
    justify-content: center;
    min-width: 0;
  }

  .share-row > :global(.stats-pill) {
    flex-basis: 100%;
  }
</style>
