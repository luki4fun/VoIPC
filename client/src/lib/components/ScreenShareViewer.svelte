<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
  import { onDestroy } from "svelte";
  import {
    watchingUserId,
    currentFrame,
    activeScreenShares,
    screenAudioReceiving,
    poppedOut,
    setPopoutWindow,
    getPopoutWindow,
    receiverFps,
    receiverBitrate,
    receiverResolution,
    receiverFramesDropped,
  } from "../stores/screenshare.js";

  let bitrateLabel = $derived(
    $receiverBitrate >= 1000
      ? `${($receiverBitrate / 1000).toFixed(1)} Mbps`
      : `${$receiverBitrate} kbps`
  );

  let sharerName = $derived(
    $activeScreenShares.find((s) => s.user_id === $watchingUserId)?.username ?? "Unknown"
  );

  // requestAnimationFrame coalescing: only render the latest frame per vsync tick
  let displayFrame = $state<string | null>(null);
  let pendingFrame: string | null = null;
  let rafScheduled = false;

  $effect(() => {
    const frame = $currentFrame;
    if (!frame) {
      displayFrame = null;
      return;
    }

    pendingFrame = frame;
    if (!rafScheduled) {
      rafScheduled = true;
      requestAnimationFrame(() => {
        rafScheduled = false;
        if (pendingFrame) {
          displayFrame = pendingFrame;
        }
      });
    }
  });

  onDestroy(() => {
    rafScheduled = false;
    pendingFrame = null;
  });

  async function stopWatching() {
    try {
      await invoke("stop_watching_screen_share");
      watchingUserId.set(null);
      currentFrame.set(null);
    } catch (e) {
      console.error("Failed to stop watching:", e);
    }
  }

  async function popOut() {
    const existing = getPopoutWindow();
    if (existing) {
      try { await existing.setFocus(); } catch {}
      return;
    }

    const name = sharerName;
    const win = new WebviewWindow("screenshare-popout", {
      url: `index.html?popout=screenshare&sharer_name=${encodeURIComponent(name)}`,
      title: `${name}'s Screen - VoIPC`,
      width: 800,
      height: 600,
      center: true,
    });

    // Clean up store state and stop watching when the popout window is destroyed.
    win.once('tauri://destroyed', () => {
      setPopoutWindow(null);
      poppedOut.set(false);
      // Notify backend to stop watching (covers X button close)
      invoke("stop_watching_screen_share").catch(() => {});
    });

    setPopoutWindow(win);
    poppedOut.set(true);
  }
</script>

<div class="viewer">
  <div class="viewer-header">
    <span class="sharer-name">{sharerName}'s screen</span>
    <span class="audio-status" class:active={$screenAudioReceiving}>
      <span class="audio-icon">&#9835;</span>
      {#if $screenAudioReceiving}
        <span class="audio-label">Audio</span>
        <span class="audio-dot"></span>
      {:else}
        <span class="audio-label">No audio</span>
      {/if}
    </span>
    {#if $receiverResolution}
      <span class="stats-pill">
        <span class="stat">{$receiverResolution}</span>
        <span class="stat-sep"></span>
        <span class="stat">{$receiverFps} fps</span>
        <span class="stat-sep"></span>
        <span class="stat">{bitrateLabel}</span>
        {#if $receiverFramesDropped > 0}
          <span class="stat-sep"></span>
          <span class="stat dropped">{$receiverFramesDropped} dropped</span>
        {/if}
      </span>
    {/if}
    <button class="popout-btn" onclick={popOut} title="Pop out to separate window">&#8599;</button>
    <button class="stop-btn" onclick={stopWatching}>Stop Watching</button>
  </div>
  <div class="viewer-content">
    {#if displayFrame}
      <img src={displayFrame} alt="Screen share" class="frame" />
    {:else}
      <div class="waiting">Waiting for video stream...</div>
    {/if}
  </div>
</div>

<style>
  .viewer {
    display: flex;
    flex-direction: column;
    height: 100%;
    flex: 1;
    min-width: 0;
    background: #000;
  }

  .viewer-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    overflow: hidden;
    min-width: 0;
  }

  .sharer-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    flex-shrink: 1;
    min-width: 0;
  }

  .audio-status {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    color: var(--text-secondary);
    padding: 2px 8px;
    border-radius: 10px;
    background: var(--bg-tertiary);
    flex-shrink: 0;
  }

  .audio-status.active {
    color: #43b581;
    background: rgba(67, 181, 129, 0.1);
  }

  .audio-icon {
    font-size: 13px;
  }

  .audio-label {
    font-size: 11px;
  }

  .audio-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #43b581;
    animation: pulse 1s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .stats-pill {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    font-size: 11px;
    color: var(--text-secondary);
    background: var(--bg-tertiary);
    border-radius: 10px;
    flex-shrink: 1;
    min-width: 0;
    overflow: hidden;
  }

  .stat {
    white-space: nowrap;
  }

  .stat-sep {
    width: 1px;
    height: 10px;
    background: var(--border);
  }

  .stat.dropped {
    color: #faa61a;
  }

  .popout-btn {
    margin-left: auto;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 8px;
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
    border-radius: 4px;
    flex-shrink: 0;
  }

  .popout-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .stop-btn {
    background: var(--danger);
    color: white;
    padding: 4px 12px;
    font-size: 11px;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .stop-btn:hover {
    opacity: 0.9;
  }

  .viewer-content {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  .frame {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
  }

  .waiting {
    color: var(--text-secondary);
    font-size: 14px;
    font-style: italic;
  }
</style>
