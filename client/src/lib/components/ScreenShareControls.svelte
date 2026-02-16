<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { currentChannelId } from "../stores/channels.js";
  import {
    isSharingScreen,
    viewerCount,
    showSourcePicker,
    pickerSwitchMode,
    screenAudioEnabled,
    screenAudioSending,
    senderFps,
    senderBitrate,
    shareResolution,
  } from "../stores/screenshare.js";
  import { addNotification } from "../stores/notifications.js";
  import Icon from "./Icons.svelte";

  let inLobby = $derived($currentChannelId === 0);

  let resLabel = $derived(
    $shareResolution === 1080 ? "1080p" :
    $shareResolution === 720 ? "720p" :
    $shareResolution === 480 ? "480p" : `${$shareResolution}p`
  );

  let bitrateLabel = $derived(
    $senderBitrate >= 1000
      ? `${($senderBitrate / 1000).toFixed(1)} Mbps`
      : `${$senderBitrate} kbps`
  );

  let audioStatus = $derived(
    !$screenAudioEnabled
      ? "off"
      : $screenAudioSending
        ? "sending"
        : "no-signal"
  );

  async function openPicker() {
    pickerSwitchMode.set(false);
    showSourcePicker.set(true);
  }

  function openSwitchPicker() {
    pickerSwitchMode.set(true);
    showSourcePicker.set(true);
  }

  async function stopSharing() {
    try {
      await invoke("stop_screen_share");
      isSharingScreen.set(false);
      viewerCount.set(0);
    } catch (e: any) {
      addNotification(e.toString(), "error");
    }
  }

  async function toggleAudio() {
    try {
      const enabled = await invoke<boolean>("toggle_screen_audio");
      screenAudioEnabled.set(enabled);
    } catch (e: any) {
      addNotification(e.toString(), "error");
    }
  }
</script>

{#if !inLobby}
  <div class="divider"></div>

  {#if $isSharingScreen}
    <button class="share-btn active" onclick={stopSharing} title="Stop sharing">
      <Icon name="monitor-off" size={16} />
      <span class="btn-label">Stop</span>
      {#if $viewerCount > 0}
        <span class="viewer-badge">{$viewerCount}</span>
      {/if}
    </button>
    <button class="icon-btn-sm" onclick={openSwitchPicker} title="Switch capture source">
      <Icon name="switch-source" size={16} />
    </button>
    <button
      class="audio-toggle {audioStatus}"
      onclick={toggleAudio}
      title={$screenAudioEnabled ? "Disable screen audio" : "Enable screen audio"}
    >
      <Icon name="music-note" size={14} />
      {#if audioStatus === "sending"}
        <span class="status-dot active"></span>
      {:else if audioStatus === "no-signal"}
        <span class="status-dot idle"></span>
      {/if}
    </button>
    {#if $senderFps > 0}
      <span class="stats-pill">
        <span class="stat">{resLabel}</span>
        <span class="stat-sep"></span>
        <span class="stat">{$senderFps} fps</span>
        <span class="stat-sep"></span>
        <span class="stat">{bitrateLabel}</span>
      </span>
    {/if}
  {:else}
    <button class="share-btn" onclick={openPicker} title="Share your screen">
      <Icon name="monitor" size={16} />
      <span class="btn-label">Share</span>
    </button>
  {/if}
{/if}

<style>
  .divider {
    width: 1px;
    height: 24px;
    background: var(--border);
  }

  .share-btn {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 6px 12px;
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .share-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .share-btn.active {
    background: var(--danger);
    color: white;
  }

  .share-btn.active:hover {
    opacity: 0.9;
  }

  .btn-label {
    font-size: 12px;
  }

  .icon-btn-sm {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: var(--icon-btn-size-sm);
    height: var(--icon-btn-size-sm);
    padding: 0;
    border-radius: var(--icon-btn-radius);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    border: none;
    cursor: pointer;
    transition: background-color 0.15s, color 0.15s;
    flex-shrink: 0;
  }

  .icon-btn-sm:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .viewer-badge {
    background: rgba(255, 255, 255, 0.25);
    font-size: 10px;
    padding: 1px 5px;
    border-radius: 8px;
    font-weight: 600;
  }

  .audio-toggle {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: var(--icon-btn-size-sm);
    height: var(--icon-btn-size-sm);
    padding: 0;
    border-radius: var(--icon-btn-radius);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    border: none;
    cursor: pointer;
    transition: background-color 0.15s, color 0.15s;
    flex-shrink: 0;
    gap: 0;
    position: relative;
  }

  .audio-toggle:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .audio-toggle.off {
    opacity: 0.5;
  }

  .audio-toggle.sending {
    color: #43b581;
  }

  .audio-toggle.no-signal {
    color: #faa61a;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    position: absolute;
    bottom: 3px;
    right: 3px;
  }

  .status-dot.active {
    background: #43b581;
    animation: pulse 1s infinite;
  }

  .status-dot.idle {
    background: #faa61a;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .stats-pill {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
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
</style>
