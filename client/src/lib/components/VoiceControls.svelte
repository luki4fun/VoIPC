<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount, onDestroy } from "svelte";
  import {
    connectionState,
    isMuted,
    isDeafened,
    isTransmitting,
  } from "../stores/connection.js";
  import { currentChannelId } from "../stores/channels.js";
  import { volume, pttKey } from "../stores/settings.js";
  import { voiceMode, vadThreshold, audioLevel } from "../stores/voice.js";
  import type { VoiceMode } from "../stores/voice.js";
  import ScreenShareControls from "./ScreenShareControls.svelte";
  import { writable } from "svelte/store";

  // Noise suppression state (default: enabled)
  const noiseSuppression = writable(true);

  // Voice is disabled in the General lobby (channel 0)
  let voiceDisabled = $derived($currentChannelId === 0);

  async function startTransmit() {
    if (voiceDisabled) return;
    try {
      await invoke("start_transmit");
      isTransmitting.set(true);
    } catch (e) {
      console.error("Failed to start transmit:", e);
    }
  }

  async function stopTransmit() {
    if (!$isTransmitting) return;
    try {
      await invoke("stop_transmit");
      isTransmitting.set(false);
    } catch (e) {
      console.error("Failed to stop transmit:", e);
    }
  }

  // VAD/AlwaysOn: auto-start transmit when connected to a channel
  $effect(() => {
    if ($voiceMode !== "ptt" && !voiceDisabled && $connectionState === "connected" && !$isTransmitting) {
      startTransmit();
    }
  });

  async function toggleMute() {
    try {
      const muted: boolean = await invoke("toggle_mute");
      isMuted.set(muted);
    } catch (e) {
      console.error("Failed to toggle mute:", e);
    }
  }

  async function toggleDeafen() {
    try {
      const deafened: boolean = await invoke("toggle_deafen");
      isDeafened.set(deafened);
    } catch (e) {
      console.error("Failed to toggle deafen:", e);
    }
  }

  async function toggleNoiseSuppression() {
    try {
      const enabled: boolean = await invoke("toggle_noise_suppression");
      noiseSuppression.set(enabled);
    } catch (e) {
      console.error("Failed to toggle noise suppression:", e);
    }
  }

  async function handleVolumeChange(e: Event) {
    const target = e.target as HTMLInputElement;
    const vol = parseFloat(target.value);
    volume.set(vol);
    try {
      await invoke("set_volume", { volume: vol });
    } catch (err) {
      console.error("Failed to set volume:", err);
    }
  }

  async function handleModeChange(e: Event) {
    const mode = (e.target as HTMLSelectElement).value as VoiceMode;
    voiceMode.set(mode);
    try {
      await invoke("set_voice_mode", { mode });
    } catch (err) {
      console.error("Failed to set voice mode:", err);
    }
    // If switching to PTT, stop transmit (user needs to hold key)
    if (mode === "ptt" && $isTransmitting) {
      stopTransmit();
    }
  }

  async function handleThresholdChange(e: Event) {
    const db = parseFloat((e.target as HTMLInputElement).value);
    vadThreshold.set(db);
    try {
      await invoke("set_vad_threshold", { thresholdDb: db });
    } catch (err) {
      console.error("Failed to set VAD threshold:", err);
    }
  }

  // Audio level meter — clamp to -60..0 range for display
  let levelPercent = $derived(Math.max(0, Math.min(100, (($audioLevel + 60) / 60) * 100)));
  let thresholdPercent = $derived(Math.max(0, Math.min(100, (($vadThreshold + 60) / 60) * 100)));

  // Poll audio level when in VAD mode and connected
  let levelPollInterval: ReturnType<typeof setInterval> | null = null;

  $effect(() => {
    if ($voiceMode === "vad" && $connectionState === "connected" && $isTransmitting) {
      if (!levelPollInterval) {
        levelPollInterval = setInterval(() => {
          invoke<number>("get_audio_level").then((level) => {
            audioLevel.set(level);
          }).catch(() => {});
        }, 66); // ~15 Hz
      }
    } else {
      if (levelPollInterval) {
        clearInterval(levelPollInterval);
        levelPollInterval = null;
      }
    }

    return () => {
      if (levelPollInterval) {
        clearInterval(levelPollInterval);
        levelPollInterval = null;
      }
    };
  });

  // Global keyboard PTT and shortcuts
  let keydownHandler: ((e: KeyboardEvent) => void) | null = null;
  let keyupHandler: ((e: KeyboardEvent) => void) | null = null;

  onMount(() => {
    keydownHandler = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in input/textarea
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

      // PTT key — only in PTT mode
      if ($voiceMode === "ptt" && e.code === $pttKey && !e.repeat) {
        e.preventDefault();
        startTransmit();
      }

      // Ctrl+M / Meta+M = toggle mute
      if ((e.ctrlKey || e.metaKey) && e.code === "KeyM") {
        e.preventDefault();
        toggleMute();
      }

      // Ctrl+D / Meta+D = toggle deafen
      if ((e.ctrlKey || e.metaKey) && e.code === "KeyD") {
        e.preventDefault();
        toggleDeafen();
      }
    };

    keyupHandler = (e: KeyboardEvent) => {
      // Don't trigger when typing in input/textarea
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

      if ($voiceMode === "ptt" && e.code === $pttKey) {
        e.preventDefault();
        stopTransmit();
      }
    };

    window.addEventListener("keydown", keydownHandler);
    window.addEventListener("keyup", keyupHandler);
  });

  onDestroy(() => {
    if (keydownHandler) window.removeEventListener("keydown", keydownHandler);
    if (keyupHandler) window.removeEventListener("keyup", keyupHandler);
  });
</script>

<div class="voice-controls">
  {#if voiceDisabled}
    <span class="voice-disabled">Voice disabled in lobby — join a channel to talk</span>
  {:else}
    <select class="mode-select" value={$voiceMode} onchange={handleModeChange}>
      <option value="ptt">PTT</option>
      <option value="vad">Voice</option>
      <option value="always_on">Open</option>
    </select>

    {#if $voiceMode === "ptt"}
      <button
        class="ptt-btn"
        class:active={$isTransmitting}
        onmousedown={startTransmit}
        onmouseup={stopTransmit}
        onmouseleave={stopTransmit}
      >
        PTT: {$pttKey}
      </button>
    {:else if $voiceMode === "vad"}
      <div class="vad-meter">
        <div class="meter-bar">
          <div class="meter-fill" style="width: {levelPercent}%"></div>
          <div class="meter-threshold" style="left: {thresholdPercent}%"></div>
        </div>
        <input
          type="range"
          class="threshold-slider"
          min="-60"
          max="0"
          step="1"
          value={$vadThreshold}
          oninput={handleThresholdChange}
          title="VAD threshold: {$vadThreshold} dB"
        />
      </div>
    {:else}
      <span class="mode-label">Always transmitting</span>
    {/if}

    <div class="divider"></div>

    <button
      class="control-btn"
      class:active={$isMuted}
      onclick={toggleMute}
      title={$isMuted ? "Unmute (Ctrl+M)" : "Mute (Ctrl+M)"}
    >
      {$isMuted ? "Unmute" : "Mute"}
    </button>

    <button
      class="control-btn"
      class:active={$isDeafened}
      onclick={toggleDeafen}
      title={$isDeafened ? "Undeafen (Ctrl+D)" : "Deafen (Ctrl+D)"}
    >
      {$isDeafened ? "Undeafen" : "Deafen"}
    </button>

    <button
      class="control-btn ns-btn"
      class:active={!$noiseSuppression}
      onclick={toggleNoiseSuppression}
      title={$noiseSuppression ? "Disable noise suppression" : "Enable noise suppression"}
    >
      NS
    </button>
  {/if}

  <ScreenShareControls />

  <div class="divider"></div>

  <div class="volume">
    <span class="vol-label">Vol</span>
    <input
      type="range"
      min="0"
      max="1"
      step="0.05"
      value={$volume}
      oninput={handleVolumeChange}
    />
  </div>
</div>

<style>
  .voice-controls {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-top: 1px solid var(--border);
    overflow: hidden;
    min-width: 0;
  }

  .voice-disabled {
    font-size: 12px;
    color: var(--text-secondary);
    font-style: italic;
  }

  .mode-select {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 6px;
    font-size: 11px;
    cursor: pointer;
    outline: none;
  }

  .mode-select:focus {
    border-color: var(--accent);
  }

  .ptt-btn {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    padding: 8px 20px;
    font-weight: 600;
    font-size: 13px;
    min-width: 100px;
  }

  .ptt-btn:hover {
    background: var(--bg-hover);
  }

  .ptt-btn.active {
    background: var(--success);
    color: white;
  }

  .mode-label {
    font-size: 12px;
    color: var(--text-secondary);
    font-style: italic;
    padding: 0 8px;
  }

  .vad-meter {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 120px;
  }

  .meter-bar {
    position: relative;
    height: 8px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    overflow: hidden;
  }

  .meter-fill {
    height: 100%;
    background: linear-gradient(90deg, #43b581, #faa61a 70%, #f04747 95%);
    border-radius: 4px;
    transition: width 0.05s linear;
  }

  .meter-threshold {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--text-primary);
    opacity: 0.7;
  }

  .threshold-slider {
    width: 100%;
    height: 10px;
    accent-color: var(--accent);
    background: transparent;
    border: none;
    padding: 0;
    margin: 0;
  }

  .control-btn {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 6px 12px;
    font-size: 12px;
  }

  .control-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .control-btn.active {
    background: var(--danger);
    color: white;
  }

  .ns-btn {
    background: var(--success);
    color: white;
  }

  .ns-btn.active {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .divider {
    width: 1px;
    height: 24px;
    background: var(--border);
  }

  .volume {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-left: auto;
  }

  .vol-label {
    font-size: 12px;
    color: var(--text-secondary);
  }

  input[type="range"] {
    width: 100px;
    accent-color: var(--accent);
    background: transparent;
    border: none;
    padding: 0;
  }
</style>
