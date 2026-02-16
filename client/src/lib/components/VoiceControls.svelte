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
  import { volume, pttKey, pttHoldMode, noiseSuppression } from "../stores/settings.js";
  import { voiceMode, vadThreshold, audioLevel } from "../stores/voice.js";
  import type { VoiceMode } from "../stores/voice.js";
  import ScreenShareControls from "./ScreenShareControls.svelte";
  import Icon from "./Icons.svelte";

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
    // Stop transmit when changing modes to reset state cleanly
    // (handles edge case: key held during mode switch, release event won't fire after unregister)
    if ($isTransmitting) {
      await stopTransmit();
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

  // Parse the PTT binding string (e.g. "Ctrl+Space", "ControlLeft") into parts
  function parsePttBinding(): { needCtrl: boolean; needAlt: boolean; needShift: boolean; keyCode: string } {
    const parts = $pttKey.split("+");
    let needCtrl = false, needAlt = false, needShift = false;
    let keyCode = "";
    for (const part of parts) {
      if (part === "Ctrl") needCtrl = true;
      else if (part === "Alt") needAlt = true;
      else if (part === "Shift") needShift = true;
      else keyCode = part;
    }
    return { needCtrl, needAlt, needShift, keyCode };
  }

  // Check if the full PTT binding matches (all modifiers + trigger key)
  function matchesPttBinding(e: KeyboardEvent): boolean {
    const { needCtrl, needAlt, needShift, keyCode } = parsePttBinding();
    if (needCtrl && !e.ctrlKey) return false;
    if (needAlt && !e.altKey) return false;
    if (needShift && !e.shiftKey) return false;
    return e.code === keyCode;
  }

  // Check if a keyup event should stop PTT.
  // In trigger mode: stop when the trigger key is released.
  // In hold mode with modifiers: stop when a required modifier is released.
  // In hold mode without modifiers: stop when the trigger key is released.
  function shouldStopPtt(e: KeyboardEvent): boolean {
    const { needCtrl, needAlt, needShift, keyCode } = parsePttBinding();
    if ($pttHoldMode && (needCtrl || needAlt || needShift)) {
      // Hold mode with modifiers — stop when any required modifier is released
      if (needCtrl && e.key === "Control") return true;
      if (needAlt && e.key === "Alt") return true;
      if (needShift && e.key === "Shift") return true;
      return false;
    }
    // Trigger mode, or no modifiers — stop when the trigger key is released
    return e.code === keyCode;
  }

  // Window-level keyboard PTT and shortcuts (fallback when app is focused)
  let keydownHandler: ((e: KeyboardEvent) => void) | null = null;
  let keyupHandler: ((e: KeyboardEvent) => void) | null = null;

  onMount(() => {
    keydownHandler = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in input/textarea
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

      // PTT key — only in PTT mode
      if ($voiceMode === "ptt" && matchesPttBinding(e) && !e.repeat) {
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

      // Stop transmit when the released key breaks the PTT binding
      if ($voiceMode === "ptt" && $isTransmitting && shouldStopPtt(e)) {
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

    <div class="control-group">
      <button
        class="icon-btn"
        class:active-danger={$isMuted}
        onclick={toggleMute}
        title={$isMuted ? "Unmute (Ctrl+M)" : "Mute (Ctrl+M)"}
      >
        <Icon name={$isMuted ? "mic-off" : "mic-on"} size={18} />
      </button>

      <button
        class="icon-btn"
        class:active-danger={$isDeafened}
        onclick={toggleDeafen}
        title={$isDeafened ? "Undeafen (Ctrl+D)" : "Deafen (Ctrl+D)"}
      >
        <Icon name={$isDeafened ? "headphones-off" : "headphones-on"} size={18} />
      </button>

      <button
        class="icon-btn"
        class:active-success={$noiseSuppression}
        class:ns-off={!$noiseSuppression}
        onclick={toggleNoiseSuppression}
        title={$noiseSuppression ? "Disable noise suppression" : "Enable noise suppression"}
      >
        <Icon name="noise-suppression" size={18} />
      </button>
    </div>
  {/if}

  <ScreenShareControls />

  <div class="divider"></div>

  <div class="volume">
    <Icon name="volume" size={16} class="vol-icon" />
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
    border-radius: 6px;
    padding: 6px 8px;
    font-size: 12px;
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

  .control-group {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 3px;
    background: rgba(0, 0, 0, 0.15);
    border-radius: 10px;
  }

  .ns-off {
    opacity: 0.5;
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
