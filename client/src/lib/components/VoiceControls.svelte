<script lang="ts">
  // The voice bar along the bottom of the classic layout.
  //
  // Chrome only. What actually opens the microphone lives in stores/voice.ts,
  // and the key handling and polling that go with it in VoiceKeys.svelte, which
  // App.svelte mounts for every layout — this bar is one of two places those
  // actions are reachable from, not their owner.

  import { invoke } from "@tauri-apps/api/core";
  import {
    isMuted,
    isDeafened,
    isTransmitting,
    transmitHeldByGame,
  } from "../stores/connection.js";
  import { currentChannelId } from "../stores/channels.js";
  import { volume, inputGain, pttKey, noiseSuppression } from "../stores/settings.js";
  import { micLane } from "../stores/mixer.js";
  import {
    audioLevel,
    setVoiceMode,
    speakerMode,
    startTransmit,
    stopTransmit,
    toggleDeafen,
    toggleMute,
    toggleNoiseSuppression,
    toggleSpeaker,
    vadThreshold,
    voiceMode,
  } from "../stores/voice.js";
  import type { VoiceMode } from "../stores/voice.js";
  import ScreenShareControls from "./ScreenShareControls.svelte";
  import { isMobile } from "../stores/platform.js";
  import { centreView, currentProximity } from "../stores/room.js";
  import Icon from "./Icons.svelte";

  // Voice is disabled in the General lobby (channel 0)
  let voiceDisabled = $derived($currentChannelId === 0);

  async function handleGainChange(e: Event) {
    const gain = parseFloat((e.target as HTMLInputElement).value);
    inputGain.set(gain);
    try {
      await invoke("set_input_gain", { gain });
    } catch (err) {
      console.error("Failed to set input gain:", err);
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

  function handleModeChange(e: Event) {
    setVoiceMode((e.target as HTMLSelectElement).value as VoiceMode);
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
      {#if !$isMobile}
        <button
          class="ptt-btn"
          class:active={$isTransmitting}
          class:by-game={$transmitHeldByGame}
          onmousedown={startTransmit}
          onmouseup={stopTransmit}
          onmouseleave={stopTransmit}
          title={$transmitHeldByGame
            ? "The game is holding your push-to-talk (Settings → Game Integration)"
            : undefined}
        >
          {$transmitHeldByGame ? "Game is talking" : `PTT: ${$pttKey}`}
        </button>
      {/if}
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

      {#if $isMobile}
        <button
          class="icon-btn"
          class:active-success={$speakerMode}
          class:ns-off={!$speakerMode}
          onclick={toggleSpeaker}
          title={$speakerMode ? "Switch to earpiece" : "Switch to speaker"}
        >
          <Icon name="volume" size={18} />
        </button>
      {/if}

      {#if !$isMobile && $currentProximity !== "off"}
        <button
          class="icon-btn"
          class:active-success={$centreView === "room"}
          onclick={() => centreView.set($centreView === "room" ? "chat" : "room")}
          title={$centreView === "room" ? "Back to chat" : "Show the virtual room"}
        >
          <Icon name="room" size={18} />
        </button>
      {/if}

      <button
        class="icon-btn"
        class:active-success={$centreView === "mixer" && $micLane.effect === "none"}
        class:active-danger={$micLane.effect !== "none"}
        onclick={() => centreView.set($centreView === "mixer" ? "chat" : "mixer")}
        title={$micLane.effect !== "none"
          ? `Mixer — your voice is going out as a ${$micLane.effect}`
          : "Mixer"}
      >
        <Icon name="music-note" size={18} />
      </button>
    </div>
  {/if}

  {#if !$isMobile}
    <ScreenShareControls />
  {/if}

  <div class="divider"></div>

  <div class="volume" title="Mic gain: {Math.round($inputGain * 100)}%">
    <Icon name="mic-on" size={16} class="vol-icon" />
    <input
      type="range"
      min="0"
      max="4"
      step="0.1"
      value={$inputGain}
      oninput={handleGainChange}
    />
  </div>

  <div class="volume" title="Output volume: {Math.round($volume * 100)}%">
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
    flex-wrap: wrap;
  }

  .voice-disabled {
    font-size: 12px;
    color: var(--text-secondary);
    font-style: italic;
  }

  .mode-select {
    background-color: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 28px 6px 8px;
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

  /* Somebody else opened this microphone. It is still a microphone that is
     open, so it stays lit — but not in the colour that means "you pressed
     the key", because you did not. */
  .ptt-btn.by-game {
    background: var(--accent);
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
    background: var(--well);
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
