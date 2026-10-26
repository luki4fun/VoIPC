<script lang="ts">
  // The voice bar along the bottom of the classic layout.
  //
  // Chrome only. What actually opens the microphone lives in stores/voice.ts,
  // and the key handling and polling that go with it in VoiceKeys.svelte, which
  // App.svelte mounts for every layout — this bar is one of two places those
  // actions are reachable from, not their owner.

  import { invoke } from "@tauri-apps/api/core";
  import { addNotification } from "../stores/notifications.js";
  import {
    isMuted,
    isDeafened,
    isTransmitting,
    transmitHeldByGame,
  } from "../stores/connection.js";
  import { viewingVoice, voice, voiceChannel } from "../stores/channels.js";
  import { serverEntries } from "../connect.js";
  import { volume, inputGain, pttKey, noiseSuppression } from "../stores/settings.js";
  import { micLane } from "../stores/mixer.js";
  import {
    audioLevel,
    leaveVoice,
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

  // In no voice channel on any server there is nothing to talk into
  let voiceDisabled = $derived($voice === null);

  async function handleGainChange(e: Event) {
    const gain = parseFloat((e.target as HTMLInputElement).value);
    inputGain.set(gain);
    try {
      await invoke("set_input_gain", { gain });
    } catch (err) {
      console.error("Failed to set input gain:", err);
      addNotification(`Could not change the microphone gain: ${err}`, "error");
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
      addNotification(`Could not change the volume: ${err}`, "error");
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
      addNotification(`Could not change the voice activation threshold: ${err}`, "error");
    }
  }

  // Where the call is, for when the server on screen is another one: the
  // sidebar then shows that server, and nothing else names the one this bar
  // (and its Leave button) acts on.
  const voiceWhere = $derived(
    `${$voiceChannel?.name ?? ""} · ${$serverEntries.find((e) => e.inVoice)?.name ?? ""}`,
  );

  // Audio level meter — clamp to -60..0 range for display
  let levelPercent = $derived(Math.max(0, Math.min(100, (($audioLevel + 60) / 60) * 100)));
  let thresholdPercent = $derived(Math.max(0, Math.min(100, (($vadThreshold + 60) / 60) * 100)));
</script>

<div class="voice-controls" class:mobile={$isMobile}>
  {#if voiceDisabled}
    <span class="voice-disabled">Not in a voice channel</span>
  {:else}
    {#if !$viewingVoice}
      <span class="voice-where" title="In voice on another server">{voiceWhere}</span>
    {/if}
    <select class="mode-select" value={$voiceMode} onchange={handleModeChange} aria-label="How your microphone opens">
      <option value="ptt">Push to talk</option>
      <option value="vad">Voice activation</option>
      <option value="always_on">Always on</option>
    </select>

    {#if $voiceMode === "ptt"}
      {#if !$isMobile}
        <!-- Held with any pointer (captured, so sliding off it does not drop
             the hold) or with Space / Enter from the keyboard -->
        <button
          class="ptt-btn"
          class:active={$isTransmitting}
          class:by-game={$transmitHeldByGame}
          aria-pressed={$isTransmitting}
          onpointerdown={(e) => {
            if (e.button !== 0) return;
            (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
            void startTransmit();
          }}
          onpointerup={() => void stopTransmit()}
          onpointercancel={() => void stopTransmit()}
          onkeydown={(e) => {
            if ((e.key === " " || e.key === "Enter") && !e.repeat) {
              e.preventDefault();
              void startTransmit();
            }
          }}
          onkeyup={(e) => {
            if (e.key === " " || e.key === "Enter") {
              e.preventDefault();
              void stopTransmit();
            }
          }}
          onblur={() => {
            if ($isTransmitting && !$transmitHeldByGame) void stopTransmit();
          }}
          title={$transmitHeldByGame
            ? "The game is holding your push-to-talk (Settings → Game Integration)"
            : undefined}
        >
          {$transmitHeldByGame ? "Game is talking" : `Talk: ${$pttKey}`}
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
          title="Voice activation threshold: {$vadThreshold} dB"
          aria-label="Voice activation threshold"
          aria-valuetext="{$vadThreshold} dB"
        />
      </div>
    {:else}
      <span class="mode-label">Microphone always on</span>
    {/if}

    <div class="divider"></div>

    <div class="control-group">
      <button aria-label="Mute" aria-pressed={$isMuted}
        class="icon-btn"
        class:active-danger={$isMuted}
        onclick={toggleMute}
        title={$isMuted ? "Unmute (Ctrl+M)" : "Mute (Ctrl+M)"}
      >
        <Icon name={$isMuted ? "mic-off" : "mic-on"} size={18} />
      </button>

      <button aria-label="Deafen" aria-pressed={$isDeafened}
        class="icon-btn"
        class:active-danger={$isDeafened}
        onclick={toggleDeafen}
        title={$isDeafened ? "Undeafen (Ctrl+D)" : "Deafen (Ctrl+D)"}
      >
        <Icon name={$isDeafened ? "headphones-off" : "headphones-on"} size={18} />
      </button>

      <button aria-label="Noise suppression" aria-pressed={$noiseSuppression}
        class="icon-btn"
        class:on={$noiseSuppression}
        class:ns-off={!$noiseSuppression}
        onclick={toggleNoiseSuppression}
        title={$noiseSuppression ? "Disable noise suppression" : "Enable noise suppression"}
      >
        <Icon name="noise-suppression" size={18} />
      </button>

      {#if $isMobile}
        <button aria-label="Speaker" aria-pressed={$speakerMode}
          class="icon-btn"
          class:on={$speakerMode}
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
          class:on={$centreView === "room"}
          onclick={() => centreView.set($centreView === "room" ? "chat" : "room")}
          title={$centreView === "room" ? "Back to chat" : "Show the virtual room"}
        >
          <Icon name="room" size={18} />
        </button>
      {/if}

      <button
        class="icon-btn"
        class:on={$centreView === "mixer" && $micLane.effect === "none"}
        class:active-danger={$micLane.effect !== "none"}
        onclick={() => centreView.set($centreView === "mixer" ? "chat" : "mixer")}
        title={$micLane.effect !== "none"
          ? `Mixer — your voice is going out as a ${$micLane.effect}`
          : "Mixer"}
      >
        <Icon name="music-note" size={18} />
      </button>

      <!-- Out of the voice channel, still on the server: stores/voice.ts -->
      <button aria-label="Leave voice" class="icon-btn leave-voice-btn" onclick={leaveVoice} title="Leave voice">
        <Icon name="disconnect" size={18} />
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
      aria-label="Microphone gain"
      aria-valuetext="{Math.round($inputGain * 100)}%"
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
      aria-label="Output volume"
      aria-valuetext="{Math.round($volume * 100)}%"
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
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    font-style: italic;
  }

  .voice-where {
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--success);
    font-size: var(--fs-sm);
  }

  .leave-voice-btn:hover {
    color: var(--danger);
  }

  .mode-select {
    background-color: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 28px 6px 8px;
    font-size: var(--fs-sm);
    cursor: pointer;
  }

  .mode-select:focus {
    border-color: var(--focus-ring);
  }

  .ptt-btn {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    padding: 8px 20px;
    font-weight: 600;
    font-size: var(--fs-body);
    min-width: 100px;
  }

  .ptt-btn:hover {
    background: var(--bg-hover);
  }

  .ptt-btn.active {
    background: var(--success);
    color: var(--on-success);
  }

  /* Somebody else opened this microphone. It is still a microphone that is
     open, so it stays lit — but not in the colour that means "you pressed
     the key", because you did not. */
  .ptt-btn.by-game {
    background: var(--accent);
    color: var(--on-accent);
  }

  .mode-label {
    font-size: var(--fs-sm);
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
    background: linear-gradient(90deg, var(--success), var(--warning) 70%, var(--danger) 95%);
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
    accent-color: var(--control-fill);
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
    accent-color: var(--control-fill);
    background: transparent;
    border: none;
    padding: 0;
  }

  /* A phone's voice bar in two rows, in every layout: the buttons first, the
     whole width; the mode and both sliders sharing the row under them. With
     the mode's name spelled out it took a row of its own otherwise. */
  .voice-controls.mobile .control-group {
    order: -1;
    flex-basis: 100%;
    justify-content: center;
  }

  .voice-controls.mobile .divider {
    display: none;
  }

  /* A slider narrower than a thumb's travel is no slider: with "Microphone
     always on" spelled out beside the mode, they take a row of their own */
  .voice-controls.mobile .volume {
    flex: 1 1 140px;
    min-width: 0;
    margin-left: 0;
  }

  .voice-controls.mobile .volume input {
    width: 100%;
    min-width: 0;
  }

  /* A phone on its side: one row. Three rows took the height a watched share
     needs; the sliders are in the mixer, and in the bar in portrait. */
  @media (max-height: 520px) and (pointer: coarse) {
    .voice-controls.mobile .control-group {
      order: 0;
      flex-basis: auto;
    }

    .voice-controls.mobile .volume {
      display: none;
    }
  }

  /* A finger's worth of height, around the same thin track */
  @media (pointer: coarse) {
    .mode-select {
      min-height: var(--hit);
    }

    input[type="range"] {
      height: var(--hit);
    }
  }
</style>
