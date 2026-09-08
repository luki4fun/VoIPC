<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onDestroy } from "svelte";
  import {
    inputDevice,
    outputDevice,
    volume,
    inputGain,
    pttKey,
    muteKey,
    deafenKey,
    chatHistoryDisabled,
    pttHoldMode,
    noiseSuppression,
    rememberConnection,
    lastHost,
    lastPort,
    lastUsername,
    lastAcceptSelfSigned,
    autoConnect,
    screenShareCodec,
    soundSettings,
    defaultSoundSettings,
  } from "../stores/settings.js";
  import type { SoundSettings, SoundEntry } from "../stores/settings.js";
  import { voiceMode, vadThreshold } from "../stores/voice.js";
  import { connectionState, isMuted, isDeafened } from "../stores/connection.js";
  import { testLabel, testSource } from "../spatial.js";
  import { clearAllHistory } from "../stores/chat.js";
  import { addNotification } from "../stores/notifications.js";
  import { isMobile, isWeb, volumeKeyPtt } from "../stores/platform.js";
  import { shareChannelHistory, spatialAudio, screenAudioSpatial } from "../stores/settings.js";
  import type { AudioDeviceInfo } from "../types.js";
  import Icon from "./Icons.svelte";

  let { onclose }: { onclose: () => void } = $props();

  let activeTab = $state<"general" | "sounds">("general");

  let inputDevices = $state<AudioDeviceInfo[]>([]);
  let outputDevices = $state<AudioDeviceInfo[]>([]);

  // Game SDK (desktop only): the local port a game mod connects to
  let sdkEnabled = $state(false);
  let sdkPort = $state(39987);
  let sdkOrigins = $state("");
  let sdkConnected = $state(false);
  let sdkGame = $state("");
  /** False where the SDK is compiled out (Android), so the section stays hidden. */
  let sdkAvailable = $state(false);

  async function loadSdkStatus() {
    if (isWeb) return;
    try {
      const status = await invoke<{
        available: boolean;
        enabled: boolean;
        port: number;
        origins: string[];
        connected: boolean;
        game: string;
      }>("get_sdk_status");
      sdkAvailable = status.available;
      sdkEnabled = status.enabled;
      sdkPort = status.port;
      sdkOrigins = status.origins.join("\n");
      // A game that connected before this panel opened sent its event to nobody
      sdkConnected = status.connected;
      sdkGame = status.game;
    } catch (e) {
      console.error("Failed to read the game SDK status:", e);
    }
  }

  async function setSdk(change: { enabled?: boolean; port?: number; origins?: string }) {
    if (change.enabled !== undefined) sdkEnabled = change.enabled;
    if (change.port !== undefined) sdkPort = change.port;
    if (change.origins !== undefined) sdkOrigins = change.origins;
    try {
      await invoke("set_sdk_config", {
        enabled: change.enabled ?? null,
        port: change.port ?? null,
        origins:
          change.origins === undefined
            ? null
            : change.origins
                .split("\n")
                .map((o) => o.trim())
                .filter((o) => o.length > 0),
      });
    } catch (e) {
      addNotification(`Failed to save the game integration settings: ${e}`, "error");
      loadSdkStatus();
    }
  }

  async function loadDevices() {
    try {
      inputDevices = await invoke("get_input_devices");
      outputDevices = await invoke("get_output_devices");
    } catch (e) {
      console.error("Failed to load devices:", e);
      addNotification(`Failed to load audio devices: ${e}`, "error");
    }
  }

  async function changeScreenShareCodec(e: Event) {
    const codec = (e.target as HTMLSelectElement).value;
    screenShareCodec.set(codec);
    try {
      await invoke("set_screen_share_codec", { codec });
    } catch (err) {
      addNotification(`Failed to set the screen share codec: ${err}`, "error");
    }
  }

  /** Both spatial preferences take effect immediately and are persisted. */
  async function setSpatial(key: "spatial_audio" | "screen_audio_spatial", value: boolean) {
    if (key === "spatial_audio") spatialAudio.set(value);
    else screenAudioSpatial.set(value);
    try {
      await invoke("set_spatial_setting", { key, value });
    } catch (err) {
      addNotification(`Failed to save setting: ${err}`, "error");
    }
  }

  async function changeInputDevice(e: Event) {
    const target = e.target as HTMLSelectElement;
    inputDevice.set(target.value);
    try {
      await invoke("set_input_device", { deviceName: target.value });
      // Re-open the test stream on the newly selected device
      if (micTestRunning) {
        stopMicTest();
        await startMicTest();
      }
    } catch (err) {
      console.error("Failed to set input device:", err);
      addNotification(`Failed to set input device: ${err}`, "error");
    }
  }

  async function changeOutputDevice(e: Event) {
    const target = e.target as HTMLSelectElement;
    outputDevice.set(target.value);
    try {
      await invoke("set_output_device", { deviceName: target.value });
    } catch (err) {
      console.error("Failed to set output device:", err);
      addNotification(`Failed to set output device: ${err}`, "error");
    }
  }

  // PTT key capture
  let isCapturingKey = $state(false);
  let captureHint = $state("Press any key or combo...");
  let nonModifierPressed = false;
  // Which binding the capture UI is editing: PTT, global mute, or global deafen
  let captureTarget = $state<"ptt" | "mute" | "deafen">("ptt");

  function startKeyCapture(target: "ptt" | "mute" | "deafen" = "ptt") {
    captureTarget = target;
    isCapturingKey = true;
    nonModifierPressed = false;
    captureHint = "Press any key or combo...";
  }

  function formatBinding(e: KeyboardEvent): string {
    const parts: string[] = [];
    if (e.ctrlKey) parts.push("Ctrl");
    if (e.altKey) parts.push("Alt");
    if (e.shiftKey) parts.push("Shift");
    parts.push(e.code);
    return parts.join("+");
  }

  function finishCapture(binding: string) {
    isCapturingKey = false;
    const targets = {
      ptt: { store: pttKey, cmd: "set_ptt_key", label: "PTT key" },
      mute: { store: muteKey, cmd: "set_mute_key", label: "mute hotkey" },
      deafen: { store: deafenKey, cmd: "set_deafen_key", label: "deafen hotkey" },
    } as const;
    const t = targets[captureTarget];
    t.store.set(binding);
    invoke(t.cmd, { keyCode: binding }).catch((err: any) => {
      console.error(`Failed to set ${t.label}:`, err);
      addNotification(`Failed to set ${t.label}: ${err}`, "error");
    });
  }

  function clearToggleKey(target: "mute" | "deafen") {
    const t =
      target === "mute"
        ? { store: muteKey, cmd: "set_mute_key" }
        : { store: deafenKey, cmd: "set_deafen_key" };
    t.store.set("");
    invoke(t.cmd, { keyCode: "" }).catch(() => {});
  }

  function handleCaptureKeyDown(e: KeyboardEvent) {
    e.preventDefault();
    e.stopPropagation();

    const isModifier = ["Control", "Shift", "Alt", "Meta"].includes(e.key);

    if (isModifier) {
      const parts: string[] = [];
      if (e.ctrlKey || e.key === "Control") parts.push("Ctrl");
      if (e.altKey || e.key === "Alt") parts.push("Alt");
      if (e.shiftKey || e.key === "Shift") parts.push("Shift");
      captureHint = parts.join("+") + "+...";
      return;
    }

    nonModifierPressed = true;
    finishCapture(formatBinding(e));
  }

  function handleCaptureKeyUp(e: KeyboardEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (!isCapturingKey) return;

    const isModifier = ["Control", "Shift", "Alt", "Meta"].includes(e.key);
    if (isModifier && !nonModifierPressed) {
      finishCapture(e.code);
    }
  }

  function cancelKeyCapture() {
    isCapturingKey = false;
  }

  function autofocus(node: HTMLElement) {
    node.focus();
  }

  function handleHoldModeChange(e: Event) {
    const checked = (e.target as HTMLInputElement).checked;
    pttHoldMode.set(checked);
    invoke("set_ptt_hold_mode", { holdMode: checked }).catch((err: any) => {
      console.error("Failed to set PTT hold mode:", err);
    });
  }

  function handleAutoConnectChange(e: Event) {
    const checked = (e.target as HTMLInputElement).checked;
    autoConnect.set(checked);
    invoke("set_config_bool", { key: "auto_connect", value: checked }).catch((err: any) => {
      console.error("Failed to save auto-connect setting:", err);
    });
  }

  async function resetConfig() {
    try {
      await invoke("reset_config");
      pttKey.set("Space");
      pttHoldMode.set(true);
      volume.set(1.0);
      inputGain.set(1.0);
      muteKey.set("");
      deafenKey.set("");
      chatHistoryDisabled.set(false);
      inputDevice.set("");
      outputDevice.set("");
      voiceMode.set("ptt");
      vadThreshold.set(-40);
      noiseSuppression.set(true);
      isMuted.set(false);
      isDeafened.set(false);
      rememberConnection.set(false);
      lastHost.set("localhost");
      lastPort.set(9987);
      lastUsername.set("");
      lastAcceptSelfSigned.set(false);
      soundSettings.set(defaultSoundSettings());
      autoConnect.set(false);
      addNotification("Settings reset to defaults", "info");
    } catch (e) {
      console.error("Failed to reset config:", e);
      addNotification(`Failed to reset settings: ${e}`, "error");
    }
  }

  // --- Sound settings helpers ---

  const soundEvents: { key: keyof SoundSettings; label: string; description: string }[] = [
    { key: "channel_switch", label: "Channel switch", description: "When you switch to a different channel" },
    { key: "user_joined", label: "User joined", description: "When someone joins your current channel" },
    { key: "user_left", label: "User left", description: "When someone leaves your current channel" },
    { key: "disconnected", label: "Disconnected", description: "When you lose connection or disconnect" },
    { key: "direct_message", label: "Direct message", description: "When you receive a direct message" },
    { key: "channel_message", label: "Channel message", description: "When a message is posted in another channel" },
    { key: "poke", label: "Poke", description: "When another user pokes you" },
  ];

  async function saveSoundSettings(settings: SoundSettings) {
    soundSettings.set(settings);
    try {
      await invoke("set_sound_settings", { settings });
    } catch (e) {
      console.error("Failed to save sound settings:", e);
      addNotification(`Failed to save sound settings: ${e}`, "error");
    }
  }

  function toggleSoundEnabled(key: keyof SoundSettings) {
    const current = $soundSettings;
    const entry = current[key];
    saveSoundSettings({ ...current, [key]: { ...entry, enabled: !entry.enabled } });
  }

  async function browseSoundFile(key: keyof SoundSettings) {
    try {
      const path = await invoke<string | null>("browse_sound_file");
      if (path) {
        const current = $soundSettings;
        saveSoundSettings({ ...current, [key]: { ...current[key], path } });
      }
    } catch (e) {
      console.error("Failed to browse sound file:", e);
    }
  }

  function clearSoundFile(key: keyof SoundSettings) {
    const current = $soundSettings;
    saveSoundSettings({ ...current, [key]: { ...current[key], path: null } });
  }

  async function previewSoundFile(path: string) {
    try {
      await invoke("preview_sound", { path });
    } catch (e) {
      console.error("Failed to preview sound:", e);
      addNotification(`Failed to play sound: ${e}`, "error");
    }
  }

  function fileNameFromPath(path: string): string {
    const parts = path.replace(/\\/g, "/").split("/");
    return parts[parts.length - 1] || path;
  }

  function handleVolumeKeyPtt(e: Event) {
    const checked = (e.target as HTMLInputElement).checked;
    // Tell the Android native layer to intercept volume key, then update store
    const bridge = (window as any).__VoIPC;
    if (bridge) bridge.setVolumeKeyPtt(checked);
    volumeKeyPtt.set(checked);
  }

  // --- Mic test (settings-panel level meter, independent of VAD/calls) ---

  let micTestRunning = $state(false);
  let micLevelDb = $state(-100);
  let micLevelPercent = $derived(
    Math.max(0, Math.min(100, ((micLevelDb + 60) / 60) * 100)),
  );
  let micUnlisten: Array<() => void> = [];

  async function startMicTest() {
    try {
      micUnlisten.push(
        await listen<{ db: number }>("mic-test-level", (e) => {
          micLevelDb = e.payload.db;
        }),
      );
      micUnlisten.push(
        await listen<{ error: string }>("mic-test-error", (e) => {
          addNotification(`Mic test failed: ${e.payload.error}`, "error");
          stopMicTest();
        }),
      );
      await invoke("start_mic_test");
      micTestRunning = true;
    } catch (e) {
      addNotification(`Mic test failed: ${e}`, "error");
      stopMicTest();
    }
  }

  function stopMicTest() {
    micUnlisten.forEach((fn) => fn());
    micUnlisten = [];
    micTestRunning = false;
    micLevelDb = -100;
    invoke("stop_mic_test").catch(() => {});
  }

  function toggleMicTest() {
    if (micTestRunning) stopMicTest();
    else startMicTest();
  }

  // --- Spatial test: a synthetic voice orbits you through the real mixer ---

  let spatialTest = $state<{ mode: "2d" | "3d"; started: number } | null>(null);
  let spatialTestWhere = $state("");
  let spatialTestPos = $state<[number, number, number]>([0, 3, 0]);
  let spatialTestTimer: ReturnType<typeof setInterval> | null = null;
  // On the desktop the test is mixed into the connection's voice mixer; the
  // browser's audio graph stands on its own.
  let canSpatialTest = $derived(isWeb || $connectionState === "connected");

  function tickSpatialTest() {
    if (!spatialTest) return;
    const t = (performance.now() - spatialTest.started) / 1000;
    spatialTestWhere = testLabel(spatialTest.mode, t);
    spatialTestPos = testSource(spatialTest.mode, t).pos;
  }

  async function startSpatialTest(mode: "2d" | "3d") {
    try {
      await invoke("start_spatial_test", { mode });
      spatialTest = { mode, started: performance.now() };
      if (!spatialTestTimer) spatialTestTimer = setInterval(tickSpatialTest, 100);
      tickSpatialTest();
    } catch (e) {
      addNotification(`Spatial test failed: ${e}`, "error");
    }
  }

  function stopSpatialTest() {
    if (spatialTestTimer) clearInterval(spatialTestTimer);
    spatialTestTimer = null;
    spatialTest = null;
    invoke("stop_spatial_test").catch(() => {});
  }

  // Losing the connection takes the desktop mixer with it
  $effect(() => {
    if (!canSpatialTest && spatialTest) stopSpatialTest();
  });

  onDestroy(() => {
    if (micTestRunning) stopMicTest();
    if (spatialTest) stopSpatialTest();
  });

  // Load devices on mount (skip on mobile — only default device available)
  if (!$isMobile) loadDevices();
  loadSdkStatus();

  // A game connecting or leaving shows up live in the panel
  const sdkUnlisten = listen<{ connected: boolean; game: string }>("sdk-status", (event) => {
    sdkConnected = event.payload.connected;
    sdkGame = event.payload.game;
  });
  onDestroy(() => {
    sdkUnlisten.then((off) => off()).catch(() => {});
  });
</script>

<div class="overlay" role="dialog" onclick={onclose} onkeydown={() => {}}>
  <div
    class="panel"
    onclick={(e) => e.stopPropagation()}
    onkeydown={() => {}}
    role="dialog"
  >
    <div class="panel-header">
      <h3>Settings</h3>
      <button class="close-btn" onclick={onclose} title="Close"><Icon name="close" size={18} /></button>
    </div>

    <div class="tabs">
      <button
        class="tab"
        class:active={activeTab === "general"}
        onclick={() => (activeTab = "general")}
      >General</button>
      {#if !$isMobile}
        <button
          class="tab"
          class:active={activeTab === "sounds"}
          onclick={() => (activeTab = "sounds")}
        >Sounds</button>
      {/if}
    </div>

    {#if activeTab === "general"}
      {#if !$isMobile}
        <div class="section">
          <h4>Audio Input</h4>
          <select onchange={changeInputDevice}>
            {#each inputDevices as device}
              <option value={device.name} selected={device.is_default}>
                {device.name}
                {device.is_default ? " (Default)" : ""}
              </option>
            {/each}
          </select>
          <div class="mic-test">
            <button class="mic-test-btn" onclick={toggleMicTest}>
              {micTestRunning ? "Stop test" : "Test microphone"}
            </button>
            {#if micTestRunning}
              <div class="level-track">
                <div class="level-fill" style="width: {micLevelPercent}%"></div>
              </div>
            {/if}
          </div>
        </div>

        <div class="section">
          <h4>Audio Output</h4>
          <select onchange={changeOutputDevice}>
            {#each outputDevices as device}
              <option value={device.name} selected={device.is_default}>
                {device.name}
                {device.is_default ? " (Default)" : ""}
              </option>
            {/each}
          </select>
        </div>

        <div class="section">
          <h4>Push to Talk Key</h4>
          <div class="ptt-config">
            {#if isCapturingKey && captureTarget === "ptt"}
              <!-- svelte-ignore a11y_no_noninteractive_tabindex a11y_no_static_element_interactions -->
              <span
                class="current-key capturing"
                tabindex="0"
                onkeydown={handleCaptureKeyDown}
                onkeyup={handleCaptureKeyUp}
                onblur={cancelKeyCapture}
                use:autofocus
              >
                {captureHint}
              </span>
            {:else}
              <span class="current-key">{$pttKey}</span>
              <button class="change-key-btn" onclick={() => startKeyCapture("ptt")}>Change</button>
            {/if}
          </div>
          <label class="toggle-row">
            <input type="checkbox" checked={$pttHoldMode} onchange={handleHoldModeChange} />
            <span class="toggle-label">Hold modifier to talk</span>
            <span class="toggle-hint">
              {$pttHoldMode
                ? "Release the modifier key to stop (trigger key only activates)"
                : "Release the trigger key to stop immediately"}
            </span>
          </label>
        </div>

        {#if !isWeb}
        <div class="section">
          <h4>Global Hotkeys</h4>
          <div class="ptt-config">
            <span class="hotkey-label">Toggle mute</span>
            {#if isCapturingKey && captureTarget === "mute"}
              <!-- svelte-ignore a11y_no_noninteractive_tabindex a11y_no_static_element_interactions -->
              <span
                class="current-key capturing"
                tabindex="0"
                onkeydown={handleCaptureKeyDown}
                onkeyup={handleCaptureKeyUp}
                onblur={cancelKeyCapture}
                use:autofocus
              >{captureHint}</span>
            {:else}
              <span class="current-key">{$muteKey || "Not set"}</span>
              <button class="change-key-btn" onclick={() => startKeyCapture("mute")}>Change</button>
              {#if $muteKey}
                <button class="change-key-btn" onclick={() => clearToggleKey("mute")}>Clear</button>
              {/if}
            {/if}
          </div>
          <div class="ptt-config">
            <span class="hotkey-label">Toggle deafen</span>
            {#if isCapturingKey && captureTarget === "deafen"}
              <!-- svelte-ignore a11y_no_noninteractive_tabindex a11y_no_static_element_interactions -->
              <span
                class="current-key capturing"
                tabindex="0"
                onkeydown={handleCaptureKeyDown}
                onkeyup={handleCaptureKeyUp}
                onblur={cancelKeyCapture}
                use:autofocus
              >{captureHint}</span>
            {:else}
              <span class="current-key">{$deafenKey || "Not set"}</span>
              <button class="change-key-btn" onclick={() => startKeyCapture("deafen")}>Change</button>
              {#if $deafenKey}
                <button class="change-key-btn" onclick={() => clearToggleKey("deafen")}>Clear</button>
              {/if}
            {/if}
          </div>
          <span class="toggle-hint">Work system-wide, even while the window is unfocused or in the tray</span>
        </div>
        {/if}
      {:else}
        <div class="section">
          <h4>Push to Talk</h4>
          <label class="toggle-row">
            <input type="checkbox" checked={$volumeKeyPtt} onchange={handleVolumeKeyPtt} />
            <span class="toggle-label">Use volume button for PTT</span>
            <span class="toggle-hint">Hold Volume Down to talk (overrides normal volume control)</span>
          </label>
        </div>
      {/if}

      {#if !isWeb}
      <div class="section">
        <h4>Screen Share</h4>
        <select value={$screenShareCodec} onchange={changeScreenShareCodec}>
          <option value="h264">H.264 — every viewer can watch</option>
          <option value="h265">H.265 — less bandwidth, desktop viewers only</option>
        </select>
        <span class="toggle-hint">
          Browsers decode H.265 only on Windows and macOS, and Firefox nowhere. Applies to your next share.
        </span>
      </div>
      {/if}

      <div class="section">
        <h4>Spatial Audio</h4>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$spatialAudio}
            onchange={(e) => setSpatial("spatial_audio", (e.target as HTMLInputElement).checked)}
          />
          <span class="toggle-label">Hear people where they stand</span>
          <span class="toggle-hint">
            In a proximity channel, voices are placed left/right and get quieter with distance.
            Turn this off for one plain, centred mix — useful on a mono headset or with hearing in one ear.
          </span>
        </label>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$screenAudioSpatial}
            onchange={(e) => setSpatial("screen_audio_spatial", (e.target as HTMLInputElement).checked)}
            disabled={!$spatialAudio}
          />
          <span class="toggle-label">Screen-share audio follows the sharer</span>
          <span class="toggle-hint">
            Off keeps a shared screen's sound centred while voices stay placed — better for music and video
          </span>
        </label>

        <div class="mic-test">
          {#if spatialTest}
            <button class="mic-test-btn" onclick={stopSpatialTest}>Stop test</button>
            <button
              class="mic-test-btn"
              onclick={() => startSpatialTest(spatialTest!.mode === "2d" ? "3d" : "2d")}
            >Switch to {spatialTest.mode === "2d" ? "3D" : "2D"}</button>
          {:else}
            <button
              class="mic-test-btn"
              disabled={!canSpatialTest || $isDeafened}
              onclick={() => startSpatialTest("2d")}
            >Test 2D</button>
            <button
              class="mic-test-btn"
              disabled={!canSpatialTest || $isDeafened}
              onclick={() => startSpatialTest("3d")}
            >Test 3D</button>
          {/if}
        </div>
        {#if spatialTest}
          <div class="spatial-test-readout">
            <svg viewBox="-4.5 -4.5 9 9" width="64" height="64" aria-hidden="true">
              <circle r="3" fill="none" stroke="currentColor" stroke-opacity="0.25" stroke-width="0.08" />
              <path d="M0,-0.7 L0.45,0.45 L-0.45,0.45 Z" fill="currentColor" opacity="0.6" />
              <circle
                cx={spatialTestPos[0]}
                cy={-spatialTestPos[1]}
                r={0.45 + spatialTestPos[2] / 20}
                fill="currentColor"
              />
            </svg>
            <span>The voice is <strong>{spatialTestWhere}</strong></span>
          </div>
        {/if}
        <span class="toggle-hint">
          {#if !canSpatialTest}
            Connect to a server first — the test plays through the live voice mixer.
          {:else if $isDeafened}
            You are deafened; undeafen to hear the test.
          {:else}
            A synthetic voice circles you 3 m away every 8 seconds: front, right, behind, left.
            In 3D it also climbs 4 m above you and sinks 4 m below, getting quieter with height.
            Turn "Hear people where they stand" off while it runs to compare with the plain mix.
            {#if $isMobile && !isWeb} This device plays a mono downmix: you hear the distance, not left/right.{/if}
          {/if}
        </span>
      </div>

      {#if !isWeb && sdkAvailable}
      <div class="section">
        <h4>Game Integration</h4>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={sdkEnabled}
            onchange={(e) => setSdk({ enabled: (e.target as HTMLInputElement).checked })}
          />
          <span class="toggle-label">Let a game place people for me</span>
          <span class="toggle-hint">
            Opens a local port only this machine can reach, so a game mod can tell VoIPC where
            every player stands. {sdkConnected ? `Connected: ${sdkGame}.` : "No game connected."}
            See docs/SDK.md.
          </span>
        </label>
        {#if sdkEnabled}
          <div class="ptt-config">
            <span class="hotkey-label">Port</span>
            <input
              class="sdk-input"
              type="number"
              min="1024"
              max="65535"
              value={sdkPort}
              onchange={(e) => setSdk({ port: Number((e.target as HTMLInputElement).value) })}
            />
          </div>
          <span class="toggle-hint">
            Extra allowed origins, one per line. Game runtimes are allowed already;
            add <code>null</code> only to test from a local file.
          </span>
          <textarea
            class="sdk-input"
            rows="2"
            value={sdkOrigins}
            onchange={(e) => setSdk({ origins: (e.target as HTMLTextAreaElement).value })}
          ></textarea>
        {/if}
      </div>
      {/if}

      <div class="section">
        <h4>Connection</h4>
        <label class="toggle-row">
          <input type="checkbox" checked={$autoConnect} onchange={handleAutoConnectChange} disabled={!$rememberConnection} />
          <span class="toggle-label">Auto-connect to last server on startup</span>
          {#if !$rememberConnection}
            <span class="toggle-hint">Enable "Remember connection details" in the connect dialog first</span>
          {/if}
        </label>
      </div>

      <div class="section">
        <h4>Data</h4>
        {#if !isWeb}
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={!$chatHistoryDisabled}
            onchange={(e) => {
              const enabled = (e.target as HTMLInputElement).checked;
              chatHistoryDisabled.set(!enabled);
              invoke("set_chat_history_disabled", { disabled: !enabled }).catch((err: any) => {
                addNotification(`Failed to save setting: ${err}`, "error");
              });
            }}
          />
          <span class="toggle-label">Save chat history (encrypted)</span>
          <span class="toggle-hint">
            {$chatHistoryDisabled
              ? "Off — chat is kept in memory only and lost on exit"
              : "Messages are stored in the encrypted vault"}
          </span>
        </label>
        {/if}
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$shareChannelHistory}
            onchange={(e) => {
              const enabled = (e.target as HTMLInputElement).checked;
              shareChannelHistory.set(enabled);
              invoke("set_config_bool", { key: "share_channel_history", value: enabled }).catch((err: any) => {
                addNotification(`Failed to save setting: ${err}`, "error");
              });
            }}
          />
          <span class="toggle-label">Share recent channel chat with newcomers</span>
          <span class="toggle-hint">
            When someone joins your channel, your client may hand them the last 50 channel messages it has — end-to-end encrypted to that person only, never through the server in the clear
          </span>
        </label>
        <div class="btn-row">
          <button class="danger-btn" onclick={async () => { await clearAllHistory(); addNotification("Chat history cleared", "info"); }}>
            Clear Chat History
          </button>
          <button class="danger-btn" onclick={resetConfig}>
            Reset Config
          </button>
        </div>
      </div>
    {/if}

    {#if activeTab === "sounds"}
      <div class="sounds-list">
        {#each soundEvents as event}
          {@const entry = $soundSettings[event.key]}
          <div class="sound-card">
            <div class="sound-header">
              <label class="sound-toggle">
                <input
                  type="checkbox"
                  checked={entry.enabled}
                  onchange={() => toggleSoundEnabled(event.key)}
                />
                <span class="sound-label">{event.label}</span>
              </label>
            </div>
            <span class="sound-desc">{event.description}</span>
            {#if isWeb}
              <!-- The browser has no files: a built-in tone per event; the
                   web backend previews by event name -->
              <div class="sound-file-row">
                <span class="sound-path">Built-in tone</span>
                <button class="sound-btn" onclick={() => previewSoundFile(event.key)} title="Play">Play</button>
              </div>
            {:else}
              <div class="sound-file-row">
                <span class="sound-path" title={entry.path ?? ""}>
                  {entry.path ? fileNameFromPath(entry.path) : "No file selected"}
                </span>
                <button class="sound-btn" onclick={() => browseSoundFile(event.key)} title="Browse">Browse</button>
                {#if entry.path}
                  <button class="sound-btn" onclick={() => previewSoundFile(entry.path!)} title="Play">Play</button>
                  <button class="sound-btn clear" onclick={() => clearSoundFile(event.key)} title="Clear"><Icon name="close" size={14} /></button>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 50;
  }

  .panel {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    width: min(480px, 92vw);
    max-height: 80vh;
    overflow-y: auto;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }

  h3 {
    font-size: 18px;
    color: var(--accent);
  }

  .close-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border-radius: 4px;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  /* Tabs */
  .tabs {
    display: flex;
    gap: 0;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }

  .tab {
    background: transparent;
    color: var(--text-secondary);
    font-size: 13px;
    padding: 8px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s;
  }

  .tab:hover {
    color: var(--text-primary);
  }

  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .section {
    margin-bottom: 20px;
  }

  .mic-test {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 8px;
  }

  .mic-test-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 10px;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }

  .mic-test-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .level-track {
    flex: 1;
    height: 8px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    overflow: hidden;
  }

  .level-fill {
    height: 100%;
    background: #43b581;
    border-radius: 4px;
    transition: width 60ms linear;
  }

  h4 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }

  select {
    width: 100%;
    padding: 8px 28px 8px 12px;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 14px;
    outline: none;
  }

  select:focus {
    border-color: var(--accent);
  }

  .toggle-row {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin-top: 8px;
    cursor: pointer;
    flex-wrap: wrap;
  }

  .toggle-row input[type="checkbox"] {
    margin-top: 2px;
    accent-color: var(--accent);
  }

  .toggle-label {
    font-size: 13px;
    color: var(--text-primary);
  }

  .toggle-hint {
    width: 100%;
    font-size: 11px;
    color: var(--text-secondary);
    margin-left: 22px;
  }

  .ptt-config {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .ptt-config + .ptt-config {
    margin-top: 8px;
  }

  .hotkey-label {
    font-size: 12px;
    color: var(--text-secondary);
    min-width: 90px;
  }

  .spatial-test-readout {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .sdk-input {
    font-size: 13px;
    padding: 6px 8px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
    width: 100%;
    font-family: inherit;
    resize: vertical;
  }

  .current-key {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 16px;
    font-size: 14px;
    font-family: monospace;
  }

  .current-key.capturing {
    border-color: var(--accent);
    color: var(--text-secondary);
    animation: pulse 1s infinite;
    outline: none;
  }

  .change-key-btn {
    background: var(--bg-tertiary, var(--bg-primary));
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 8px 16px;
    font-size: 13px;
    border-radius: 4px;
    cursor: pointer;
  }

  .change-key-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  @keyframes pulse {
    0%, 100% { border-color: var(--accent); }
    50% { border-color: var(--border); }
  }

  .btn-row {
    display: flex;
    gap: 8px;
  }

  .danger-btn {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
    padding: 8px 16px;
    font-size: 13px;
    border-radius: 4px;
    cursor: pointer;
  }

  .danger-btn:hover {
    background: var(--danger);
    color: white;
  }

  /* Sounds tab */
  .sounds-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .sound-card {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
  }

  .sound-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .sound-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }

  .sound-toggle input[type="checkbox"] {
    accent-color: var(--accent);
  }

  .sound-label {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-primary);
  }

  .sound-desc {
    display: block;
    font-size: 11px;
    color: var(--text-secondary);
    margin: 4px 0 8px 0;
  }

  .sound-file-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .sound-path {
    flex: 1;
    font-size: 12px;
    color: var(--text-secondary);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 4px 8px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sound-btn {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 10px;
    font-size: 11px;
    border-radius: 3px;
    cursor: pointer;
    white-space: nowrap;
  }

  .sound-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .sound-btn.clear {
    color: var(--danger);
    border-color: var(--danger);
    padding: 4px 8px;
  }

  .sound-btn.clear:hover {
    background: var(--danger);
    color: white;
  }
</style>
