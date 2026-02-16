<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    inputDevice,
    outputDevice,
    volume,
    pttKey,
    pttHoldMode,
    noiseSuppression,
    rememberConnection,
    lastHost,
    lastPort,
    lastUsername,
    lastAcceptSelfSigned,
    autoConnect,
    soundSettings,
    defaultSoundSettings,
  } from "../stores/settings.js";
  import type { SoundSettings, SoundEntry } from "../stores/settings.js";
  import { voiceMode, vadThreshold } from "../stores/voice.js";
  import { isMuted, isDeafened } from "../stores/connection.js";
  import { clearAllHistory } from "../stores/chat.js";
  import { addNotification } from "../stores/notifications.js";
  import type { AudioDeviceInfo } from "../types.js";
  import Icon from "./Icons.svelte";

  let { onclose }: { onclose: () => void } = $props();

  let activeTab = $state<"general" | "sounds">("general");

  let inputDevices = $state<AudioDeviceInfo[]>([]);
  let outputDevices = $state<AudioDeviceInfo[]>([]);

  async function loadDevices() {
    try {
      inputDevices = await invoke("get_input_devices");
      outputDevices = await invoke("get_output_devices");
    } catch (e) {
      console.error("Failed to load devices:", e);
    }
  }

  async function changeInputDevice(e: Event) {
    const target = e.target as HTMLSelectElement;
    inputDevice.set(target.value);
    try {
      await invoke("set_input_device", { deviceName: target.value });
    } catch (err) {
      console.error("Failed to set input device:", err);
    }
  }

  async function changeOutputDevice(e: Event) {
    const target = e.target as HTMLSelectElement;
    outputDevice.set(target.value);
    try {
      await invoke("set_output_device", { deviceName: target.value });
    } catch (err) {
      console.error("Failed to set output device:", err);
    }
  }

  // PTT key capture
  let isCapturingKey = $state(false);
  let captureHint = $state("Press any key or combo...");
  let nonModifierPressed = false;

  function startKeyCapture() {
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
    pttKey.set(binding);
    isCapturingKey = false;
    invoke("set_ptt_key", { keyCode: binding }).catch((err: any) => {
      console.error("Failed to set PTT key:", err);
    });
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
    }
  }

  function fileNameFromPath(path: string): string {
    const parts = path.replace(/\\/g, "/").split("/");
    return parts[parts.length - 1] || path;
  }

  // Load devices on mount
  loadDevices();
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
      <button
        class="tab"
        class:active={activeTab === "sounds"}
        onclick={() => (activeTab = "sounds")}
      >Sounds</button>
    </div>

    {#if activeTab === "general"}
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
          {#if isCapturingKey}
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
            <button class="change-key-btn" onclick={startKeyCapture}>Change</button>
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
    width: 480px;
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

  h4 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }

  select {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-primary);
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
