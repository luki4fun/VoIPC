<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { inputDevice, outputDevice, pttKey } from "../stores/settings.js";
  import { clearAllHistory } from "../stores/chat.js";
  import { addNotification } from "../stores/notifications.js";
  import type { AudioDeviceInfo } from "../types.js";

  let { onclose }: { onclose: () => void } = $props();

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
      <button class="close-btn" onclick={onclose}>X</button>
    </div>

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
        <span class="current-key">{$pttKey}</span>
      </div>
    </div>

    <div class="section">
      <h4>Chat History</h4>
      <button class="danger-btn" onclick={async () => { await clearAllHistory(); addNotification("Chat history cleared", "info"); }}>
        Clear All Chat History
      </button>
    </div>
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
    width: 400px;
    max-height: 80vh;
    overflow-y: auto;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }

  h3 {
    font-size: 18px;
    color: var(--accent);
  }

  .close-btn {
    background: transparent;
    color: var(--text-secondary);
    font-size: 16px;
    padding: 4px 8px;
  }

  .close-btn:hover {
    color: var(--text-primary);
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
</style>
