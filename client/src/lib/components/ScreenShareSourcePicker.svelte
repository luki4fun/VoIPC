<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { addNotification } from "../stores/notifications.js";
  import {
    showSourcePicker,
    isSharingScreen,
    shareResolution,
    shareFps,
  } from "../stores/screenshare.js";

  let resolution = $state<number>(720);
  let fps = $state<number>(30);
  let starting = $state(false);

  function close() {
    if (!starting) showSourcePicker.set(false);
  }

  async function startShare() {
    starting = true;
    try {
      // This opens the native OS screen/window picker (XDG Desktop Portal)
      await invoke("start_screen_share", { resolution, fps });
      isSharingScreen.set(true);
      shareResolution.set(resolution);
      shareFps.set(fps);
      showSourcePicker.set(false);
    } catch (e: any) {
      addNotification(e.toString(), "error");
    } finally {
      starting = false;
    }
  }
</script>

<div class="overlay" onclick={close} role="presentation">
  <div class="picker" onclick={(e) => e.stopPropagation()} role="dialog">
    <div class="picker-header">
      <span>Share Screen</span>
      <button class="close-btn" onclick={close} disabled={starting}>&times;</button>
    </div>

    <div class="settings-body">
      <p class="hint">
        The system screen picker will appear after you click Start.
      </p>

      <div class="setting-row">
        <label>Resolution:</label>
        <select bind:value={resolution} disabled={starting}>
          <option value={480}>480p</option>
          <option value={720}>720p</option>
          <option value={1080}>1080p</option>
        </select>
      </div>

      <div class="setting-row">
        <label>Frame Rate:</label>
        <select bind:value={fps} disabled={starting}>
          <option value={30}>30 FPS</option>
          <option value={60}>60 FPS</option>
        </select>
      </div>
    </div>

    <div class="picker-footer">
      <button class="cancel-btn" onclick={close} disabled={starting}>Cancel</button>
      <button
        class="start-btn"
        onclick={startShare}
        disabled={starting}
      >{starting ? "Opening picker..." : "Start Sharing"}</button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .picker {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: 400px;
    max-height: 500px;
    display: flex;
    flex-direction: column;
  }

  .picker-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 14px;
  }

  .close-btn {
    background: transparent;
    color: var(--text-secondary);
    font-size: 18px;
    border: none;
    cursor: pointer;
    padding: 0 4px;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .settings-body {
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .hint {
    color: var(--text-secondary);
    font-size: 12px;
    margin: 0;
  }

  .setting-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
  }

  .setting-row label {
    min-width: 80px;
  }

  .setting-row select {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 13px;
    flex: 1;
  }

  .picker-footer {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
  }

  .cancel-btn {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 6px 14px;
    font-size: 12px;
  }

  .cancel-btn:hover {
    color: var(--text-primary);
  }

  .start-btn {
    background: var(--accent);
    color: white;
    padding: 6px 14px;
    font-size: 12px;
  }

  .start-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .start-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
