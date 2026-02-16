<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { addNotification } from "../stores/notifications.js";
  import {
    showSourcePicker,
    pickerSwitchMode,
    isSharingScreen,
    shareResolution,
    shareFps,
    currentSourceType,
    currentSourceId,
  } from "../stores/screenshare.js";

  interface DisplayInfo {
    id: string;
    name: string;
    width: number;
    height: number;
    is_primary: boolean;
  }

  interface WindowInfo {
    id: string;
    title: string;
    app_name: string;
  }

  let activeTab = $state<"displays" | "windows">("displays");
  let displays = $state<DisplayInfo[]>([]);
  let windows = $state<WindowInfo[]>([]);
  let selectedId = $state<string | null>(null);
  let resolution = $state<number>(720);
  let fps = $state<number>(30);
  let starting = $state(false);
  let loading = $state(true);
  let platform = $state<string>("linux");

  // Load sources on mount
  $effect(() => {
    loadSources();
  });

  async function loadSources() {
    loading = true;
    try {
      platform = await invoke<string>("get_platform");
      const [d, w] = await Promise.all([
        invoke<DisplayInfo[]>("enumerate_displays"),
        invoke<WindowInfo[]>("enumerate_windows"),
      ]);
      displays = d;
      windows = w;
      // Auto-select primary display on Windows
      if (platform === "windows" && displays.length > 0) {
        const primary = displays.find((d) => d.is_primary);
        selectedId = primary ? primary.id : displays[0].id;
      }
    } catch (e: any) {
      addNotification("Failed to enumerate sources: " + e.toString(), "error");
    } finally {
      loading = false;
    }
  }

  function close() {
    if (!starting) {
      showSourcePicker.set(false);
      pickerSwitchMode.set(false);
    }
  }

  function selectSource(id: string) {
    selectedId = id;
  }

  function switchTab(tab: "displays" | "windows") {
    activeTab = tab;
    selectedId = null;
    // Auto-select first item on Windows
    if (platform === "windows") {
      if (tab === "displays" && displays.length > 0) {
        const primary = displays.find((d) => d.is_primary);
        selectedId = primary ? primary.id : displays[0].id;
      } else if (tab === "windows" && windows.length > 0) {
        selectedId = windows[0].id;
      }
    }
  }

  async function startOrSwitch() {
    const sourceType = activeTab === "displays" ? "display" : "window";
    // On Linux, source_id is ignored (portal handles selection)
    const sourceId = platform === "linux" ? "0" : (selectedId ?? "0");

    // On Windows, require a selection
    if (platform === "windows" && !selectedId) {
      addNotification("Please select a source", "error");
      return;
    }

    starting = true;
    try {
      if ($pickerSwitchMode) {
        await invoke("switch_screen_share_source", {
          sourceType,
          sourceId,
          resolution,
          fps,
        });
      } else {
        await invoke("start_screen_share", {
          sourceType,
          sourceId,
          resolution,
          fps,
        });
        isSharingScreen.set(true);
      }
      currentSourceType.set(sourceType);
      currentSourceId.set(sourceId);
      shareResolution.set(resolution);
      shareFps.set(fps);
      showSourcePicker.set(false);
      pickerSwitchMode.set(false);
    } catch (e: any) {
      addNotification(e.toString(), "error");
    } finally {
      starting = false;
    }
  }

  let isLinux = $derived(platform === "linux");
  let buttonLabel = $derived(
    starting
      ? isLinux
        ? "Opening picker..."
        : "Starting..."
      : $pickerSwitchMode
        ? "Switch Source"
        : "Start Sharing"
  );
</script>

<div class="overlay" onclick={close} role="presentation">
  <div class="picker" onclick={(e) => e.stopPropagation()} role="dialog">
    <div class="picker-header">
      <span>{$pickerSwitchMode ? "Switch Source" : "Share Screen"}</span>
      <button class="close-btn" onclick={close} disabled={starting}>&times;</button>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        class="tab"
        class:active={activeTab === "displays"}
        onclick={() => switchTab("displays")}
        disabled={starting}
      >
        Displays
      </button>
      <button
        class="tab"
        class:active={activeTab === "windows"}
        onclick={() => switchTab("windows")}
        disabled={starting}
      >
        Windows
      </button>
    </div>

    <!-- Source list -->
    <div class="source-list">
      {#if loading}
        <div class="placeholder">Loading sources...</div>
      {:else if isLinux}
        <!-- Linux: portal handles enumeration -->
        <div class="portal-hint">
          {#if activeTab === "displays"}
            <div class="portal-icon">&#9638;</div>
            <p>Display capture</p>
            <p class="portal-sub">Your system's display picker will appear after clicking Start.</p>
          {:else}
            <div class="portal-icon">&#9645;</div>
            <p>Window capture</p>
            <p class="portal-sub">Your system's window picker will appear after clicking Start.</p>
          {/if}
        </div>
      {:else if activeTab === "displays"}
        {#if displays.length === 0}
          <div class="placeholder">No displays found</div>
        {:else}
          {#each displays as display (display.id)}
            <button
              class="source-card"
              class:selected={selectedId === display.id}
              onclick={() => selectSource(display.id)}
              disabled={starting}
            >
              <div class="source-icon">&#9638;</div>
              <div class="source-info">
                <span class="source-title">
                  {display.name}
                  {#if display.is_primary}
                    <span class="primary-badge">Primary</span>
                  {/if}
                </span>
                <span class="source-detail">{display.width} x {display.height}</span>
              </div>
            </button>
          {/each}
        {/if}
      {:else}
        {#if windows.length === 0}
          <div class="placeholder">No windows found</div>
        {:else}
          {#each windows as win (win.id)}
            <button
              class="source-card"
              class:selected={selectedId === win.id}
              onclick={() => selectSource(win.id)}
              disabled={starting}
            >
              <div class="source-icon">&#9645;</div>
              <div class="source-info">
                <span class="source-title">{win.title}</span>
                {#if win.app_name}
                  <span class="source-detail">{win.app_name}</span>
                {/if}
              </div>
            </button>
          {/each}
        {/if}
      {/if}
    </div>

    <!-- Settings -->
    <div class="settings-body">
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
        onclick={startOrSwitch}
        disabled={starting}
      >{buttonLabel}</button>
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
    width: 480px;
    max-height: 600px;
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

  /* ── Tabs ────────────────────────────────────────── */

  .tabs {
    display: flex;
    border-bottom: 1px solid var(--border);
  }

  .tab {
    flex: 1;
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 500;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: all 0.15s;
  }

  .tab:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  /* ── Source list ─────────────────────────────────── */

  .source-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    min-height: 160px;
    max-height: 280px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .placeholder {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    min-height: 120px;
    color: var(--text-secondary);
    font-size: 13px;
  }

  .portal-hint {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    min-height: 120px;
    gap: 4px;
    text-align: center;
    padding: 16px;
  }

  .portal-icon {
    font-size: 32px;
    color: var(--text-secondary);
    opacity: 0.5;
  }

  .portal-hint p {
    margin: 0;
    color: var(--text-primary);
    font-size: 13px;
    font-weight: 500;
  }

  .portal-sub {
    color: var(--text-secondary) !important;
    font-weight: 400 !important;
    font-size: 12px !important;
  }

  .source-card {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    transition: all 0.15s;
    width: 100%;
  }

  .source-card:hover {
    background: var(--bg-hover);
    border-color: var(--text-secondary);
  }

  .source-card.selected {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 8%, var(--bg-primary));
  }

  .source-icon {
    font-size: 20px;
    color: var(--text-secondary);
    flex-shrink: 0;
    width: 28px;
    text-align: center;
  }

  .source-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }

  .source-title {
    font-size: 13px;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .primary-badge {
    font-size: 10px;
    background: var(--accent);
    color: white;
    padding: 1px 5px;
    border-radius: 3px;
    flex-shrink: 0;
  }

  .source-detail {
    font-size: 11px;
    color: var(--text-secondary);
  }

  /* ── Settings ───────────────────────────────────── */

  .settings-body {
    padding: 12px 16px;
    display: flex;
    gap: 12px;
    border-top: 1px solid var(--border);
  }

  .setting-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    flex: 1;
  }

  .setting-row label {
    white-space: nowrap;
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

  /* ── Footer ─────────────────────────────────────── */

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
