<script lang="ts">
  import { backdrop, dialog } from "../actions/dialog.js";
  import { onDestroy, onMount } from "svelte";
  import Icon from "./Icons.svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { addNotification } from "../stores/notifications.js";
  import { canShareDisplayAudio } from "../display-capture.js";
  import {
    showSourcePicker,
    pickerSwitchMode,
    isSharingScreen,
    shareResolution,
    shareFps,
    currentSourceType,
    currentSourceId,
    viewerCount,
    lastShareFrame,
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
  /** Linux: the portal can restore the last screen or window without its dialog. */
  let againKnown = $state(false);

  // ── Windows: a picture on every tile (source_preview: a still, a window's icon) ──
  interface SourcePicture {
    picture: string | null;
    icon: string | null;
  }
  /** By "display:<id>" / "window:<id>". Drawn here only: never sent, never stored. */
  let pictures = $state<Record<string, SourcePicture>>({});
  /** Asked at most this many at a time: each is a GDI draw, a window's one can be slow. */
  const PICTURES_AT_ONCE = 4;
  const REFRESH_MS = 3000;
  let refreshing = false;
  let refreshTimer: ReturnType<typeof setInterval> | null = null;
  let closed = false;

  async function fetchPictures() {
    if (refreshing || closed || platform !== "windows") return;
    refreshing = true;
    const items = [
      ...displays.map((d) => ({ kind: "display", id: d.id })),
      ...windows.map((w) => ({ kind: "window", id: w.id })),
    ];
    let next = 0;
    const worker = async () => {
      while (next < items.length && !closed) {
        const it = items[next++];
        const got = await invoke<SourcePicture>("source_preview", { sourceType: it.kind, sourceId: it.id }).catch(() => null);
        if (got && !closed) pictures = { ...pictures, [`${it.kind}:${it.id}`]: got };
      }
    };
    await Promise.all(Array.from({ length: PICTURES_AT_ONCE }, worker));
    refreshing = false;
  }

  onDestroy(() => {
    closed = true;
    if (refreshTimer !== null) clearInterval(refreshTimer);
  });

  /** Arrows move the selection over the tiles, Enter starts (Windows). */
  function onListKey(e: KeyboardEvent) {
    if (platform !== "windows" || starting) return;
    const ids = (activeTab === "displays" ? displays : windows).map((x) => x.id);
    if (e.key === "Enter" && selectedId) {
      e.preventDefault();
      void startOrSwitch();
      return;
    }
    const list = e.currentTarget as HTMLElement;
    const columns = Math.max(1, getComputedStyle(list).gridTemplateColumns.split(" ").filter(Boolean).length);
    const step = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: columns, ArrowUp: -columns }[e.key];
    if (step === undefined || ids.length === 0) return;
    e.preventDefault();
    const at = Math.max(0, ids.indexOf(selectedId ?? ids[0]));
    selectedId = ids[Math.min(ids.length - 1, Math.max(0, at + step))];
    list.querySelector<HTMLElement>(`[data-id="${CSS.escape(selectedId)}"]`)?.focus();
  }

  // Load sources on mount — once: an effect would fetch again whenever
  // something the fetch reads changed
  onMount(() => {
    loadSources();
  });

  async function loadSources() {
    loading = true;
    try {
      platform = await invoke<string>("get_platform");
      // The browser runs its own picker after Start: nothing to enumerate here
      if (platform === "web") {
        loading = false;
        return;
      }
      // Linux: the portal's dialog lists the screens and windows, with its own pictures
      if (platform === "linux") {
        againKnown = await invoke<boolean>("share_again_known").catch(() => false);
        loading = false;
        return;
      }
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
      // The names show at once; the pictures follow, and keep up while the picker is open
      if (platform === "windows") {
        void fetchPictures();
        refreshTimer = setInterval(() => void fetchPictures(), REFRESH_MS);
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

  /** Linux: forget the remembered screen or window; the next share asks again. */
  async function forgetAgain() {
    await invoke("forget_share_again").catch((e) => addNotification(String(e), "error"));
    againKnown = false;
  }

  /** `again` (Linux): restore the last screen or window without the portal's dialog. */
  async function startOrSwitch(again = false) {
    // Linux asks the portal for either, in one step: its dialog lists both
    const sourceType = platform === "linux" ? "any" : activeTab === "displays" ? "display" : "window";
    // Linux and the browser ignore source_id — their own picker decides
    const sourceId = usesOwnPicker ? "0" : (selectedId ?? "0");

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
          again,
        });
      } else {
        await invoke("start_screen_share", {
          sourceType,
          sourceId,
          resolution,
          fps,
          again,
        });
        // A new share starts unwatched: a count left from the last one would
        // start capture (in the browser, encoding) for nobody
        viewerCount.set(0);
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

  // Said out loud rather than downgraded silently: on Firefox the share goes
  // out without the screen's sound, which is the price of being offered
  // anything but a browser tab.
  let noShareAudio = $derived(platform === "web" && !canShareDisplayAudio());
  let usesOwnPicker = $derived(platform === "linux" || platform === "web");
  let buttonLabel = $derived(
    starting
      ? usesOwnPicker
        ? "Opening picker..."
        : "Starting..."
      : platform === "linux"
        ? "Choose screen or window…"
        : $pickerSwitchMode
          ? "Switch source"
          : "Start sharing"
  );
</script>

<div class="overlay" onclick={backdrop(close)} role="presentation">
  <div
    class="picker"
    class:wide={platform === "windows"}
    aria-label={$pickerSwitchMode ? "Switch source" : "Share screen"}
    use:dialog={{ onclose: starting ? undefined : close }}
  >
    <div class="picker-header">
      <span>{$pickerSwitchMode ? "Switch source" : "Share screen"}</span>
      <button class="close-btn" onclick={close} disabled={starting} aria-label="Close">&times;</button>
    </div>

    <!-- Tabs: not on Linux, whose portal dialog offers screens and windows together -->
    {#if platform !== "linux"}
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
    {/if}

    <!-- Source list -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="source-list"
      class:tiles={platform === "windows"}
      onkeydown={onListKey}
      role={platform === "windows" ? "listbox" : undefined}
      aria-label={platform === "windows" ? "Sources" : undefined}
    >
      {#if loading}
        <div class="placeholder">Loading sources...</div>
      {:else if platform === "linux"}
        <div class="linux-pick">
          {#if againKnown}
            <button class="again-tile" onclick={() => startOrSwitch(true)} disabled={starting}>
              {#if $lastShareFrame}
                <img src={$lastShareFrame} alt="" class="again-picture" />
              {:else}
                <span class="again-picture again-icon" aria-hidden="true"><Icon name="monitor" size={28} /></span>
              {/if}
              <span class="again-text">
                <span class="again-title">Share again</span>
                <span class="again-sub">What you shared last, without your system's dialog</span>
              </span>
            </button>
            <button class="forget-btn" onclick={forgetAgain} disabled={starting}>Forget it</button>
          {/if}
          <p class="portal-sub">
            {againKnown ? "Or choose" : "Choose"} a screen or a window in your system's dialog.
          </p>
        </div>
      {:else if usesOwnPicker}
        <!-- Linux portal and the browser enumerate sources themselves -->
        <div class="portal-hint">
          {#if activeTab === "displays"}
            <div class="portal-icon" aria-hidden="true"><Icon name="monitor" size={32} /></div>
            <p>Display capture</p>
            <p class="portal-sub">
              {platform === "web"
                ? "Your browser's share picker will appear after clicking Start."
                : "Your system's display picker will appear after clicking Start."}
            </p>
          {:else}
            <div class="portal-icon" aria-hidden="true"><Icon name="split-side" size={32} /></div>
            <p>Window capture</p>
            <p class="portal-sub">
              {platform === "web"
                ? "Your browser's share picker will appear after clicking Start."
                : "Your system's window picker will appear after clicking Start."}
            </p>
          {/if}
          {#if noShareAudio}
            <p class="portal-note">
              Firefox cannot share a screen's sound, and while it is asked for it offers
              browser tabs and nothing else. VoIPC asks without it, so you can pick a display
              or a window — share from Chrome, Edge or another Chromium browser if you need
              the sound as well.
            </p>
          {/if}
        </div>
      {:else if activeTab === "displays"}
        {#if displays.length === 0}
          <div class="placeholder">No displays found</div>
        {:else}
          {#each displays as display (display.id)}
            <button
              class="source-card source-tile"
              class:selected={selectedId === display.id}
              onclick={() => selectSource(display.id)}
              disabled={starting}
              data-id={display.id}
              role="option"
              aria-selected={selectedId === display.id}
            >
              <div class="tile-picture" aria-hidden="true">
                {#if pictures[`display:${display.id}`]?.picture}
                  <img src={pictures[`display:${display.id}`].picture} alt="" />
                {:else}
                  <Icon name="monitor" size={28} />
                {/if}
              </div>
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
              class="source-card source-tile"
              class:selected={selectedId === win.id}
              onclick={() => selectSource(win.id)}
              disabled={starting}
              data-id={win.id}
              role="option"
              aria-selected={selectedId === win.id}
            >
              <div class="tile-picture" aria-hidden="true">
                {#if pictures[`window:${win.id}`]?.picture}
                  <img src={pictures[`window:${win.id}`].picture} alt="" />
                {:else if pictures[`window:${win.id}`]?.icon}
                  <img src={pictures[`window:${win.id}`].icon} alt="" class="tile-icon" />
                {:else}
                  <Icon name="split-side" size={28} />
                {/if}
              </div>
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
        <label for="share-resolution">Resolution:</label>
        <select id="share-resolution" bind:value={resolution} disabled={starting}>
          <option value={480}>480p</option>
          <option value={720}>720p</option>
          <option value={1080}>1080p</option>
        </select>
      </div>

      <div class="setting-row">
        <label for="share-fps">Frame Rate:</label>
        <select id="share-fps" bind:value={fps} disabled={starting}>
          <option value={30}>30 FPS</option>
          <option value={60}>60 FPS</option>
        </select>
      </div>
    </div>

    <div class="picker-footer">
      <button class="cancel-btn" onclick={close} disabled={starting}>Cancel</button>
      <button
        class="start-btn btn btn-primary"
        onclick={() => startOrSwitch()}
        disabled={starting}
      >{buttonLabel}</button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-picker);
  }

  .picker {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: min(480px, calc(100vw - 32px));
    max-height: min(600px, calc(100dvh - 32px));
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }

  .picker-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: var(--fs-md);
  }

  .close-btn {
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-xl);
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
    font-size: var(--fs-body);
    font-weight: 500;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: background-color var(--dur-fast), border-color var(--dur-fast), color var(--dur-fast);
  }

  .tab:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .tab.active {
    color: var(--text-primary);
    border-bottom-color: var(--text-primary);
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
    font-size: var(--fs-body);
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
    font-size: var(--fs-body);
    font-weight: 500;
  }

  .portal-sub {
    color: var(--text-secondary) !important;
    font-weight: 400 !important;
    font-size: 12px !important;
  }

  .portal-note {
    margin-top: 8px !important;
    max-width: 340px;
    color: var(--text-secondary) !important;
    font-weight: 400 !important;
    font-size: 11px !important;
    line-height: 1.5;
  }

  .linux-pick {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    justify-content: center;
    gap: 8px;
    min-height: 120px;
    padding: 12px;
    text-align: center;
  }

  .again-tile {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    transition: background-color var(--dur-fast), border-color var(--dur-fast);
  }

  .again-tile:hover {
    background: var(--bg-hover);
    border-color: var(--text-secondary);
  }

  .again-picture {
    flex-shrink: 0;
    width: 128px;
    aspect-ratio: 16 / 9;
    max-width: 100%;
    object-fit: cover;
    border-radius: 4px;
    background: var(--bg-tertiary);
  }

  .again-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-secondary);
  }

  .again-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .again-title {
    color: var(--text-primary);
    font-size: var(--fs-body);
    font-weight: 600;
  }

  .again-sub {
    color: var(--text-secondary);
    font-size: 12px;
  }

  .forget-btn {
    align-self: flex-end;
    padding: 2px 6px;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 12px;
    text-decoration: underline;
    cursor: pointer;
  }

  .linux-pick .portal-sub {
    margin: 4px 0 0;
  }

  .picker.wide {
    width: min(720px, calc(100vw - 32px));
  }

  .source-list.tiles {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    align-content: start;
    gap: 8px;
  }

  .source-card.source-tile {
    flex-direction: column;
    align-items: stretch;
    gap: 6px;
    padding: 6px;
  }

  .tile-picture {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    max-width: 100%;
    aspect-ratio: 16 / 9;
    overflow: hidden;
    border-radius: 4px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .tile-picture img {
    width: 100%;
    height: 100%;
    object-fit: contain;
  }

  .tile-picture img.tile-icon {
    width: 32px;
    height: 32px;
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
    transition: background-color var(--dur-fast), border-color var(--dur-fast), color var(--dur-fast);
    width: 100%;
  }

  .source-card:hover {
    background: var(--bg-hover);
    border-color: var(--text-secondary);
  }

  .source-card.selected {
    border-color: var(--text-primary);
    background: var(--bg-hover);
  }


  .source-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    flex: 1;
  }

  .source-title {
    font-size: var(--fs-body);
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .primary-badge {
    font-size: var(--fs-micro);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 1px 5px;
    border-radius: 3px;
    flex-shrink: 0;
  }

  .source-detail {
    font-size: var(--fs-micro);
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
    font-size: var(--fs-body);
    flex: 1;
  }

  .setting-row label {
    white-space: nowrap;
  }

  .setting-row select {
    background-color: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 28px 4px 8px;
    font-size: var(--fs-body);
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
    font-size: var(--fs-sm);
  }

  .cancel-btn:hover {
    color: var(--text-primary);
  }

  .start-btn {
    padding: 6px 14px;
    font-size: var(--fs-sm);
  }

  /* A finger needs 44px (--hit) */
  @media (pointer: coarse) {
    .close-btn {
      min-width: var(--hit);
      min-height: var(--hit);
    }
  }
</style>
