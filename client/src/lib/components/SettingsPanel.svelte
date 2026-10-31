<script lang="ts">
  import { backdrop, dialog } from "../actions/dialog.js";
  import { roving } from "../actions/roving.js";
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
    savedServers,
  } from "../stores/settings.js";
  import type { SoundSettings } from "../stores/settings.js";
  import { voiceMode, vadThreshold, setVoiceMode, type VoiceMode } from "../stores/voice.js";
  import {
    connectionState,
    isDeafened,
    isTransmitting,
    setSelfDeafened,
    setSelfMuted,
  } from "../stores/connection.js";
  import { testLabel, testSource } from "../spatial.js";
  import { clearAllHistory } from "../stores/chat.js";
  import { confirmAction } from "../stores/confirm.js";
  import { addNotification } from "../stores/notifications.js";
  import { isMobile, isWeb, volumeKeyPtt } from "../stores/platform.js";
  import {
    micMonitor,
    shareChannelHistory,
    maxConversations,
    spatialAudio,
    screenAudioSpatial,
    audioSetupRequested,
  } from "../stores/settings.js";
  import {
    defaultDeviceName,
    inputDevices,
    loadDevices as loadDeviceLists,
    outputDevices,
    pickInput,
    pickOutput,
  } from "../stores/audio-devices.js";
  import { micTestLevel, micTesting, startMicTest, stopMicTest } from "../stores/mic-test.js";
  import { availableUpdate, checkForUpdate, checkUpdates, installUpdate, setCheckUpdates, updateBusy, updatesSupported } from "../stores/updates.js";
  import { protocolWarning, updateOffer } from "../update-rules.js";
  import { serverName } from "../stores/servers.js";
  import { voice } from "../stores/channels.js";
  import Icon from "./Icons.svelte";
  import PaletteEditor from "./PaletteEditor.svelte";
  import FileManager from "./FileManager.svelte";
  import { LINUX_APP, playsMedia } from "../media.js";
  import { settingsAsk } from "../stores/channel-ui.js";
  import { get } from "svelte/store";
  import LayoutPreview from "./LayoutPreview.svelte";
  import { uiPrefs, updateUiPrefs } from "../stores/ui-prefs.js";
  import { reducedMotion } from "../stores/emotes.js";
  import { buildHash, buildLine, buildTime } from "../build-info.js";
  import {
    CHAT_FONT_MAX,
    CHAT_FONT_MIN,
    ZOOM_MAX,
    ZOOM_MIN,
    defaultUiPrefs,
  } from "../ui-prefs.js";
  import { KeyCapture, shadows } from "../keybind.js";

  let { onclose }: { onclose: () => void } = $props();

  // What used to be one General tab of 25-30 controls and some twenty hints,
  // split by what somebody comes to Settings to do
  type Tab = "voice" | "appearance" | "sounds" | "privacy" | "files" | "games" | "about";
  let activeTab = $state<Tab>(get(settingsAsk)?.tab ?? "voice");
  let panelBody = $state<HTMLElement | null>(null);

  /** A touch screen: nothing is ever under its pointer. */
  const coarsePointer = typeof matchMedia === "function" && matchMedia("(pointer: coarse)").matches;

  // The accounts this device signs in to without a password (1.0 audit H5-12)
  let remembered = $state<{ server: string; name: string }[]>([]);
  const loadRemembered = () =>
    invoke<{ server: string; name: string }[]>("account_devices").then((list) => (remembered = list), () => (remembered = []));
  $effect(() => {
    if (activeTab === "privacy") void loadRemembered();
  });
  async function forgetRemembered(list: { server: string; name: string }[]) {
    for (const d of list) await invoke("forget_device", { server: d.server, name: d.name }).catch(() => {});
    await loadRemembered();
  }

  /** Everything on this tab, back to defaults — but not which layout they chose,
   *  and not the fact that they were asked. Those are answers, not decoration. */
  function resetAppearance() {
    updateUiPrefs((p) => {
      const d = defaultUiPrefs();
      p.palette = d.palette;
      p.palette_overrides = {};
      p.density = d.density;
      p.chat_font_size = d.chat_font_size;
      p.group_threads = d.group_threads;
      p.dm_previews = d.dm_previews;
      p.zoom = d.zoom;
      p.panels = d.panels;
    });
  }


  // Game SDK (desktop only): the local port a game mod connects to
  let sdkEnabled = $state(false);
  let sdkPort = $state(39987);
  let sdkOrigins = $state("");
  /** The two things a game may do *to* the player rather than for them. */
  let sdkBeacon = $state(false);
  let sdkTransmit = $state(false);
  let sdkMumble = $state(false);
  let sdkConnected = $state(false);
  let sdkGame = $state("");
  /** False where the SDK is compiled out (Android), so the section stays hidden. */
  let sdkAvailable = $state(false);
  /** Why the port could not be taken; empty while the listener is fine. */
  let sdkError = $state("");

  async function loadSdkStatus() {
    if (isWeb) return;
    try {
      const status = await invoke<{
        available: boolean;
        enabled: boolean;
        port: number;
        origins: string[];
        beaconAllowed: boolean;
        transmitAllowed: boolean;
        mumblelink: boolean;
        connected: boolean;
        game: string;
        error: string | null;
      }>("get_sdk_status");
      sdkAvailable = status.available;
      sdkEnabled = status.enabled;
      sdkPort = status.port;
      sdkOrigins = status.origins.join("\n");
      sdkBeacon = status.beaconAllowed ?? false;
      sdkTransmit = status.transmitAllowed ?? false;
      sdkMumble = status.mumblelink ?? false;
      // A game that connected before this panel opened sent its event to nobody
      sdkConnected = status.connected;
      sdkGame = status.game;
      sdkError = status.error ?? "";
    } catch (e) {
      console.error("Failed to read the game SDK status:", e);
    }
  }

  async function setSdk(change: {
    enabled?: boolean;
    port?: number;
    origins?: string;
    beaconAllowed?: boolean;
    transmitAllowed?: boolean;
    mumblelink?: boolean;
  }) {
    if (change.enabled !== undefined) sdkEnabled = change.enabled;
    if (change.port !== undefined) sdkPort = change.port;
    if (change.origins !== undefined) sdkOrigins = change.origins;
    if (change.beaconAllowed !== undefined) sdkBeacon = change.beaconAllowed;
    if (change.transmitAllowed !== undefined) sdkTransmit = change.transmitAllowed;
    if (change.mumblelink !== undefined) sdkMumble = change.mumblelink;
    try {
      await invoke("set_sdk_config", {
        enabled: change.enabled ?? null,
        port: change.port ?? null,
        beaconAllowed: change.beaconAllowed ?? null,
        transmitAllowed: change.transmitAllowed ?? null,
        mumblelink: change.mumblelink ?? null,
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
      await loadDeviceLists();
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
    try {
      // A running test moves to the new device (stores/audio-devices.ts)
      await pickInput((e.target as HTMLSelectElement).value);
    } catch (err) {
      console.error("Failed to set input device:", err);
      addNotification(`Failed to set input device: ${err}`, "error");
    }
  }

  async function changeOutputDevice(e: Event) {
    try {
      await pickOutput((e.target as HTMLSelectElement).value);
    } catch (err) {
      console.error("Failed to set output device:", err);
      addNotification(`Failed to set output device: ${err}`, "error");
    }
  }


  // PTT key capture
  let isCapturingKey = $state(false);
  let captureHint = $state(KeyCapture.PROMPT);
  /** The rules live in lib/keybind.ts, shared with the first-run audio setup. */
  let capture: KeyCapture | null = null;
  // Which binding the capture UI is editing: PTT, global mute, or global deafen
  let captureTarget = $state<"ptt" | "mute" | "deafen">("ptt");

  function startKeyCapture(target: "ptt" | "mute" | "deafen" = "ptt") {
    captureTarget = target;
    isCapturingKey = true;
    capture = new KeyCapture();
    captureHint = KeyCapture.PROMPT;
  }

  function finishCapture(binding: string) {
    isCapturingKey = false;
    capture = null;
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
    if (!capture) return;
    const step = capture.keydown(e);
    // Tab moves on (the blur cancels); everything else is the capture's
    if (step.kind === "pass") return;
    e.preventDefault();
    e.stopPropagation();
    if (step.kind === "cancel") cancelKeyCapture();
    else if (step.kind === "hint") captureHint = step.hint;
    else finishCapture(step.binding);
  }

  function handleCaptureKeyUp(e: KeyboardEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (!isCapturingKey) return;
    const done = capture?.keyup(e);
    if (done) finishCapture(done.binding);
  }

  function cancelKeyCapture() {
    isCapturingKey = false;
    capture = null;
  }

  function autofocus(node: HTMLElement) {
    node.focus();
  }

  /** What a picker shows when nothing is saved: the system's own default. */
  /** Ask the four first-run questions again, from Settings. */
  function runAudioSetup() {
    audioSetupRequested.set(true);
    onclose();
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

  async function clearHistory() {
    const ok = await confirmAction({
      title: "Clear all chat history?",
      body:
        "Every channel and every direct conversation, on every server, is removed from this " +
        "device, with the copy of the history an update kept for an older VoIPC. Copies a server " +
        "keeps for your account are not touched. This cannot be undone.",
      confirm: "Clear all history",
      danger: true,
    });
    if (!ok) return;
    const failure = await clearAllHistory();
    if (failure) {
      addNotification(
        `The chat is cleared from this window, but the saved history on this device could not be removed: ${failure}`,
        "error",
      );
    } else {
      addNotification("Chat history cleared", "info");
    }
  }

  async function resetConfig() {
    const ok = await confirmAction({
      title: "Reset all settings?",
      body:
        "Every setting on this device goes back to its default: devices and volumes, push to " +
        "talk and hotkeys, voice mode and noise suppression, sounds, and the remembered " +
        "connection. Chat history is not touched.",
      confirm: "Reset settings",
      danger: true,
    });
    if (!ok) return;
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
      // The backend closed the microphone (the default mode is push-to-talk)
      // and told every server about the mute and deafen: our own rows follow.
      isTransmitting.set(false);
      setSelfMuted(false);
      setSelfDeafened(false);
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

  // Updates (B6): what the last "Check now" or install said
  let upToDate = $state(false);
  let updateError = $state("");
  /** An update on another protocol takes a second press: the first one only
   *  arms it (design input 5). Armed for that version only. */
  let updateArmed = $state<string | null>(null);
  const updateStates = connectionState.all();
  /** What Settings says about an update on another protocol: the servers it
   *  would lock this app out of are the ones it is connected to now. */
  const updateWarning = $derived(
    $availableUpdate && updateOffer($availableUpdate) === "protocol"
      ? protocolWarning(
          $availableUpdate,
          [...$updateStates].filter(([, s]) => s === "connected").map(([id]) => serverName(id, $savedServers)),
        )
      : null,
  );

  async function pressUpdate(version: string) {
    if (updateWarning && updateArmed !== version) {
      updateArmed = version;
      return;
    }
    updateArmed = null;
    updateError = await installUpdate();
  }

  /** THIRD-PARTY-NOTICES.txt, which every bundle carries beside index.html
   *  (tools/tasks/notices.mjs, R4-09): read when it is first opened.
   *  undefined: not read yet; null: not in this build. */
  let notices = $state<string | null | undefined>(undefined);
  async function loadNotices() {
    if (notices !== undefined) return;
    notices = await invoke<string | null>("third_party_notices").catch(() => null);
  }

  // A browser grants notifications only from a click (H5-13)
  let notifyPermission = $state(
    typeof Notification === "undefined" ? "denied" : Notification.permission,
  );
  async function askNotifyPermission() {
    notifyPermission = await Notification.requestPermission();
  }

  // --- Mic test (settings-panel level meter, independent of VAD/calls) ---

  let micLevelPercent = $derived(
    Math.max(0, Math.min(100, (($micTestLevel + 60) / 60) * 100)),
  );

  function toggleMicTest() {
    if ($micTesting) void stopMicTest();
    else void startMicTest($micMonitor);
  }


  // --- Spatial test: a synthetic voice orbits you through the real mixer ---

  let spatialTest = $state<{ mode: "2d" | "3d"; started: number } | null>(null);
  let spatialTestWhere = $state("");
  let spatialTestPos = $state<[number, number, number]>([0, 3, 0]);
  let spatialTestTimer: ReturnType<typeof setInterval> | null = null;
  // On the desktop the test is mixed into a connection's voice mixer — the
  // call's, else any open one's; the browser's audio graph stands on its own.
  const connectionStates = connectionState.all();
  let canSpatialTest = $derived(
    isWeb || [...$connectionStates.values()].some((s) => s === "connected"),
  );

  function tickSpatialTest() {
    if (!spatialTest) return;
    const t = (performance.now() - spatialTest.started) / 1000;
    spatialTestWhere = testLabel(spatialTest.mode, t);
    spatialTestPos = testSource(spatialTest.mode, t).pos;
  }

  async function startSpatialTest(mode: "2d" | "3d") {
    try {
      await invoke("start_spatial_test", { mode });
      if (destroyed) {
        invoke("stop_spatial_test").catch(() => {});
        return;
      }
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

  /** A test still starting when the panel closes stops itself on arrival. */
  let destroyed = false;
  onDestroy(() => {
    destroyed = true;
    if ($micTesting) void stopMicTest();
    if (spatialTest) stopSpatialTest();
  });

  // Load devices on mount (skip on mobile — only default device available)
  if (!$isMobile) loadDevices();
  loadSdkStatus();

  // A game connecting or leaving shows up live in the panel
  // Two kinds of update share this event: a game connecting or leaving, and
  // the listener failing (or managing) to bind. Merge by what is present.
  const sdkUnlisten = listen<{
    connected?: boolean;
    game?: string;
    error?: string | null;
  }>("sdk-status", (event) => {
    if (event.payload.connected !== undefined) {
      sdkConnected = event.payload.connected;
      sdkGame = event.payload.game ?? "";
    }
    if ("error" in event.payload) sdkError = event.payload.error ?? "";
  });
  onDestroy(() => {
    sdkUnlisten.then((off) => off()).catch(() => {});
  });
  /**
   * Hand the build line over for a bug report. If the clipboard is blocked —
   * it is, in a webview without a user gesture on some platforms — put it in a
   * notification instead, where it can at least be read off the screen.
   */
  async function copyBuildLine() {
    try {
      await navigator.clipboard.writeText(buildLine());
      addNotification("Build copied", "info", 2000);
    } catch {
      addNotification(buildLine(), "info", 10000);
    }
  }

  const tabs = $derived<{ id: Tab; label: string }[]>([
    { id: "voice", label: "Voice & video" },
    { id: "appearance", label: "Appearance" },
    ...(!$isMobile || (isWeb && notifyPermission === "default")
      ? [{ id: "sounds" as Tab, label: "Sounds & alerts" }]
      : []),
    { id: "privacy", label: "Privacy & data" },
    { id: "files", label: "Files" },
    ...(!isWeb && sdkAvailable ? [{ id: "games" as Tab, label: "Games" }] : []),
    { id: "about", label: "About" },
  ]);
</script>

<div class="overlay" role="presentation" onclick={backdrop(onclose)}>
  <div class="panel" use:dialog={{ onclose }}>
    <div class="panel-header">
      <h3>Settings</h3>
      <button class="close-btn" onclick={onclose} title="Close" aria-label="Close settings"><Icon name="close" size={18} /></button>
    </div>

    <div class="tabs" role="tablist" aria-label="Settings" use:roving>
      {#each tabs as t (t.id)}
        <button
          class="tab"
          class:active={activeTab === t.id}
          role="tab"
          aria-selected={activeTab === t.id}
          onclick={() => {
            activeTab = t.id;
            // Each tab from its top, not where the last one was scrolled to
            panelBody?.scrollTo({ top: 0 });
          }}
        >{t.label}</button>
      {/each}
    </div>

    <!-- Only this part scrolls: the title, the close button and the tabs stay
         on screen however long a tab is -->
    <div class="panel-body" bind:this={panelBody}>
    {#if activeTab === "voice"}
      <!-- Before any call, on every platform: the voice bar's own copy of this
           only exists in a call, so a phone joined with whatever mode it had
           stored, an open microphone included, before it could be seen -->
      <div class="section">
        <h4 id="voice-mode-heading">How your microphone opens</h4>
        <select
          value={$voiceMode}
          aria-labelledby="voice-mode-heading"
          aria-describedby="voice-mode-hint"
          onchange={(e) => setVoiceMode((e.currentTarget as HTMLSelectElement).value as VoiceMode)}
        >
          <option value="ptt">Push to talk</option>
          <option value="vad">Voice activation</option>
          <option value="always_on">Always on</option>
        </select>
        <span class="toggle-hint" id="voice-mode-hint">
          From the moment you join a voice channel.
          {$voiceMode === "ptt"
            ? "Nothing is sent until you hold the talk key or button."
            : $voiceMode === "vad"
              ? "Sent whenever your voice is louder than the threshold."
              : "Sent all the time you are in the channel, unless you mute."}
        </span>
      </div>

      {#if !$isMobile}
        <div class="section">
          <h4>Audio input</h4>
          <!-- Bound to what is saved, not to `is_default`: a device somebody
               chose on purpose was shown as unselected, so the panel claimed
               they were on the system default when they were not. -->
          <select value={$inputDevice || defaultDeviceName($inputDevices)} onchange={changeInputDevice}>
            {#each $inputDevices as device}
              <option value={device.name}>
                {device.name}
                {device.is_default ? " (Default)" : ""}
              </option>
            {/each}
          </select>
          <div class="mic-test">
            <button class="mic-test-btn" onclick={toggleMicTest}>
              {$micTesting ? "Stop test" : "Test microphone"}
            </button>
            {#if $micTesting}
              <div class="level-track">
                <div class="level-fill" style="width: {micLevelPercent}%"></div>
              </div>
            {/if}
          </div>
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={$micMonitor}
              disabled={$micTesting}
              onchange={(e) => micMonitor.set((e.target as HTMLInputElement).checked)}
            />
            <span class="toggle-label">Hear myself during the test (headphones only)</span>
            <span class="toggle-hint">
              Plays your microphone back to you through your own voice effect, so you can
              hear what the channel hears before anyone else does. On speakers it feeds
              back. Not saved: it is a deliberate act each session.
            </span>
          </label>
        </div>

        <div class="section">
          <h4>Audio output</h4>
          <select value={$outputDevice || defaultDeviceName($outputDevices)} onchange={changeOutputDevice}>
            {#each $outputDevices as device}
              <option value={device.name}>
                {device.name}
                {device.is_default ? " (Default)" : ""}
              </option>
            {/each}
          </select>
          <button class="mic-test-btn" onclick={runAudioSetup}>Run audio setup again</button>
          <span class="toggle-hint">
            Walks through the microphone, the speakers and how your microphone opens — the
            same four questions VoIPC asks the first time.
          </span>
        </div>

        <div class="section">
          <h4>Push-to-talk key</h4>
          <div class="ptt-config">
            {#if isCapturingKey && captureTarget === "ptt"}
              <span
                class="current-key capturing"
                tabindex="0"
                role="button"
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
          {#if shadows($pttKey)}
            <span class="toggle-hint">
              {$pttKey} also toggles {shadows($pttKey) === "mute" ? "mute" : "deafen"}. Push to talk
              wins, so that shortcut stops working while this is your key.
            </span>
          {/if}
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
          <h4>Global hotkeys</h4>
          <div class="ptt-config">
            <span class="hotkey-label">Toggle mute</span>
            {#if isCapturingKey && captureTarget === "mute"}
              <span
                class="current-key capturing"
                tabindex="0"
                role="button"
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
              <span
                class="current-key capturing"
                tabindex="0"
                role="button"
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
          <h4>Push to talk</h4>
          <label class="toggle-row">
            <input type="checkbox" checked={$volumeKeyPtt} onchange={handleVolumeKeyPtt} />
            <span class="toggle-label">Use the volume button to talk</span>
            <span class="toggle-hint">Hold Volume Down to talk (overrides normal volume control)</span>
          </label>
        </div>
      {/if}

      {#if !isWeb}
      <div class="section">
        <h4>Screen share</h4>
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
        <h4>Spatial audio</h4>
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

      {#if !$isMobile}
        <div class="section">
          <h4>Keyboard shortcuts</h4>
          <dl class="shortcuts">
            <dt><kbd>{$pttKey}</kbd></dt><dd>Talk, while held (push to talk)</dd>
            <dt><kbd>Ctrl</kbd> <kbd>M</kbd></dt><dd>Mute or unmute your microphone</dd>
            <dt><kbd>Ctrl</kbd> <kbd>D</kbd></dt><dd>Deafen or undeafen{#if isWeb} (in a browser this replaces its bookmark key){/if}</dd>
            <dt><kbd>Esc</kbd></dt><dd>Close a dialog, a menu or the room and mixer view</dd>
            <dt><kbd>+</kbd> <kbd>−</kbd> <kbd>0</kbd></dt><dd>Zoom a shared screen in, out, or back to fit</dd>
          </dl>
        </div>
      {/if}
    {/if}

    {#if activeTab === "games"}
      {#if !isWeb && sdkAvailable}
      <div class="section">
        <h4>Game integration</h4>
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
        {#if sdkEnabled && sdkError}
          <span class="toggle-hint sdk-error">{sdkError}</span>
        {/if}
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
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={sdkBeacon}
              onchange={(e) => setSdk({ beaconAllowed: (e.target as HTMLInputElement).checked })}
            />
            <span class="toggle-label">Let a game broadcast my position to the channel</span>
            <span class="toggle-hint">
              For games whose mods can only see where you are, not where everyone else is. Your
              position is encrypted with the channel key like your voice — the server cannot read
              it, but everyone in the channel can. Off by default; without it, positions a game
              feeds in never leave this machine. Unticking it stops a broadcast that is running,
              this instant; ticking it applies the next time a game says hello.
            </span>
          </label>
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={sdkMumble}
              onchange={(e) => setSdk({ mumblelink: (e.target as HTMLInputElement).checked })}
            />
            <span class="toggle-label">Follow MumbleLink</span>
            <span class="toggle-hint">
              Some games — Guild Wars 2 among them — write your own position into shared memory
              instead of letting a mod talk to VoIPC. This reads that, and nothing else in it:
              not your account name, not which server you are on. It places people for you
              locally; they see you only if you also allow the setting above.
            </span>
          </label>
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={sdkTransmit}
              onchange={(e) => setSdk({ transmitAllowed: (e.target as HTMLInputElement).checked })}
            />
            <span class="toggle-label">Let a game press my push-to-talk</span>
            <span class="toggle-hint">
              So the in-game radio key is the only key you hold. It can never talk over your mute,
              it shows in the voice bar like any other transmission, and it lets go as soon as the
              game stops driving. Off by default. Unticking it lets go of the microphone at once,
              even mid-word.
            </span>
          </label>
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

    {/if}

    {#if activeTab === "about"}
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

      {#if !isWeb && $updatesSupported}
        <div class="section">
          <h4>Updates</h4>
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={$checkUpdates}
              onchange={(e) => void setCheckUpdates(e.currentTarget.checked)}
            />
            <span class="toggle-label">Check for updates once a day</span>
            <span class="toggle-hint">Each check asks GitHub for the newest release, so GitHub sees your address and this version.</span>
          </label>
          {#if $availableUpdate}
            {@const version = $availableUpdate.version}
            {#if updateWarning}
              <span class="toggle-hint update-warning" role="note">{updateWarning} Installing it restarts VoIPC.</span>
            {:else}
              <span class="toggle-hint">VoIPC {version} is available. Installing it restarts VoIPC.</span>
            {/if}
            <button
              class="mic-test-btn"
              class:armed={updateArmed === version}
              onclick={() => pressUpdate(version)}
              disabled={$updateBusy !== null || $voice !== null}
            >
              {$updateBusy === "installing"
                ? "Updating…"
                : $voice !== null
                  ? "Update after the call"
                  : updateArmed === version
                    ? `Press again to update to ${version}`
                    : `Update to ${version}`}
            </button>
          {:else if $checkUpdates}
            <button
              class="mic-test-btn"
              onclick={async () => {
                await checkForUpdate();
                upToDate = $availableUpdate === null;
              }}
              disabled={$updateBusy !== null}
            >
              {$updateBusy === "checking" ? "Checking…" : "Check now"}
            </button>
            {#if upToDate}<span class="toggle-hint">No newer VoIPC.</span>{/if}
          {/if}
          {#if updateError}<span class="toggle-hint">{updateError}</span>{/if}
        </div>
      {/if}

      <div class="section">
        <h4>Licences</h4>
        <span class="toggle-hint">VoIPC's own code is MIT. What it is built from comes with its own licences.</span>
        <details class="notices" ontoggle={(e) => e.currentTarget.open && loadNotices()}>
          <summary>Third-party notices</summary>
          {#if notices === undefined}
            <span class="toggle-hint">Reading…</span>
          {:else if notices === null}
            <span class="toggle-hint">This build carries no notices file. The licences are listed in VoIPC's README, under "License".</span>
          {:else}
            <pre class="notices-text">{notices}</pre>
          {/if}
        </details>
      </div>

    {/if}

    {#if activeTab === "sounds"}
      {#if isWeb && notifyPermission === "default"}
        <div class="section">
          <h4>Notifications</h4>
          <button class="mic-test-btn" onclick={askNotifyPermission}>Allow notifications</button>
          <span class="toggle-hint">
            For direct messages while this tab is in the background. A browser asks only
            after a click, so it is asked here.
          </span>
        </div>
      {/if}

    {/if}

    {#if activeTab === "privacy"}
      <div class="section">
        <h4>Remembered accounts</h4>
        {#if remembered.length === 0}
          <span class="toggle-hint">No account signs in here without its password.</span>
        {:else}
          {#each remembered as d (`${d.server}|${d.name}`)}
            <div class="device-row">
              <span>{d.name} on {d.server}</span>
              <button class="danger-btn btn btn-danger-outline" onclick={() => forgetRemembered([d])}>Forget</button>
            </div>
          {/each}
          {#if remembered.length > 1}
            <button class="danger-btn btn btn-danger-outline" onclick={() => forgetRemembered(remembered)}>Forget all</button>
          {/if}
          <span class="toggle-hint">Forgotten, an account needs its password again on this {isWeb ? "browser" : "device"}.</span>
        {/if}
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
              : "Saved on this device, encrypted with your password"}
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
              // The people here see who would answer them, so say so now
              // rather than at the next connect.
              invoke("set_history_sharing", { enabled }).catch(() => {
                // Not connected: it goes out with the next connection
              });
            }}
          />
          <span class="toggle-label">Share recent channel chat with newcomers</span>
          <span class="toggle-hint">
            When someone joins a channel you are in, your client may hand them the last 50 messages it has there — end-to-end encrypted to that person only, never through the server in the clear. While this is on, the other people there can see that you are one of the members worth asking.
          </span>
        </label>
        <div class="ptt-config">
          <span class="hotkey-label">Conversations kept</span>
          <input
            class="sdk-input"
            type="number"
            min="0"
            max="100000"
            value={$maxConversations}
            onchange={(e) => {
              const raw = Number((e.target as HTMLInputElement).value);
              const value = Number.isFinite(raw) ? Math.max(0, Math.min(100000, Math.floor(raw))) : 1000;
              maxConversations.set(value);
              (e.target as HTMLInputElement).value = String(value);
              invoke("set_config_u32", { key: "max_conversations", value }).catch((err: any) => {
                addNotification(`Failed to save setting: ${err}`, "error");
              });
            }}
          />
        </div>
        <span class="toggle-hint">
          Channels and people together, across every server. The oldest beyond this are dropped
          the next time chat is saved. 0 keeps all of them — each conversation is capped at 500
          messages either way, so this is about how much is written out at once, not how far back
          any one conversation goes.
        </span>
        <div class="btn-row">
          <button class="danger-btn btn btn-danger-outline" onclick={clearHistory}>Clear all chat history…</button>
          <button class="danger-btn btn btn-danger-outline" onclick={resetConfig}>Reset all settings…</button>
        </div>
      </div>
    {/if}

    {#if activeTab === "files"}
      <div class="section">
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={playsMedia($uiPrefs)}
            onchange={(e) => updateUiPrefs((p) => (p.play_media = (e.target as HTMLInputElement).checked))}
          />
          <span class="toggle-label">Play videos and sounds in VoIPC</span>
          <span class="toggle-hint">
            Through this system's own video and sound decoders, after you press Load.
            {#if LINUX_APP}Off by default here: on Linux they run outside any sandbox.{/if}
            Pictures are always made safe before they are shown.
          </span>
        </label>
      </div>
      <FileManager {onclose} />
    {/if}

    {#if activeTab === "appearance"}
      <div class="section">
        <h4>Layout</h4>
        <div class="layout-choices" role="radiogroup" aria-label="Layout" use:roving>
          {#each ["modern", "classic", "stage"] as const as id (id)}
            <LayoutPreview
              layout={id}
              selected={$uiPrefs.layout === id}
              onpick={() => updateUiPrefs((p) => (p.layout = id))}
            />
          {/each}
        </div>
      </div>

      <div class="section">
        <h4>Theme</h4>
        <PaletteEditor />
      </div>

      <div class="section">
        <h4>Messages</h4>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$uiPrefs.density === "compact"}
            onchange={(e) =>
              updateUiPrefs((p) => {
                p.density = (e.target as HTMLInputElement).checked ? "compact" : "cosy";
              })}
          />
          <span class="toggle-label">Compact message list</span>
          <span class="toggle-hint">
            Takes the air out from between messages. The grouping is the same either way.
          </span>
        </label>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$uiPrefs.group_threads}
            onchange={(e) =>
              updateUiPrefs((p) => {
                p.group_threads = (e.target as HTMLInputElement).checked;
              })}
          />
          <span class="toggle-label">Group busy replies into threads</span>
          <span class="toggle-hint">
            When a message draws three replies from two people or more, they move under it into a thread.
            Replies sent into a thread go there either way.
          </span>
        </label>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$uiPrefs.dm_previews}
            onchange={(e) =>
              updateUiPrefs((p) => {
                p.dm_previews = (e.target as HTMLInputElement).checked;
              })}
          />
          <span class="toggle-label">Show the last message under each direct conversation</span>
          <span class="toggle-hint">
            With how long ago it was written. Anyone who sees your screen sees it too. A message with a timer
            never shows there.
          </span>
        </label>
        <label class="toggle-row">
          <input
            type="checkbox"
            checked={$uiPrefs.show_stickers}
            onchange={(e) => updateUiPrefs((p) => (p.show_stickers = (e.target as HTMLInputElement).checked))}
          />
          <span class="toggle-label">Show stickers</span>
          <span class="toggle-hint">Off, a sticker someone sends shows as its name.</span>
        </label>
        <h4 class="sub-heading">Moving emotes and stickers</h4>
        <!-- The system's "less motion" wins (Emote.svelte); a touch screen has no pointer to hover -->
        <select
          value={$reducedMotion ? "never" : $uiPrefs.animate_emotes}
          aria-label="Moving emotes and stickers"
          aria-describedby={$reducedMotion ? "motion-hint" : undefined}
          disabled={$reducedMotion}
          onchange={(e) => updateUiPrefs((p) => (p.animate_emotes = (e.target as HTMLSelectElement).value as "always" | "hover" | "never"))}
        >
          <option value="always">Always move</option>
          {#if !coarsePointer || $uiPrefs.animate_emotes === "hover"}
            <option value="hover">Move under the pointer</option>
          {/if}
          <option value="never">Never move</option>
        </select>
        {#if $reducedMotion}
          <span class="toggle-hint" id="motion-hint">Your system asks for less motion, so none of them move.</span>
        {:else}
          <span class="toggle-hint">Pictures posted in chat follow this too: "Never" shows their first frame.</span>
        {/if}
        <label class="slider-row">
          <span>Chat text size: {$uiPrefs.chat_font_size}px</span>
          <input
            type="range"
            min={CHAT_FONT_MIN}
            max={CHAT_FONT_MAX}
            step="1"
            value={$uiPrefs.chat_font_size}
            oninput={(e) =>
              updateUiPrefs((p) => {
                p.chat_font_size = Number((e.target as HTMLInputElement).value);
              })}
          />
        </label>
      </div>

      <div class="section">
        <h4>Zoom</h4>
        <label class="slider-row">
          <span>Interface scale: {Math.round($uiPrefs.zoom * 100)}%</span>
          <input
            type="range"
            min={ZOOM_MIN * 100}
            max={ZOOM_MAX * 100}
            step="5"
            value={Math.round($uiPrefs.zoom * 100)}
            oninput={(e) =>
              updateUiPrefs((p) => {
                p.zoom = Number((e.target as HTMLInputElement).value) / 100;
              })}
          />
        </label>
      </div>

      <div class="section">
        <h4>Reset</h4>
        <button class="danger-btn btn btn-danger-outline" onclick={resetAppearance}>
          Reset appearance to defaults
        </button>
        <span class="danger-hint">
          Palette, colours, text size, zoom and panel sizes. Nothing else is touched.
        </span>
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

    <!-- Outside every tab on purpose: which build this is has to be readable
         without knowing which tab to look under. -->
    <button
      class="build-stamp"
      onclick={copyBuildLine}
      title={`Built from ${buildHash} at ${buildTime}. Click to copy.`}
    >{buildLine()}</button>
    </div>
  </div>
</div>

<style>
  .update-warning {
    color: var(--warning);
  }

  .armed {
    outline: 2px solid var(--warning);
    outline-offset: 1px;
  }

  .notices summary {
    cursor: pointer;
    font-size: 13px;
    color: var(--text-secondary);
  }

  .notices-text {
    max-height: 320px;
    overflow: auto;
    margin: 8px 0 0;
    padding: 8px;
    font-size: 11px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    background: var(--bg-tertiary);
    border-radius: 4px;
    user-select: text;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-settings);
  }

  .panel {
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px 24px 0;
    width: min(640px, 92vw);
    max-height: min(80vh, calc(100dvh - 32px));
    overflow: hidden;
  }

  .panel-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding-bottom: 24px;
  }

  .shortcuts {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 8px 16px;
    align-items: baseline;
    font-size: var(--fs-body);
    color: var(--text-secondary);
  }

  .shortcuts dt {
    white-space: nowrap;
  }

  kbd {
    display: inline-block;
    min-width: 22px;
    padding: 1px 6px;
    border: 1px solid var(--border);
    border-bottom-width: 2px;
    border-radius: var(--r-sm);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font: inherit;
    font-size: var(--fs-sm);
    text-align: center;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }

  h3 {
    font-size: var(--fs-xl);
    color: var(--text-primary);
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
  /* Six tabs do not fit a phone: the row scrolls sideways instead of wrapping */
  /* Every tab on screen: a row that scrolled hid About (the version and the
     updates) past the edge with nothing to say it was there. Where six do
     not fit in one row they take two. */
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .tab {
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-body);
    padding: 8px 12px;
    white-space: nowrap;
    flex-shrink: 0;
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    transition: color var(--dur-fast), border-color var(--dur-fast);
  }

  .tab:hover {
    color: var(--text-primary);
  }

  .tab.active {
    color: var(--text-primary);
    border-bottom-color: var(--text-primary);
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
    font-size: var(--fs-sm);
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
    background: var(--success);
    border-radius: 4px;
    transition: width 60ms linear;
  }

  h4 {
    font-size: var(--fs-sm);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }
  /* A second heading inside one section: room above it, so the hint before
     does not read as part of it */
  h4.sub-heading {
    margin-top: var(--sp-4);
  }
  /* A finger's size for the panel's own controls (its close, its tabs) */
  @media (pointer: coarse) {
    .close-btn {
      min-width: var(--hit);
      min-height: var(--hit);
    }
    .tab {
      min-height: var(--hit);
    }
  }

  /* Every select in Settings, its tabs' own components' too (Files) */
  .panel-body :global(select) {
    width: 100%;
    padding: 8px 28px 8px 12px;
    background-color: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: var(--fs-md);
  }

  .panel-body :global(select:focus) {
    border-color: var(--focus-ring);
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
    accent-color: var(--control-fill);
  }

  .toggle-label {
    font-size: var(--fs-body);
    color: var(--text-primary);
  }

  /* Its own block, indented as a whole under the control it explains (a
     margin on an inline span moved only the first line), at the 12 px floor */
  .toggle-hint {
    display: block;
    box-sizing: border-box;
    width: 100%;
    padding-left: 22px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
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
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    min-width: 90px;
  }

  .spatial-test-readout {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .sdk-error {
    color: var(--danger);
  }

  .sdk-input {
    font-size: var(--fs-body);
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

  .sdk-input:focus {
    border-color: var(--focus-ring);
  }

  .current-key {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 16px;
    font-size: var(--fs-md);
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
    font-size: var(--fs-body);
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

  .device-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 6px;
    font-size: var(--fs-body);
  }

  .danger-btn {
    padding: 8px 16px;
    font-size: var(--fs-body);
  }

  /* Appearance tab */
  .layout-choices {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }

  /* Deliberately quiet: it is reference material, not a control. */
  .build-stamp {
    display: block;
    width: 100%;
    margin-top: 20px;
    padding: 8px 0 0;
    border: none;
    border-top: 1px solid var(--border);
    background: none;
    color: var(--text-secondary);
    font-family: inherit;
    font-size: var(--fs-micro);
    text-align: center;
    cursor: pointer;
  }

  .build-stamp:hover {
    color: var(--text-primary);
  }

  .danger-hint {
    display: block;
    margin-top: 6px;
    font-size: var(--fs-micro);
    line-height: 1.4;
    color: var(--text-secondary);
  }

  .slider-row {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-top: 10px;
    font-size: var(--fs-body);
    color: var(--text-secondary);
  }

  .slider-row input[type="range"] {
    width: 100%;
    accent-color: var(--control-fill);
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
    accent-color: var(--control-fill);
  }

  .sound-label {
    font-size: var(--fs-md);
    font-weight: 500;
    color: var(--text-primary);
  }

  .sound-desc {
    display: block;
    font-size: var(--fs-micro);
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
    font-size: var(--fs-sm);
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
    font-size: var(--fs-micro);
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
    color: var(--on-danger);
  }
</style>
