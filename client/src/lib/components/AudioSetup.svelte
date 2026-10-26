<script lang="ts">
  import { dialog } from "../actions/dialog.js";
  // The one time VoIPC asks about audio before anything goes wrong.
  //
  // Everything here already existed in Settings; what did not exist was anyone
  // being walked through it. A voice app whose first call is "I can't hear you"
  // has failed at the only thing it does, and the fix — pick a microphone,
  // check the meter moves, check your ears are the right way round, decide how
  // the mic opens — takes about twenty seconds if somebody asks.
  //
  // Two rules it keeps:
  //
  //   * **Every choice is written as it is made**, through the same per-setting
  //     command Settings uses. Someone who quits halfway keeps what they
  //     picked; only the version stays 0, so they are asked again. A bulk
  //     setter at the end would be a second writer for seven settings that
  //     already have one, which is the bug class the mixer had.
  //   * **Skip is always available.** A modal that cannot be dismissed is a
  //     modal people learn to dread. Skipping leaves the version at 0 — the
  //     offer stands, it was not taken.
  //
  // It doubles as the compact re-pick when a saved device disappears: pass
  // `only` and it shows that step alone and never touches the version.

  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onDestroy } from "svelte";
  import {
    AUDIO_SETUP_VERSION,
    inputDevice,
    outputDevice,
    pttKey,
    audioSetupOpen,
  } from "../stores/settings.js";
  import { voiceMode, vadThreshold } from "../stores/voice.js";
  import type { VoiceMode } from "../stores/voice.js";
  import { isWeb } from "../stores/platform.js";
  import { addNotification } from "../stores/notifications.js";
  import { KeyCapture, shadows } from "../keybind.js";
  import {
    defaultDeviceName as defaultName,
    inputDevices,
    loadDevices as loadDeviceLists,
    outputDevices,
    pickInput as saveInput,
    pickOutput as saveOutput,
  } from "../stores/audio-devices.js";
  import {
    micTestError,
    micTestLevel,
    micTesting,
    startMicTest as startTest,
    stopMicTest,
  } from "../stores/mic-test.js";

  interface Props {
    /** Show one step only: the compact re-pick for a device that vanished. */
    only?: "input" | "output";
    onclose: () => void;
  }
  let { only, onclose }: Props = $props();

  type Step = "permission" | "input" | "output" | "mode" | "done";

  /** The steps this run shows, in order. Fixed for the life of the component:
   *  it is mounted for one purpose, and `only` does not change under it. */
  const steps: Step[] = $derived(
    only
      ? [only]
      : isWeb
        ? ["permission", "input", "output", "mode", "done"]
        : ["input", "output", "mode", "done"],
  );

  let at = $state(0);
  const step = $derived(steps[at]);
  const last = $derived(at === steps.length - 1);

  let error = $state("");
  let busy = $state(false);

  // ── Microphone permission (web only) ──────────────────────────────────

  let permissionAsked = $state(false);

  async function askForMicrophone() {
    busy = true;
    error = "";
    try {
      await invoke("request_microphone");
      permissionAsked = true;
      await loadDevices();
      next();
    } catch (e) {
      // The one place a denial is said out loud. Everywhere else it becomes
      // blank device labels or a toast about retrying.
      error = `${e}. VoIPC can still play what others say — you just will not be heard.`;
      permissionAsked = true;
    } finally {
      busy = false;
    }
  }

  // ── Devices ───────────────────────────────────────────────────────────

  async function loadDevices() {
    await loadDeviceLists().catch((e) => (error = String(e)));
  }

  async function pickInput(name: string) {
    await saveInput(name).catch((e) => (error = String(e)));
  }

  async function pickOutput(name: string) {
    await saveOutput(name).catch((e) => (error = String(e)));
  }

  // ── The microphone meter ──────────────────────────────────────────────

  /** Loud enough that somebody is clearly speaking, in dBFS. */
  const HEARD_DB = -40;
  /** Loud enough to be clipping, where the fix is the gain and not the mic. */
  const CLIPPING_DB = -1;

  let heard = $state(false);
  let clipped = $state(false);
  /** A test still starting when the dialog closes stops itself on arrival. */
  let destroyed = false;

  const levelPercent = $derived(Math.max(0, Math.min(100, (($micTestLevel + 60) / 60) * 100)));
  $effect(() => {
    if ($micTestLevel >= HEARD_DB) heard = true;
    if ($micTestLevel >= CLIPPING_DB) clipped = true;
  });
  // Said here as well as in the toast: this is the step it is about
  $effect(() => {
    if ($micTestError) error = $micTestError;
  });

  /** The wizard's meter never plays the microphone back. */
  const startMicTest = () => startTest(false);

  // ── The output test ───────────────────────────────────────────────────

  let playing = $state(false);
  let side = $state<"left" | "right" | null>(null);
  let canPickOutput = $state(true);
  let outUnlisten: Array<() => void> = [];

  async function startOutputTest() {
    if (playing) return;
    try {
      outUnlisten.push(
        await listen<{ side: "left" | "right" }>("output-test-side", (e) => {
          side = e.payload.side;
        }),
      );
      outUnlisten.push(
        await listen<{ error: string }>("output-test-error", (e) => {
          error = e.payload.error;
          void stopOutputTest();
        }),
      );
      await invoke("start_output_test");
      if (destroyed) return void stopOutputTest();
      playing = true;
    } catch (e) {
      error = String(e);
      void stopOutputTest();
    }
  }

  async function stopOutputTest() {
    playing = false;
    side = null;
    outUnlisten.forEach((off) => off());
    outUnlisten = [];
    await invoke("stop_output_test").catch(() => {});
  }

  // ── How the microphone opens ──────────────────────────────────────────

  let capture: KeyCapture | null = $state(null);
  let captureHint = $state(KeyCapture.PROMPT);
  const shadowed = $derived(shadows($pttKey));

  function beginCapture() {
    capture = new KeyCapture();
    captureHint = KeyCapture.PROMPT;
  }

  function onCaptureKeyDown(e: KeyboardEvent) {
    const c = capture;
    if (!c) return;
    const step = c.keydown(e);
    // Tab moves on; everything else is the capture's
    if (step.kind === "pass") return;
    e.preventDefault();
    e.stopPropagation();
    if (step.kind === "cancel") capture = null;
    else if (step.kind === "hint") captureHint = step.hint;
    else commitBinding(step.binding);
  }

  function onCaptureKeyUp(e: KeyboardEvent) {
    e.preventDefault();
    e.stopPropagation();
    const done = capture?.keyup(e);
    if (done) commitBinding(done.binding);
  }

  function commitBinding(binding: string) {
    capture = null;
    pttKey.set(binding);
    invoke("set_ptt_key", { keyCode: binding }).catch((e) => {
      error = String(e);
    });
  }

  async function pickMode(mode: VoiceMode) {
    voiceMode.set(mode);
    await invoke("set_voice_mode", { mode }).catch((e) => (error = String(e)));
    // Voice activation wants the meter running, so the threshold can be set
    // against a voice rather than against a number.
    if (mode === "vad") await startMicTest();
    else if ($micTesting && step === "mode") await stopMicTest();
  }

  async function changeThreshold(e: Event) {
    const db = parseFloat((e.target as HTMLInputElement).value);
    vadThreshold.set(db);
    await invoke("set_vad_threshold", { thresholdDb: db }).catch(() => {});
  }

  function autofocus(node: HTMLElement) {
    node.focus();
  }

  // ── Moving through it ─────────────────────────────────────────────────

  async function enter(s: Step) {
    error = "";
    if (s === "input") {
      heard = false;
      clipped = false;
      await startMicTest();
    } else {
      await stopMicTest();
    }
    if (s !== "output") await stopOutputTest();
  }

  async function next() {
    if (last) return finish();
    at += 1;
    await enter(steps[at]);
  }

  async function back() {
    if (at === 0) return;
    at -= 1;
    await enter(steps[at]);
  }

  /** Finished on purpose: remember it, so this is the last time. */
  async function finish() {
    if (!only) {
      await invoke("set_audio_setup_version", { version: AUDIO_SETUP_VERSION }).catch((e) =>
        addNotification(`Could not save the audio setup: ${e}`, "error"),
      );
    }
    await close();
  }

  /** Skipped, or the re-pick closed: everything chosen so far is already
   *  saved, but the offer was not taken, so it stands. */
  async function close() {
    await stopMicTest();
    await stopOutputTest();
    audioSetupOpen.set(false);
    onclose();
  }

  $effect(() => {
    audioSetupOpen.set(true);
    void (async () => {
      // On the web the device list is unlabelled until the permission is
      // granted, so the first step asks before this means anything.
      if (!isWeb || only) await loadDevices();
      if (isWeb) {
        canPickOutput = await invoke<boolean>("can_pick_output").catch(() => true);
      }
      await enter(steps[0]);
    })();
  });

  onDestroy(() => {
    destroyed = true;
    audioSetupOpen.set(false);
    outUnlisten.forEach((off) => off());
    void stopMicTest();
    invoke("stop_output_test").catch(() => {});
  });
</script>

<div class="overlay">
  <div class="dialog audio-setup" use:dialog={{ onclose: close }}>
    {#if step === "permission"}
      <h2>Let VoIPC hear you</h2>
      <p class="hint">
        Your browser will ask for the microphone. VoIPC sends your voice to the people in your
        channel, encrypted, and to nobody else — there is no server that can listen in.
      </p>
      {#if error}
        <div class="error" role="alert">{error}</div>
      {/if}
      <button class="submit-btn btn btn-primary" onclick={askForMicrophone} disabled={busy}>
        {busy ? "Asking…" : permissionAsked ? "Ask again" : "Ask for the microphone"}
      </button>
      <button class="text-link" onclick={next}>Continue without a microphone (listen only)</button>

    {:else if step === "input"}
      <h2>Which microphone?</h2>
      <p class="hint">Say something. The bar should move.</p>

      <select
        class="device"
        aria-label="Microphone"
        value={$inputDevice || defaultName($inputDevices)}
        onchange={(e) => pickInput(e.currentTarget.value)}
      >
        {#each $inputDevices as device (device.name)}
          <option value={device.name}>{device.name}{device.is_default ? " (Default)" : ""}</option>
        {/each}
      </select>

      <div class="level-track"><div class="level-fill" style="width: {levelPercent}%"></div></div>

      <p class="verdict" class:good={heard} class:warn={clipped}>
        {#if clipped}
          That is loud enough to distort — turn the microphone down, or move it further away.
        {:else if heard}
          We heard you.
        {:else}
          Waiting to hear you…
        {/if}
      </p>

    {:else if step === "output"}
      <h2>Which ear is which?</h2>
      <p class="hint">
        A voice plays on one side at a time. If it comes from the wrong side, your headphones are
        on backwards — which is a nicer thing to find out now.
      </p>

      <select
        class="device"
        aria-label="Speakers"
        disabled={!canPickOutput}
        value={$outputDevice || defaultName($outputDevices)}
        onchange={(e) => pickOutput(e.currentTarget.value)}
      >
        {#each $outputDevices as device (device.name)}
          <option value={device.name}>{device.name}{device.is_default ? " (Default)" : ""}</option>
        {/each}
      </select>
      {#if !canPickOutput}
        <p class="hint">
          This browser always plays through whatever your system has chosen, so the list above is
          for reference. Change it in your system settings.
        </p>
      {/if}

      <button class="secondary-btn play" onclick={playing ? stopOutputTest : startOutputTest}>
        {playing ? "Stop" : "Play a voice"}
      </button>
      <p class="verdict" class:good={playing}>
        {#if side === "left"}
          ◀ You should be hearing this on the <strong>left</strong>.
        {:else if side === "right"}
          You should be hearing this on the <strong>right</strong>. ▶
        {:else}
          &nbsp;
        {/if}
      </p>

    {:else if step === "mode"}
      <h2>How should your microphone open?</h2>

      <div class="choices">
        <button
          class="choice"
          class:chosen={$voiceMode === "ptt"}
          onclick={() => pickMode("ptt")}
        >
          <strong>Push to talk</strong>
          <span>You hold a key while you speak. Nothing goes out otherwise.</span>
        </button>
        <button
          class="choice"
          class:chosen={$voiceMode === "vad"}
          onclick={() => pickMode("vad")}
        >
          <strong>Voice activation</strong>
          <span>VoIPC sends when you are speaking and stops when you are not.</span>
        </button>
        <button
          class="choice"
          class:chosen={$voiceMode === "always_on"}
          onclick={() => pickMode("always_on")}
        >
          <strong>Always on</strong>
          <span>Everything your microphone hears goes out, all the time.</span>
        </button>
      </div>

      {#if $voiceMode === "ptt"}
        <div class="ptt-row">
          <span class="tiny">Key</span>
          {#if capture}
            <span
              class="current-key capturing"
              tabindex="0"
              role="button"
              use:autofocus
              onkeydown={onCaptureKeyDown}
              onkeyup={onCaptureKeyUp}
              onblur={() => (capture = null)}
            >
              {captureHint}
            </span>
          {:else}
            <span class="current-key">{$pttKey}</span>
            <button class="secondary-btn" onclick={beginCapture}>Change</button>
          {/if}
        </div>
        {#if shadowed}
          <p class="hint warn">
            {$pttKey} also toggles {shadowed === "mute" ? "mute" : "deafen"}. Push-to-talk wins, so
            the shortcut stops working while this is your key.
          </p>
        {/if}
      {:else if $voiceMode === "vad"}
        <div class="level-track">
          <div class="level-fill" style="width: {levelPercent}%"></div>
          <div
            class="level-threshold"
            style="left: {Math.max(0, Math.min(100, (($vadThreshold + 60) / 60) * 100))}%"
          ></div>
        </div>
        <p class="hint">
          Speak normally and drag the marker just below where the bar sits. Above the marker, you
          are sending.
        </p>
        <input
          type="range"
          class="threshold"
          min="-60"
          max="0"
          step="1"
          value={$vadThreshold}
          oninput={changeThreshold}
        />
      {:else}
        <p class="hint warn">
          Everything your microphone picks up will be sent for as long as you are in a channel.
        </p>
      {/if}

    {:else}
      <h2>Ready</h2>
      <p class="hint">
        All of this lives in Settings if you want to change it — including running this again.
      </p>
    {/if}

    {#if error && step !== "permission"}
      <div class="error" role="alert">{error}</div>
    {/if}

    <div class="button-row">
      {#if at > 0 && !only}
        <button class="cancel-btn" onclick={back}>Back</button>
      {/if}
      <button class="submit-btn btn btn-primary" onclick={next}>
        {only ? "Done" : last ? "Finish" : "Next"}
      </button>
    </div>
    {#if !only}
      <button class="text-link skip-link" onclick={close}>Skip — I will sort it out myself</button>
    {/if}
  </div>
</div>

<style>
  /* Shaped like ChatHistorySetup, which is the other thing that greets a new
     user: same overlay, same dialog, so the two do not look like two apps. */
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-modal);
  }

  .dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 32px;
    width: 420px;
    display: flex;
    flex-direction: column;
    gap: 16px;
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
  }

  h2 {
    text-align: center;
    font-size: var(--fs-2xl);
    color: var(--text-primary);
  }

  .hint {
    text-align: center;
    font-size: var(--fs-body);
    color: var(--text-secondary);
    line-height: 1.45;
  }

  .hint.warn {
    color: var(--warning);
  }

  .error {
    color: var(--danger);
    font-size: var(--fs-body);
    text-align: center;
  }

  .device {
    width: 100%;
    padding: 8px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: var(--fs-body);
  }

  .device:disabled {
    opacity: 0.6;
  }

  /* The same meter Settings uses, so the two read as one thing. */
  .level-track {
    position: relative;
    height: 10px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 5px;
    overflow: hidden;
  }

  .level-fill {
    height: 100%;
    background: var(--success);
    transition: width 60ms linear;
  }

  .level-threshold {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--text-primary);
  }

  .threshold {
    width: 100%;
  }

  .verdict {
    text-align: center;
    font-size: var(--fs-body);
    min-height: 18px;
    color: var(--text-secondary);
  }

  .verdict.good {
    color: var(--success);
  }

  .verdict.warn {
    color: var(--warning);
  }

  .choices {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .choice {
    display: flex;
    flex-direction: column;
    gap: 2px;
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
  }

  .choice:hover {
    background: var(--bg-hover);
  }

  .choice.chosen {
    border-color: var(--text-primary);
  }

  .choice span {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .ptt-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .tiny {
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  .current-key {
    flex: 1;
    padding: 6px 10px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-family: monospace;
    font-size: var(--fs-body);
    text-align: center;
  }

  .current-key.capturing {
    border-color: var(--accent);
    animation: pulse 1s ease-in-out infinite;
  }

  @keyframes pulse {
    50% {
      opacity: 0.55;
    }
  }

  .play {
    align-self: center;
  }

  .submit-btn {
    padding: 10px;
    font-size: var(--fs-md);
    flex: 1;
  }

  .secondary-btn {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 6px 12px;
    font-size: var(--fs-sm);
    white-space: nowrap;
  }

  .secondary-btn:hover {
    background: var(--border);
  }

  .cancel-btn {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 10px;
    font-size: var(--fs-md);
    flex: 1;
  }

  .cancel-btn:hover {
    background: var(--border);
  }

  .button-row {
    display: flex;
    gap: 8px;
  }

  .text-link {
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
    cursor: pointer;
    padding: 2px 0;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
</style>
