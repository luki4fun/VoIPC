<script lang="ts">
  // The mixing desk. Takes the centre column the way the virtual room does, so
  // the faders have room to be faders.
  //
  // A lane is a lane. Your microphone on the way out and each person's voice on
  // the way in are the same thing pointed in different directions, so they get
  // one strip design and one set of controls:
  //
  //   Effect   a preset — radio, phone, megaphone…
  //   Muffle   0-10
  //   Reverb   0-10
  //   Water    0-10
  //
  // Nothing here is "the room", and none of the three sliders is a special
  // case: they are three scalable effects on the same scale, sitting together
  // under the same disclosure, on every strip.
  //
  // The one asymmetry is who the setting reaches, and it is not a control:
  // your own lane is rendered into the voice before Opus, so everybody hears
  // it and no listener can switch it off, while an incoming lane only ever
  // changes what you hear. A game takes over the incoming ones while it drives
  // — the same player can be heard directly by one listener and over a phone by
  // another, and only the game knows which — and never touches yours.

  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onDestroy } from "svelte";
  import { users } from "../stores/users.js";
  import { isAdmin, isMuted, userId, username } from "../stores/connection.js";
  import { channels, currentChannelId } from "../stores/channels.js";
  import { addNotification } from "../stores/notifications.js";
  import { avatarColor } from "../avatar.js";
  import { audibleIds, drivenBy } from "../stores/room.js";
  import { micMonitor, inputGain } from "../stores/settings.js";
  import {
    MAX_LEVEL,
    PLAIN_LANE,
    loadUser,
    micLane,
    selectedStrip,
    setLaneField,
    setUserVolume,
    sourceLevels,
    toggleUserMute,
    userFx,
    userVolumes,
    type Lane,
  } from "../stores/mixer.js";
  import { PRESETS } from "../../web/backend/worklets/mixer-worklet.js";
  import Icon from "./Icons.svelte";

  /** How often the meters are refreshed, matching the existing level poll. */
  const LEVEL_POLL_MS = 66;
  /** Meter fall-off per poll: fast enough to follow speech, slow enough to read. */
  const METER_RELEASE = 0.75;

  /** A game owns the receiver side while it drives this channel. */
  const gameDriven = $derived($drivenBy !== null);

  /** One strip. `"mic"` is ours; every other id is a user id. */
  type Strip = { id: number | "mic"; name: string; colour: string; own: boolean };

  const hidesMembers = $derived(
    !$isAdmin &&
      ($channels.find((c) => c.channel_id === $currentChannelId)?.hide_members ?? false),
  );
  const roster = $derived(hidesMembers ? [] : $users.filter((u) => u.user_id !== $userId));

  /** Ours first, then everyone else. The same shape for both, on purpose. */
  const lanes = $derived<Strip[]>([
    { id: "mic", name: $username || "You", colour: avatarColor($username), own: true },
    ...roster.map((u) => ({
      id: u.user_id,
      name: u.username,
      colour: avatarColor(u.username),
      own: false,
    })),
  ]);

  /** Effect options, grouped so five radios do not read as one long list. */
  const groups = [
    { family: "radio", label: "Radios" },
    { family: "phone", label: "Phones" },
    { family: "colour", label: "Other" },
  ];

  /** The three scalable effects, in the order they appear on every strip. */
  const SLIDERS = [
    { key: "muffle" as const, label: "Muffle", hint: "How much wall is in the way." },
    { key: "reverb" as const, label: "Reverb", hint: "How big the space around the voice is." },
    { key: "water" as const, label: "Water", hint: "How far under the surface the voice is." },
  ];

  /**
   * One strip's lane. The store values are arguments rather than reads so that
   * Svelte tracks them — this is called from the markup for every strip.
   */
  function laneFor(strip: Strip, mic: Lane, map: Map<number, Lane>): Lane {
    return strip.id === "mic" ? mic : (map.get(strip.id as number) ?? PLAIN_LANE);
  }

  /** A strip's fader: our own input gain, or that person's volume. */
  function faderValue(strip: Strip, gain: number, vols: Map<number, number>): number {
    return strip.own ? gain : (vols.get(strip.id as number) ?? 1);
  }

  function setFader(strip: Strip, value: number) {
    if (strip.own) {
      inputGain.set(value);
      invoke("set_input_gain", { gain: value }).catch((e) =>
        addNotification(`Could not set the gain: ${e}`, "error"),
      );
    } else {
      void setUserVolume(strip.id as number, value);
    }
  }

  function toggleStripMute(strip: Strip) {
    if (strip.own) {
      invoke<boolean>("toggle_mute")
        .then((m) => isMuted.set(m))
        .catch((e) => addNotification(`Could not mute: ${e}`, "error"));
    } else {
      void toggleUserMute(strip.id as number);
    }
  }

  /** Only the receiving side is ever taken over, and only the effects. */
  const locked = (strip: Strip) => gameDriven && !strip.own;

  /**
   * Is the game leaving this person out of the mix entirely? A fader that does
   * nothing because nothing is coming through should say so — and leaving
   * somebody out is also how a game would silence them, so it is shown rather
   * than left to be discovered. See `audibleIds`.
   */
  const isCulled = (strip: Strip, audible: Set<number> | null) =>
    !strip.own && audible !== null && !audible.has(strip.id as number);

  // ── Meters ─────────────────────────────────────────────────────────────

  let meters = $state<Record<number, number>>({});
  let ownLevel = $state(0);
  let poll: ReturnType<typeof setInterval> | null = null;

  function dbToPercent(db: number): number {
    return Math.max(0, Math.min(100, ((db + 60) / 60) * 100));
  }

  async function tickMeters() {
    try {
      const levels = await invoke<Record<string, number>>("get_source_levels");
      const next: Record<number, number> = {};
      for (const u of roster) {
        const rms = levels[String(u.user_id)] ?? 0;
        const db = rms > 0 ? 20 * Math.log10(rms) : -100;
        next[u.user_id] = Math.max(dbToPercent(db), (meters[u.user_id] ?? 0) * METER_RELEASE);
      }
      meters = next;
      sourceLevels.set(new Map(Object.entries(levels).map(([k, v]) => [Number(k), v])));
    } catch {
      meters = {};
    }
    // Our own meter has two sources, because the two never run at once: the
    // capture task writes `get_audio_level` while we transmit, and the mic
    // test refuses to start while we do. Polling it during the test therefore
    // read a dead value for exactly the strip the test is about — so while the
    // test runs, the `mic-test-level` event feeds the meter instead.
    if (micTesting) return;
    try {
      const db = await invoke<number>("get_audio_level");
      ownLevel = Math.max(dbToPercent(db), ownLevel * METER_RELEASE);
    } catch {
      ownLevel = 0;
    }
  }

  $effect(() => {
    if (!poll) poll = setInterval(tickMeters, LEVEL_POLL_MS);
    return () => {
      if (poll) clearInterval(poll);
      poll = null;
    };
  });

  onDestroy(() => {
    if (poll) clearInterval(poll);
  });

  // Read each member's settings once, so a reconnect cannot leave the desk lying
  $effect(() => {
    for (const u of roster) if (!$userFx.has(u.user_id)) void loadUser(u.user_id);
  });

  // ── The microphone test, which lives with our own strip ────────────────

  let micTesting = $state(false);
  /** Dropped when the test stops, so the meter goes back to the capture task. */
  let micTestUnlisten: Array<() => void> = [];

  async function toggleMicTest() {
    try {
      if (micTesting) {
        await invoke("stop_mic_test");
        stopListeningToMicTest();
      } else {
        micTestUnlisten.push(
          await listen<{ db: number }>("mic-test-level", (e) => {
            ownLevel = Math.max(dbToPercent(e.payload.db), ownLevel * METER_RELEASE);
          }),
        );
        micTestUnlisten.push(
          await listen<{ error: string }>("mic-test-error", (e) => {
            addNotification(`Microphone test failed: ${e.payload.error}`, "error");
            invoke("stop_mic_test").catch(() => {});
            stopListeningToMicTest();
          }),
        );
        await invoke("start_mic_test", { monitor: $micMonitor });
        micTesting = true;
      }
    } catch (e) {
      stopListeningToMicTest();
      addNotification(`Microphone test failed: ${e}`, "error");
    }
  }

  function stopListeningToMicTest() {
    micTesting = false;
    micTestUnlisten.forEach((off) => off());
    micTestUnlisten = [];
    ownLevel = 0;
  }

  onDestroy(() => {
    if (micTesting) invoke("stop_mic_test").catch(() => {});
    micTestUnlisten.forEach((off) => off());
  });

  const selected = $derived(lanes.find((l) => l.id === $selectedStrip) ?? null);
</script>

<!--
  The layout switches on the mixer's OWN width, not the window's. It lives in
  the centre column between the channel list and the member list, so a 700 px
  window leaves it barely 300 px — a window-width media query put the desktop
  layout into a third of the space it needs, and strips ran off the side.
-->
<div class="mixer">
  {#if gameDriven}
    <div class="banner">
      {$drivenBy} is driving what you hear, so the effects on everyone else are its
      call. Your own voice, and every fader, are still yours.
    </div>
  {/if}

  <div class="rack">
    {#each lanes as strip (strip.id)}
      {@const lane = laneFor(strip, $micLane, $userFx)}
      {@const value = faderValue(strip, $inputGain, $userVolumes)}
      {@const muted = strip.own ? $isMuted : value === 0}
      {@const culled = isCulled(strip, $audibleIds)}
      <div
        class="strip"
        class:own={strip.own}
        class:culled
        data-strip={strip.own ? "mic" : String(strip.id)}
        data-user={strip.own ? undefined : strip.id}
      >
        <div class="plate">
          <span class="dot" style="background: {strip.colour}"></span>
          <span class="name">{strip.name}</span>
          {#if strip.own}<span class="tag">you</span>{/if}
          {#if culled}
            <span class="tag out" title="The game is not letting this voice through right now"
              >out of earshot</span
            >
          {/if}
        </div>

        <label class="pick">
          <span class="tiny">Effect</span>
          <select
            value={lane.effect}
            disabled={locked(strip)}
            aria-label="{strip.name} effect"
            onchange={(e) => setLaneField(strip.id, "effect", e.currentTarget.value)}
          >
            <option value="none">No effect</option>
            {#each groups as g (g.family)}
              <optgroup label={g.label}>
                {#each PRESETS.filter((p) => p.family === g.family) as p (p.id)}
                  <option value={p.id}>{p.label}</option>
                {/each}
              </optgroup>
            {/each}
          </select>
        </label>

        <div class="travel">
          <div class="meter">
            <div
              class="fill"
              style="height: {strip.own ? ownLevel : (meters[strip.id as number] ?? 0)}%"
            ></div>
          </div>
          <input
            class="fader"
            type="range"
            min="0"
            max={strip.own ? 4 : 2}
            step="0.05"
            {value}
            aria-label="{strip.name} {strip.own ? 'gain' : 'volume'}"
            oninput={(e) => setFader(strip, Number(e.currentTarget.value))}
          />
        </div>
        <span class="readout">{Math.round(value * 100)}%</span>

        <button
          class="mute"
          class:muted
          title={muted ? "Unmute" : "Mute"}
          onclick={() => toggleStripMute(strip)}
        >
          <Icon name={muted ? "volume-off" : "volume"} size={16} />
        </button>

        <button
          class="params"
          class:open={$selectedStrip === strip.id}
          title="More of this lane"
          onclick={() => selectedStrip.set($selectedStrip === strip.id ? null : strip.id)}
        >⋯</button>
      </div>
    {/each}

    {#if lanes.length === 1}
      <div class="empty">
        Nobody else is here yet.
        {#if hidesMembers}This channel hides its members.{/if}
      </div>
    {/if}
  </div>

  <!-- Always rendered, so opening it reserves space instead of shoving the
       strips around mid-drag. The same three sliders whichever strip is open:
       they are scalable effects, and a lane is a lane. -->
  <div class="inspector" class:open={selected !== null}>
    {#if selected}
      {@const strip = selected}
      {@const lane = laneFor(strip, $micLane, $userFx)}
      <div class="inspect-head">
        <span>{strip.name}{strip.own ? " — your voice going out" : ""}</span>
        <button class="close" onclick={() => selectedStrip.set(null)} title="Close">
          <Icon name="close" size={16} />
        </button>
      </div>

      <div class="sliders">
        {#each SLIDERS as s (s.key)}
          <label class="knob wide" title={s.hint}>
            <span class="tiny">{s.label}</span>
            <input
              type="range"
              min="0"
              max={MAX_LEVEL}
              step="1"
              value={lane[s.key]}
              disabled={locked(strip)}
              aria-label="{strip.name} {s.label.toLowerCase()}"
              oninput={(e) => setLaneField(strip.id, s.key, Number(e.currentTarget.value))}
            />
            <span class="tiny num">{lane[s.key] === 0 ? "off" : lane[s.key]}</span>
          </label>
        {/each}
      </div>

      {#if strip.own}
        <div class="extras">
          <button class="mic-test" class:on={micTesting} onclick={toggleMicTest}>
            {micTesting ? "Stop test" : "Test mic"}
          </button>
          <label class="check">
            <input
              type="checkbox"
              checked={$micMonitor}
              disabled={micTesting}
              onchange={(e) => micMonitor.set(e.currentTarget.checked)}
            />
            <span class="tiny">Hear myself</span>
          </label>
          <span class="tiny hint">
            Everyone hears all four of these: they are rendered into your voice before it
            is sent, so no listener can turn them off, and no game overrides them.
          </span>
        </div>
      {:else}
        <span class="tiny hint">
          Only you hear these four. Distance and placement live in the virtual room, not
          here.{#if gameDriven} {$drivenBy} is setting them right now.{/if}
        </span>
      {/if}
    {:else}
      <span class="tiny hint">Pick ⋯ on a strip for its muffle, reverb and water.</span>
    {/if}
  </div>
</div>

<style>
  .mixer {
    container: mixer / inline-size;
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    background: var(--bg-primary);
  }

  .banner {
    padding: 8px 12px;
    font-size: 12px;
    color: var(--text-secondary);
    background: var(--bg-hover);
    border-bottom: 1px solid var(--border);
  }

  .rack {
    flex: 1;
    min-height: 0;
    display: flex;
    gap: 8px;
    padding: 8px;
    overflow-x: auto;
    overflow-y: hidden;
  }

  .strip {
    flex: 0 0 104px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    min-height: 0;
    padding: 8px 6px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  /* Ours is pinned and accented so it is easy to find — same controls, same
     order, same sizes. Only the border knows the difference. */
  .strip.own {
    border-color: var(--accent);
    background: var(--bg-tertiary);
    position: sticky;
    left: 0;
    z-index: 1;
  }

  .plate {
    display: flex;
    align-items: center;
    gap: 5px;
    width: 100%;
    font-size: 12px;
    color: var(--text-primary);
  }

  .dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    flex: none;
  }

  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tag {
    flex: none;
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--accent);
  }

  /* The game is leaving this voice out of the mix. The strip stays usable —
     the fader is still yours, and it takes effect the moment they come back
     into earshot — it just says why nothing is coming through. */
  .tag.out {
    color: var(--text-secondary);
  }

  .strip.culled .plate .name,
  .strip.culled .meter {
    opacity: 0.5;
  }

  .tiny {
    font-size: 10px;
    color: var(--text-secondary);
  }

  .hint {
    line-height: 1.35;
    opacity: 0.85;
  }

  .pick {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  select {
    width: 100%;
    min-width: 0;
    padding: 4px;
    font-size: 11px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  /* The fader and its meter, side by side like a real desk. */
  .travel {
    flex: 1;
    min-height: 120px;
    display: flex;
    align-items: stretch;
    justify-content: center;
    gap: 8px;
    padding: 4px 0;
  }

  .meter {
    width: 8px;
    align-self: stretch;
    background: var(--bg-tertiary);
    border-radius: 4px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
  }

  .fill {
    width: 100%;
    background: var(--accent);
    transition: height 60ms linear;
  }

  /* A vertical range input. `direction: rtl` puts zero at the bottom, where a
     fader's zero belongs. The native thumb is kept on purpose: restyling it
     drops accent-color and swaps what width and height mean here. 44 px wide
     is the touch target, not the visible track. */
  .fader {
    writing-mode: vertical-rl;
    direction: rtl;
    appearance: slider-vertical;
    -webkit-appearance: slider-vertical;
    width: 44px;
    height: auto;
    align-self: stretch;
    margin: 0;
    padding: 0;
    background: transparent;
    border: none;
    accent-color: var(--accent);
    /* Or the rack's horizontal scroll eats the drag before the fader sees it */
    touch-action: none;
    cursor: pointer;
  }

  .readout {
    font-size: 11px;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }

  .mute,
  .params,
  .mic-test,
  .close {
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 36px;
    min-height: 36px;
    padding: 0 8px;
    font-size: 11px;
    background: var(--bg-primary);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
  }

  .mute:hover,
  .params:hover,
  .mic-test:hover,
  .close:hover {
    color: var(--text-primary);
    border-color: var(--accent);
  }

  .mute.muted {
    color: var(--danger);
    border-color: var(--danger);
  }

  .params.open,
  .mic-test.on {
    color: var(--accent);
    border-color: var(--accent);
  }

  .check {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .knob {
    display: flex;
    align-items: center;
    gap: 5px;
  }

  .knob > .tiny:first-child {
    min-width: 42px;
  }

  .knob input[type="range"] {
    flex: 1;
    min-width: 0;
    accent-color: var(--accent);
    height: 32px;
  }

  .knob .num {
    min-width: 22px;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .empty {
    align-self: center;
    margin: auto;
    font-size: 13px;
    color: var(--text-secondary);
  }

  .inspector {
    display: flex;
    flex-direction: column;
    gap: 6px;
    height: 168px;
    padding: 10px 12px;
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
  }

  .inspect-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 13px;
    color: var(--text-primary);
  }

  /* Three sliders side by side where there is room, stacked where there is
     not. They are the same kind of control, so they get the same treatment. */
  .sliders {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 4px 16px;
  }

  .extras {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .extras .hint {
    flex: 1 1 220px;
    min-width: 0;
  }

  input:disabled,
  select:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* ── Narrow: one strip per row, stacked and scrolling ──────────────────
     Keyed off the mixer's OWN width with a container query, not the window's.
     The mixer lives in the centre column between the channel list and the
     member list, so a 700 px window leaves it barely 300 px: a window-width
     media query put the desktop layout into a third of the space it needs and
     strips ran off the side.

     A container query rather than a ResizeObserver because the observer
     reports a size one frame late, so the layout stayed a step behind the
     resize — correct only after you dragged the window twice.

     Every strip becomes a small grid rather than a wrapped flex row. Wrapping
     was the other half of the breakage: the strip's own height stopped
     accounting for its children, so one strip's controls painted straight over
     the strip below it. A grid's rows always add up. */
  @container mixer (max-width: 520px) {
    .rack {
      flex-direction: column;
      gap: 6px;
      overflow-x: hidden;
      overflow-y: auto;
      /* Momentum scrolling, and never bounce the page behind it */
      overscroll-behavior-y: contain;
    }

    .strip {
      position: static;
      flex: 0 0 auto;
      width: 100%;
      min-width: 0;
      display: grid;
      grid-template-columns: 1fr auto auto auto;
      align-items: center;
      gap: 6px 8px;
    }

    /* Name and picker span the row; the fader shares it with the readout and
       the buttons. */
    .plate,
    .pick {
      grid-column: 1 / -1;
      width: auto;
    }

    .travel {
      grid-column: 1;
      min-height: 0;
      height: 44px;
      padding: 0;
      align-items: center;
      min-width: 0;
    }

    .meter {
      flex: 0 0 8px;
      height: 32px;
      align-self: center;
    }

    /* Horizontal here: a vertical fader in a 44 px row is a dot. */
    .fader {
      writing-mode: horizontal-tb;
      direction: ltr;
      appearance: auto;
      -webkit-appearance: auto;
      width: auto;
      flex: 1 1 0;
      min-width: 0;
      height: 44px;
      align-self: center;
    }

    .readout {
      grid-column: 2;
      min-width: 38px;
      text-align: right;
    }

    .mute {
      grid-column: 3;
    }

    .params {
      grid-column: 4;
    }

    /* Closed, the inspector is a single line rather than a fixed slab: on a
       300 px column a permanent reservation is most of the screen. */
    .inspector {
      height: auto;
      max-height: 50%;
      overflow-y: auto;
    }

    .inspector:not(.open) {
      padding: 6px 12px;
    }
  }

  /* Very narrow: the fader takes a row of its own. With the readout and both
     buttons beside it there is under 60 px left for the travel, which is a
     thumb-sized stub rather than a fader. */
  @container mixer (max-width: 400px) {
    .travel {
      grid-column: 1 / -1;
    }

    .readout {
      grid-column: 1;
      text-align: left;
    }

    .mute {
      grid-column: 3;
    }

    .params {
      grid-column: 4;
    }
  }
</style>
