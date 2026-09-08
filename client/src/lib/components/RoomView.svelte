<script lang="ts">
  // The virtual room of a proximity channel, drawn top-down as plain SVG.
  //
  // While "sync my position" is off, you arrange everyone yourself and nothing
  // leaves this machine. Turn it on and you can only move yourself: your
  // position is broadcast to the channel (encrypted like voice) and everyone
  // else's comes from their own beacons.

  import { invoke } from "@tauri-apps/api/core";
  import { users, speakingUsers } from "../stores/users.js";
  import { userId } from "../stores/connection.js";
  import { channels, currentChannelId } from "../stores/channels.js";
  import { addNotification } from "../stores/notifications.js";
  import { avatarColor } from "../avatar.js";
  import {
    PRESETS,
    ROOM_EXTENT,
    clampToRoom,
    currentProximity,
    drivenBy,
    layout,
    positionOf,
    positions,
    selectedUserId,
    syncing,
    type PresetName,
    type Point,
  } from "../stores/room.js";
  import { REF_DIST, DEFAULT_RANGE } from "../spatial.js";
  import Icon from "./Icons.svelte";

  let svgEl: SVGSVGElement | undefined = $state();
  let preset = $state<PresetName>("free");
  let dragging: number | null = $state(null);

  const channelCreator = $derived(
    $channels.find((c) => c.channel_id === $currentChannelId)?.created_by ?? null,
  );
  const is3d = $derived($currentProximity === "3d");
  const locked = $derived($drivenBy !== null);

  /** Everyone in the channel, own user first so it draws on top. */
  const placed = $derived(
    $users
      .map((u) => ({ user: u, at: $positions.get(u.user_id) ?? null }))
      .filter((e) => e.at !== null) as { user: (typeof $users)[number]; at: Point }[],
  );
  const unplaced = $derived($users.filter((u) => !$positions.has(u.user_id)));

  function canDrag(id: number): boolean {
    if (locked) return false;
    return !$syncing || id === $userId;
  }

  /** Push one placement to the mixer (and to the channel, when it is ours). */
  async function apply(id: number, p: Point | null): Promise<void> {
    try {
      if (id === $userId) {
        if (p) await invoke("set_own_position", { pos: [p.x, p.y, p.z] });
      } else {
        await invoke("set_user_position", { userId: id, pos: p ? [p.x, p.y, p.z] : null });
      }
    } catch (e) {
      console.error("failed to apply position:", e);
    }
  }

  // A pointer fires 60-144 times a second; a shared position may go out about
  // ten times (the server relays 12/s). The avatar still follows every event —
  // only the invoke is coalesced, and onPointerUp flushes the final spot.
  const APPLY_INTERVAL_MS = 100;
  let lastApplied = 0;

  function place(id: number, p: Point): void {
    const clamped = clampToRoom(p);
    positions.update((m) => new Map(m).set(id, clamped));
    const now = performance.now();
    if (dragging !== null && now - lastApplied < APPLY_INTERVAL_MS) return;
    lastApplied = now;
    apply(id, clamped);
  }

  /** Screen coordinates to room metres. */
  function toRoom(e: PointerEvent): Point | null {
    if (!svgEl) return null;
    const ctm = svgEl.getScreenCTM();
    if (!ctm) return null;
    const pt = new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
    return { x: pt.x, y: -pt.y, z: 0 };
  }

  function onPointerDown(e: PointerEvent, id: number): void {
    if (!canDrag(id)) return;
    e.stopPropagation();
    dragging = id;
    selectedUserId.set(id);
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
  }

  function onPointerMove(e: PointerEvent): void {
    if (dragging === null) return;
    const p = toRoom(e);
    if (!p) return;
    const height = $positions.get(dragging)?.z ?? 0;
    place(dragging, { ...p, z: height });
  }

  function onPointerUp(e: PointerEvent): void {
    if (dragging === null) return;
    (e.currentTarget as Element).releasePointerCapture(e.pointerId);
    const id = dragging;
    dragging = null;
    // The drag was throttled; make sure the resting place is the one that
    // reaches the mixer and the channel
    apply(id, $positions.get(id) ?? null);
  }

  /** Click on an empty spot: place the selected (or your own) avatar there. */
  function onCanvasClick(e: PointerEvent): void {
    if (locked) return;
    const target = $syncing ? $userId : ($selectedUserId ?? $userId);
    if (!canDrag(target)) return;
    const p = toRoom(e);
    if (p) place(target, { ...p, z: $positions.get(target)?.z ?? 0 });
  }

  function setHeight(id: number, z: number): void {
    const at = $positions.get(id);
    if (!at) return;
    place(id, { ...at, z });
  }

  function applyPreset(name: PresetName): void {
    preset = name;
    if (name === "free") return;
    const seats = layout(
      name,
      $users.map((u) => u.user_id),
      channelCreator,
    );
    // While syncing you may only move yourself; the preset still tells you
    // where to stand, and everyone else's beacon puts them in their seat.
    for (const [id, p] of seats) {
      if (!canDrag(id)) continue;
      place(id, p);
    }
  }

  async function toggleSync(e: Event): Promise<void> {
    const next = !$syncing;
    try {
      await invoke("set_position_sync", { enabled: next });
      syncing.set(next);
      if (next) {
        // Peers replace their own placements from here on
        positions.update((m) => {
          const own = m.get($userId);
          return own ? new Map([[$userId, own]]) : new Map();
        });
        const own = $positions.get($userId) ?? { x: 0, y: 0, z: 0 };
        place($userId, own);
      }
    } catch (err) {
      addNotification(`Could not change position sharing: ${err}`, "error");
      // The click already flipped the box; put it back where the state is
      const box = e.currentTarget as HTMLInputElement | null;
      if (box) box.checked = $syncing;
    }
  }

  async function reset(): Promise<void> {
    preset = "free";
    selectedUserId.set(null);
    // While sharing, "unplaced" is not a state we can be in: the beacon keeps
    // announcing us. Keep our own spot and drop everyone else's.
    const own = $syncing ? positionOf($userId) : null;
    positions.set(own ? new Map([[$userId, own]]) : new Map());
    try {
      await invoke("clear_positions");
      if (own) await apply($userId, own);
    } catch (e) {
      console.error("failed to clear positions:", e);
    }
  }

  const selectedHeight = $derived(
    $selectedUserId !== null ? ($positions.get($selectedUserId)?.z ?? 0) : 0,
  );
</script>

<div class="room">
  <div class="toolbar">
    <span class="title">
      <Icon name="room" size={16} />
      Virtual room
      <span class="mode-tag">{$currentProximity.toUpperCase()}</span>
    </span>

    <select
      class="control"
      value={preset}
      onchange={(e) => applyPreset((e.currentTarget as HTMLSelectElement).value as PresetName)}
      disabled={locked}
      title="Arrange everyone"
    >
      {#each PRESETS as p (p.id)}
        <option value={p.id}>{p.label}</option>
      {/each}
    </select>

    <label class="control sync" title="Share your position with the channel">
      <input type="checkbox" checked={$syncing} onchange={(e) => toggleSync(e)} disabled={locked} />
      Sync my position
    </label>

    <button class="control" onclick={reset} disabled={locked}>Reset</button>
  </div>

  {#if locked}
    <div class="banner">Positions come from {$drivenBy}. Close the game to place people yourself.</div>
  {:else if $syncing}
    <div class="banner">Sharing your position. Others appear where they say they are.</div>
  {:else}
    <div class="banner">Your own arrangement, kept on this machine. Drag anyone.</div>
  {/if}

  <!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
  <svg
    bind:this={svgEl}
    class="canvas"
    viewBox="{-ROOM_EXTENT} {-ROOM_EXTENT} {ROOM_EXTENT * 2} {ROOM_EXTENT * 2}"
    onpointermove={onPointerMove}
    onpointerup={onPointerUp}
    onpointerdown={(e) => { if (e.target === svgEl) onCanvasClick(e); }}
  >
    <!-- grid every 2 m -->
    {#each Array(ROOM_EXTENT + 1) as _, i}
      <line class="grid" x1={-ROOM_EXTENT} y1={i * 2 - ROOM_EXTENT} x2={ROOM_EXTENT} y2={i * 2 - ROOM_EXTENT} />
      <line class="grid" x1={i * 2 - ROOM_EXTENT} y1={-ROOM_EXTENT} x2={i * 2 - ROOM_EXTENT} y2={ROOM_EXTENT} />
    {/each}

    <!-- how far your own voice carries -->
    {#if $positions.has($userId)}
      {@const me = $positions.get($userId)!}
      <circle class="ring near" cx={me.x} cy={-me.y} r={REF_DIST} />
      <circle class="ring far" cx={me.x} cy={-me.y} r={DEFAULT_RANGE} />
    {/if}

    {#each placed as entry (entry.user.user_id)}
      {@const id = entry.user.user_id}
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <g
        class="avatar"
        class:self={id === $userId}
        class:speaking={$speakingUsers.has(id)}
        class:draggable={canDrag(id)}
        class:selected={$selectedUserId === id}
        transform="translate({entry.at.x} {-entry.at.y})"
        onpointerdown={(e) => onPointerDown(e, id)}
      >
        <circle class="halo" r="0.95" />
        <circle
          class="disc"
          r={0.6 + Math.max(-0.3, Math.min(0.3, entry.at.z * 0.06))}
          fill={avatarColor(entry.user.username)}
        />
        <text class="initial" y="0.18">{entry.user.username.charAt(0).toUpperCase()}</text>
        <text class="name" y="1.5">
          {entry.user.username}{#if is3d && entry.at.z !== 0}&nbsp;({entry.at.z > 0 ? "+" : ""}{entry.at.z.toFixed(1)} m){/if}
        </text>
      </g>
    {/each}
  </svg>

  {#if is3d && $selectedUserId !== null && $positions.has($selectedUserId)}
    <div class="height">
      <span>Height</span>
      <input
        type="range"
        min="-5"
        max="5"
        step="0.25"
        value={selectedHeight}
        oninput={(e) => setHeight($selectedUserId!, Number((e.currentTarget as HTMLInputElement).value))}
        disabled={!canDrag($selectedUserId)}
      />
      <span class="height-value">{selectedHeight.toFixed(2)} m</span>
    </div>
  {/if}

  {#if unplaced.length > 0}
    <div class="tray">
      <span class="tray-label">Not placed (heard at normal volume):</span>
      {#each unplaced as u (u.user_id)}
        <button
          class="chip"
          disabled={!canDrag(u.user_id)}
          onclick={() => place(u.user_id, { x: 0, y: 0, z: 0 })}
          title="Place {u.username} in the middle"
        >
          <span class="chip-dot" style="background: {avatarColor(u.username)}"></span>
          {u.username}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .room {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    background: var(--bg-primary);
  }

  .toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }

  .title {
    display: flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
    font-size: 14px;
    color: var(--text-primary);
    margin-right: auto;
  }

  .mode-tag {
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 0.05em;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid var(--border);
    color: var(--text-secondary);
  }

  .control {
    font-size: 12px;
    padding: 4px 8px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
  }

  .control:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .sync {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .banner {
    padding: 6px 12px;
    font-size: 12px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
  }

  .canvas {
    flex: 1;
    min-height: 0;
    width: 100%;
    touch-action: none;
    background: var(--bg-secondary);
  }

  .grid {
    stroke: var(--border);
    stroke-width: 0.02;
    opacity: 0.6;
  }

  .ring {
    fill: none;
    stroke: var(--accent);
    stroke-width: 0.04;
    stroke-dasharray: 0.3 0.25;
    opacity: 0.5;
    pointer-events: none;
  }

  .ring.far {
    opacity: 0.22;
  }

  .avatar {
    cursor: default;
  }

  .avatar.draggable {
    cursor: grab;
  }

  .halo {
    fill: none;
    stroke: transparent;
    stroke-width: 0.12;
  }

  .avatar.speaking .halo {
    stroke: var(--success, #57f287);
  }

  .avatar.selected .halo {
    stroke: var(--accent);
    stroke-dasharray: 0.2 0.15;
  }

  .disc {
    stroke: var(--bg-primary);
    stroke-width: 0.06;
  }

  .avatar.self .disc {
    stroke: var(--text-primary);
    stroke-width: 0.12;
  }

  .initial {
    font-size: 0.6px;
    text-anchor: middle;
    fill: #fff;
    font-weight: 600;
    pointer-events: none;
  }

  .name {
    font-size: 0.5px;
    text-anchor: middle;
    fill: var(--text-secondary);
    pointer-events: none;
  }

  .height {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    font-size: 12px;
    color: var(--text-secondary);
    border-top: 1px solid var(--border);
  }

  .height input {
    flex: 1;
  }

  .height-value {
    min-width: 56px;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .tray {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    padding: 8px 12px;
    border-top: 1px solid var(--border);
  }

  .tray-label {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .chip {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    padding: 3px 8px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 12px;
    cursor: pointer;
  }

  .chip:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .chip-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
</style>
