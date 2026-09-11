// The mixing desk's state, and the one place a lane's settings live.
//
// A lane is a lane. Our own microphone on the way out and one other person's
// voice on the way in carry exactly the same four controls — an effect, and
// muffle, reverb and water at 0-10 each — so there is one shape here, one set
// of clamps, and no control that exists on one side and not the other.
//
// Volume used to live in two component-local records, one in the member list
// and one in the effects panel, so the same person had two different volumes
// depending on which control you looked at. There is now exactly one writer of
// `set_user_volume` in the whole client, and it is here. The same rule holds
// for `set_user_fx` and `set_mic_fx`.
//
// Its own file rather than users.ts or room.ts: those two are imported by the
// Node test runner, and pulling `@tauri-apps/api` into them breaks `npm test`
// on an unresolvable bare specifier.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import { addNotification } from "./notifications.js";

/**
 * One lane. `effect` is a preset id ("none", "radio", "phone", …); the other
 * three are scalable effects on the same 0-10 scale.
 */
export interface Lane {
  effect: string;
  muffle: number;
  reverb: number;
  water: number;
}

/** A lane with nothing switched on. */
export const PLAIN_LANE: Lane = { effect: "none", muffle: 0, reverb: 0, water: 0 };

/** The scale every scalable effect runs on. */
export const MAX_LEVEL = 10;

const level = (v: number) => Math.min(Math.max(Math.round(v), 0), MAX_LEVEL);

/** Clamp every level of a lane, whoever it came from. */
export function cleanLane(lane: Lane): Lane {
  return {
    effect: lane.effect || "none",
    muffle: level(lane.muffle),
    reverb: level(lane.reverb),
    water: level(lane.water),
  };
}

/** user_id -> volume, 0-2. Absent means 1.0, the rule the backend also uses. */
export const userVolumes = writable<Map<number, number>>(new Map());

/** user_id -> that incoming lane, as the backend holds it. */
export const userFx = writable<Map<number, Lane>>(new Map());

/**
 * Our own microphone's lane. The same shape as any other, but persisted, and
 * everybody hears it — it is rendered into the voice before Opus, so no
 * listener can switch it off.
 */
export const micLane = writable<Lane>({ ...PLAIN_LANE });

/** user_id -> most recent RMS level, for the meters. */
export const sourceLevels = writable<Map<number, number>>(new Map());

/** Whose strip has its controls open. `"mic"` is our own. */
export const selectedStrip = writable<number | "mic" | null>(null);

export const DEFAULT_VOLUME = 1;

export function volumeOf(id: number): number {
  return get(userVolumes).get(id) ?? DEFAULT_VOLUME;
}

export function fxOf(id: number): Lane {
  return get(userFx).get(id) ?? { ...PLAIN_LANE };
}

/** What a muted strip goes back to. Scratch, not state anything renders. */
const premute = new Map<number, number>();

/** The only caller of `set_user_volume` in the client. Optimistic. */
export async function setUserVolume(id: number, volume: number): Promise<void> {
  const v = Math.min(Math.max(volume, 0), 2);
  userVolumes.update((m) => new Map(m).set(id, v));
  try {
    await invoke("set_user_volume", { userId: id, volume: v });
  } catch (e) {
    addNotification(`Could not set the volume: ${e}`, "error");
  }
}

export async function toggleUserMute(id: number): Promise<void> {
  const current = volumeOf(id);
  if (current > 0) {
    premute.set(id, current);
    await setUserVolume(id, 0);
  } else {
    await setUserVolume(id, premute.get(id) ?? DEFAULT_VOLUME);
  }
}

/** The only caller of `set_user_fx`. Optimistic, like the volume above. */
export async function setUserFx(id: number, lane: Lane): Promise<void> {
  const l = cleanLane(lane);
  userFx.update((m) => new Map(m).set(id, l));
  try {
    await invoke("set_user_fx", { userId: id, ...l });
  } catch (e) {
    addNotification(`Could not set the effect: ${e}`, "error");
  }
}

/** The only caller of `set_mic_fx`. Same lane, same clamps, one command over. */
export async function setMicFx(lane: Lane): Promise<void> {
  const l = cleanLane(lane);
  micLane.set(l);
  try {
    await invoke("set_mic_fx", { ...l });
  } catch (e) {
    addNotification(`Could not set the effect: ${e}`, "error");
  }
}

/**
 * Set one control of a lane, leaving the other three alone. Every slider and
 * every dropdown in the mixer goes through here, whichever lane it belongs to,
 * which is why there is no second code path for our own voice.
 */
export function setLaneField<K extends keyof Lane>(
  id: number | "mic",
  key: K,
  value: Lane[K],
): Promise<void> {
  if (id === "mic") return setMicFx({ ...get(micLane), [key]: value });
  return setUserFx(id, { ...fxOf(id), [key]: value });
}

/** One lane, whoever it belongs to. */
export function laneOf(id: number | "mic"): Lane {
  return id === "mic" ? get(micLane) : fxOf(id);
}

/**
 * Read one member's settings back from the backend.
 *
 * The store is the single writer, so it cannot normally drift — this exists for
 * the one case that can: a reconnect, where the backend has forgotten
 * everything and the UI has not.
 */
export async function loadUser(id: number): Promise<void> {
  try {
    const [effect, muffle, reverb, water] = await invoke<[string, number, number, number]>(
      "get_user_fx",
      { userId: id },
    );
    const volume = await invoke<number>("get_user_volume", { userId: id });
    userVolumes.update((m) => new Map(m).set(id, volume));
    userFx.update((m) => new Map(m).set(id, cleanLane({ effect, muffle, reverb, water })));
  } catch {
    // Not connected yet; the defaults are already right
  }
}

/**
 * Forget everything about other people. Called on disconnect only — a user id
 * is a session id and is handed to somebody else next time. Deliberately NOT on
 * a channel change: the backend keeps volumes across one, so clearing there
 * would make the UI disagree with what you actually hear.
 *
 * Our own lane survives, because it is ours and it is saved to disk.
 */
export function clearMixer(): void {
  userVolumes.set(new Map());
  userFx.set(new Map());
  sourceLevels.set(new Map());
  selectedStrip.set(null);
  premute.clear();
}
