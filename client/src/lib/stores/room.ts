// Virtual room: where each member of a proximity channel stands.
//
// Placements are local. While "sync my position" is off you may drag anyone,
// and nothing leaves the machine; while it is on you may only move yourself,
// your position is broadcast, and the other members' positions come from their
// own beacons.

import { derived, writable, get } from "svelte/store";
// Explicit extensions so Node's test runner can load this file as-is
import { channels, currentChannelId } from "./channels.ts";
import type { ProximityMode } from "../spatial.ts";

export type Point = { x: number; y: number; z: number };

/** Half-width of the room in metres; the view is 2·ROOM_EXTENT square. */
export const ROOM_EXTENT = 10;

/** Is the room panel showing? */
export const roomOpen = writable(false);

/** Are we broadcasting our own position (and accepting the others')? */
export const syncing = writable(false);

/** user_id -> placement. Absent means "not placed": that user sounds flat. */
export const positions = writable<Map<number, Point>>(new Map());

/** The avatar whose height slider is shown (3D channels). */
export const selectedUserId = writable<number | null>(null);

/** A game is driving positions: the room shows them but nothing is draggable. */
export const drivenBy = writable<string | null>(null);

/** The proximity mode of the channel we are in. */
export const currentProximity = derived(
  [channels, currentChannelId],
  ([$channels, $id]) =>
    ($channels.find((c) => c.channel_id === $id)?.proximity ?? "off") as ProximityMode,
);

export function setPosition(userId: number, p: Point): void {
  positions.update((m) => new Map(m).set(userId, p));
}

export function clearRoom(): void {
  positions.set(new Map());
  selectedUserId.set(null);
  syncing.set(false);
}

/** Disconnected: the room and the game that drove it are both gone. */
export function resetRoom(): void {
  clearRoom();
  roomOpen.set(false);
  drivenBy.set(null);
}

export type PresetName = "free" | "round" | "classroom" | "line";

export const PRESETS: { id: PresetName; label: string }[] = [
  { id: "free", label: "Free placement" },
  { id: "round", label: "Round table" },
  { id: "classroom", label: "Class room" },
  { id: "line", label: "Line" },
];

/**
 * Where each user stands under a preset. Pure and ordered by user id, so two
 * clients that pick the same preset lay the room out identically without
 * exchanging anything.
 *
 * `presenter` faces the rest from the front of the class room; it defaults to
 * the lowest id (in practice the channel's creator, who joined first).
 */
export function layout(
  preset: PresetName,
  userIds: number[],
  presenter: number | null = null,
): Map<number, Point> {
  const ids = [...userIds].sort((a, b) => a - b);
  const out = new Map<number, Point>();
  if (preset === "free" || ids.length === 0) return out;

  if (preset === "round") {
    const radius = Math.max(2, 0.45 * ids.length);
    ids.forEach((id, i) => {
      const angle = (2 * Math.PI * i) / ids.length;
      out.set(id, { x: round(radius * Math.sin(angle)), y: round(radius * Math.cos(angle)), z: 0 });
    });
    return out;
  }

  if (preset === "line") {
    const start = (-(ids.length - 1) * 1.5) / 2;
    ids.forEach((id, i) => out.set(id, { x: round(start + i * 1.5), y: 0, z: 0 }));
    return out;
  }

  // Class room: the presenter up front, everyone else in rows of four facing them
  const front = presenter !== null && ids.includes(presenter) ? presenter : ids[0];
  out.set(front, { x: 0, y: 6, z: 0 });
  const seats = ids.filter((id) => id !== front);
  seats.forEach((id, i) => {
    const col = i % 4;
    const row = Math.floor(i / 4);
    out.set(id, { x: round((col - 1.5) * 1.5), y: round(-row * 1.5), z: 0 });
  });
  return out;
}

function round(v: number): number {
  return Math.round(v * 100) / 100;
}

/** Clamp a point into the room. */
export function clampToRoom(p: Point): Point {
  return {
    x: Math.min(ROOM_EXTENT, Math.max(-ROOM_EXTENT, p.x)),
    y: Math.min(ROOM_EXTENT, Math.max(-ROOM_EXTENT, p.y)),
    z: Math.min(5, Math.max(-5, p.z)),
  };
}

/** The placement a user has right now, or the origin. */
export function positionOf(userId: number): Point {
  return get(positions).get(userId) ?? { x: 0, y: 0, z: 0 };
}
