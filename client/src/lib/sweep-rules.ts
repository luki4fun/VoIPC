// When an app asks who is in the channels that go by a list. Asking for the list of the one
// on screen would tell the relay which one a person looks at, so all of them are asked at a
// moment nobody chose, whether open or not.
// Pure, for sweep-rules.test.ts.

import type { UserInfo } from "./types.ts";

/** The longest a list goes without a reason to ask sooner. */
export const SWEEP_EVERY_MS = 10 * 60_000;
/** What a sweep may cost over time, whatever its size. */
const SWEEP_BYTES_PER_SEC = 40;
/** What a page costs, roughly: a bare id, and a whole row. */
const ID_BYTES = 3;
const ROW_BYTES = 83;

/** A moment nobody chose in the first minute. */
export function firstSweepDelay(random: number): number {
  return random * 60_000;
}

/** From one sweep to the next. */
export function nextSweepDelay(lastBytes: number): number {
  return Math.max(SWEEP_EVERY_MS, (lastBytes / SWEEP_BYTES_PER_SEC) * 1000);
}

/** Whether a stranger's ask may move the next sweep up: the byte budget still holds. */
export function mayMoveUp(sinceLast: number, lastBytes: number): boolean {
  return sinceLast >= (lastBytes / SWEEP_BYTES_PER_SEC) * 1000;
}

export function pageBytes(ids: number, rows: number): number {
  return ids * ID_BYTES + rows * ROW_BYTES;
}

/** A page as people. A bare id means a public list here names them; one that does not, yet,
 *  is left out rather than guessed at: not being listed only means no answer for now. */
export function pagePeople(
  ids: readonly number[],
  rows: readonly UserInfo[],
  known: (id: number) => UserInfo | undefined,
): UserInfo[] {
  const named = ids.flatMap((id) => known(id) ?? []);
  return [...rows, ...named];
}
