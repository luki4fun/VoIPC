// Who may not speak on each server (`Restrictions`, 1.10). Marks, composers and the
// talk button read this. The relay enforces it all; this says so before a click
// finds out.

import { derived, type Readable } from "svelte/store";
import { voiceServer } from "./channels.js";
import { userId, voiceUserId } from "./connection.js";
import { scoped } from "./scoped.js";
import { withRows, type Held, type RestrictionRow } from "../restrict-rules.js";

/** By this connection's user ids. A connection lost clears them (App.svelte): a
 *  restarted relay numbers from 1 again, and an old row would hold back a stranger. */
export const restrictions = scoped<ReadonlyMap<number, Held>>(() => new Map());

/** Ours on the server on screen. */
export const myRestriction: Readable<Held | null> = derived(
  [restrictions, userId],
  ([$rows, $id]) => $rows.get($id) ?? null,
);

/** Ours on the server carrying the call. */
export const voiceRestriction: Readable<Held | null> = derived(
  [restrictions.at(voiceServer), voiceUserId],
  ([$rows, $id]) => $rows.get($id) ?? null,
);

export function onRestrictions(server: string, list: readonly RestrictionRow[]): void {
  restrictions.of(server).update((had) => withRows(had, list, Date.now()));
}
