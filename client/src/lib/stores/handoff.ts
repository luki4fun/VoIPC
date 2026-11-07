// Asking people for a channel's recent chat, as far as the screen goes (`history-rules.ts`).
//
// No ask goes at connect. The first opening of a channel on a connection asks up to three who
// share, one on mobile data, and a ring on opening does the same; everything after that is a
// click. Nothing retries on a timer. Who was asked lasts until the connection ends or the
// channel is left, since ids change.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { channels } from "./channels.js";
import { metered } from "./emotes.js";
import { openedQuiet } from "./quiet.js";
import { channelRings, clearRing, dropOpenedRings, moveRead, ringOpened } from "./marks.js";
import { activeDmUserId, activeTextChannelId, joinedTextChannelIds, noteNeverOpened, openTextChannel } from "./chat.js";
import { uiPrefs, updateUiPrefs } from "./ui-prefs.js";
import { goneFrom, currentRosterOf, onlineById, textSeats } from "./rosters.js";
import { scoped } from "./scoped.js";
import { serverKey, userId } from "./connection.js";
import { goesByList, marksChannel, stableName } from "../follow-rules.js";
import { sharersIn } from "../history-rules.js";
import type { ChannelInfo, UserInfo } from "../types.js";

export interface HandOff {
  /** Asked on this connection, whether or not they answered. */
  asked: ReadonlySet<number>;
  /** An ask is out, up to five seconds. */
  asking: boolean;
  /** It has been on screen on this connection. */
  opened: boolean;
  /** Put back on screen by a reconnect: the person did not open it. */
  reopened: boolean;
}

export const handOffs = scoped<ReadonlyMap<number, HandOff>>(() => new Map());

const NO_HAND_OFF: HandOff = { asked: new Set(), asking: false, opened: false, reopened: false };

/** How long an ask is said to be out. */
const ASKING_MS = 5000;
/** A channel put back by a reconnect and still not followed by then has refused them. */
const REOPEN_WAITS_MS = 20_000;

function patch(server: string, channelId: number, change: Partial<HandOff>): void {
  handOffs.of(server).update((m) => new Map(m).set(channelId, { ...(m.get(channelId) ?? NO_HAND_OFF), ...change }));
}

/** Everyone here who shares, by the list that counts for this channel: a stranger to it is
 *  not asked, and someone it has just lost neither. Nobody in an anonymous channel: an ask
 *  says who is asking, by name, which is what the channel's pseudonym hides. */
export function sharersOf(server: string, channelId: number): UserInfo[] {
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (channel?.anonymous) return [];
  const listed = goesByList(channel, get(textSeats.peek(server)).get(channelId)?.gated)
    ? currentRosterOf(server, channelId)
    : [...onlineById(server).values()];
  return sharersIn(listed, get(userId.peek(server)), get(goneFrom.peek(server)).get(channelId));
}

/**
 * Asks these, or as many of them as the backend picks. Who was asked comes back, as a person
 * is told only that. It rejects when nobody can be asked.
 */
export async function askSharers(server: string, channelId: number, ids: readonly number[]): Promise<number[]> {
  const asked: number[] = await invoke("request_channel_history", { server, channelId, targetUserIds: [...ids] });
  const before = get(handOffs.peek(server)).get(channelId)?.asked ?? [];
  patch(server, channelId, { asked: new Set([...before, ...asked]), asking: true });
  setTimeout(() => {
    if (get(handOffs.peek(server)).get(channelId)?.asking) patch(server, channelId, { asking: false });
  }, ASKING_MS);
  return asked;
}

/** Someone answered, with something or nothing: no ask is out. */
export function handOffAnswered(server: string, channelId: number): void {
  if (get(handOffs.peek(server)).get(channelId)?.asking) patch(server, channelId, { asking: false });
}

/** We left it: if we come back, these may be asked again. */
export function forgetHandOff(server: string, channelId: number): void {
  handOffs.of(server).update((m) => {
    if (!m.has(channelId)) return m;
    const next = new Map(m);
    next.delete(channelId);
    return next;
  });
  clearRing(server, channelId);
}

/** Opened on this device: it keeps the usual number of messages from now on. */
function keepWhole(server: string, channel: ChannelInfo): void {
  noteNeverOpened(server, channel.name, false);
  const key = serverKey(server);
  if (!key || marksChannel(get(uiPrefs).opened_channels[key] ?? [], channel)) return;
  updateUiPrefs((p) => {
    p.opened_channels[key] = [...(p.opened_channels[key] ?? []), stableName(channel)];
  });
}

/**
 * The channel on screen when the connection dropped, back on screen from the new list. Nothing
 * goes out for it, and it is no first opening: asking its sharers is for a person's own click.
 */
export function reopenAfterDrop(server: string, channel: ChannelInfo): void {
  if (get(activeTextChannelId.peek(server)) !== null || get(activeDmUserId.peek(server)) !== null) return;
  const id = channel.channel_id;
  patch(server, id, { reopened: true });
  openTextChannel(server, id);
  setTimeout(() => {
    if (get(activeTextChannelId.peek(server)) === id && !get(joinedTextChannelIds.peek(server)).has(id)) openTextChannel(server, null);
  }, REOPEN_WAITS_MS);
}

/**
 * A followed channel came on screen. On a first opening, or with a ring lit, the sharers not
 * asked yet are asked; a ring with nobody at all left to ask has said what it can, and goes.
 */
export function channelOpened(server: string, channelId: number): void {
  dropOpenedRings(server, channelId);
  openedQuiet(server, channelId);
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  const ringing = get(channelRings.peek(server)).get(channelId) === "lit";
  if (channel) {
    keepWhole(server, channel);
    const lastPost = get(textSeats.peek(server)).get(channelId)?.lastPost ?? 0;
    if (!ringing && lastPost > 0) moveRead(server, channel, lastPost);
  }
  const state = get(handOffs.peek(server)).get(channelId) ?? NO_HAND_OFF;
  if (state.reopened) {
    patch(server, channelId, { opened: true, reopened: false });
    return;
  }
  if (state.opened && !ringing) return;
  patch(server, channelId, { opened: true });
  const left = sharersOf(server, channelId).filter((u) => !state.asked.has(u.user_id));
  if (left.length > 0) {
    const ids = left.map((u) => u.user_id);
    void askSharers(server, channelId, metered() ? [ids[Math.floor(Math.random() * ids.length)]] : ids).catch(() => {});
  } else if (ringing && !state.asking) {
    ringOpened(server, channelId);
  }
}
