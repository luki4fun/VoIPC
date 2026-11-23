// What each channel's group key says (plan 3h), per server and by channel id. Filled from the
// `gk-*` events that `gkListeners` names, for App.svelte's `listenServer`; ChatPanel draws the
// lines (gk-rules.ts), the member list the keyholders. Gone with the connection, as the ids are.

import { get } from "svelte/store";
import { channels } from "./channels.js";
import { addNotification } from "./notifications.js";
import { scoped } from "./scoped.js";
import {
  dismissed,
  emptyGk,
  unlistedLine,
  withAnew,
  withDropped,
  withHolders,
  withReaders,
  withState,
  withWarning,
  type GkAnew,
  type GkChannel,
  type GkKeyholders,
  type GkPostDropped,
  type GkReaders,
  type GkState,
  type GkWarning,
} from "../gk-rules.js";

export const gkChannels = scoped<Map<number, GkChannel>>(() => new Map());

function apply(server: string, channelId: number, step: (ch: GkChannel) => GkChannel): void {
  gkChannels.of(server).update((all) => new Map(all).set(channelId, step(all.get(channelId) ?? emptyGk())));
}

/** Each event's name and its handler. */
export const gkListeners = {
  "gk-state": (server: string, e: GkState) => apply(server, e.channel_id, (ch) => withState(ch, e)),
  "gk-post-dropped": (server: string, e: GkPostDropped) => apply(server, e.channel_id, (ch) => withDropped(ch, e)),
  "gk-readers": (server: string, e: GkReaders) => apply(server, e.channel_id, (ch) => withReaders(ch, e)),
  "gk-keyholders": (server: string, e: GkKeyholders) => apply(server, e.channel_id, (ch) => withHolders(ch, e)),
  "gk-anew": (server: string, e: GkAnew) => apply(server, e.channel_id, (ch) => withAnew(ch, e)),
  "gk-warning": (server: string, e: GkWarning) => {
    // A channel no longer listed shows its lines in no chat: said on its own, until closed
    const listed = get(channels.of(server)).some((c) => c.channel_id === e.channel_id);
    const alone = listed ? null : unlistedLine(e);
    if (alone) addNotification(alone, "warning", 0);
    else apply(server, e.channel_id, (ch) => withWarning(ch, e));
  },
};

/** Waves off one of a channel's lines (`GkLine.key`). */
export function dismissGk(server: string, channelId: number, key: string): void {
  apply(server, channelId, (ch) => dismissed(ch, key));
}
