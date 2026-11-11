// What waits for this app to have joined a text channel (`TextJoined`).
//
// A sealed ask for a channel's history can come before its join: on a one-page account the
// relay answers the page first and then `JoinTextChannels`, so an ask held there always ran
// first, found the channel not one of ours and was dropped with no word (device pass). Each
// waits for its channel's join, a while at most, and is tried again then.

/** Long enough for a connect's joins; an ask older than this has been given up by its asker. */
export const JOIN_WAIT_MS = 15_000;
/** Per server: past this, the oldest goes. */
const MOST = 32;

const waiting = new Map<string, { channel: number; at: number; retry: () => void }[]>();

/** `retry` once `channel` is joined on `server`, if that is soon. */
export function afterJoin(server: string, channel: number, retry: () => void, now = Date.now()): void {
  let list = waiting.get(server);
  if (!list) waiting.set(server, (list = []));
  if (list.length >= MOST) list.shift();
  list.push({ channel, at: now, retry });
}

/** These channels are joined now: what waited for them goes on, what waited too long goes. */
export function joinedNow(server: string, channels: readonly number[], now = Date.now()): void {
  const list = waiting.get(server);
  if (!list) return;
  const due = list.filter((w) => channels.includes(w.channel) && now - w.at <= JOIN_WAIT_MS);
  const rest = list.filter((w) => !channels.includes(w.channel) && now - w.at <= JOIN_WAIT_MS);
  if (rest.length > 0) waiting.set(server, rest);
  else waiting.delete(server);
  for (const w of due) w.retry();
}

/** The connection went: nothing waiting for it is for the next. */
export function dropJoinWaits(server: string): void {
  waiting.delete(server);
}
