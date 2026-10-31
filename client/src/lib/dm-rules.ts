// Direct conversations as the sidebar lists them: the ones the archive keeps
// for a server, whether their person is here, where writing to them goes, and
// in what order they show.
//
// The list of conversations belongs to a connection and starts empty on each
// one, while their messages are kept (stores/chat.ts). Without the archived
// ones listed again, yesterday's conversation could only be read once its
// person wrote again.
//
// Pure, so dm-rules.test.ts can load it under Node's own test runner.

import type { ChatMessage, UserInfo } from "./types.ts";

/** Lines of our own, a hand-off's divider and tombstones: nothing anybody said. */
const NOT_SAID = new Set(["notice", "history-marker", "deleted"]);

/** The newest message somebody actually wrote there. */
export function lastSaid(msgs: ChatMessage[]): ChatMessage | undefined {
  let last: ChatMessage | undefined;
  for (const m of msgs) {
    if (NOT_SAID.has(m.kind ?? "")) continue;
    if (!last || m.timestamp >= last.timestamp) last = m;
  }
  return last;
}

/** The key a conversation is filed under, from an already normalised server
 *  key (`dmKey` in stores/chat.ts, which this must agree with). */
export function dmKeyIn(serverKey: string, name: string): string {
  return serverKey ? `${serverKey}/${name}` : name;
}

/** Where a conversation's "closed" mark is kept: beside its own deletion
 *  watermark, in the same encrypted map (`clearedBefore`). */
export function closeMarkKey(key: string): string {
  return `${key}\u0002`;
}

export interface ArchivedPeer {
  name: string;
  /** Their relay account (hex), from the newest message they wrote with one:
   *  where writing to them goes while they are away. */
  account?: string;
}

/**
 * The people the archive holds a conversation with on one server. Not one
 * made only of our own notices or of what was deleted, and not "Unknown",
 * which is what an echo is filed under when its peer had no name.
 */
export function archivedPeers(dms: Map<string, ChatMessage[]>, serverKey: string): ArchivedPeer[] {
  const prefix = `${serverKey}/`;
  const out: ArchivedPeer[] = [];
  for (const [key, msgs] of dms) {
    if (!serverKey || !key.startsWith(prefix)) continue;
    const name = key.slice(prefix.length);
    if (!name || name === "Unknown" || !lastSaid(msgs)) continue;
    let theirs: ChatMessage | undefined;
    for (const m of msgs) {
      if (m.username === name && m.account && (!theirs || m.timestamp >= theirs.timestamp)) theirs = m;
    }
    out.push(theirs ? { name, account: theirs.account } : { name });
  }
  return out;
}

/**
 * Their user id now, by their exact name, on any list this client may see:
 * our own room and every roster it was told. Absent means "away", which may
 * be wrong — a hidden channel's members are not told — so it never claims
 * more than that.
 */
export function liveIdOf(name: string, users: UserInfo[], rosters: Map<number, UserInfo[]>): number | undefined {
  if (!name) return undefined;
  const here = users.find((u) => u.username === name);
  if (here) return here.user_id;
  for (const list of rosters.values()) {
    const u = list.find((x) => x.username === name);
    if (u) return u.user_id;
  }
  return undefined;
}

/**
 * Where writing goes. "live": to them now, by their id. "kept": they are away,
 * and the server keeps it for their account (both of us need one, and this
 * side cloud copies on). "readonly": nothing can reach them until they are back.
 */
export type Reach = "live" | "kept" | "readonly";

export function reach(userId: number, liveId: number | undefined, account: string | undefined, cloudOn: boolean): Reach {
  if (userId > 0 || liveId !== undefined) return "live";
  return account && cloudOn ? "kept" : "readonly";
}

/** What "away" means, for a row's and the header's tooltip. Away is not
 *  "offline": somebody in a hidden channel is on no list we see. */
export function awayHint(who: string, r: Reach): string {
  return r === "kept"
    ? `${who} is away — messages are kept on the server for them`
    : `${who} is away — you can read, and write when they're back`;
}

export interface ListedRow<T> {
  convo: T;
  /** The newest message written there, for the order and the preview. */
  last: ChatMessage | undefined;
}

/**
 * The rows the sidebar shows, newest conversation first. A closed one stays
 * out until something newer than its close is written there; the one open
 * and one with unread messages always show.
 */
export function listRows<T extends { username: string; unread: number }>(
  rows: T[],
  dms: Map<string, ChatMessage[]>,
  serverKey: string,
  marks: Map<string, number>,
  activeName: string | null,
): ListedRow<T>[] {
  const out: ListedRow<T>[] = [];
  for (const convo of rows) {
    const key = dmKeyIn(serverKey, convo.username);
    const last = lastSaid(dms.get(key) ?? []);
    const closedAt = marks.get(closeMarkKey(key));
    const closed = closedAt !== undefined && (last?.timestamp ?? 0) <= closedAt;
    if (closed && convo.username !== activeName && convo.unread === 0) continue;
    out.push({ convo, last });
  }
  // Stable: two with nothing written keep the order they came in
  return out.sort((a, b) => (b.last?.timestamp ?? 0) - (a.last?.timestamp ?? 0));
}

/** "now", "5m", "3h", "2d", "4w", "1y": how long ago, as short as a row allows. */
export function ago(ts: number, now: number): string {
  const s = Math.max(0, Math.floor((now - ts) / 1000));
  if (s < 60) return "now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d`;
  if (d < 365) return `${Math.floor(d / 7)}w`;
  return `${Math.floor(d / 365)}y`;
}
