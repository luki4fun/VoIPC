// Who this person blocked, and what that does to what they see and hear.
//
// A block is a view: it changes this person's screen and speakers and nothing
// else. Every message is still received and kept, so unblocking brings it all
// back and what they hand on to others stays the same. The relay and the blocked
// person are told nothing: never a declined invite, a refused message, an audio
// filter or a refused request for history, each of which would say so.
//
// A list is `key -> what to call them`, per server: `a:<hex>` for an account and
// `g:<lowercase name>` for a guest, who has nothing but a name. Never a user id,
// which is one connection's. Accounts keep it sealed in their vault (sync.rs
// `Blocks`), guests in `UiPrefs.blocked`, on this device.
//
// Pure, so block-rules.test.ts runs it under Node's own test runner.

import { foldedByHide, hiddenLine, rowKey } from "./chat-rules.ts";
import { toHex } from "./hex.ts";
import type { ChatMessage } from "./types.ts";

/** The most people a list holds (sync.rs `BLOCKS_MAX`). */
export const BLOCKS_MAX = 200;
/** The characters kept of a name (sync.rs `BLOCK_NAME_MAX`). */
export const BLOCK_NAME_MAX = 64;

/** What a message from someone blocked says instead of itself. */
export const BLOCKED_LINE = "Message from someone you blocked";

export type BlockList = ReadonlyMap<string, string>;

/** A person, on a roster (`account` in bytes) or as a message names them (in
 *  hex). Browser wasm gives undefined for no account, the desktop null. */
export interface Who {
  account?: number[] | string | null;
  username?: string;
}

const hexOf = (account: number[] | string) => (typeof account === "string" ? account : toHex(account));

/** The key that blocks `who`: the account where there is one, else the name. */
export function blockKey(who: Who): string {
  return who.account ? `a:${hexOf(who.account)}` : `g:${(who.username ?? "").toLowerCase()}`;
}

/**
 * The entry of `list` that says `who` is blocked, if any.
 *
 * Nothing in an anonymous channel, whatever its roster or a message's tag says:
 * a block there would tell who is behind a pseudonym. The channel's anonymity is
 * always passed in, because a row can carry an account there (an admin's view).
 *
 * By account where we know one, so another account under a blocked guest's name
 * goes free. Without one (a live message from someone on no list we see, an
 * invite, which carries only a name) by the name, against guests and against
 * what the accounts on the list go by: on an honest relay with accounts, a guest
 * cannot take an account's name.
 */
export function blockMatch(list: BlockList, who: Who, anonymous: boolean): string | undefined {
  if (anonymous || list.size === 0) return undefined;
  if (who.account) {
    const key = `a:${hexOf(who.account)}`;
    return list.has(key) ? key : undefined;
  }
  const name = (who.username ?? "").toLowerCase();
  if (!name) return undefined;
  const guest = `g:${name}`;
  if (list.has(guest)) return guest;
  for (const [key, label] of list) {
    if (key.startsWith("a:") && label.toLowerCase() === name) return key;
  }
  return undefined;
}

export function isBlocked(list: BlockList, who: Who, anonymous: boolean): boolean {
  return blockMatch(list, who, anonymous) !== undefined;
}

/**
 * Whether a row shows `BLOCKED_LINE`: written by someone blocked, and not shown
 * anyway (`revealed` holds `rowKey`s). A line of our own or a tombstone says
 * nothing of theirs.
 */
export function foldedByBlock(
  list: BlockList,
  m: ChatMessage,
  anonymous: boolean,
  revealed: ReadonlySet<ChatMessage>,
): boolean {
  if (m.kind === "notice" || m.kind === "history-marker" || m.kind === "deleted") return false;
  return isBlocked(list, m, anonymous) && !revealed.has(rowKey(m));
}

/** When the last row a block does not fold was written: someone blocked brings no news. */
export function newestUnfolded(
  list: BlockList,
  messages: readonly ChatMessage[],
  anonymous: boolean,
  revealed: ReadonlySet<ChatMessage>,
): number {
  return messages.findLast((m) => !foldedByBlock(list, m, anonymous, revealed))?.timestamp ?? 0;
}

/** What a row says instead of itself, or null where it shows itself: a moderator's
 *  hide first, which says more than that its writer is blocked here. */
export function foldedLine(
  list: BlockList,
  m: ChatMessage,
  anonymous: boolean,
  revealed: ReadonlySet<ChatMessage>,
): string | null {
  if (foldedByHide(m, revealed)) return hiddenLine(m);
  return foldedByBlock(list, m, anonymous, revealed) ? BLOCKED_LINE : null;
}

export interface SilenceChange {
  id: number;
  on: boolean;
}

/**
 * Who in a call to silence or give back, from who stands there now and the ids
 * already silenced (`silencedIds` in mixer.ts). By the account, so somebody who
 * reconnects under a new id is caught; somebody who left is given back, since
 * their id means nobody to the mixer until they return.
 *
 * In an anonymous room nobody is silenced, and whoever was is given back: going
 * quiet for one pseudonym would tell who it is.
 */
export function silenceChanges(
  people: readonly (Who & { user_id: number })[],
  list: BlockList,
  anonymous: boolean,
  silenced: ReadonlySet<number>,
): SilenceChange[] {
  const out: SilenceChange[] = [];
  const here = new Set<number>();
  for (const u of people) {
    here.add(u.user_id);
    const want = isBlocked(list, u, anonymous);
    if (want !== silenced.has(u.user_id)) out.push({ id: u.user_id, on: want });
  }
  for (const id of silenced) {
    if (!here.has(id)) out.push({ id, on: false });
  }
  return out;
}
