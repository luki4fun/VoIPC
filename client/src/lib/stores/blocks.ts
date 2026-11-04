// Who this person blocked on each server: the lists, and changing them. The
// rules are block-rules.ts. Filled at a connection's start: from `UiPrefs` for a
// guest, and replaced by the vault's when an account signs in (AccountPrompts),
// which hears every change of its list from the backend (`account-blocks`).

import { derived, get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { BLOCK_NAME_MAX, BLOCKS_MAX, blockKey, blockMatch, foldedByBlock, isBlocked, type Who } from "../block-rules.js";
import { rowKey } from "../chat-rules.js";
import type { ChatMessage } from "../types.js";
import { account } from "./account.js";
import { channels } from "./channels.js";
import { addNotification } from "./notifications.js";
import { scoped } from "./scoped.js";
import { serverKey } from "./servers.js";
import { uiPrefs, updateUiPrefs } from "./ui-prefs.js";
import { shortName } from "../username.js";

/** Key -> what to call them (block-rules.ts). Written through `.of(server)` only. */
export const blocked = scoped<Map<string, string>>(() => new Map());

/** Messages shown anyway, by `rowKey`, for as long as this page runs. */
export const revealedRows = writable<ReadonlySet<ChatMessage>>(new Set());

export function revealRow(m: ChatMessage): void {
  revealedRows.update((shown) => new Set(shown).add(rowKey(m)));
}

/** A connection starts: the list a guest keeps on this device. An account's
 *  sign-in replaces it before anything is read. */
export function loadGuestBlocks(server: string): void {
  blocked.of(server).set(new Map(Object.entries(get(uiPrefs).blocked[serverKey(server)] ?? {})));
}

/** What the backends say: on `account-signed-in`, and `account-blocks`. */
export function onAccountBlocks(server: string, entries: [string, string][] | null | undefined): void {
  blocked.of(server).set(new Map(entries ?? []));
}

function setGuestBlock(server: string, key: string, label: string, on: boolean): void {
  const at = serverKey(server);
  const had = get(uiPrefs).blocked[at] ?? {};
  if (on && !(key in had) && Object.keys(had).length >= BLOCKS_MAX) {
    throw new Error(`You can block at most ${BLOCKS_MAX} people here.`);
  }
  updateUiPrefs((p) => {
    const list = { ...had };
    if (on) list[key] = [...label].slice(0, BLOCK_NAME_MAX).join("");
    else delete list[key];
    if (Object.keys(list).length > 0) p.blocked[at] = list;
    else delete p.blocked[at];
  });
  loadGuestBlocks(server);
}

/** Change one entry: a sealed vault item for an account, this device for a guest. */
async function setBlock(server: string, key: string, label: string, on: boolean): Promise<void> {
  if (get(account.peek(server))) await invoke("account_block", { server, key, label, on });
  else setGuestBlock(server, key, label, on);
  // Blocked anew, what was shown from before folds again
  if (on) revealedRows.set(new Set());
}

function couldNot(e: unknown): void {
  addNotification(`Could not change your blocked list: ${String(e).replace(/^Error: /, "")}`, "warning");
}

/** Block someone from their row, or take it back; says so, or why it could not be done. */
export async function toggleBlock(server: string, user: Who & { username: string }): Promise<void> {
  const match = blockMatch(get(blocked.peek(server)), user, false);
  const who = shortName(user.username);
  try {
    await setBlock(server, match ?? blockKey(user), user.username, !match);
    if (match) addNotification(`${who} is no longer blocked`, "info", 3000);
    else if (user.account) addNotification(`You blocked ${who}. They are not told.`, "info");
    else addNotification(`You blocked the guest name ${who}. They are not told, and a new name would get past it.`, "info");
  } catch (e) {
    couldNot(e);
  }
}

/** Take a block back from the list in Settings, where the person may be away. */
export async function unblock(server: string, key: string, label: string): Promise<void> {
  await setBlock(server, key, label, false).catch(couldNot);
}

/** Whether a member row of the server on screen is someone blocked, in the
 *  channel it is listed under. */
export const blockedMember = derived(
  [blocked, channels],
  ([$blocked, $channels]) =>
    (u: Who & { channel_id: number }) =>
      isBlocked($blocked, u, !!$channels.find((c) => c.channel_id === u.channel_id)?.anonymous),
);

const allBlocked = blocked.all();
const allChannels = channels.all();

/** Where a message is, as a chat key names it (`ChatPlace`). */
interface Place {
  kind: "channel" | "dm";
  server: string;
  name: string;
}

/**
 * Whether a message on any open server is folded, for what lists messages from
 * everywhere (search, Settings → Files): what is not shown is not found there
 * either. A server not open says nothing, its list being with its connection.
 */
export const foldedAt = derived(
  [allBlocked, allChannels, revealedRows],
  ([$lists, $channels, $shown]) => {
    const lists = new Map([...$lists].map(([id, list]) => [serverKey(id), { list, channels: $channels.get(id) ?? [] }]));
    return (place: Place, m: ChatMessage) => {
      const at = lists.get(place.server);
      if (!at?.list.size) return false;
      const anonymous = place.kind === "channel" && !!at.channels.find((c) => c.name === place.name)?.anonymous;
      return foldedByBlock(at.list, m, anonymous, $shown);
    };
  },
);
