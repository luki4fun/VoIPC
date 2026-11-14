// Display names and pictures (1.9), by account: names asked for once at connect for everyone
// on this device, then as they first appear, pictures as rows come on screen, all at a pace the
// relay's `profile_rate` allows, and told again when one changes.
//
// A picture here is only ever the sanitizer's PNG. What a relay sends is somebody
// else's file, and goes through `prepareEmote` before anything may draw it.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { prepareEmote } from "../emote-import.ts";
import { fromHex, toHex } from "../hex.ts";
import { pictureUrl } from "../media.ts";
import { cleanDisplayName, MAX_PICTURE_BYTES, SANITIZE_ONLY_BYTES, type WireProfile } from "../profile-rules.ts";
import { scoped } from "./scoped.ts";

export interface Profile {
  name: string | null;
  /** The picture's hash, in hex. */
  picture: string | null;
}

/** By account (hex). */
export const profiles = scoped<Map<string, Profile>>(() => new Map());

/** Sanitized pictures as `blob:` URLs, by `pictureKey`. Kept for the page: one per
 *  picture per server, and a reconnect asks for none of them again. */
export const pictures = writable<Map<string, string>>(new Map());

export const pictureKey = (server: string, hash: string) => `${server}|${hash}`;

/** About 130 MB at the most a 128 × 128 PNG can take. */
const MAX_PICTURES = 2000;
/** 8 a second, under the relay's 10. One message each. */
const PUMP_MS = 125;
const BATCH = 64;

interface Asking {
  accounts: Set<string>;
  hashes: Set<string>;
  asked: Set<string>;
  timer: ReturnType<typeof setInterval> | null;
}
const asking = new Map<string, Asking>();

function asker(server: string): Asking {
  let a = asking.get(server);
  if (!a) {
    a = { accounts: new Set(), hashes: new Set(), asked: new Set(), timer: null };
    asking.set(server, a);
  }
  return a;
}

function pump(server: string, a: Asking) {
  if (a.accounts.size > 0) {
    const accounts = [...a.accounts].slice(0, BATCH);
    accounts.forEach((x) => a.accounts.delete(x));
    invoke("profiles_get", { server, accounts: accounts.map(fromHex) }).catch(() => {});
  } else if (a.hashes.size > 0) {
    const [hash] = a.hashes;
    a.hashes.delete(hash);
    invoke("profile_picture_get", { server, hash: fromHex(hash) }).catch(() => {});
  } else if (a.timer !== null) {
    clearInterval(a.timer);
    a.timer = null;
  }
}

function start(server: string, a: Asking) {
  a.timer ??= setInterval(() => pump(server, a), PUMP_MS);
}

export function askProfile(server: string, account: string): void {
  const a = asker(server);
  if (!server || a.asked.has(account)) return;
  a.asked.add(account);
  a.accounts.add(account);
  start(server, a);
}

/**
 * Many at once, in an order of their own: a page of these says who is on this device, not in
 * which channel, as their names asked when drawn would.
 */
export function askProfiles(server: string, accounts: Iterable<string>): void {
  if (!server) return;
  const a = asker(server);
  for (const account of [...new Set(accounts)].sort()) {
    if (a.asked.has(account)) continue;
    a.asked.add(account);
    a.accounts.add(account);
  }
  if (a.accounts.size > 0) start(server, a);
}

export function askPicture(server: string, hash: string): void {
  const a = asker(server);
  const key = `picture:${hash}`;
  if (!server || a.asked.has(key) || get(pictures).has(pictureKey(server, hash))) return;
  a.asked.add(key);
  a.hashes.add(hash);
  start(server, a);
}

/**
 * An answer, or a change the relay sends everyone connected (`profile::tell`). Kept only for
 * an account this page shows or asked about: drawing a name asks for it first, and a page
 * keeps no list of every account on the server.
 */
export function onProfiles(server: string, list: WireProfile[]): void {
  const asked = asking.get(server)?.asked;
  profiles.of(server).update((m) => {
    const next = new Map(m);
    for (const p of list) {
      const key = toHex(p.account);
      if (!next.has(key) && !asked?.has(key)) continue;
      next.set(key, {
        name: cleanDisplayName(p.name),
        picture: p.picture ? toHex(p.picture) : null,
      });
    }
    return next;
  });
}

export async function onPicture(server: string, hash: number[], image: number[]): Promise<void> {
  if (image.length === 0 || image.length > MAX_PICTURE_BYTES) return;
  // Only what was asked for, and once: a relay could otherwise keep the sanitizer
  // busy, and fill this page with pictures nobody will see
  const hex = toHex(hash);
  const a = asking.get(server);
  if (!a?.asked.delete(`picture:${hex}`)) return;
  a.hashes.delete(hex);
  try {
    const made = await prepareEmote(Uint8Array.from(image), false, SANITIZE_ONLY_BYTES);
    const png = made.still ?? made.preview;
    const url = pictureUrl(png);
    pictures.update((m) => {
      const key = pictureKey(server, hex);
      const had = m.get(key);
      if (had) URL.revokeObjectURL(had);
      const next = new Map(m).set(key, url);
      // Someone changing theirs over and over: the oldest goes back to initials
      if (next.size > MAX_PICTURES) {
        const [oldest, was] = next.entries().next().value as [string, string];
        next.delete(oldest);
        URL.revokeObjectURL(was);
      }
      return next;
    });
  } catch {
    // Not a picture after all: the initials stay
  }
}

export interface ServerProfile {
  name: string;
  description: string;
  /** The icon's hash, in hex: a picture like any other. */
  icon: string | null;
}

/** What a server calls itself. Never kept: bookmarks stay the person's own words. */
export const serverProfile = scoped<ServerProfile | null>(() => null);

export function onServerProfile(
  server: string,
  p: { name?: unknown; description?: unknown; icon?: number[] | null },
): void {
  const icon = p.icon ? toHex(p.icon) : null;
  serverProfile.of(server).set({
    name: typeof p.name === "string" ? p.name : "",
    description: typeof p.description === "string" ? p.description : "",
    icon,
  });
  if (icon) askPicture(server, icon);
}

/** A connection's questions die with it; a new one asks for names again, which may
 *  have changed meanwhile. */
export function clearProfiles(server: string): void {
  const a = asking.get(server);
  if (a?.timer != null) clearInterval(a.timer);
  asking.delete(server);
}

/** Set our own, or clear them: the answers are `ProfileDone` and a `Profiles`. */
export const setDisplayName = (server: string, name: string | null) =>
  invoke("account_request", { server, request: { ProfileSet: { name } } });

export const setProfilePicture = (server: string, image: Uint8Array | null) =>
  invoke("account_request", {
    server,
    request: { ProfilePictureSet: { image: image ? [...image] : null } },
  });
