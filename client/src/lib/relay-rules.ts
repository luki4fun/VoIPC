// What the app holds back on a relay of an older protocol (1.6). The relay's
// protocol stands in for its members' apps: each of them speaks it, or talks
// down to it as this one does. `null` is a relay of our own protocol.
// Pure, for relay-rules.test.ts.

/** Edits, deletes, reactions, pins and forwards (protocol 13). A 1.0 app
 *  shows each event as "a message from a newer VoIPC", and a forward as the
 *  forwarder's own words. */
export function chatEvents(p: number | null): boolean {
  return p === null || p >= 13;
}

/** Hex digits of an emote token: a 1.4 app reads only 20. */
export function emoteTokenHex(p: number | null): number {
  return p === null || p >= 15 ? 32 : 20;
}

/** Moving emotes between packs, or between emote and sticker (protocol 15). */
export function packMoves(p: number | null): boolean {
  return p === null || p >= 15;
}

/** A new recovery key (protocol 13). */
export function newRecoveryKey(p: number | null): boolean {
  return p === null || p >= 13;
}

/** What a relay answers `TotpEnable` for an account with no password and no fresh proof
 *  (protocol 20). The same code goes again once a provider has said it's them. */
export const PROVE_FIRST = "Confirm it's you with a provider you have linked first.";

/** Users, groups and channel gates in the admin panel (protocol 16). */
export function adminOps(p: number | null): boolean {
  return p === null || p >= 16;
}

/** What 1.9 brought (protocol 18): channels made in the app, categories, a welcome
 *  channel, group colours, display names and pictures, a server's name, invite links. */
export function community(p: number | null): boolean {
  return p === null || p >= 18;
}

/** What 1.10 brought (protocol 19): mute and timeouts, hiding messages, summons,
 *  the moderation log, reports. */
export function moderation(p: number | null): boolean {
  return p === null || p >= 19;
}

/** What 1.11 brought (protocol 20): the move from Discord, its dashboard, and the
 *  archive of what came from there. */
export function moves(p: number | null): boolean {
  return p === null || p >= 20;
}

/** What the banner names as off on a relay of protocol `p`. */
export function missing(p: number | null): string[] {
  if (p === null) return [];
  const off: string[] = [];
  if (p < 13) off.push("files");
  if (p < 14) off.push("emotes");
  if (p < 13) off.push("edits, reactions, pins, forwards", "a new recovery key");
  if (p === 14) off.push("moving emotes between packs");
  if (p < 16) off.push("users, groups and channel gates");
  if (p < 17) off.push("sign-in with a provider");
  if (p < 18) off.push("channels made in the app, display names and pictures, invite links, @everyone");
  if (p < 19) off.push("mute and timeouts, hiding messages, summons, the moderation log, reports");
  if (p < 20) off.push("the move from Discord and its archive");
  return off;
}

/** The banner, or null on a relay of our own protocol: a short head, and
 *  what is off there until its operator updates. */
export function relayBanner(r: { protocol: number; version: string } | null): { head: string; off: string } | null {
  if (!r) return null;
  const off = missing(r.protocol);
  return {
    head: `This server runs VoIPC ${r.version}`,
    off: off.length ? `Off until it updates: ${off.join("; ")}.` : "",
  };
}
