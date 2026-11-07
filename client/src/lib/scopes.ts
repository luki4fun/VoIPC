// What this account may do on a relay (1.7): its scopes, as the relay sent
// them in `AccountInfo`, matched the way l4f-accounts matches them
// (`scope::grants`). The relay checks every step itself; this only decides
// what the app offers.
//
// Pure, so scopes.test.ts can load it under Node's own test runner.

/** A scope (no wildcard): lowercase segments joined by `:`. */
function validScope(s: string): boolean {
  return s.length <= 64 && s.split(":").every((seg) => /^[a-z0-9_.-]+$/.test(seg));
}

/** A grant as a role holds it: a scope, `prefix:*`, or `*`. */
function validGrant(s: string): boolean {
  return s === "*" || (s.length <= 64 && validScope(s.endsWith(":*") ? s.slice(0, -2) : s));
}

/** Whether `grant` grants `required`. `links:*` must not grant `linksx`. */
export function grants(grant: string, required: string): boolean {
  if (!validGrant(grant) || !validScope(required)) return false;
  return grant.endsWith("*") ? required.startsWith(grant.slice(0, -1)) : grant === required;
}

/** A relay before 1.7 (protocol 15 and older) names the moderator's
 *  privileges with one scope. */
const BEFORE_1_7: Record<string, readonly string[]> = {
  "voipc:moderate": ["voipc:kick", "voipc:ban", "voipc:channels"],
};

export function allowed(held: readonly string[], required: string): boolean {
  return held.some((g) => grants(g, required) || (BEFORE_1_7[g]?.includes(required) ?? false));
}

/** A privilege by the name the group editor gives it. */
export function privilegeLabel(scope: string): string {
  return scope === "voipc:moderate" ? "Moderator" : (PRIVILEGES.find((p) => p.scope === scope)?.label ?? scope);
}

/** The privilege to share history with newcomers (`types.rs`). */
export const SHARE_HISTORY = "voipc:share_history";

/** Nothing, or only sharing what its holder holds: such a group acts on nobody, needs no
 *  codes and may start a link (`no_power_over_anyone`). */
export function noPowerOverAnyone(scopes: readonly string[]): boolean {
  return scopes.every((s) => s === SHARE_HISTORY);
}

/** The privileges a group can hand out, in the order the group editor lists
 *  them. A group may hold others (from the server's shell): those show as
 *  they are named. `since`: the protocol that brought it, if newer than the
 *  group editor. */
export const PRIVILEGES: readonly { scope: string; label: string; hint: string; since?: number }[] = [
  { scope: "*", label: "Everything (admin)", hint: "Every privilege, and the real names behind anonymous channels" },
  { scope: "voipc:kick", label: "Kick", hint: "Kick people from the server and from any channel they can see" },
  { scope: "voipc:ban", label: "Ban", hint: "Ban people, by address and account, and remove the posts of someone banned" },
  { scope: "voipc:bans", label: "Ban list", hint: "See the ban list, lift bans, ban an account by name, and remove the posts of someone banned" },
  { scope: "voipc:restrict", label: "Restrict", hint: "Mute someone's voice or stop their channel posts for a while", since: 19 },
  { scope: "voipc:hide", label: "Hide messages", hint: "Hide a message from its readers, who can still open it. Only an admin can then kick them or hide what they write", since: 19 },
  { scope: "voipc:reports", label: "Take reports", hint: "Receive what people report. Spares nobody from a kick", since: 19 },
  { scope: "voipc:modlog", label: "Moderation log", hint: "Read who did what to whom. Spares nobody from a kick", since: 19 },
  { scope: "voipc:channels", label: "Channels", hint: "Change the settings and gates of the channels they can see; post in announcement channels; invite people to a room they stand in" },
  { scope: "voipc:profiles", label: "Profiles", hint: "Clear the display name and picture of someone holding no more than they do", since: 18 },
  { scope: "voipc:mention_all", label: "Call on everybody", hint: "Use @everyone, @here and a group's @&badge", since: 18 },
  { scope: SHARE_HISTORY, label: "Share history", hint: "May turn on sharing with newcomers: recent chat when asked, and what they kept before someone joined. Nobody starts sharing until they turn it on themselves. Power over no one, needs no codes, spares nobody from a kick. A modified app is not stopped", since: 21 },
  { scope: "voipc:emotes", label: "Emotes", hint: "Add, rename and remove the server's emotes and stickers" },
  { scope: "users:read", label: "See accounts", hint: "The account list, an account's groups and history" },
  { scope: "users:admin", label: "Manage accounts", hint: "Give and take groups, reset two-factor codes, make invites" },
  { scope: "roles:admin", label: "Manage groups", hint: "Make, change and delete groups and what they hand out" },
];

/** What a relay of protocol `p` can hand out (`null`: our own). It refuses a whole
 *  group whose privileges it has never heard of, so the others are not offered. */
export function privilegesOn(p: number | null): readonly (typeof PRIVILEGES)[number][] {
  return PRIVILEGES.filter((x) => p === null || !x.since || p >= x.since);
}

/** The admin panel's tabs, and what opens each. */
export const PANEL_SCOPES = ["voipc:bans", "voipc:emotes", "users:read", "users:admin", "roles:admin"] as const;

/** `can(scope)`: the account's scopes, or every scope for an admin (by
 *  token, or holding `*`). The store over it is `can` in stores/account.ts. */
export function canWith(scopes: readonly string[], admin: boolean): (scope: string) => boolean {
  return (scope) => admin || allowed(scopes, scope);
}
