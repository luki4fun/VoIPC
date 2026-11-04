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

/** The privileges a group can hand out, in the order the group editor lists
 *  them. A group may hold others (from the server's shell): those show as
 *  they are named. */
export const PRIVILEGES: readonly { scope: string; label: string; hint: string }[] = [
  { scope: "*", label: "Everything (admin)", hint: "Every privilege, and the real names behind anonymous channels" },
  { scope: "voipc:kick", label: "Kick", hint: "Kick people from the server and from any channel" },
  { scope: "voipc:ban", label: "Ban", hint: "Ban people, by address and account" },
  { scope: "voipc:bans", label: "Ban list", hint: "See the ban list, lift bans, ban an account by name" },
  { scope: "voipc:channels", label: "Channels", hint: "Change the settings and gates of the channels they can see; post in announcement channels" },
  { scope: "voipc:emotes", label: "Emotes", hint: "Add, rename and remove the server's emotes and stickers" },
  { scope: "users:read", label: "See accounts", hint: "The account list, an account's groups and history" },
  { scope: "users:admin", label: "Manage accounts", hint: "Give and take groups, reset two-factor codes, make invites" },
  { scope: "roles:admin", label: "Manage groups", hint: "Make, change and delete groups and what they hand out" },
];

/** The admin panel's tabs, and what opens each. */
export const PANEL_SCOPES = ["voipc:bans", "voipc:emotes", "users:read", "users:admin", "roles:admin"] as const;

/** `can(scope)`: the account's scopes, or every scope for an admin (by
 *  token, or holding `*`). The store over it is `can` in stores/account.ts. */
export function canWith(scopes: readonly string[], admin: boolean): (scope: string) => boolean {
  return (scope) => admin || allowed(scopes, scope);
}
