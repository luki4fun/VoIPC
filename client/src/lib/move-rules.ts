// The move from Discord, for the panel (AdminMove.svelte): what relay rows and the dry-run
// come to on screen. Pure, so the tests load it under Node.
//
// What the wizard holds is RAM: nothing here reaches settings.json, and a channel's
// choices never reach the relay. Every Discord id is a decimal string: a JS number cannot
// hold one.

import { toHex } from "./hex.ts";
import type { BanInfo, ImportFacts, ImportOptions, ImportUndoCounts, ImportUndone, MoveAccount, MoveFilter, MoveRun, MoveState, PowerRow } from "./types.js";

// ── Active bans, a page at a time ──

/** What `admin-bans-page` carries. */
export interface BanPage {
  search: string;
  offset: number;
  total: number;
  bans: BanInfo[];
}

/** The rows after a page: offset 0 starts the list again. Each id once, whatever comes twice
 *  because the list moved between two pages; the rows are a keyed list. */
export function mergeBanPage(held: readonly BanInfo[], page: BanPage): BanInfo[] {
  const seen = new Set<number>();
  return [...(page.offset === 0 ? [] : held), ...page.bans].filter((b) => {
    if (seen.has(b.id)) return false;
    seen.add(b.id);
    return true;
  });
}

// ── What the importer's commands answer (crates/voipc-import, plan.rs and run.rs) ──

/** The hub's words when it holds no token: after an hour with nothing going, the dry-run went
 *  with it, so only the token step has a way on. `NO_TOKEN` in client/src-tauri/src/import.rs. */
export const NO_TOKEN = "Enter the bot's token again.";

export interface OpenGuild {
  id: string;
  name: string;
  admin: boolean;
}
/** `import_open`: what a token can reach. */
export interface Opening {
  bot_name: string;
  app_id: string;
  member_intent: boolean;
  content_intent: boolean;
  guilds: OpenGuild[];
  invite: string;
}
export interface PlanChannel {
  id: string;
  name: string;
  final_name: string;
  type: number;
  category?: string | null;
  private: boolean;
  private_why: string;
  bot_can_read: boolean;
  messages?: number | null;
  /** An earlier run made it, so `see` and `speak` say what would be made, not what is here. */
  in_ledger: boolean;
  see: { open: boolean; roles: string[] };
  speak: { open: boolean; roles: string[] };
  lossy: string[];
  left_out: boolean;
  left_out_why: string;
  messages_on: boolean;
  messages_why: string;
}
export interface PlanRole {
  id: string;
  name: string;
  members?: number | null;
  power: string[];
  unmapped: string[];
  managed: boolean;
}
export interface PlanWarning {
  level: "info" | "warn" | "red";
  code: string;
  text: string;
}
/** A toggle that cannot be on, or `run`: nothing can start. */
export interface PlanBlock {
  toggle: string;
  text: string;
}
/** `import_plan`: the dry-run. */
export interface Plan {
  guild: { id: string; name: string; members: number; online: number; mfa: boolean; post_channel?: string | null };
  bot: { admin: boolean; member_intent: boolean; content_intent: boolean };
  options: ImportOptions;
  /** An earlier run stands: this one takes new messages only. */
  delta: boolean;
  channels: PlanChannel[];
  categories: { id: string; name: string }[];
  roles: PlanRole[];
  emojis: number;
  stickers: number;
  emote_room: number;
  bans: number;
  threads: { active: number; archived: number; private_skipped: number };
  estimate: { messages: number; at_least: boolean; requests: number; secs_low: number; secs_high: number; bytes: number };
  warnings: PlanWarning[];
  blocks: PlanBlock[];
  report_preview: string[];
}
/** `run::Progress`, and what Discord asked to wait for, in words. */
export interface ImportProgress {
  phase: string;
  done: number;
  /** 0: not known. */
  total: number;
  channel: string;
  waiting?: string | null;
}
/** A run's end. `notes`: all of it, for the screen, and in RAM only: it may name people
 *  and what was left out, so nothing here has a save button. */
export interface ImportEnded {
  run: number;
  /** Why it stopped; null: it finished. Everything stored stays either way. */
  stopped?: string | null;
  notes: string[];
}

// ── The dashboard ──────────────────────────────────────────────────────────

export const MOVE_FILTERS: readonly [MoveFilter, string][] = [
  ["All", "All"],
  ["Waiting", "Waiting to sign in"],
  ["Claimed", "Signed in"],
  ["Banned", "Banned"],
];

/** What the move knows of an account, for its row; null: nothing. */
export function moveChip(state: MoveState): string | null {
  switch (state) {
    case "Waiting":
      return "Waiting to sign in";
    case "Claimed":
      return "Signed in";
    case "Banned":
      return "Banned on Discord";
    default:
      return null;
  }
}

/** A ban that came from Discord can be lifted by whoever is shown the id: `*` only. */
export const canLiftBan = (r: Pick<MoveAccount, "state" | "dc_id">): boolean => r.state === "Banned" && !!r.dc_id;

/** A key for each row, each once: a repeated key stops a keyed each and the panel with it. */
function eachOnce<T>(rows: readonly T[], key: (row: T) => string): T[] {
  const byKey = new Map<string, T>();
  for (const row of rows) byKey.set(key(row), row);
  return [...byKey.values()];
}

export const moveAccountKey = (row: Pick<MoveAccount, "user">): string => toHex(row.user.id);
export const powerKey = (row: Pick<PowerRow, "account" | "group">): string => `${toHex(row.account)}|${row.group}`;

/** What the importer read off Discord, as the wizard's keyed eachs can have it. */
export function openingOnce(o: Opening): Opening {
  return { ...o, guilds: eachOnce(o.guilds, (g) => g.id) };
}

export function planOnce(p: Plan): Plan {
  return { ...p, channels: eachOnce(p.channels, (c) => c.id), roles: eachOnce(p.roles, (r) => r.id) };
}

/** Accounts from the relay, as a keyed each can have them. Browser wasm gives undefined
 *  for a missing value, the desktop null. */
export function moveAccounts(rows: readonly MoveAccount[]): MoveAccount[] {
  return eachOnce(rows, moveAccountKey).map((r) => ({ ...r, dc_id: r.dc_id ?? "", expires_at: r.expires_at ?? 0 }));
}

export function powerRows(rows: readonly PowerRow[]): PowerRow[] {
  return eachOnce(rows, powerKey);
}

/** Runs as the panel holds them, newest first: none of them missing a value it asks about. */
export function moveRuns(rows: readonly MoveRun[]): MoveRun[] {
  return eachOnce(rows, (r) => String(r.id))
    .map((r) => ({ ...r, finished_at: r.finished_at ?? null, undone_at: r.undone_at ?? null }))
    .sort((a, b) => b.id - a.id);
}

export interface ExcludedRow {
  id: string;
  /** They asked for it themselves, by deleting their account. It stays. */
  own: boolean;
  /** Their posts go. Otherwise held: no account, and their posts stay. */
  erase: boolean;
  at: number;
}

export function excludedRows(had: readonly ExcludedRow[], page: readonly [string, boolean, boolean, number][]): ExcludedRow[] {
  return eachOnce(
    [...had, ...page.map(([id, own, erase, at]) => ({ id, own, erase, at }))],
    (r) => r.id,
  );
}

/** What an excluded row is, in words. */
export function excludedLine(r: Pick<ExcludedRow, "own" | "erase">): string {
  if (r.own) return "Deleted their account: stays out for good";
  return r.erase ? "Left out, and their posts deleted" : "Held for now: their posts stay";
}

/** "412 of 1,530 signed in". Banned rows are nobody who can. */
export function signedInLine(s: { claimed: number; waiting: number }): string {
  const all = s.claimed + s.waiting;
  return `${s.claimed.toLocaleString("en-US")} of ${all.toLocaleString("en-US")} signed in`;
}

/** When a waiting account goes, if it does. */
export function expiryText(expiresAt: number, nowMs = Date.now(), locale?: string): string {
  if (!expiresAt) return "Stays until someone removes it";
  const at = expiresAt * 1000;
  if (at <= nowMs) return "Goes at the next sweep";
  return `Goes on ${new Date(at).toLocaleDateString(locale)}`;
}

/** A run, in a few words. */
export function runState(r: Pick<MoveRun, "finished_at" | "undone_at" | "clearing">): string {
  if (r.clearing) return "Being undone";
  if (r.undone_at != null) return "Undone";
  return r.finished_at != null ? "Finished" : "Did not finish";
}

/** What Undo of a run takes along: the relay refuses a run while a later one of that
 *  guild stands, so the panel goes newest first, after one question. */
export function undoChain(runs: readonly MoveRun[], run: number): number[] {
  const picked = runs.find((r) => r.id === run);
  if (!picked) return [];
  return runs
    .filter((r) => r.guild_id === picked.guild_id && r.id >= run && (r.undone_at == null || r.clearing))
    .map((r) => r.id)
    .sort((a, b) => b - a);
}

const counted = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** A run before this one that stays: an undo takes what a run made, and not what it changed
 *  in who holds an earlier run's groups, with no record of which run did that. */
export function earlierStands(runs: readonly MoveRun[], run: number): boolean {
  const picked = runs.find((r) => r.id === run);
  return !!picked && runs.some((r) => r.guild_id === picked.guild_id && r.id < run && r.undone_at == null);
}

/** What goes, said before it goes. */
export function undoSays(all: readonly ImportUndoCounts[], earlier = false): string {
  const sum = (pick: (c: ImportUndoCounts) => number) => all.reduce((n, c) => n + pick(c), 0);
  const channels = sum((c) => c.channels);
  const posts = sum((c) => c.live_posts);
  const parts = [
    channels > 0 ? `${counted(channels, "channel")} and everything written in them since (${counted(posts, "post")})` : "",
    sum((c) => c.groups) > 0 ? counted(sum((c) => c.groups), "group") : "",
    sum((c) => c.placeholders) > 0 ? counted(sum((c) => c.placeholders), "unclaimed account") : "",
    sum((c) => c.archive_rows) > 0 ? `about ${counted(sum((c) => c.archive_rows), "imported message")}` : "",
    sum((c) => c.emotes) > 0 ? counted(sum((c) => c.emotes), "emote") : "",
  ].filter(Boolean);
  const kept = sum((c) => c.claimed_kept);
  const goes = parts.length ? `This takes ${parts.join(", ")}.` : "There is nothing left of it to take.";
  const stay = kept === 1 ? " 1 person who claimed keeps their account and loses those groups." : kept > 1 ? ` ${counted(kept, "person", "people")} who claimed keep their accounts and lose those groups.` : "";
  const runs = all.length > 1 ? ` That is ${all.length} runs, newest first.` : "";
  const groups = earlier ? " Any change it made to who holds an earlier run's groups stays, so check your gates afterwards." : "";
  return `${goes}${stay}${runs}${groups} What a person deleted stays deleted, and a copy from before the run, if you still have one, has the rest.`;
}

export interface UndoTotal {
  channels: number;
  accounts: number;
  kept_claimed: number;
  groups: number;
  groups_kept: string[];
  emotes: number;
}

export const NO_UNDO: UndoTotal = { channels: 0, accounts: 0, kept_claimed: 0, groups: 0, groups_kept: [], emotes: 0 };

/** One call's counts, added up: a call says only what it did. */
export function addUndone(total: UndoTotal, r: ImportUndone): UndoTotal {
  return {
    channels: total.channels + r.channels,
    accounts: total.accounts + r.accounts,
    kept_claimed: total.kept_claimed + r.kept_claimed,
    groups: total.groups + r.groups,
    groups_kept: [...new Set([...total.groups_kept, ...r.groups_kept])],
    emotes: total.emotes + r.emotes,
  };
}

export function undoneLine(t: UndoTotal): string {
  const parts = [
    counted(t.channels, "channel"),
    counted(t.accounts, "account"),
    counted(t.groups, "group"),
    counted(t.emotes, "emote"),
  ].join(", ");
  const kept = t.groups_kept.length ? ` Kept, because a gate elsewhere uses them: ${t.groups_kept.join(", ")}.` : "";
  return `${parts} gone so far. Imported messages go from the disk soon after.${kept}`;
}

/** An undo that stopped with runs still to go, by a refusal, a cut or a press. */
export function undoLeftLine(left: { runs: readonly number[]; cut: boolean }): string {
  const lost = left.cut ? "The connection to the server was lost. " : "";
  return `${lost}Undo stopped with ${counted(left.runs.length, "run")} not finished. Each run's row says how far it got.`;
}

/** The report the relay keeps: counts and notes about what was imported. */
export function storedReport(text: string): { counts: [string, number][]; notes: string[] } {
  try {
    const r = JSON.parse(text) as { counts?: Record<string, unknown>; notes?: unknown };
    const counts = Object.entries(r.counts ?? {}).filter((e): e is [string, number] => typeof e[1] === "number");
    const notes = Array.isArray(r.notes) ? r.notes.filter((n): n is string => typeof n === "string") : [];
    return { counts, notes };
  } catch {
    return { counts: [], notes: [] };
  }
}

// ── The toggles ────────────────────────────────────────────────────────────

export type ToggleKey = Exclude<keyof ImportOptions, "acknowledged">;

export const TOGGLES: readonly { key: ToggleKey; label: string; hint: string }[] = [
  { key: "channels", label: "Channels and categories", hint: "In Discord's order, with their topics" },
  { key: "permissions", label: "Who may enter them", hint: "Discord's permissions, as gates" },
  { key: "roles", label: "Roles, as groups", hint: "Badges and colours. Power waits for your OK" },
  { key: "members", label: "Members and their roles", hint: "A waiting account each. Anyone holding that Discord login claims it" },
  { key: "bans", label: "Bans", hint: "By Discord id only: no names and no reasons are kept" },
  { key: "emotes", label: "Emotes and stickers", hint: "As many as there is room for" },
  { key: "messages", label: "Messages", hint: "Read by this server, labelled as imported" },
  { key: "threads", label: "Threads", hint: "Read only, in the archive pane. Private threads never move" },
  { key: "pins", label: "Pins", hint: "Which messages were pinned" },
  { key: "reactions", label: "Reactions", hint: "How many, never who" },
  { key: "anonymise", label: "Anonymise ex-members", hint: "Their name and id stay on this machine. What they wrote still comes" },
];

/** What needs what: as `plan::effective`, or each frame would be refused for a channel that
 *  is not there. A toggle off takes those that need it with it, and they are shown so. */
export function effectiveOptions(o: ImportOptions): ImportOptions {
  const messages = o.messages && o.channels;
  return {
    ...o,
    messages,
    permissions: o.permissions && o.channels,
    threads: o.threads && messages,
    pins: o.pins && messages,
    reactions: o.reactions && messages,
  };
}

/** Why a toggle cannot be on, from what the dry-run found or a toggle it needs. */
export function toggleBlock(key: ToggleKey, o: ImportOptions, blocks: readonly PlanBlock[]): string | null {
  const blocked = blocks.find((b) => b.toggle === key)?.text;
  if (blocked) return blocked;
  if ((key === "messages" || key === "permissions") && !o.channels) return "Needs channels.";
  if ((key === "threads" || key === "pins" || key === "reactions") && !effectiveOptions(o).messages) return "Needs messages.";
  return null;
}

/** What the wizard's step 3 holds. The sets go to `import_run` and stop there. */
export interface MoveChoices {
  options: ImportOptions;
  /** Channels left out: nothing about them reaches the relay. */
  leftOut: Set<string>;
  /** Channels whose messages come: a list of yes, so a channel missing from it stays on Discord. */
  messagesOn: Set<string>;
}

/** Where the toggles start: the dry-run's own answer, and never with the tick given. */
export function startChoices(plan: Plan): MoveChoices {
  const blocked = new Set(plan.blocks.map((b) => b.toggle));
  const options = { ...plan.options, acknowledged: false };
  for (const t of TOGGLES) if (blocked.has(t.key)) options[t.key] = false;
  return {
    options,
    leftOut: new Set(plan.channels.filter((c) => c.left_out).map((c) => c.id)),
    messagesOn: new Set(plan.channels.filter((c) => c.messages_on).map((c) => c.id)),
  };
}

/** What `ImportBegin` and `import_run` are given. */
export function optionsToSend(c: MoveChoices, acknowledged: boolean): ImportOptions {
  return { ...effectiveOptions(c.options), acknowledged };
}

export function choicesToSend(c: MoveChoices, acknowledged: boolean) {
  return { options: optionsToSend(c, acknowledged), left_out: [...c.leftOut], messages_on: [...c.messagesOn] };
}

/** What a row says of its gate when it came in an earlier run. `see` is what Discord says now,
 *  and the relay leaves a gate it holds alone. What is not in the ledger starts with its
 *  messages off for `private_why`, or for a bot that cannot read it: `start_of` in plan.rs. */
export function gateHereLine(c: Pick<PlanChannel, "in_ledger" | "see" | "bot_can_read">): string {
  if (!c.in_ledger || c.see.open || !c.bot_can_read) return "";
  return "Its gate here stays as it is. While that is open, its new messages stay on Discord: give it a gate, then run again.";
}

/** Why Run stays shut, or null. The relay holds to the same: a tick asked for here is
 *  also asked for of the run it stored. */
export function beginBlock(
  c: MoveChoices,
  plan: Plan,
  facts: ImportFacts,
  acknowledged: boolean,
  backupTaken: boolean,
): string | null {
  const run = plan.blocks.find((b) => b.toggle === "run");
  if (run) return run.text;
  if (facts.running != null) return "Another admin's import is running here.";
  if (effectiveOptions(c.options).messages && !facts.cloud) return "This server keeps no messages: set cloud = true first, or turn messages off.";
  if (effectiveOptions(c.options).messages && !acknowledged) return "Tick what copying messages means, above.";
  if (!facts.backup_here && !backupTaken) return "Say that you have made a copy of the database, above.";
  return null;
}

/** Discord ids typed one to a line, for leaving someone out before they are ever read.
 *  What fits a relay's id only: `bad` is what could not be one. */
export function discordIds(text: string): { ids: string[]; bad: string[] } {
  const words = text.split(/[\s,]+/).filter(Boolean);
  const ok = (w: string) => /^[1-9]\d{0,18}$/.test(w) && BigInt(w) <= 9_223_372_036_854_775_807n;
  return { ids: [...new Set(words.filter(ok))], bad: words.filter((w) => !ok(w)) };
}

/** One Discord id, or null. */
export function discordId(text: string): string | null {
  const { ids, bad } = discordIds(text);
  return ids.length === 1 && bad.length === 0 ? ids[0] : null;
}

/** A list of ids that stopped before its end. Who was refused, if one was, stays out of the
 *  box: pressing again would only hear the same. What did not go is back in it. */
export function idsBackLine(refused: { id: string; reason: string } | null, unsent: number): string {
  const back = unsent === 1 ? "1 id was not sent: it is back in the box." : `${counted(unsent, "id")} were not sent: they are back in the box.`;
  if (!refused) return back;
  const who = `Discord id ${refused.id} was refused. ${refused.reason}`;
  return unsent > 0 ? `${who} ${back}` : who;
}

/** When a list asks again, for one that shares its store with someone else's (the Users tab
 *  and the dashboard): a page for another filter took the place of its own, which had come.
 *  Not while its own is on its way, which would ask twice on a change of filter, and never
 *  for the answer to itself, which could go round for ever. */
export function ownPage<T extends { filter: MoveFilter }>() {
  let asked: T | null = null;
  let came = false;
  return {
    /** What was asked for just now; null: nothing this watches. */
    asking(ask: T | null): void {
      asked = ask;
      came = false;
    },
    /** A page for this filter has come. What to ask for again, or null. */
    page(filter: MoveFilter): T | null {
      if (!asked) return null;
      if (filter === asked.filter) {
        came = true;
        return null;
      }
      if (!came) return null;
      came = false;
      return asked;
    },
  };
}

/** Sizes as the dry-run's estimate gives them. */
export function humanBytes(n: number): string {
  const units = ["bytes", "KiB", "MiB", "GiB", "TiB"];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit + 1 < units.length) {
    value /= 1024;
    unit++;
  }
  return unit === 0 ? `${n} bytes` : `${value.toFixed(1)} ${units[unit]}`;
}

export function humanTime(secs: number): string {
  if (secs < 90) return `${Math.max(1, Math.round(secs))} seconds`;
  if (secs < 5400) return `${Math.round(secs / 60)} minutes`;
  if (secs < 129_600) return `${Math.round(secs / 3600)} hours`;
  return `${Math.round(secs / 86_400)} days`;
}

/** The dry-run's estimate, in a line. */
export function estimateLine(e: Plan["estimate"]): string {
  const about = e.at_least ? "at least " : "";
  return `${about}${e.messages.toLocaleString("en-US")} messages, ${humanTime(e.secs_low)} to ${humanTime(e.secs_high)}, about ${humanBytes(e.bytes)} on this server's disk.`;
}

/** What a run says of itself while it goes. Counts and a channel's name, never anything anyone wrote. */
export function progressLine(p: ImportProgress): string {
  const of = p.total > 0 ? ` of ${p.total.toLocaleString("en-US")}` : "";
  const where = p.channel ? `, ${p.channel}` : "";
  return `${p.phase[0]?.toUpperCase() ?? ""}${p.phase.slice(1)}: ${p.done.toLocaleString("en-US")}${of}${where}`;
}

// ── Words ──────────────────────────────────────────────────────────────────

export const POLICY_URL = "https://discord.com/developers/docs/policies-and-agreements/developer-policy";

/** The acknowledgement, here and in MOVING.md. */
export const ACKNOWLEDGEMENT =
  'This copies your members\' messages out of Discord to this server, which can read them. Discord\'s Terms forbid "scraping our services without our written consent", and its Developer Policy has a rule against mining or scraping; read the current policy. Discord may act against your bot or your account. Members\' messages are their personal data: you answer for telling them and for the law where you are. This is not legal advice.';

/** Whether any message came by these choices: the toggle on is not enough, with every
 *  channel's turned off or left out. */
export function messagesCame(c: MoveChoices): boolean {
  return effectiveOptions(c.options).messages && [...c.messagesOn].some((id) => !c.leftOut.has(id));
}

/** What the post says first. It has to say what happened to the messages, or the first some
 *  members hear of it is the post being gone. Only what this run did: `took` is its options. */
export function movePostText(publicUrl: string, took: Pick<ImportOptions, "messages" | "members">): string {
  const lines = [
    "**We are moving to VoIPC.**",
    "",
    `Join here: ${publicUrl}`,
    `${CHOOSE_LINE}${took.members ? ": your name and groups are waiting." : "."}`,
    ...(took.messages
      ? [
          "",
          "Our message history from this server has been copied there. Whoever runs that server can read it, and it is marked as imported. Once you have signed in you can hide or delete your own posts. Direct messages and files do not move.",
        ]
      : []),
  ];
  return lines.join("\n");
}

const CHOOSE_LINE = "Choose *Continue with Discord*";
const JOIN_LINE = "New here? ";

/** The post with its line for newcomers, or without: the rest may have been edited, and stays. */
export function withJoinLine(text: string, joinLink: string | null): string {
  const lines = text.split("\n").filter((l) => !l.startsWith(JOIN_LINE));
  if (joinLink) {
    const choose = lines.findIndex((l) => l.startsWith(CHOOSE_LINE));
    lines.splice(choose < 0 ? lines.length : choose + 1, 0, `${JOIN_LINE}${joinLink}`);
  }
  return lines.join("\n");
}

/** A link's code that came after it was asked for. One already on hand is someone's from the
 *  Users tab, for however few people and days they chose there. */
export function newLinkCode(code: string | null, before: string | null): string | null {
  return code && code !== before ? code : null;
}

/** Discord's limit on a post. */
export const MOVE_POST_CHARS = 2000;

export function postable(text: string): boolean {
  const n = [...text].length;
  return n > 0 && n <= MOVE_POST_CHARS;
}

/** Where a post can go: text channels here, not one of the private ones. */
export function postChannels(plan: Plan): PlanChannel[] {
  return plan.channels.filter((c) => (c.type === 0 || c.type === 5) && !c.private);
}

/** Where a post starts: the server's rules or system channel, if a post can go there. */
export function postChannelOf(plan: Plan): string {
  const can = postChannels(plan);
  return can.find((c) => c.id === plan.guild.post_channel)?.id ?? can[0]?.id ?? "";
}
