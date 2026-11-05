// The Discord move, for the admin panel: what its dashboard shows, the wizard on a desktop,
// and Undo, which goes on for as long as the relay says there is more.
//
// Each server's own, written through `.of`, and only in memory: a run's plan, its choices
// and its report stay in RAM and are gone with the page. The wizard's outlive a cut, so a
// run can go on. The token never comes here: the page hands it to `import_open` and clears
// its field.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { listenServer } from "../connect.js";
import {
  NO_TOKEN,
  NO_UNDO,
  addUndone,
  choicesToSend,
  earlierStands,
  excludedRows,
  idsBackLine,
  moveAccounts as cleanAccounts,
  moveRuns,
  openingOnce,
  optionsToSend,
  planOnce,
  powerRows,
  startChoices,
  undoChain,
  undoSays,
  type ExcludedRow,
  type ImportEnded,
  type ImportProgress,
  type MoveChoices,
  type Opening,
  type Plan,
  type UndoTotal,
} from "../move-rules.js";
import { adminOp, adminRead, codeAskedAgain } from "./admin-ops.js";
import { confirmAction } from "./confirm.js";
import { connectionState } from "./connection.js";
import { importedChanged } from "./imported.js";
import { scoped } from "./scoped.js";
import type { AdminReply, ImportFacts, ImportUndoCounts, MoveAccount, MoveFilter, MoveStatus, PowerRow } from "../types.js";

export interface MoveAccountsPage {
  search: string;
  offset: number;
  filter: MoveFilter;
  total: number;
  rows: MoveAccount[];
}
export interface PowerPage {
  offset: number;
  total: number;
  rows: PowerRow[];
}
export interface ExcludedPage {
  rows: ExcludedRow[];
  more: boolean;
}
export interface UndoView {
  /** Runs still to go, newest first; the first is the one going. */
  runs: number[];
  total: UndoTotal;
  /** All of them are gone. */
  done: boolean;
}

export const moveStatus = scoped<MoveStatus | null>(() => null);
export const moveAccountsPage = scoped<MoveAccountsPage | null>(() => null);
export const powerPage = scoped<PowerPage | null>(() => null);
export const excludedPage = scoped<ExcludedPage | null>(() => null);
/** Outlives a cut for as long as it takes to say so: `wizardCut`. */
export const moveUndo = scoped<UndoView | null>(() => null, { kept: true });
/** The runs an undo stopped short of. A cut closes the panel, and it is still to be said. */
export const moveUndoLeft = scoped<{ runs: number[]; cut: boolean } | null>(() => null, { kept: true });
/** A kept report, opened from a run's row. */
export const moveReport = scoped<{ run: number; report: string } | null>(() => null);

export type WizardStep =
  | "idle"
  | "token"
  /** Asking Discord what the token reaches. */
  | "opening"
  /** Which of its servers. */
  | "pick"
  /** The dry-run: `ImportFacts`, then `import_plan`. */
  | "reading"
  | "choose"
  /** `ImportBegin` out, with its code and the copy of the database. */
  | "beginning"
  | "running"
  | "ended";

export interface Wizard {
  step: WizardStep;
  opening: Opening | null;
  guild: string;
  facts: ImportFacts | null;
  plan: Plan | null;
  choices: MoveChoices | null;
  acknowledged: boolean;
  backupTaken: boolean;
  run: number | null;
  /** The relay is copying its database: a label only, `ImportBegun` is what counts. */
  backingUp: boolean;
  resumed: boolean;
  backup: string | null;
  progress: ImportProgress | null;
  ended: ImportEnded | null;
  /** The connection went under a run: its end says that, whatever stopped it. */
  cut: boolean;
  error: string;
  /** The box of ids to leave out. Here, since what it holds has not gone and a cut closes the panel. */
  idBox: string;
  /** Those of them with no answer yet, oldest first, the first one out. */
  leaving: string[];
  /** What became of them if they stopped short. Said beside the box as well as at the top:
   *  a press there is far from the top, and a prompt or a cut brings the panel back to it. */
  idsSaid: string;
}

function noWizard(): Wizard {
  return {
    step: "idle",
    opening: null,
    guild: "",
    facts: null,
    plan: null,
    choices: null,
    acknowledged: false,
    backupTaken: false,
    run: null,
    backingUp: false,
    resumed: false,
    backup: null,
    progress: null,
    ended: null,
    cut: false,
    error: "",
    idBox: "",
    leaving: [],
    idsSaid: "",
  };
}

/** Outlives a cut: a person's choices over hours of a run, and its end screen, which only
 *  this holds. Dropped when they close the server. */
export const moveWizard = scoped<Wizard>(noWizard, { kept: true });

const wizardSay = (server: string, patch: Partial<Wizard>) => moveWizard.of(server).update((w) => ({ ...w, ...patch }));

/** While a dry-run or a run goes, the importer asks the relay these same things on this
 *  connection and sorts out the replies by what it asked. The page keeps out of its way. */
export const importerAsking = (step: WizardStep): boolean => step === "reading" || step === "running";

/** What the dashboard shows, afresh. */
export function moveRefresh(server: string): void {
  if (importerAsking(get(moveWizard.peek(server)).step)) return;
  adminRead("MoveStatus", server);
  adminRead({ PowerWaiting: { offset: 0 } }, server);
  adminRead({ MoveAccounts: { search: "", offset: 0, filter: "Waiting" } }, server);
  excludedMore.of(server).set(false);
  readExcluded(server, "");
}

// ── The wizard ─────────────────────────────────────────────────────────────

const cutWaiting = (button: string, said = "") => `The connection to the server was lost. ${said}Press ${button} again once it is back.`;
const CUT_RUN = "The connection to the server was lost. Nothing is lost: Go on takes it up from here.";

export function wizardStart(server: string): void {
  moveWizard.of(server).set({ ...noWizard(), step: "token" });
}

/** Leave it: this machine forgets the token and all it read. */
export function wizardForget(server: string): void {
  invoke("import_forget", { server }).catch(() => {});
  moveWizard.of(server).set(noWizard());
}

/** The token check asked for last. Not a scoped store: a cut must not start the count again
 *  under an older check that is still waiting on Discord. */
const openAttempt = new Map<string, number>();

export async function wizardOpen(server: string, token: string): Promise<void> {
  const attempt = (openAttempt.get(server) ?? 0) + 1;
  openAttempt.set(server, attempt);
  wizardSay(server, { step: "opening", error: "" });
  const still = () => openAttempt.get(server) === attempt && get(moveWizard.peek(server)).step === "opening";
  try {
    const opening = openingOnce(await invoke<Opening>("import_open", { server, token }));
    if (still()) wizardSay(server, { step: "pick", opening, guild: opening.guilds[0]?.id ?? "" });
  } catch (e) {
    if (still()) wizardSay(server, { step: "token", error: String(e) });
  }
}

/** A command refused: back to `back`, unless the token is gone. That takes the dry-run and
 *  the choices with it, so what is left to do is the token. Ids not sent stay in their box. */
function wizardFailed(server: string, back: Partial<Wizard>, e: unknown): void {
  const error = String(e);
  if (error === NO_TOKEN) moveWizard.of(server).update((w) => ({ ...noWizard(), step: "token", error, idBox: w.idBox }));
  else wizardSay(server, { ...back, error });
}

/** The dry-run: nothing is written anywhere. */
export function wizardRead(server: string): void {
  wizardSay(server, { step: "reading", error: "" });
  adminRead("ImportFacts", server);
}

async function planWith(server: string, facts: ImportFacts): Promise<void> {
  const w = get(moveWizard.peek(server));
  if (w.step !== "reading") return;
  wizardSay(server, { facts });
  const still = () => get(moveWizard.peek(server)).step === "reading";
  try {
    const plan = planOnce(await invoke<Plan>("import_plan", { server, guild: w.guild }));
    if (still()) wizardSay(server, { step: "choose", plan, choices: startChoices(plan), acknowledged: false, backupTaken: false });
  } catch (e) {
    if (still()) wizardFailed(server, { step: "pick" }, e);
  }
}

export function wizardChoices(server: string, choices: MoveChoices): void {
  wizardSay(server, { choices });
}

/** `ImportBegin`: the StepUp prompt asks for the code, and the relay makes its copy. */
export function wizardBegin(server: string): void {
  const w = get(moveWizard.peek(server));
  if (w.step !== "choose" || !w.choices || w.leaving.length) return;
  wizardSay(server, { step: "beginning", error: "", backingUp: false, ended: null, progress: null });
  void adminOp(
    { ImportBegin: { guild_id: w.guild, options: optionsToSend(w.choices, w.acknowledged), backup_taken: w.backupTaken } },
    null,
    server,
  );
}

async function runBegun(server: string, run: number, resumed: boolean, backup: string | null): Promise<void> {
  const w = get(moveWizard.peek(server));
  if (w.step !== "beginning" || !w.choices) return;
  wizardSay(server, { step: "running", run, resumed, backup, backingUp: false });
  try {
    await invoke("import_run", { server, run, choices: choicesToSend(w.choices, w.acknowledged) });
  } catch (e) {
    wizardFailed(server, { step: "choose", run: null }, e);
  }
}

/** Stop is always there, and loses nothing: what is stored stays, and a run takes it up. */
export function wizardStop(server: string): void {
  invoke("import_stop", { server }).catch((e: unknown) => wizardSay(server, { error: String(e) }));
}

/** A refusal, or a code not given: whatever waited for an answer goes back to where it
 *  can be tried again. The relay stopped at what it had done, which a run or an undo goes
 *  on from. */
export function moveStepEnded(server: string): void {
  const w = get(moveWizard.peek(server));
  if (w.step === "beginning") wizardSay(server, { step: "choose", backingUp: false });
  else if (w.step === "reading") wizardSay(server, { step: "pick" });
  idsBack(server);
  excludeOut.of(server).set(false);
  powerOut.of(server).set(false);
  undoStopped(server);
}

/** A refusal, shown in the panel. One that the prompt asks a code for again is about that
 *  code, and what waited on it still waits. */
export function moveRefused(server: string): void {
  if (!codeAskedAgain(server)) moveStepEnded(server);
}

/** After a stop: the same read and the same choices, since a new dry-run could not tell a
 *  channel turned off from one the run did not reach. The tick is given again. */
export function wizardGoOn(server: string): void {
  wizardSay(server, { step: "choose", ended: null, progress: null, acknowledged: false, error: "" });
}

/** The connection went. The wizard stays, and the token its hour, so only what was waiting
 *  for an answer moves. Dropped when the server is closed. */
export function wizardCut(server: string): void {
  const { step } = get(moveWizard.peek(server));
  if (step === "beginning") wizardSay(server, { step: "choose", backingUp: false, error: cutWaiting("Run") });
  else if (step === "reading") wizardSay(server, { step: "pick", error: cutWaiting("Read it") });
  else if (step === "running") wizardSay(server, { cut: true });
  // No frame can land now, and what it read from Discord meanwhile would go nowhere
  if (step === "reading" || step === "running") invoke("import_stop", { server }).catch(() => {});
  idsBack(server, "cut");
  undoCut(server);
}

export function onImportEnded(server: string, ended: ImportEnded): void {
  const w = get(moveWizard.peek(server));
  if (w.step !== "running") return;
  wizardSay(server, { step: "ended", ended: w.cut && ended.stopped ? { ...ended, stopped: CUT_RUN } : ended, cut: false });
  importedChanged(server);
  // With no connection nothing would answer: the tab reads it all when it opens again
  if (get(connectionState.peek(server)) === "connected") moveRefresh(server);
}

/** The move post: the one write the importer ever makes, and only on this press. */
export async function wizardPost(server: string, channel: string, text: string, everyone: boolean): Promise<void> {
  await invoke("import_move_post", { server, channel, text, everyone });
}

// ── Leaving people out ─────────────────────────────────────────────────────

/** A `MoveExclude` is out: the next `MoveExcluded` is its answer, and calls for a refresh. */
const excludeOut = scoped<boolean>(() => false);
/** The next `MoveExcluded` is a further page. */
const excludedMore = scoped<boolean>(() => false);
/** Reads of that list out. Each answer looks like a `MoveExclude`'s, and one can land while
 *  the code is asked for: these go first, so that nobody passes for answered. */
const excludedReads = scoped<number>(() => 0);

function readExcluded(server: string, after: string): void {
  excludedReads.of(server).update((n) => n + 1);
  adminRead({ MoveExcluded: { after } }, server);
}

/** One at a time: a `StepUp` is about the step sent last. */
function excludeNext(server: string): void {
  const next = get(moveWizard.peek(server)).leaving[0];
  if (!next) return;
  excludeOut.of(server).set(true);
  void adminOp({ MoveExclude: { dc_id: next, on: true, erase: true } }, null, server);
}

/** Left out before they were ever read, as the notice to members promises: each takes
 *  the code, which holds ten minutes. The box keeps them until the last has its answer. */
export function excludeIds(server: string, ids: readonly string[]): void {
  wizardSay(server, { leaving: [...ids], error: "", idsSaid: "" });
  excludeNext(server);
}

function excludeAnswered(server: string): void {
  const { leaving } = get(moveWizard.peek(server));
  const left = leaving.slice(1);
  if (left.length) {
    wizardSay(server, { leaving: left });
    excludeNext(server);
    return;
  }
  if (leaving.length) wizardSay(server, { leaving: [], idBox: "" });
  moveRefresh(server);
}

/** The list stops: what has no answer goes back in the box, and the words say how many. If
 *  the relay told the first one no, that stays out. At a cut the first one goes back with the
 *  rest, with no answer to say what became of it: it can go twice. */
function idsBack(server: string, how: "stopped" | "cut" | { refused: string } = "stopped"): void {
  const { leaving } = get(moveWizard.peek(server));
  if (!leaving.length) return;
  const refused = typeof how === "object";
  const unsent = refused ? leaving.slice(1) : leaving;
  const idsSaid = idsBackLine(refused ? { id: leaving[0], reason: how.refused } : null, unsent.length);
  wizardSay(server, { leaving: [], idBox: unsent.join("\n"), idsSaid, error: how === "cut" ? cutWaiting("Leave them out", `${idsSaid} `) : idsSaid });
}

/** One person: `erase` takes their posts for good, and otherwise they are held. */
export function excludeOne(server: string, dcId: string, on: boolean, erase: boolean): void {
  // The prompt, if up, is now about this one
  idsBack(server);
  excludeOut.of(server).set(true);
  void adminOp({ MoveExclude: { dc_id: dcId, on, erase } }, null, server);
}

export function excludedNextPage(server: string): void {
  const last = get(excludedPage.peek(server))?.rows.at(-1);
  if (!last) return;
  excludedMore.of(server).set(true);
  readExcluded(server, last.id);
}

/** Says yes or no to someone's held-back power. The list comes back as the answer; the
 *  count beside it does not. */
const powerOut = scoped<boolean>(() => false);

export function powerAnswer(server: string, row: PowerRow, grant: boolean): void {
  powerOut.of(server).set(true);
  void adminOp({ PowerAnswer: { id: row.account, group: row.group, grant } }, null, server);
}

// ── Undo ───────────────────────────────────────────────────────────────────

/** Previews still to come for the question about to be asked. */
const undoAsked = scoped<{ chain: number[]; counts: Map<number, ImportUndoCounts>; earlier: boolean } | null>(() => null);

/** Ask what it would take, with no code, then ask the person, once for the whole chain. */
export function undoStart(server: string, run: number): void {
  const status = get(moveStatus.peek(server));
  const runs = moveRuns(status?.runs ?? []);
  const chain = undoChain(runs, run);
  if (!chain.length) return;
  moveUndoLeft.of(server).set(null);
  undoAsked.of(server).set({ chain, counts: new Map(), earlier: earlierStands(runs, run) });
  for (const id of chain) adminRead({ ImportUndoPreview: { run: id } }, server);
}

async function undoAsk(server: string, chain: number[], counts: ImportUndoCounts[], earlier: boolean): Promise<void> {
  const ok = await confirmAction({
    title: chain.length > 1 ? `Undo ${chain.length} runs?` : "Undo this run?",
    body: undoSays(counts, earlier),
    confirm: "Undo it",
    danger: true,
  });
  if (!ok) return;
  moveUndo.of(server).set({ runs: chain, total: NO_UNDO, done: false });
  void adminOp({ ImportUndo: { run: chain[0] } }, null, server);
}

/** A run left halfway needs no second question: its marks are made, and it can only go on. */
export function undoCarryOn(server: string, run: number): void {
  moveUndoLeft.of(server).set(null);
  moveUndo.of(server).set({ runs: [run], total: NO_UNDO, done: false });
  void adminOp({ ImportUndo: { run } }, null, server);
}

function undoStopped(server: string): void {
  const u = get(moveUndo.peek(server));
  if (u && !u.done) {
    moveUndo.of(server).set(null);
    moveUndoLeft.of(server).set({ runs: u.runs, cut: false });
    moveRefresh(server);
  }
}

/** No answer will come, and the panel closes with the connection. The rows say how far it got
 *  when it opens again, and this says the rest did not go. */
function undoCut(server: string): void {
  const u = get(moveUndo.peek(server));
  if (!u) return;
  moveUndo.of(server).set(null);
  if (!u.done) moveUndoLeft.of(server).set({ runs: u.runs, cut: true });
}

function onUndone(server: string, r: Extract<AdminReply, { ImportUndone: unknown }>["ImportUndone"]): void {
  const u = get(moveUndo.peek(server));
  // Stop asking was pressed with this on its way: nothing more goes, and the row says how far it got
  if (!u) {
    if (!r.more) {
      moveUndoLeft.of(server).update((left) => {
        const runs = left?.runs.filter((id) => id !== r.run) ?? [];
        return left && runs.length ? { ...left, runs } : null;
      });
    }
    moveRefresh(server);
    return;
  }
  const total = addUndone(u.total, r);
  const runs = u.runs;
  if (r.more) {
    moveUndo.of(server).set({ runs, total, done: false });
    void adminOp({ ImportUndo: { run: r.run } }, null, server);
    return;
  }
  const left = runs.filter((id) => id !== r.run);
  if (left.length) {
    moveUndo.of(server).set({ runs: left, total, done: false });
    void adminOp({ ImportUndo: { run: left[0] } }, null, server);
    return;
  }
  moveUndo.of(server).set({ runs: [], total, done: true });
  importedChanged(server);
  moveRefresh(server);
}

// ── What the relay and the importer say ────────────────────────────────────

export function onMoveReply(server: string, raw: unknown): void {
  const r = raw as { Admin?: AdminReply; Error?: { request: string; reason: string } };
  if (r.Error?.request === "Admin") {
    if (!codeAskedAgain(server)) idsBack(server, { refused: r.Error.reason });
    moveRefused(server);
    undoAsked.of(server).set(null);
    return;
  }
  const a = r.Admin;
  if (typeof a !== "object" || !a) return;
  if ("MoveStatus" in a) moveStatus.of(server).set({ ...a.MoveStatus, runs: moveRuns(a.MoveStatus.runs) });
  else if ("MoveAccounts" in a) moveAccountsPage.of(server).set({ ...a.MoveAccounts, rows: cleanAccounts(a.MoveAccounts.rows) });
  else if ("PowerWaiting" in a) {
    powerPage.of(server).set({ ...a.PowerWaiting, rows: powerRows(a.PowerWaiting.rows) });
    if (get(powerOut.of(server))) {
      powerOut.of(server).set(false);
      adminRead("MoveStatus", server);
    }
  }
  else if ("MoveExcluded" in a) {
    const paging = get(excludedMore.of(server));
    excludedMore.of(server).set(false);
    excludedPage.of(server).update((had) => ({
      rows: excludedRows(paging ? (had?.rows ?? []) : [], a.MoveExcluded.ids),
      more: a.MoveExcluded.more,
    }));
    const reads = get(excludedReads.of(server));
    if (reads > 0) excludedReads.of(server).set(reads - 1);
    else if (get(excludeOut.of(server))) {
      excludeOut.of(server).set(false);
      excludeAnswered(server);
    }
  } else if ("ImportUndoPreview" in a) {
    const asked = get(undoAsked.peek(server));
    if (!asked?.chain.includes(a.ImportUndoPreview.run)) return;
    asked.counts.set(a.ImportUndoPreview.run, a.ImportUndoPreview.counts);
    if (asked.counts.size === asked.chain.length) {
      undoAsked.of(server).set(null);
      void undoAsk(server, asked.chain, asked.chain.map((id) => asked.counts.get(id)!), asked.earlier);
    }
  } else if ("ImportUndone" in a) onUndone(server, a.ImportUndone);
  else if ("ImportReport" in a) moveReport.of(server).set(a.ImportReport);
  else if ("ImportFacts" in a) void planWith(server, a.ImportFacts.facts);
  else if ("ImportBackingUp" in a) wizardSay(server, { backingUp: true, run: a.ImportBackingUp.run });
  else if ("ImportBegun" in a) void runBegun(server, a.ImportBegun.run, a.ImportBegun.resumed, a.ImportBegun.backup ?? null);
}

listenServer<unknown>("account-reply", onMoveReply);
listenServer<ImportProgress>("import-progress", (server, progress) => {
  if (importerAsking(get(moveWizard.peek(server)).step)) wizardSay(server, { progress });
});
listenServer<ImportEnded>("import-ended", onImportEnded);
listenServer<unknown>("connection-lost", wizardCut);
