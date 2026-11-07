<script lang="ts">
  // The admin panel's Discord move tab (1.11): who has come over, who waits for the owner's
  // OK on what they could do on Discord, who was left out, and each run with its Undo.
  // Everything here is the relay's, so it works from any device. Reading a Discord server
  // is the wizard above it, on a desktop. Its look is AdminDialogs.svelte's.

  import { onMount } from "svelte";
  import { get } from "svelte/store";
  import {
    excludedLine,
    expiryText,
    moveAccountKey,
    powerKey,
    runState,
    signedInLine,
    storedReport,
    undoLeftLine,
    undoneLine,
    discordId,
  } from "../move-rules.js";
  import { adminError, adminOp, adminRead } from "../stores/admin-ops.js";
  import { confirmAction } from "../stores/confirm.js";
  import { serverAddress, serverKey } from "../stores/connection.js";
  import { hasImporter, isWeb } from "../stores/platform.js";
  import { uiPrefs, updateUiPrefs } from "../stores/ui-prefs.js";
  import {
    excludedNextPage,
    excludedPage,
    excludeOne,
    importerAsking,
    moveAccountsPage,
    moveRefresh,
    moveRefused,
    moveReport,
    moveStatus,
    moveStepEnded,
    moveUndo,
    moveUndoLeft,
    moveWizard,
    powerAnswer,
    powerPage,
    undoCarryOn,
    undoStart,
  } from "../stores/move.js";
  import { privilegeLabel } from "../scopes.js";
  import AdminMoveWizard from "./AdminMoveWizard.svelte";
  import type { MoveAccount, MoveRun } from "../types.js";

  const PAGE = 50;
  const when = (secs: number) => new Date(secs * 1000).toLocaleString();

  const server = $derived($serverAddress);
  const status = $derived($moveStatus);
  const waiting = $derived($moveAccountsPage?.filter === "Waiting" ? $moveAccountsPage : null);
  const running = $derived(importerAsking($moveWizard.step));
  const botGone = $derived($uiPrefs.discord_bot_gone.includes(serverKey(server)));
  const anyRun = $derived(!!status?.runs.some((r) => r.finished_at != null && r.undone_at == null));

  onMount(() => moveRefresh(get(serverAddress)));

  // A code not given: nothing comes back to say so, and what waited on it should not wait on
  $effect(() => {
    if ($adminError) moveRefused(server);
  });

  function waitingPage(offset: number) {
    adminRead({ MoveAccounts: { search: "", offset, filter: "Waiting" } }, server);
  }
  function powerAt(offset: number) {
    adminRead({ PowerWaiting: { offset } }, server);
  }

  async function leaveOut(row: MoveAccount) {
    const ok = await confirmAction({
      title: `Leave out ${row.user.name} and delete their posts?`,
      body: "Their waiting account goes. What they wrote goes from this server for good, and no later import brings it back or makes them an account. The log names nobody.",
      confirm: "Leave out and delete",
      danger: true,
    });
    if (ok) excludeOne(server, row.dc_id, true, true);
  }
  async function hold(row: MoveAccount) {
    const ok = await confirmAction({
      title: `Hold ${row.user.name} for now?`,
      body: "Their waiting account goes, and no import makes another until you let them back in. Their posts stay and keep arriving. This is the way to let someone with an account here link Discord first.",
      confirm: "Hold for now",
    });
    if (ok) excludeOne(server, row.dc_id, true, false);
  }
  async function letBack(id: string, erased: boolean) {
    const ok =
      !erased ||
      (await confirmAction({
        title: "Let them back in?",
        body: "The next import can make them an account again. Posts already gone do not come back.",
        confirm: "Let back in",
      }));
    if (ok) excludeOne(server, id, false, false);
  }

  function report(run: MoveRun) {
    moveReport.of(server).set(null);
    adminRead({ ImportReport: { run: run.id } }, server);
  }

  let deleteId = $state("");
  const deleteTarget = $derived(discordId(deleteId));
  async function deleteById() {
    const id = deleteTarget;
    if (!id) return;
    const ok = await confirmAction({
      title: `Delete everything imported from Discord id ${id}?`,
      body: "All of it goes from this server for good, and no later import brings it back. Any account of theirs stays. The log names nobody.",
      confirm: "Delete it all",
      danger: true,
    });
    if (ok) {
      void adminOp({ ArchiveDelete: { target: { Author: { id } } } }, null, server);
      deleteId = "";
    }
  }
</script>

{#if hasImporter}
  <AdminMoveWizard />
{:else}
  <section class="section callout move-desktop-only">
    <div class="section-title">Reading a Discord server</div>
    <p class="admin-hint">
      Reading a Discord server runs in the desktop app. It asks Discord directly with a bot token that stays on that machine.
      {#if isWeb}A page cannot do that, and would hand the token to whatever served it.{/if}
      Everything below works from here.
    </p>
  </section>
{/if}

{#if hasImporter && anyRun && !botGone}
  <label class="check-row bot-reminder">
    <input
      type="checkbox"
      onchange={() => updateUiPrefs((p) => { p.discord_bot_gone = [...p.discord_bot_gone, serverKey(server)]; })}
    />
    <span class="check-text">
      <span>I removed the bot</span>
      <span class="check-hint">It holds Administrator on your Discord server, and its token opens all of it.</span>
    </span>
  </label>
{/if}

{#if running}
  <p class="admin-hint move-running">These counts catch up when the run ends.</p>
{/if}

<section class="section move-status">
  <div class="section-title">Who has come over</div>
  {#if status}
    <p class="move-line">{signedInLine(status)}</p>
    <p class="admin-hint">
      {status.banned.toLocaleString("en-US")} banned on Discord · {status.power_waiting.toLocaleString("en-US")} waiting for your OK · {status.excluded.toLocaleString("en-US")} left out.
      {status.unclaimed_days
        ? `An account nobody opens goes ${status.unclaimed_days} days after its import: set unclaimed_days to change it.`
        : "An account nobody opens stays until someone removes it."}
    </p>
  {:else}
    <p class="admin-hint">Loading…</p>
  {/if}
</section>

<section class="section move-power">
  <div class="section-title">Waiting for your OK</div>
  <p class="admin-hint">
    What they could do on Discord, or a group their account held before it was opened, held back until you say yes. Check
    with them outside Discord first: anyone holding that Discord account has claimed this. Whoever you OK with this can give
    it to others. Managing channels includes deleting one with a code, but not one holding what came from Discord: that
    takes an admin.
  </p>
  {#if $powerPage?.rows.length}
    {@const page = $powerPage}
    <ul class="list">
      {#each page.rows as row (powerKey(row))}
        <li class="list-item power-row" class:unclaimed={!row.claimed} data-group={row.group}>
          <span class="row-text">
            <span class="row-name">{row.name}{#if row.badge}<span class="pill">{row.badge}</span>{/if}</span>
            <span class="row-meta" title={row.scopes.join(", ")}>
              {row.group}: {row.scopes.map(privilegeLabel).join(", ")}
            </span>
            {#if !row.claimed}<span class="row-meta">Has not signed in yet</span>{/if}
          </span>
          {#if row.claimed}
            <button type="button" class="btn btn-secondary power-no" onclick={() => powerAnswer(server, row, false)}>No</button>
            <button type="button" class="btn btn-primary power-ok" onclick={() => powerAnswer(server, row, true)}>OK</button>
          {/if}
        </li>
      {/each}
    </ul>
    {#if page.total > PAGE}
      <div class="form-actions">
        <span class="admin-hint push-left">{page.offset + 1}–{page.offset + page.rows.length} of {page.total}</span>
        <button type="button" class="btn btn-secondary" disabled={page.offset === 0} onclick={() => powerAt(Math.max(0, page.offset - PAGE))}>Earlier</button>
        <button type="button" class="btn btn-secondary" disabled={page.offset + PAGE >= page.total} onclick={() => powerAt(page.offset + PAGE)}>Later</button>
      </div>
    {/if}
  {:else if $powerPage}
    <p class="admin-hint">Nobody.</p>
  {/if}
</section>

<section class="section move-waiting">
  <div class="section-title">Still to sign in</div>
  {#if waiting?.rows.length}
    <ul class="list">
      {#each waiting.rows as row (moveAccountKey(row))}
        <li class="list-item waiting-row">
          <span class="row-text">
            <span class="row-name">{row.user.name}</span>
            <span class="row-meta">{expiryText(row.expires_at)}{row.dc_id ? ` · Discord ${row.dc_id}` : ""}</span>
          </span>
          {#if row.dc_id}
            <button type="button" class="btn btn-secondary move-hold" onclick={() => hold(row)}>Hold for now</button>
            <button type="button" class="btn btn-danger-outline move-leave" onclick={() => leaveOut(row)}>Leave out and delete their posts</button>
          {/if}
        </li>
      {/each}
    </ul>
    {#if waiting.total > PAGE}
      <div class="form-actions">
        <span class="admin-hint push-left">{waiting.offset + 1}–{waiting.offset + waiting.rows.length} of {waiting.total}</span>
        <button type="button" class="btn btn-secondary" disabled={waiting.offset === 0} onclick={() => waitingPage(Math.max(0, waiting.offset - PAGE))}>Newer</button>
        <button type="button" class="btn btn-secondary" disabled={waiting.offset + PAGE >= waiting.total} onclick={() => waitingPage(waiting.offset + PAGE)}>Older</button>
      </div>
    {/if}
  {:else if waiting}
    <p class="admin-hint">Nobody.</p>
  {/if}
</section>

<section class="section move-left-out">
  <div class="section-title">Left out</div>
  {#if $excludedPage?.rows.length}
    <ul class="list">
      {#each $excludedPage.rows as row (row.id)}
        <li class="list-item excluded-row">
          <span class="row-text">
            <span class="row-name">Discord {row.id}</span>
            <span class="row-meta">{excludedLine(row)} · {when(row.at)}</span>
          </span>
          {#if !row.own}
            <button type="button" class="btn btn-secondary let-back" onclick={() => letBack(row.id, row.erase)}>Let back in</button>
          {/if}
        </li>
      {/each}
    </ul>
    {#if $excludedPage.more}
      <div class="form-actions">
        <button type="button" class="btn btn-secondary excluded-more" onclick={() => excludedNextPage(server)}>Show more</button>
      </div>
    {/if}
  {:else if $excludedPage}
    <p class="admin-hint">Nobody.</p>
  {/if}
</section>

<section class="section move-runs">
  <div class="section-title">Runs</div>
  {#if $moveUndoLeft}
    <p class="admin-hint move-undo-left" role="alert">{undoLeftLine($moveUndoLeft)}</p>
  {/if}
  {#if $moveUndo}
    {@const undo = $moveUndo}
    <div class="callout move-undoing" role="status">
      <p class="admin-hint">
        {undo.done ? "Undone. " : `Undoing run ${undo.runs[0]}: `}{undoneLine(undo.total)}
      </p>
      {#if undo.done}
        <div class="form-actions">
          <button type="button" class="btn btn-ghost" onclick={() => moveUndo.of(server).set(null)}>Done</button>
        </div>
      {:else}
        <div class="form-actions">
          <button type="button" class="btn btn-ghost move-undo-stop" onclick={() => moveStepEnded(server)}>Stop asking</button>
        </div>
      {/if}
    </div>
  {/if}
  {#if status?.runs.length}
    <ul class="list">
      {#each status.runs as run (run.id)}
        <li class="list-item run-row" data-run={run.id}>
          <span class="row-text">
            <span class="row-name">Run {run.id}: {runState(run)}</span>
            <span class="row-meta">
              {when(run.started_at)} · by {run.by} · {run.accounts.toLocaleString("en-US")} accounts, {run.groups.toLocaleString("en-US")} groups
            </span>
          </span>
          <button type="button" class="btn btn-secondary run-report" onclick={() => report(run)}>Report</button>
          {#if run.clearing}
            <button type="button" class="btn btn-secondary run-carry-on" disabled={!!$moveUndo || running} onclick={() => undoCarryOn(server, run.id)}>Carry on</button>
          {:else if run.undone_at == null}
            <button type="button" class="btn btn-danger-outline run-undo" disabled={!!$moveUndo || running} onclick={() => undoStart(server, run.id)}>Undo</button>
          {/if}
        </li>
      {/each}
    </ul>
  {:else if status}
    <p class="admin-hint">No import has run on this server.</p>
  {/if}
  {#if $moveReport}
    {@const kept = storedReport($moveReport.report)}
    <div class="callout move-report">
      <div class="section-title">Run {$moveReport.run}</div>
      {#if kept.counts.length}
        <ul class="report-counts">
          {#each kept.counts as [name, count] (name)}
            <li>{name}: {count.toLocaleString("en-US")}</li>
          {/each}
        </ul>
      {/if}
      {#each kept.notes as note, i (i)}
        <p class="admin-hint">{note}</p>
      {/each}
      {#if !kept.counts.length && !kept.notes.length}
        <p class="admin-hint">This run left no report.</p>
      {/if}
      <div class="form-actions">
        <button type="button" class="btn btn-ghost" onclick={() => moveReport.of(server).set(null)}>Close</button>
      </div>
    </div>
  {/if}
</section>

<section class="section move-delete-id">
  <div class="section-title">Delete by Discord id</div>
  <p class="admin-hint">For someone who writes in from outside: what they wrote goes, and their account, if any, stays.</p>
  <form class="inline-form" onsubmit={(e) => { e.preventDefault(); void deleteById(); }}>
    <input class="admin-input grow delete-id" inputmode="numeric" placeholder="Discord id" aria-label="Discord id" bind:value={deleteId} />
    <button type="submit" class="btn btn-danger-outline delete-id-go" disabled={!deleteTarget}>Delete their posts</button>
  </form>
</section>

<style>
  .callout {
    padding: var(--sp-3, 12px);
    border: 1px solid var(--border);
    border-radius: var(--r-md, 6px);
    background: var(--bg-tertiary);
    display: flex;
    flex-direction: column;
    gap: var(--sp-2, 8px);
  }

  .move-line {
    margin: 0;
    font-size: var(--fs-md, 14px);
    font-weight: 600;
  }

  /* Someone who has not come has nothing to say yes to: greyed, and still there to see */
  .power-row.unclaimed {
    opacity: 0.6;
  }

  .run-row {
    flex-wrap: wrap;
  }

  /* A Discord id does not fit beside two long buttons, and a group's powers are read whole before an OK */
  .waiting-row,
  .power-row {
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  .list-item.waiting-row .row-text,
  .list-item.power-row .row-text {
    flex: 1 1 100%;
  }

  .list-item.power-row .row-name,
  .list-item.power-row .row-meta {
    white-space: normal;
    overflow-wrap: anywhere;
  }

  .report-counts {
    margin: 0;
    padding-left: 18px;
    font-size: var(--fs-sm);
  }
</style>
