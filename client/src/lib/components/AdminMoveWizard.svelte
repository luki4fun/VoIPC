<script lang="ts">
  // Reading a Discord server, from the desktop app: the token, the dry-run, what comes,
  // the run, and what is left to do after it. All in this machine's memory: the token goes
  // to `import_open` and this field is cleared, the plan is gone with the page, and rows go
  // from Discord to the relay without touching a disk.

  import { get } from "svelte/store";
  import {
    ACKNOWLEDGEMENT,
    MOVE_POST_CHARS,
    POLICY_URL,
    TOGGLES,
    beginBlock,
    discordIds,
    effectiveOptions,
    estimateLine,
    gateHereLine,
    messagesCame,
    movePostText,
    newLinkCode,
    postChannelOf,
    postChannels,
    postable,
    progressLine,
    toggleBlock,
    withJoinLine,
    type MoveChoices,
    type PlanChannel,
    type ToggleKey,
  } from "../move-rules.js";
  import { adminOp, inviteLinkCode } from "../stores/admin-ops.js";
  import { serverAddress, serverKey } from "../stores/connection.js";
  import { addNotification } from "../stores/notifications.js";
  import { updateUiPrefs } from "../stores/ui-prefs.js";
  import {
    excludeIds,
    moveStatus,
    moveWizard,
    wizardBegin,
    wizardChoices,
    wizardForget,
    wizardGoOn,
    wizardOpen,
    wizardPost,
    wizardRead,
    wizardStart,
    wizardStop,
    moveStepEnded,
  } from "../stores/move.js";
  import { buildJoinLink, splitAddress } from "../invite.js";
  import { privilegeLabel } from "../scopes.js";
  import Markdown from "./chat/Markdown.svelte";

  const server = $derived($serverAddress);
  const w = $derived($moveWizard);
  const plan = $derived(w.plan);
  const choices = $derived(w.choices);
  const shownOptions = $derived(choices ? effectiveOptions(choices.options) : null);
  /** Ids in the box are on their way: Run would read those people before their answer. */
  const sending = $derived(w.leaving.length > 0);
  const blocked = $derived(plan && choices && w.facts ? (sending ? "Still leaving people out, below." : beginBlock(choices, plan, w.facts, w.acknowledged, w.backupTaken)) : null);
  const anyRun = $derived(!!$moveStatus?.runs.length);

  let token = $state("");

  function submitToken(e: SubmitEvent) {
    e.preventDefault();
    const t = token.trim();
    // Cleared before anything else can happen: nothing of it stays on this page
    token = "";
    if (t) void wizardOpen(server, t);
  }

  function setChoices(change: (c: MoveChoices) => void) {
    if (!choices) return;
    const next: MoveChoices = { options: { ...choices.options }, leftOut: new Set(choices.leftOut), messagesOn: new Set(choices.messagesOn) };
    change(next);
    wizardChoices(server, next);
  }
  function toggle(key: ToggleKey, on: boolean) {
    setChoices((c) => {
      c.options[key] = on;
    });
  }
  function leaveChannel(ch: PlanChannel, out: boolean) {
    setChoices((c) => {
      if (out) c.leftOut.add(ch.id);
      else c.leftOut.delete(ch.id);
    });
  }
  function channelMessages(ch: PlanChannel, on: boolean) {
    setChoices((c) => {
      if (on) c.messagesOn.add(ch.id);
      else c.messagesOn.delete(ch.id);
    });
  }

  // Someone left out before anyone reads them: the notice to members promises it
  const typed = $derived(discordIds(w.idBox));
  function leaveIdsOut() {
    if (typed.ids.length > 0) excludeIds(server, typed.ids);
  }

  function begin() {
    updateUiPrefs((p) => {
      p.discord_bot_gone = p.discord_bot_gone.filter((k) => k !== serverKey(server));
    });
    wizardBegin(server);
  }

  // ── The move post ────────────────────────────────────────────────────────

  let postOpen = $state(false);
  let postText = $state("");
  let postChannel = $state("");
  let postEveryone = $state(false);
  let wantLink = $state(false);
  let posting = $state(false);
  let posted = $state(false);
  const channelsToPost = $derived(plan ? postChannels(plan) : []);
  const publicUrl = $derived(w.facts?.public_url ?? "");
  /** The code on hand when the link was asked for: not the one that is coming. */
  let codeBefore = $state<string | null>(null);
  const linkCode = $derived(newLinkCode($inviteLinkCode, codeBefore));
  const joinLink = $derived.by(() => {
    const at = splitAddress(server);
    return wantLink && linkCode && at ? buildJoinLink(at.host, at.port, linkCode) : null;
  });

  function openPost() {
    if (!plan || !shownOptions || !choices) return;
    postOpen = true;
    posted = false;
    postText = movePostText(publicUrl, { ...shownOptions, messages: messagesCame(choices) });
    postChannel = postChannelOf(plan);
  }
  /** A join link for newcomers, only if asked: a new one is made, and shown as any other. */
  function askLink() {
    if (wantLink) {
      codeBefore = $inviteLinkCode;
      void adminOp({ InviteLinkNew: { max_uses: 100_000, days: 30, group: null } }, null, server);
    } else {
      if (linkCode) inviteLinkCode.of(server).set(null);
      postText = withJoinLine(postText, null);
    }
  }
  $effect(() => {
    // The code came after the tick, or an edit took its line away
    if (postOpen && joinLink && !postText.includes(joinLink)) postText = withJoinLine(postText, joinLink);
  });

  async function post() {
    if (posting || posted || !postable(postText)) return;
    posting = true;
    try {
      await wizardPost(server, postChannel, postText, postEveryone);
      posted = true;
    } catch (e) {
      addNotification(`The post did not go: ${e}`, "error");
    } finally {
      posting = false;
    }
  }

  function done() {
    postOpen = false;
    wizardForget(get(serverAddress));
  }
</script>

<section class="section callout wizard" data-step={w.step}>
  <div class="section-title">Read a Discord server</div>

  {#if w.error}
    <div class="wizard-error" role="alert">{w.error}</div>
  {/if}

  {#if w.step === "idle"}
    <p class="admin-hint">
      Copies a Discord server's channels, roles, members and messages here, with a bot you make. It only reads, apart from one post you may ask for at the end.
    </p>
    <div class="form-actions">
      <button type="button" class="btn btn-primary wizard-start" onclick={() => wizardStart(server)}>{anyRun ? "Run again" : "Start"}</button>
    </div>
  {:else if w.step === "token" || w.step === "opening"}
    <ol class="steps">
      <li>In the Discord Developer Portal, make an application.</li>
      <li>On its Bot page, turn on Server Members and Message Content <strong>first</strong>, and reset the token to copy it.</li>
      <li>Then invite the bot, with the link this shows next. A server with two-factor for moderators needs it on your Discord account first.</li>
    </ol>
    <p class="admin-hint">It only reads, apart from one post you may ask for at the end. The token goes to discord.com only and is kept nowhere.</p>
    <form class="inline-form" onsubmit={submitToken}>
      <input class="admin-input grow wizard-token" type="password" autocomplete="off" placeholder="Bot token" aria-label="Bot token" bind:value={token} disabled={w.step === "opening"} />
      <button type="button" class="btn btn-ghost" onclick={() => wizardForget(server)}>Cancel</button>
      <button type="submit" class="btn btn-primary wizard-open" disabled={!token.trim() || w.step === "opening"}>{w.step === "opening" ? "Asking…" : "Next"}</button>
    </form>
  {:else if w.step === "pick" && w.opening}
    {@const o = w.opening}
    <p class="admin-hint">
      Signed in as <strong>{o.bot_name}</strong>. Server Members is {o.member_intent ? "on" : "off"}, Message Content is {o.content_intent ? "on" : "off"}.
    </p>
    <div class="field">
      Invite link
      <code class="invite-link">{o.invite}</code>
    </div>
    {#if o.guilds.length === 0}
      <p class="admin-hint">The bot is on no server yet: invite it with this link, then start again.</p>
    {:else}
      <label class="field">
        Which server
        <select class="admin-select wizard-guild" value={w.guild} onchange={(e) => moveWizard.of(server).update((v) => ({ ...v, guild: e.currentTarget.value }))}>
          {#each o.guilds as g (g.id)}
            <option value={g.id}>{g.name}{g.admin ? "" : " (the bot is not an administrator)"}</option>
          {/each}
        </select>
      </label>
    {/if}
    <div class="form-actions">
      <button type="button" class="btn btn-ghost" onclick={() => wizardForget(server)}>Cancel</button>
      <button type="button" class="btn btn-primary wizard-read" disabled={!w.guild} onclick={() => wizardRead(server)}>Read it</button>
    </div>
  {:else if w.step === "reading"}
    <p class="admin-hint" role="status">Reading, and counting. Nothing is written anywhere, and this can take a few minutes.</p>
    {#if w.progress?.waiting}
      <p class="admin-hint wizard-wait">{w.progress.waiting}</p>
    {/if}
    <div class="form-actions">
      <button type="button" class="btn btn-ghost" onclick={() => wizardForget(server)}>Cancel</button>
    </div>
  {:else if w.step === "choose" && plan && choices && shownOptions && w.facts}
    <p class="move-line">
      {plan.guild.name}: {plan.guild.members.toLocaleString("en-US")} members, {plan.guild.online.toLocaleString("en-US")} online
    </p>
    {#if plan.delta}
      <p class="admin-hint wizard-delta">An earlier run stands, so this takes new messages only. Starting over is Undo, then run.</p>
    {/if}
    <p class="admin-hint wizard-estimate">{estimateLine(plan.estimate)}</p>
    {#if w.facts.unfinished}
      <p class="admin-hint">A run of this server did not finish: this goes on from where it stopped.</p>
    {/if}

    {#if plan.warnings.length}
      <ul class="warnings">
        {#each plan.warnings as warning, i (i)}
          <li class="warning {warning.level}" data-code={warning.code}>{warning.text}</li>
        {/each}
      </ul>
    {/if}

    <div class="sub-title">What comes</div>
    <ul class="check-list wizard-toggles">
      {#each TOGGLES as t (t.key)}
        {@const why = toggleBlock(t.key, choices.options, plan.blocks)}
        <li>
          <label class="check-row" class:disabled={!!why}>
            <input type="checkbox" data-toggle={t.key} checked={shownOptions[t.key]} disabled={!!why} onchange={(e) => toggle(t.key, e.currentTarget.checked)} />
            <span class="check-text">
              <span>{t.label}</span>
              <span class="check-hint">{why ?? t.hint}</span>
            </span>
          </label>
        </li>
      {/each}
    </ul>

    <div class="sub-title">Channels</div>
    <p class="admin-hint">
      A private channel's history needs its own tick. Its name and topic go regardless; Leave out to keep them off. A channel's messages off covers its threads too.
    </p>
    {#if plan.delta}
      <p class="admin-hint wizard-again">A channel that came before starts on again unless you leave it out each time. A private one starts off: tick it each run.</p>
    {/if}
    <ul class="list wizard-channels">
      {#each plan.channels as ch (ch.id)}
        {@const out = choices.leftOut.has(ch.id)}
        {@const gateHere = gateHereLine(ch)}
        <li class="list-item channel-row" class:left-out={out} data-channel={ch.name}>
          <span class="row-text">
            <span class="row-name">{ch.final_name}{#if ch.private}<span class="pill">{gateHere ? "private on Discord" : "private"}</span>{/if}</span>
            <span class="row-meta" title={ch.private_why || ch.messages_why || ch.left_out_why}>
              {ch.messages == null ? "Messages not known" : `${ch.messages.toLocaleString("en-US")} messages`}{ch.private_why ? ` · ${ch.private_why}` : ch.messages_why ? ` · ${ch.messages_why}` : ""}{gateHere ? ` · ${gateHere}` : ""}{ch.left_out_why ? ` · ${ch.left_out_why}` : ""}
            </span>
          </span>
          <label class="tick">
            <input type="checkbox" class="channel-messages" checked={!out && shownOptions.messages && choices.messagesOn.has(ch.id)} disabled={out || !shownOptions.messages} onchange={(e) => channelMessages(ch, e.currentTarget.checked)} />
            Messages
          </label>
          <label class="tick">
            <input type="checkbox" class="channel-out" checked={out} onchange={(e) => leaveChannel(ch, e.currentTarget.checked)} />
            Leave out
          </label>
        </li>
      {/each}
    </ul>

    {#if plan.roles.some((r) => r.power.length)}
      <div class="sub-title">Power waits for your OK</div>
      <ul class="report-preview">
        {#each plan.roles.filter((r) => r.power.length) as role (role.id)}
          <li>{role.name}: {role.power.map(privilegeLabel).join(", ")}</li>
        {/each}
      </ul>
    {/if}

    {#if plan.report_preview.length}
      <details class="wizard-lossy">
        <summary>What does not come ({plan.report_preview.length})</summary>
        <ul class="report-preview">
          {#each plan.report_preview as line, i (i)}
            <li>{line}</li>
          {/each}
        </ul>
      </details>
    {/if}

    <div class="sub-title">Anyone who asked to be left out</div>
    <p class="admin-hint">Discord ids, one to a line. They get no account here and none of their posts come. Each takes your code, which holds ten minutes.</p>
    <textarea class="admin-input wizard-ids" rows="2" aria-label="Discord ids to leave out" value={w.idBox} disabled={sending} oninput={(e) => moveWizard.of(server).update((v) => ({ ...v, idBox: e.currentTarget.value }))}></textarea>
    {#if typed.bad.length}
      <p class="wizard-error" role="alert">Not a Discord id: {typed.bad.slice(0, 3).join(", ")}</p>
    {/if}
    {#if w.idsSaid}
      <p class="wizard-error wizard-ids-said" role="alert">{w.idsSaid}</p>
    {/if}
    <div class="form-actions">
      {#if sending}
        <button type="button" class="btn btn-ghost wizard-ids-stop" onclick={() => moveStepEnded(server)}>Stop</button>
      {/if}
      <button type="button" class="btn btn-secondary wizard-ids-go" disabled={sending || typed.ids.length === 0 || typed.bad.length > 0} onclick={leaveIdsOut}>{sending ? "Sending…" : "Leave them out"}</button>
    </div>

    {#if !w.facts.backup_here}
      <label class="check-row wizard-backup">
        <input type="checkbox" checked={w.backupTaken} onchange={(e) => moveWizard.of(server).update((v) => ({ ...v, backupTaken: e.currentTarget.checked }))} />
        <span class="check-text">
          <span>I have made a copy of this server's database</span>
          <span class="check-hint">On Postgres there is no copy from here: run pg_dump now.</span>
        </span>
      </label>
    {/if}

    {#if shownOptions.messages}
      <label class="check-row wizard-ack">
        <input type="checkbox" checked={w.acknowledged} onchange={(e) => moveWizard.of(server).update((v) => ({ ...v, acknowledged: e.currentTarget.checked }))} />
        <span class="check-text">
          <span>{ACKNOWLEDGEMENT}</span>
          <span class="check-hint">The policy: <code>{POLICY_URL}</code></span>
        </span>
      </label>
    {/if}

    {#if blocked}
      <p class="admin-hint wizard-why">{blocked}</p>
    {/if}
    <div class="form-actions">
      <button type="button" class="btn btn-ghost" onclick={() => wizardForget(server)}>Cancel</button>
      <button type="button" class="btn btn-primary wizard-begin" disabled={!!blocked} onclick={begin}>Run</button>
    </div>
  {:else if w.step === "beginning"}
    <p class="admin-hint" role="status">
      {w.backingUp ? "This server is copying its database." : "Asking this server to begin. It asks for your code above."}
    </p>
    <div class="form-actions">
      <button type="button" class="btn btn-ghost wizard-back" onclick={() => moveStepEnded(server)}>Back</button>
    </div>
  {:else if w.step === "running"}
    {@const p = w.progress}
    {#if w.resumed}<p class="admin-hint">Going on from where the last run stopped.</p>{/if}
    {#if w.backup}<p class="admin-hint wizard-backup-path">The copy of the database: <code>{w.backup}</code>. It stays until you delete it. Delete it when you know the move went well.</p>{/if}
    <p class="move-line wizard-progress" role="status">{p ? progressLine(p) : "Starting"}</p>
    {#if p && p.total > 0}
      <progress max={p.total} value={p.done} aria-label="How far it has got"></progress>
    {/if}
    {#if p?.waiting}
      <p class="admin-hint wizard-wait">{p.waiting}</p>
    {/if}
    <div class="form-actions">
      <button type="button" class="btn btn-danger-outline wizard-stop" onclick={() => wizardStop(server)}>Stop</button>
    </div>
    <p class="admin-hint">Stopping loses nothing: what is stored stays, and running again goes on from there.</p>
  {:else if w.step === "ended" && w.ended}
    {@const e = w.ended}
    <p class="move-line wizard-ended">{e.stopped ? `Stopped: ${e.stopped}` : "Done."}</p>
    {#if e.notes.length}
      <details class="wizard-notes" open>
        <summary>What to know ({e.notes.length})</summary>
        <ul class="report-preview">
          {#each e.notes as note, i (i)}
            <li>{note}</li>
          {/each}
        </ul>
        <p class="admin-hint">This list stays on this screen only.</p>
      </details>
    {/if}

    {#if !e.stopped}
      {#if !postOpen}
        <div class="form-actions">
          <button type="button" class="btn btn-secondary wizard-post-open" disabled={channelsToPost.length === 0} onclick={openPost}>Write a post on Discord…</button>
        </div>
      {:else}
        <div class="sub-title">A post on Discord</div>
        <p class="admin-hint">The one thing this ever writes there, and only when you press Post. Nothing goes to anyone directly.</p>
        <label class="field">
          Where
          <select class="admin-select post-channel" bind:value={postChannel}>
            {#each channelsToPost as ch (ch.id)}
              <option value={ch.id}>#{ch.name}</option>
            {/each}
          </select>
        </label>
        <textarea class="admin-input post-text" rows="8" maxlength={MOVE_POST_CHARS} aria-label="The post" bind:value={postText}></textarea>
        <div class="post-preview" aria-label="How it reads"><Markdown text={postText} onlink={() => {}} /></div>
        <label class="check-row">
          <input type="checkbox" class="post-everyone" bind:checked={postEveryone} />
          <span class="check-text"><span>Ping @everyone</span><span class="check-hint">No pings otherwise.</span></span>
        </label>
        <label class="check-row">
          <input type="checkbox" class="post-link" bind:checked={wantLink} onchange={askLink} />
          <span class="check-text"><span>Add a link for newcomers</span><span class="check-hint">A new invite link, for up to 100,000 people, for 30 days. Revoke it on the Users tab.</span></span>
        </label>
        <div class="form-actions">
          {#if posted}<span class="admin-hint push-left post-done">Posted.</span>{/if}
          <button type="button" class="btn btn-primary post-go" disabled={posting || posted || !postable(postText)} onclick={post}>{posting ? "Posting…" : "Post"}</button>
        </div>
      {/if}
    {/if}

    {#if e.stopped}
      <p class="admin-hint end-words">When you are finished, remove the bot: it holds Administrator on your Discord server. Go on needs it, and this token, until then.</p>
    {:else}
      <div class="callout-inner end-words">
        <p><strong>Now remove the bot.</strong> It holds Administrator on your Discord server, and its token opens all of it.</p>
        <ol class="steps">
          <li>On Discord: Server Settings, Integrations, the app, Kick.</li>
          <li>In the Developer Portal: Bot, Reset Token, and do not keep the new one.</li>
        </ol>
        {#if w.opening}
          <p class="admin-hint">A later run needs it back, with this invite link:</p>
          <code class="invite-link">{w.opening.invite}</code>
        {:else}
          <p class="admin-hint">A later run needs it back: the invite link is shown when you start one.</p>
        {/if}
        <p class="admin-hint">The token was kept nowhere, so nothing on this machine needs cleaning.</p>
      </div>
    {/if}
    <div class="form-actions">
      {#if e.stopped}
        <button type="button" class="btn btn-secondary wizard-go-on" onclick={() => wizardGoOn(server)}>Go on</button>
      {/if}
      <button type="button" class="btn btn-primary wizard-done" onclick={done}>Done</button>
    </div>
  {/if}
</section>

<style>
  .wizard {
    padding: var(--sp-3, 12px);
    border: 1px solid var(--border);
    border-radius: var(--r-md, 6px);
    background: var(--bg-tertiary);
  }

  .wizard-error {
    color: var(--danger);
    font-size: var(--fs-sm);
    margin: 0;
  }

  .move-line {
    margin: 0;
    font-size: var(--fs-md, 14px);
    font-weight: 600;
  }

  .steps {
    margin: 0;
    padding-left: 20px;
    font-size: var(--fs-sm);
    line-height: 1.4;
  }

  .invite-link {
    display: block;
    font-weight: 400;
    font-size: var(--fs-sm);
    user-select: all;
    word-break: break-all;
  }

  .warnings,
  .report-preview {
    margin: 0;
    padding-left: 18px;
    font-size: var(--fs-sm);
    line-height: 1.4;
    color: var(--text-secondary);
  }

  .warning.warn {
    color: var(--text-primary);
  }

  .warning.red {
    color: var(--danger);
    font-weight: 600;
  }

  .channel-row {
    flex-wrap: wrap;
  }

  .channel-row.left-out .row-text {
    opacity: 0.6;
  }

  .tick {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-height: var(--hit);
    font-size: var(--fs-sm);
    font-weight: 400;
    cursor: pointer;
    white-space: nowrap;
  }

  .tick input {
    width: 16px;
    height: 16px;
    margin: 0;
  }

  .wizard-ids,
  .post-text {
    resize: vertical;
    padding: 6px 8px;
    font: inherit;
    font-size: var(--fs-body);
  }

  .post-preview {
    padding: var(--sp-2, 8px);
    border: 1px solid var(--border);
    border-radius: var(--r-sm, 4px);
    background: var(--bg-primary);
    font-size: var(--fs-sm);
    overflow-wrap: anywhere;
  }

  .callout-inner {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2, 8px);
    padding: var(--sp-3, 12px);
    border: 1px solid var(--danger);
    border-radius: var(--r-md, 6px);
  }

  .callout-inner p {
    margin: 0;
  }

  progress {
    width: 100%;
  }
</style>
