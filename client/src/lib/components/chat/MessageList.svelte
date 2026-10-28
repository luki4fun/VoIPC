<script module lang="ts">
  import type { ChatMessage as Message } from "../../types.js";

  /** What can be done to a message here, beside answering it; each absent
   *  where it cannot (ChatPanel decides: who may, and whether posting is). */
  export interface MessageActions {
    react?: (m: Message, emoji: string, on: boolean) => void;
    /** Our own messages only. */
    edit?: (m: Message, text: string) => void;
    remove?: (m: Message) => void;
    /** For the channel's managers. */
    pin?: (m: Message, on: boolean) => void;
    forward?: (m: Message) => void;
  }
</script>

<script lang="ts">
  import { tick } from "svelte";
  import type { ChatMessage, FileConv } from "../../types.js";
  import { userId } from "../../stores/connection.js";
  import { account, accountHex } from "../../stores/account.js";
  import { addNotification } from "../../stores/notifications.js";
  import { menu } from "../../actions/menu.js";
  import { portal } from "../../actions/portal.js";
  import { nativeMenuWanted } from "../../context-menu.js";
  import { dayKey, dayLabel, fullTime } from "../../chat-time.js";
  import { mentionsName, parse, plainText } from "../../markdown.js";
  import { ambiguousTarget, findTarget, indexById, isOwn } from "../../thread-rules.js";
  import { reactionChips, rowKey, sameRow } from "../../chat-rules.js";
  import { receivedNow } from "../../stores/chat.js";
  import { confirmAction } from "../../stores/confirm.js";
  import { EMOJI_CATEGORIES, QUICK_REACTIONS } from "../../emoji.js";
  import { shortName } from "../../username.js";
  import Icon from "../Icons.svelte";
  import Markdown from "./Markdown.svelte";
  import FileCard from "./FileCard.svelte";
  import Lightbox from "./Lightbox.svelte";

  interface Props {
    /** The rows to draw, oldest first. */
    messages: ChatMessage[];
    /** Where what a reply answers is looked up: the whole conversation, which
     *  in a thread pane is more than the rows drawn. Defaults to `messages`. */
    all?: ChatMessage[];
    /** A link was pressed: the owner shows its copy popup (never a browser). */
    onlink: (url: string) => void;
    /** Answer a message. Absent where nothing can be written (a preview). */
    onreply?: (m: ChatMessage) => void;
    /** Answer it in its own thread. */
    onthread?: (m: ChatMessage) => void;
    /** Threads whose first message is drawn here, with their answers. */
    threads?: Map<ChatMessage, ChatMessage[]>;
    /** Answers whose thread's first message is not here. */
    orphans?: Set<ChatMessage>;
    /** Open a thread; `seen` is when its answers were last looked at. */
    onopenthread?: (root: ChatMessage) => void;
    threadSeen?: (root: ChatMessage) => number;
    /** A message the owner has to bring into view (folded into a thread, or
     *  not in this list at all) when a quote is pressed. */
    onjumpelsewhere?: (m: ChatMessage) => void;
    /** The thread these rows are in: an answer to its first message needs no quote. */
    under?: ChatMessage;
    /** Who an `@` may name here, and our own names (see Markdown). */
    names?: readonly string[];
    me?: readonly string[];
    /** Where the unread part began: a "New" divider goes before the first message after it. */
    newSince?: number;
    /** The server and conversation these rows are in, for their files. */
    server?: string;
    fileConv?: FileConv | null;
    /** React, edit, delete, pin, forward. */
    actions?: MessageActions;
  }
  let {
    messages,
    all,
    onlink,
    onreply,
    onthread,
    threads,
    orphans,
    onopenthread,
    threadSeen,
    onjumpelsewhere,
    under,
    names = [],
    me = [],
    newSince,
    server = "",
    fileConv = null,
    actions = {},
  }: Props = $props();

  /** A loaded picture shown big. */
  let picture = $state<{ url: string; name: string; save: () => void } | null>(null);

  const index = $derived(indexById(all ?? messages));
  const myAccount = $derived($account ? accountHex($account.info.id) : undefined);

  function isRow(m: ChatMessage): boolean {
    return m.kind !== "history-marker" && m.kind !== "notice";
  }

  /** Written by us: the account where both have one, else this connection's
   *  id on a message it received (thread-rules.ts `isOwn`). */
  function isMine(m: ChatMessage): boolean {
    return isOwn(m, { account: myAccount, user_id: $userId }, (x) => receivedNow(server, x));
  }

  /** The messages among the rows, without our own dividers. */
  const rows = $derived(messages.filter(isRow));

  /** Whether `m` names us with an `@` (outside code). */
  function mentionsMe(m: ChatMessage): boolean {
    if (me.length === 0 || !m.content.includes("@") || isMine(m)) return false;
    const tree = parse(m.content, { names: me });
    return me.some((n) => mentionsName(tree, n));
  }

  /** The first message after `newSince` that somebody else wrote. */
  const newFrom = $derived(
    newSince === undefined ? undefined : rows.find((m) => m.timestamp >= newSince && !isMine(m)),
  );
  let newEl = $state<HTMLElement | null>(null);
  /** The divider has been on screen: no need to point at it any more. */
  let newSeen = $state(false);
  $effect(() => {
    void newFrom;
    newSeen = false;
  });
  $effect(() => {
    const el = newEl;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) newSeen = true;
    });
    io.observe(el);
    return () => io.disconnect();
  });

  /** Something a person wrote that can be answered: it has the id an answer names. */
  function answerable(m: ChatMessage): boolean {
    return !!m.id && isRow(m) && m.kind !== "undecryptable";
  }

  /** A divider before the first message of every day (lib/chat-time.ts). */
  function startsDay(index: number): boolean {
    const curr = messages[index];
    if (!isRow(curr)) return false;
    for (let j = index - 1; j >= 0; j--) {
      const prev = messages[j];
      if (!isRow(prev)) continue;
      return dayKey(prev.timestamp) !== dayKey(curr.timestamp);
    }
    return true;
  }

  function formatTime(timestamp: number): string {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function shouldShowHeader(index: number): boolean {
    if (index === 0) return true;
    const prev = messages[index - 1];
    const curr = messages[index];
    // Show header if different user, after a history divider, or more than 5 minutes apart
    return (
      !isRow(prev) ||
      prev.user_id !== curr.user_id ||
      dayKey(prev.timestamp) !== dayKey(curr.timestamp) ||
      // Where a name came from is part of what the header says, so a second-hand
      // message never folds into a run of first-hand ones and inherits its badge.
      (prev.kind === "shared") !== (curr.kind === "shared") ||
      // An answer starts its own group: its quote sits above its name
      !!curr.reply_to ||
      curr.timestamp - prev.timestamp > 5 * 60 * 1000
    );
  }

  /** The line a quote shows of the message answered. */
  function snippet(m: ChatMessage): string {
    const text = m.kind === "undecryptable" ? m.content : plainText(m.content);
    return text.length > 120 ? `${text.slice(0, 120)}…` : text || m.file?.name || "…";
  }

  // ── Rows, focus and jumping ─────────────────────────────────────────────
  //
  // The list is one tab stop: the arrow keys move between messages, and the
  // focused one shows its tools, the way hovering does. Every row a tab stop
  // would be five hundred of them before the message box.

  const rowEls = new Map<ChatMessage, HTMLElement>();
  function row(node: HTMLElement, m: ChatMessage) {
    let key = m;
    rowEls.set(key, node);
    return {
      update(next: ChatMessage) {
        rowEls.delete(key);
        key = next;
        rowEls.set(key, node);
      },
      destroy() {
        if (rowEls.get(key) === node) rowEls.delete(key);
      },
    };
  }

  // Raw: a $state proxy of a message is never === the message itself. An
  // event (a reaction, an edit) makes a new object of a message: still its row.
  let focused = $state.raw<ChatMessage | null>(null);
  const current = $derived((focused && rows.find((r) => sameRow(r, focused!))) ?? rows.at(-1));

  function onRowKeydown(e: KeyboardEvent, m: ChatMessage) {
    if (e.target !== e.currentTarget) return;
    const at = rows.indexOf(m);
    const to =
      e.key === "ArrowUp" ? at - 1 : e.key === "ArrowDown" ? at + 1 : e.key === "Home" ? 0 : e.key === "End" ? rows.length - 1 : null;
    if (to === null) return;
    e.preventDefault();
    const next = rows[Math.max(0, Math.min(rows.length - 1, to))];
    focused = next;
    rowEls.get(next)?.focus();
  }

  let flashing = $state.raw<ChatMessage | null>(null);
  let flashTimer: ReturnType<typeof setTimeout> | undefined;

  /** Bring `m` into view and mark it for a moment. False if it is not drawn here. */
  export function jumpTo(m: ChatMessage): boolean {
    const el = rowEls.get(m);
    if (!el) return false;
    const still = globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ block: "center", behavior: still ? "auto" : "smooth" });
    focused = m;
    el.focus({ preventScroll: true });
    flashing = m;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => (flashing = null), 1000);
    return true;
  }

  function jump(target: ChatMessage) {
    if (!jumpTo(target)) onjumpelsewhere?.(target);
  }

  // ── Actions ─────────────────────────────────────────────────────────────

  async function copyText(m: ChatMessage) {
    try {
      await navigator.clipboard.writeText(m.content);
      addNotification("Message copied", "info", 2000);
    } catch {
      addNotification("Could not copy: select the text and copy it yourself", "warning");
    }
  }

  let opened = $state.raw<{ m: ChatMessage; x: number; y: number; up: number } | null>(null);

  /** The phone's gesture bar, which an edge-to-edge web view draws over. */
  function safeBottom(): number {
    const probe = document.createElement("div");
    probe.style.cssText = "position:fixed;bottom:0;height:env(safe-area-inset-bottom,0px);visibility:hidden";
    document.body.append(probe);
    const h = probe.getBoundingClientRect().height;
    probe.remove();
    return h;
  }

  /** A pop-up at `y` that would run off the bottom (of what is visible: a
   *  phone's keyboard and gesture bar take some, D2-13) goes above `up`. */
  function fit(node: HTMLElement, up: number) {
    const r = node.getBoundingClientRect();
    const vv = globalThis.visualViewport;
    const floor = (vv ? vv.offsetTop + vv.height : innerHeight) - 8 - safeBottom();
    if (r.bottom > floor) node.style.top = `${Math.max(8, up - r.height)}px`;
  }

  // ── Touch ───────────────────────────────────────────────────────────────
  //
  // The last pointer was a finger. Then a long press opens the message menu
  // whatever it selected (D1-01), and no tool bar stands over the text (D2-09:
  // a finger leaves :hover on what it last touched): the long-press menu holds
  // every action. Told by the pointer event itself, never by `(hover: none)`
  // alone, which a headless browser reports too.
  let touch = $state(false);
  function notePointer(e: PointerEvent) {
    touch = e.pointerType === "touch";
  }

  /** Right click, a long press on a touch screen, or the menu key. */
  function onContextMenu(e: MouseEvent, m: ChatMessage) {
    const fromTouch = (e as PointerEvent).pointerType === "touch" || (touch && (e as PointerEvent).pointerType !== "mouse");
    // Selected text keeps the native menu, with its Copy; on a touch screen
    // the long press made that selection, and the app's menu has Copy text
    if (nativeMenuWanted(e.target, globalThis.getSelection?.()?.toString() ?? "", fromTouch)) return;
    e.preventDefault();
    if (fromTouch) globalThis.getSelection?.()?.removeAllRanges();
    let [x, y] = [e.clientX, e.clientY];
    if (x === 0 && y === 0) {
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      [x, y] = [r.left + 24, r.top + 8];
    }
    // Kept on screen: narrow, and above the pointer where there is no room below (`fit`)
    opened = { m, x: Math.min(x, innerWidth - 220), y, up: y };
  }

  function act(fn: (m: ChatMessage) => void) {
    const m = opened?.m;
    opened = null;
    if (m) fn(m);
  }

  // ── Reactions, edits, deletes, pins, forwards ───────────────────────────

  /** Ours, as a reaction names its person (`authorKey`): our account's key
   *  where we have one, else this connection's id. */
  function isMyKey(key: string): boolean {
    return myAccount !== undefined ? key === `a:${myAccount}` : key.startsWith(`u:${$userId}:`);
  }

  /** Written by us first-hand: what an edit or a delete can name. A copy a
   *  member handed over is theirs to keep. */
  function ownEditable(m: ChatMessage): boolean {
    return answerable(m) && m.kind !== "shared" && isMine(m);
  }

  /** The reaction picker, for `m`, where it was opened. */
  let picking = $state.raw<{ m: ChatMessage; x: number; y: number; up: number } | null>(null);
  let pickCategory = $state(0);

  /** Open the picker under `from` (a tool), or at the menu's place. */
  function openPicker(m: ChatMessage, from: { x: number; y: number; up: number } | Element) {
    const r = from instanceof Element ? from.getBoundingClientRect() : null;
    const at = r ? { x: r.right - 300, y: r.bottom + 4, up: r.top - 4 } : (from as { x: number; y: number; up: number });
    pickCategory = 0;
    // Kept on screen across; the picker is 300 wide (`fit` keeps it in down)
    picking = { m, x: Math.max(8, Math.min(at.x, innerWidth - 308)), y: at.y, up: at.up };
  }

  function pick(emoji: string) {
    const was = picking?.m;
    picking = null;
    if (!was || !actions.react) return;
    // As it is now: another reaction may have come in while the picker was open
    const m = rows.find((r) => sameRow(r, was)) ?? was;
    const mine = reactionChips(m, isMyKey).some((c) => c.emoji === emoji && c.mine);
    actions.react(m, emoji, !mine);
  }

  /** The message being edited here, and its new text. */
  let editing = $state.raw<ChatMessage | null>(null);
  let draft = $state("");
  let editBox = $state<HTMLTextAreaElement | null>(null);

  function startEdit(m: ChatMessage) {
    editing = m;
    draft = m.content;
    tick().then(() => {
      editBox?.focus({ preventScroll: true });
      editBox?.setSelectionRange(draft.length, draft.length);
      // Save and Cancel in view, not under the composer; again once a phone's
      // keyboard has come up and made the list shorter (D2-08)
      const show = () => editBox?.closest(".edit-box")?.scrollIntoView({ block: "nearest" });
      show();
      const vv = globalThis.visualViewport;
      if (vv) {
        vv.addEventListener("resize", show, { once: true });
        setTimeout(() => vv.removeEventListener("resize", show), 1000);
      }
    });
  }

  function finishEdit(save: boolean) {
    const m = editing;
    editing = null;
    const text = draft.trim();
    if (save && m && text && text !== m.content.trim()) actions.edit?.(m, text);
    // Back on the row, where the keyboard was
    if (m) tick().then(() => rowEls.get(rows.find((r) => sameRow(r, m)) ?? m)?.focus());
  }

  function onEditKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      // Not the thread pane's Escape too
      e.preventDefault();
      e.stopPropagation();
      finishEdit(false);
    } else if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      finishEdit(true);
    }
  }

  async function askDelete(m: ChatMessage) {
    // As offered when asked: the conversation on screen may change meanwhile
    const remove = actions.remove;
    const ok = await confirmAction({
      title: "Delete this message?",
      body: "It goes for everyone in this conversation, from the server's copy too. Someone who already read it may have kept a copy of their own.",
      confirm: "Delete",
      danger: true,
    });
    if (ok) remove?.(m);
  }

  /** The menu, opened from the row's own "More" tool. */
  function openMore(e: MouseEvent, m: ChatMessage) {
    e.stopPropagation();
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    opened = { m, x: Math.max(8, Math.min(r.right - 220, innerWidth - 228)), y: r.bottom + 4, up: r.top - 4 };
  }

  function threadLine(answers: ChatMessage[]): string {
    const names = [...new Set(answers.map((a) => shortName(a.username)))];
    const who = names.length > 3 ? `${names.slice(0, 3).join(", ")} +${names.length - 3}` : names.join(", ");
    const last = answers.at(-1);
    return `${answers.length} ${answers.length === 1 ? "reply" : "replies"} · ${who}${last ? ` · ${formatTime(last.timestamp)}` : ""}`;
  }
</script>

<svelte:window
  onclick={() => { opened = null; picking = null; }}
  onkeydown={(e) => { if (e.key === "Escape") { opened = null; picking = null; } }}
  onpointerdowncapture={notePointer}
  onpointermove={(e) => { if (touch && e.pointerType === "mouse") touch = false; }}
/>

<!-- Keyed by the message object, which the stores carry over from one
     update to the next. The index used to be in the key, so once a
     conversation was full every new message shifted every key and
     rebuilt all 500 rows; the ids a sender mints are not unique enough
     on their own — a peer can repeat one, and a duplicate key throws.
     A message an event remade (a reaction, an edit) keeps its first
     object's key (`rowKey`), so its row, and a picture loaded in it, stay. -->
{#if newFrom && !newSeen}
  <button class="jump-new" type="button" onclick={() => newEl?.scrollIntoView({ block: "center" })}>
    New messages <Icon name="chevron-down" size={14} class="up" />
  </button>
{/if}

{#each messages as msg, i (rowKey(msg))}
  {#if !isRow(msg)}
    <div class="history-marker"><span>{msg.content}</span></div>
  {:else}
    {#if startsDay(i)}
      <div class="day-divider" role="separator"><span>{dayLabel(msg.timestamp)}</span></div>
    {/if}
    {#if msg === newFrom}
      <div class="new-divider" role="separator" bind:this={newEl}><span>New</span></div>
    {/if}
    {@const target = msg.reply_to ? findTarget(index, msg.reply_to, msg.timestamp) : undefined}
    {@const tabbable = msg === current}
    {@const isEditing = !!editing && sameRow(editing, msg)}
    <!-- A row the keyboard can stand on, with the arrows to move: one tab stop
         for the whole list (see "Rows, focus and jumping") -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <div
      class="msg"
      class:to-me={(!!target && isMine(target) && !isMine(msg)) || mentionsMe(msg)}
      class:flash={flashing === msg}
      class:grouped={!shouldShowHeader(i)}
      class:touch
      tabindex={tabbable ? 0 : -1}
      role="article"
      aria-label="{shortName(msg.username)}, {formatTime(msg.timestamp)}"
      use:row={msg}
      onfocusin={() => (focused = msg)}
      onkeydown={(e) => onRowKeydown(e, msg)}
      oncontextmenu={(e) => onContextMenu(e, msg)}
    >
      {#if msg.reply_to && !(under && target === under)}
        {#if target}
          <button
            class="quote"
            type="button"
            tabindex={msg === current ? 0 : -1}
            onclick={() => jump(target)}
            title="Go to the message this answers"
          >
            <Icon name="reply" size={12} />
            <span class="quote-name">{shortName(target.username)}</span>
            <span class="quote-text">{snippet(target)}</span>
          </button>
        {:else if ambiguousTarget(index, msg.reply_to, msg.timestamp)}
          <span class="quote missing" title="Ids are chosen by whoever writes, and more than one person's message here has this one"
            ><Icon name="reply" size={12} /> Answers a message whose writer is unclear</span
          >
        {:else}
          <span class="quote missing"><Icon name="reply" size={12} /> Original message is not here</span>
        {/if}
      {:else if orphans?.has(msg)}
        <span class="quote missing"><Icon name="thread" size={12} /> In a thread whose first message is not here</span>
      {/if}
      {#if shouldShowHeader(i)}
        <div class="msg-header">
          <span class="msg-username" class:self={isMine(msg)} title={msg.username}>{shortName(msg.username)}</span>
          <time class="msg-time" datetime={new Date(msg.timestamp).toISOString()} title={fullTime(msg.timestamp)}
            >{formatTime(msg.timestamp)}</time
          >
          {#if msg.kind === "shared"}
            <span
              class="shared-tag"
              title="From a member's copy of this channel's past. Who wrote it and when is their word for it — nothing signs a message, so there is nothing to check it against."
            >shared</span>
          {/if}
        </div>
      {/if}
      {#if msg.fwd}
        <div class="fwd-label" title="Forwarded: first written {fullTime(msg.fwd.at)}">
          <Icon name="forward" size={12} /> Forwarded from {shortName(msg.fwd.name)}
        </div>
      {/if}
      <div class="msg-content" class:shared={msg.kind === "shared"}>
        {#if msg.kind === "undecryptable"}
          <span class="attachment-placeholder">{msg.content}</span>
        {:else if msg.kind && msg.kind !== "text" && msg.kind !== "shared"}
          <span class="attachment-placeholder">[attachment — not shared]</span>
        {:else}
          {#if isEditing}
            <form class="edit-box" onsubmit={(e) => { e.preventDefault(); finishEdit(true); }}>
              <textarea
                class="edit-input"
                aria-label="Edit message"
                bind:this={editBox}
                bind:value={draft}
                onkeydown={onEditKeydown}
                maxlength="2000"
                rows="2"
              ></textarea>
              <div class="edit-actions">
                <span class="edit-hint">Enter to save · Escape to cancel</span>
                <button class="btn-ghost" type="button" onclick={() => finishEdit(false)}>Cancel</button>
                <button class="btn-secondary" type="submit" disabled={!draft.trim()}>Save</button>
              </div>
            </form>
          {:else if msg.content}
            <Markdown text={msg.content} {onlink} {names} {me} {tabbable} />
          {/if}
          {#if msg.edited_at && !isEditing}
            <span class="edited" title="Edited {fullTime(msg.edited_at)}">(edited)</span>
          {/if}
          {#if msg.pin?.on}
            <span class="pinned-tag" title="Pinned by {shortName(msg.pin.by)}"><Icon name="pin" size={11} /> Pinned</span>
          {/if}
          {#if msg.file}
            <FileCard
              file={msg.file}
              {server}
              conv={fileConv}
              {tabbable}
              onopen={(p) => (picture = p)}
              ongone={(u) => {
                if (picture?.url === u) picture = null;
              }}
            />
          {/if}
        {/if}
      </div>
      {#if msg.reactions?.length}
        {@const chips = reactionChips(msg, isMyKey)}
        <div class="reactions" role="group" aria-label="Reactions" hidden={chips.length === 0}>
          {#each chips as c (c.emoji)}
            <button
              class="reaction"
              class:mine={c.mine}
              type="button"
              tabindex={msg === current ? 0 : -1}
              aria-pressed={c.mine}
              aria-label="{c.emoji} {c.count}: {c.names.map((n) => shortName(n)).join(', ')}"
              title={c.names.map((n) => shortName(n)).join(", ")}
              disabled={!actions.react}
              onclick={() => actions.react?.(msg, c.emoji, !c.mine)}
            ><span class="reaction-emoji">{c.emoji}</span><span class="num">{c.count}</span></button>
          {/each}
        </div>
      {/if}
      {#if threads?.get(msg)}
        {@const answers = threads.get(msg)!}
        {@const unread = answers.some((a) => a.timestamp > (threadSeen?.(msg) ?? 0) && !isMine(a))}
        <button
          class="thread-summary"
          type="button"
          tabindex={msg === current ? 0 : -1}
          onclick={() => onopenthread?.(msg)}
        >
          <Icon name="thread" size={14} />
          <span>{threadLine(answers)}</span>
          {#if unread}<span class="unread-dot" title="New replies"></span>{/if}
        </button>
      {/if}
      {#if !isEditing}
      <div class="msg-tools" role="toolbar" aria-label="Message actions">
        {#if actions.react && answerable(msg)}
          <button
            class="icon-btn tool"
            type="button"
            tabindex={msg === current ? 0 : -1}
            title="React"
            aria-label="React"
            onclick={(e) => { e.stopPropagation(); openPicker(msg, e.currentTarget); }}
          >
            <Icon name="smile" size={16} />
          </button>
        {/if}
        {#if onreply && answerable(msg)}
          <button class="icon-btn tool" type="button" tabindex={msg === current ? 0 : -1} title="Reply" aria-label="Reply" onclick={() => onreply(msg)}>
            <Icon name="reply" size={16} />
          </button>
        {/if}
        {#if onthread && answerable(msg)}
          <button class="icon-btn tool" type="button" tabindex={msg === current ? 0 : -1} title="Reply in thread" aria-label="Reply in thread" onclick={() => onthread(msg)}>
            <Icon name="thread" size={16} />
          </button>
        {/if}
        {#if actions.edit && ownEditable(msg)}
          <button class="icon-btn tool" type="button" tabindex={msg === current ? 0 : -1} title="Edit" aria-label="Edit" onclick={() => startEdit(msg)}>
            <Icon name="pencil" size={16} />
          </button>
        {/if}
        <button class="icon-btn tool" type="button" tabindex={msg === current ? 0 : -1} title="More" aria-label="More" onclick={(e) => openMore(e, msg)}>
          <Icon name="more-vertical" size={16} />
        </button>
      </div>
      {/if}
    </div>
  {/if}
{/each}

{#if opened}
  {@const m = opened.m}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="msg-menu"
    style="left: {opened.x}px; top: {opened.y}px"
    use:portal
    use:fit={opened.up}
    use:menu={{ onclose: () => (opened = null), label: `Message from ${shortName(m.username)}` }}
    onclick={(e) => e.stopPropagation()}
  >
    {#if actions.react && answerable(m)}
      <button type="button" onclick={(e) => { e.stopPropagation(); const at = opened!; opened = null; openPicker(at.m, at); }}
        ><Icon name="smile" size={16} /> React</button
      >
    {/if}
    {#if onreply && answerable(m)}
      <button type="button" onclick={() => act(onreply)}><Icon name="reply" size={16} /> Reply</button>
    {/if}
    {#if onthread && answerable(m)}
      <button type="button" onclick={() => act(onthread)}><Icon name="thread" size={16} /> Reply in thread</button>
    {/if}
    <!-- Not a copy a member handed over: forwarded, its claimed writer would
         become a "Forwarded from" label with no mark of hearsay (D-15) -->
    {#if actions.forward && answerable(m) && m.kind !== "shared"}
      <button type="button" onclick={() => act(actions.forward!)}><Icon name="forward" size={16} /> Forward</button>
    {/if}
    {#if actions.edit && ownEditable(m)}
      <button type="button" onclick={() => act(startEdit)}><Icon name="pencil" size={16} /> Edit</button>
    {/if}
    {#if actions.pin && answerable(m)}
      <button type="button" onclick={() => act((x) => actions.pin!(x, !x.pin?.on))}
        ><Icon name="pin" size={16} /> {m.pin?.on ? "Unpin" : "Pin"}</button
      >
    {/if}
    <button type="button" onclick={() => act(copyText)}><Icon name="copy" size={16} /> Copy text</button>
    {#if actions.remove && ownEditable(m)}
      <button class="danger" type="button" onclick={() => act(askDelete)}><Icon name="trash" size={16} /> Delete</button>
    {/if}
  </div>
{/if}

{#if picking}
  {@const m = picking.m}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="react-picker"
    style="left: {picking.x}px; top: {picking.y}px"
    use:portal
    use:fit={picking.up}
    use:menu={{ onclose: () => (picking = null), label: `React to ${shortName(m.username)}` }}
    onclick={(e) => e.stopPropagation()}
  >
    <div class="react-quick">
      {#each QUICK_REACTIONS as emoji (emoji)}
        <button class="react-item" type="button" aria-label="React with {emoji}" onclick={() => pick(emoji)}>{emoji}</button>
      {/each}
    </div>
    <div class="react-tabs">
      {#each EMOJI_CATEGORIES as cat, idx (cat.label)}
        <button class="react-tab" class:active={pickCategory === idx} type="button" title={cat.label} aria-label={cat.label} onclick={() => (pickCategory = idx)}
          >{cat.emojis[0]}</button
        >
      {/each}
    </div>
    <div class="react-grid">
      {#each EMOJI_CATEGORIES[pickCategory].emojis as emoji (emoji)}
        <button class="react-item" type="button" aria-label="React with {emoji}" onclick={() => pick(emoji)}>{emoji}</button>
      {/each}
    </div>
  </div>
{/if}

{#if picture}
  <Lightbox url={picture.url} name={picture.name} onsave={picture.save} onclose={() => (picture = null)} />
{/if}

<style>
  .history-marker {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 10px 0;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .history-marker::before,
  .history-marker::after {
    content: "";
    flex: 1;
    border-top: 1px solid var(--border);
  }

  .attachment-placeholder {
    color: var(--text-secondary);
    font-style: italic;
  }

  /* Second-hand: a member's copy of what was said before we arrived. Drawn in
     the divider's own language — the divider is what introduces it — so it
     reads as a quieter kind of message rather than a broken one. */
  .shared-tag {
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 1px 5px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .day-divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 16px 0 8px;
    font-size: var(--fs-sm);
    font-weight: 600;
    color: var(--text-muted);
  }

  .day-divider::before,
  .day-divider::after {
    content: "";
    flex: 1;
    border-top: 1px solid var(--border);
  }

  /* Where the unread part begins: ink, like the day divider, but louder */
  .new-divider {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 12px 0 4px;
    font-size: var(--fs-micro);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-primary);
  }

  .new-divider::before,
  .new-divider::after {
    content: "";
    flex: 1;
    border-top: 1px solid var(--text-secondary);
  }

  /* Rides the top of the list while the divider is above it */
  .jump-new {
    position: sticky;
    top: 0;
    z-index: var(--z-sticky);
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0 auto 4px;
    padding: 6px 12px;
    border-radius: var(--r-pill);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-menu);
    font-size: var(--fs-sm);
  }

  .jump-new :global(.up) {
    transform: rotate(180deg);
  }

  /* One message: what it answers, who wrote it, what they wrote, its tools.
     A row off screen is not laid out until it comes near (R2-05: a full
     channel cost a phone about 160 ms per message); the list follows its end
     by state, not by measured height (ChatPanel). Its paint is contained, so
     the tools that sit over its top edge get room to show */
  .msg {
    position: relative;
    margin: 0 -8px;
    padding: 0 8px 1px;
    border-radius: var(--r-sm);
    outline: none;
    transition: background-color var(--dur-base);
    content-visibility: auto;
    contain-intrinsic-size: auto 48px;
    overflow-clip-margin: 16px;
  }

  .msg:not(.grouped) {
    margin-top: var(--msg-gap, 8px);
  }

  .msg:focus-visible {
    box-shadow: inset 0 0 0 2px var(--focus-ring);
  }

  /* An answer to something we wrote: ink, never the live mint */
  .msg.to-me {
    background: color-mix(in srgb, var(--text-primary) 6%, transparent);
    box-shadow: inset 2px 0 0 var(--text-secondary);
  }

  /* Where a quote led: marked for a moment, then fading back */
  .msg.flash {
    background: color-mix(in srgb, var(--text-primary) 8%, transparent);
  }

  .msg-header {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin-bottom: 2px;
  }

  .msg-username {
    font-size: var(--chat-font-size, 13px);
    font-weight: 600;
    color: var(--text-primary);
  }

  .msg-username.self {
    color: var(--text-primary);
  }

  .msg-time {
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  .msg-content {
    font-size: var(--chat-font-size, 13px);
    color: var(--text-primary);
    padding-left: 0;
    line-height: 1.4;
    word-break: break-word;
  }

  .msg-content.shared {
    color: var(--text-secondary);
  }

  .quote {
    display: flex;
    align-items: center;
    gap: 6px;
    max-width: 100%;
    margin: 2px 0 1px;
    padding: 0 0 0 8px;
    border: none;
    border-left: 2px solid var(--border);
    background: none;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    text-align: left;
    cursor: pointer;
  }

  .quote.missing {
    font-style: italic;
    cursor: default;
  }

  .quote-name {
    flex-shrink: 0;
    font-weight: 600;
    color: var(--text-primary);
  }

  .quote-text {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  button.quote:hover .quote-text {
    color: var(--text-primary);
  }

  .thread-summary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 28px;
    margin: 4px 0 2px;
    padding: 2px 10px;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: var(--fs-sm);
    cursor: pointer;
  }

  .thread-summary:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .unread-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-primary);
  }

  /* The tools: on hover, and on the row the keyboard is on */
  .msg-tools {
    position: absolute;
    top: -10px;
    right: 8px;
    display: none;
    gap: 2px;
    padding: 2px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    box-shadow: var(--shadow-menu);
    z-index: var(--z-raised);
  }

  /* Keyboard focus, not any focus: a quote's jump focuses its target, and a
     mouse that clicked one should not leave tools standing over the row.
     Hover only after a mouse: a finger leaves hover on whatever it touched,
     and the long press holds every action there (D2-09) */
  .msg:not(.touch):hover .msg-tools,
  .msg:focus-visible .msg-tools,
  .msg:has(:focus-visible) .msg-tools {
    display: flex;
  }

  /* A long press on a touch screen is the message menu, not a word selected
     (D1-01: the menu has Copy text). The edit box stays a text field */
  @media (pointer: coarse) {
    .msg {
      -webkit-user-select: none;
      user-select: none;
      -webkit-touch-callout: none;
    }
    .msg textarea {
      -webkit-user-select: text;
      user-select: text;
    }
  }

  /* A finger leaves hover on whatever it last touched: only a mouse tints */
  @media (hover: hover) {
    .msg:hover:not(.to-me):not(.flash) {
      background: color-mix(in srgb, var(--text-primary) 3%, transparent);
    }
  }

  .tool {
    width: var(--hit);
    height: var(--hit);
    background: transparent;
  }

  .msg-menu {
    position: fixed;
    z-index: var(--z-menu);
    display: flex;
    flex-direction: column;
    min-width: 200px;
    padding: 4px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-menu);
  }

  .msg-menu button {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: var(--hit);
    padding: 0 10px;
    border: none;
    border-radius: var(--r-sm);
    background: none;
    color: var(--text-primary);
    font-size: var(--fs-body);
    text-align: left;
    cursor: pointer;
  }

  .msg-menu button:hover,
  .msg-menu button:focus-visible {
    background: var(--bg-hover);
  }

  .msg-menu button.danger {
    color: var(--danger);
  }

  /* Forwarded: a quiet line above the text, like a quote's */
  .fwd-label {
    display: flex;
    align-items: center;
    gap: 4px;
    margin: 2px 0 1px;
    font-size: var(--fs-sm);
    font-style: italic;
    color: var(--text-secondary);
  }

  .edited,
  .pinned-tag {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    margin-right: 6px;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  .edit-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin: 2px 0 4px;
  }

  .edit-input {
    width: 100%;
    min-height: 2.6em;
    padding: 6px 8px;
    resize: vertical;
    font: inherit;
    color: var(--text-primary);
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
  }

  .edit-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: 6px;
  }

  .edit-hint {
    margin-right: auto;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  /* Reactions: ink chips under the message; ours outlined in the text colour */
  .reactions {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin: 4px 0 2px;
  }

  .reaction {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-height: 28px;
    padding: 0 8px;
    border: 1px solid var(--border);
    border-radius: var(--r-pill);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: var(--fs-sm);
    cursor: pointer;
  }

  .reaction.mine {
    border-color: var(--text-secondary);
    color: var(--text-primary);
    background: color-mix(in srgb, var(--text-primary) 8%, var(--bg-secondary));
  }

  .reaction:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .reaction:disabled {
    cursor: default;
  }

  .reaction-emoji {
    font-size: 1.1em;
    line-height: 1;
  }

  .react-picker {
    position: fixed;
    z-index: var(--z-menu);
    display: flex;
    flex-direction: column;
    width: 300px;
    max-width: calc(100vw - 16px);
    padding: 6px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-menu);
  }

  .react-quick,
  .react-tabs {
    display: flex;
    gap: 2px;
    padding-bottom: 4px;
    margin-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }

  .react-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 2px;
    max-height: 180px;
    overflow-y: auto;
  }

  .react-item,
  .react-tab {
    min-width: 32px;
    min-height: 32px;
    padding: 0;
    border: none;
    border-radius: var(--r-sm);
    background: none;
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
  }

  .react-tab {
    opacity: 0.6;
  }

  .react-tab.active {
    opacity: 1;
    background: var(--bg-tertiary);
  }

  .react-item:hover,
  .react-item:focus-visible,
  .react-tab:hover,
  .react-tab:focus-visible {
    background: var(--bg-hover);
  }
</style>
