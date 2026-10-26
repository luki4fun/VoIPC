<script lang="ts">
  import type { ChatMessage } from "../../types.js";
  import { userId } from "../../stores/connection.js";
  import { account, accountHex } from "../../stores/account.js";
  import { addNotification } from "../../stores/notifications.js";
  import { menu } from "../../actions/menu.js";
  import { portal } from "../../actions/portal.js";
  import { nativeMenuWanted } from "../../context-menu.js";
  import { dayKey, dayLabel, fullTime } from "../../chat-time.js";
  import { mentionsName, parse, plainText } from "../../markdown.js";
  import { findTarget, indexById } from "../../thread-rules.js";
  import { shortName } from "../../username.js";
  import Icon from "../Icons.svelte";
  import Markdown from "./Markdown.svelte";

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
  }: Props = $props();

  const index = $derived(indexById(all ?? messages));
  const myAccount = $derived($account ? accountHex($account.info.id) : undefined);

  function isRow(m: ChatMessage): boolean {
    return m.kind !== "history-marker" && m.kind !== "notice";
  }

  /** Written by us: the account where there is one, else this connection. */
  function isMine(m: ChatMessage): boolean {
    return (myAccount !== undefined && m.account === myAccount) || m.user_id === $userId;
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
    return text.length > 120 ? `${text.slice(0, 120)}…` : text || "…";
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

  // Raw: a $state proxy of a message is never === the message itself
  let focused = $state.raw<ChatMessage | null>(null);
  const current = $derived(focused && rows.includes(focused) ? focused : rows.at(-1));

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

  let opened = $state.raw<{ m: ChatMessage; x: number; y: number } | null>(null);

  /** Right click, a long press on a touch screen, or the menu key. */
  function onContextMenu(e: MouseEvent, m: ChatMessage) {
    // Selected text keeps the native menu, with its Copy
    if (nativeMenuWanted(e.target, globalThis.getSelection?.()?.toString() ?? "")) return;
    e.preventDefault();
    let [x, y] = [e.clientX, e.clientY];
    if (x === 0 && y === 0) {
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      [x, y] = [r.left + 24, r.top + 8];
    }
    // Kept on screen; the menu is narrow and short
    opened = { m, x: Math.min(x, innerWidth - 220), y: Math.min(y, innerHeight - 160) };
  }

  function act(fn: (m: ChatMessage) => void) {
    const m = opened?.m;
    opened = null;
    if (m) fn(m);
  }

  function threadLine(answers: ChatMessage[]): string {
    const names = [...new Set(answers.map((a) => shortName(a.username)))];
    const who = names.length > 3 ? `${names.slice(0, 3).join(", ")} +${names.length - 3}` : names.join(", ");
    const last = answers.at(-1);
    return `${answers.length} ${answers.length === 1 ? "reply" : "replies"} · ${who}${last ? ` · ${formatTime(last.timestamp)}` : ""}`;
  }
</script>

<svelte:window
  onclick={() => (opened = null)}
  onkeydown={(e) => { if (e.key === "Escape") opened = null; }}
/>

<!-- Keyed by the message object, which the stores carry over from one
     update to the next. The index used to be in the key, so once a
     conversation was full every new message shifted every key and
     rebuilt all 500 rows; the ids a sender mints are not unique enough
     on their own — a peer can repeat one, and a duplicate key throws. -->
{#if newFrom && !newSeen}
  <button class="jump-new" type="button" onclick={() => newEl?.scrollIntoView({ block: "center" })}>
    New messages <Icon name="chevron-down" size={14} class="up" />
  </button>
{/if}

{#each messages as msg, i (msg)}
  {#if !isRow(msg)}
    <div class="history-marker"><span>{msg.content}</span></div>
  {:else}
    {#if startsDay(i)}
      <div class="day-divider" role="separator"><span>{dayLabel(msg.timestamp)}</span></div>
    {/if}
    {#if msg === newFrom}
      <div class="new-divider" role="separator" bind:this={newEl}><span>New</span></div>
    {/if}
    {@const target = msg.reply_to ? findTarget(index, msg.reply_to) : undefined}
    <!-- A row the keyboard can stand on, with the arrows to move: one tab stop
         for the whole list (see "Rows, focus and jumping") -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <div
      class="msg"
      class:to-me={(!!target && isMine(target) && !isMine(msg)) || mentionsMe(msg)}
      class:flash={flashing === msg}
      class:grouped={!shouldShowHeader(i)}
      tabindex={msg === current ? 0 : -1}
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
        {:else}
          <span class="quote missing"><Icon name="reply" size={12} /> Original message is not here</span>
        {/if}
      {:else if orphans?.has(msg)}
        <span class="quote missing"><Icon name="thread" size={12} /> In a thread whose first message is not here</span>
      {/if}
      {#if shouldShowHeader(i)}
        <div class="msg-header">
          <span class="msg-username" class:self={msg.user_id === $userId} title={msg.username}>{shortName(msg.username)}</span>
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
      <div class="msg-content" class:shared={msg.kind === "shared"}>
        {#if msg.kind === "undecryptable"}
          <span class="attachment-placeholder">{msg.content}</span>
        {:else if msg.kind && msg.kind !== "text" && msg.kind !== "shared"}
          <span class="attachment-placeholder">[attachment — not shared]</span>
        {:else}
          <Markdown text={msg.content} {onlink} {names} {me} />
        {/if}
      </div>
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
      <div class="msg-tools" role="toolbar" aria-label="Message actions">
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
        <button class="icon-btn tool" type="button" tabindex={msg === current ? 0 : -1} title="Copy text" aria-label="Copy text" onclick={() => copyText(msg)}>
          <Icon name="copy" size={16} />
        </button>
      </div>
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
    use:menu={{ onclose: () => (opened = null), label: `Message from ${shortName(m.username)}` }}
    onclick={(e) => e.stopPropagation()}
  >
    {#if onreply && answerable(m)}
      <button type="button" onclick={() => act(onreply)}><Icon name="reply" size={16} /> Reply</button>
    {/if}
    {#if onthread && answerable(m)}
      <button type="button" onclick={() => act(onthread)}><Icon name="thread" size={16} /> Reply in thread</button>
    {/if}
    <button type="button" onclick={() => act(copyText)}><Icon name="copy" size={16} /> Copy text</button>
  </div>
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

  /* One message: what it answers, who wrote it, what they wrote, its tools */
  .msg {
    position: relative;
    margin: 0 -8px;
    padding: 0 8px 1px;
    border-radius: var(--r-sm);
    outline: none;
    transition: background-color var(--dur-base);
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
     mouse that clicked one should not leave tools standing over the row */
  .msg:hover .msg-tools,
  .msg:focus-visible .msg-tools,
  .msg:has(:focus-visible) .msg-tools {
    display: flex;
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
</style>
