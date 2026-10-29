<script lang="ts">
  import { backdrop, dialog } from "../actions/dialog.js";
  import type { Snippet } from "svelte";

  interface Props {
    /**
     * Extra controls for the right-hand end of the header.
     *
     * The classic layout has a voice bar to put its room and mixer buttons in;
     * the modern one does not, so they live here. A snippet rather than a
     * `variant` string: one prop, and the shell keeps its own markup.
     */
    headerExtra?: Snippet;
  }
  let { headerExtra }: Props = $props();
  import { invoke } from "@tauri-apps/api/core";
  import { tick, untrack } from "svelte";
  import { channels } from "../stores/channels.js";
  import { uiPrefs } from "../stores/ui-prefs.js";
  import { serverAddress, serverKey, userId, username } from "../stores/connection.js";
  import { addNotification } from "../stores/notifications.js";
  import { confirmAction } from "../stores/confirm.js";
  import { get } from "svelte/store";
  import { account, accountHex } from "../stores/account.js";
  import { users } from "../stores/users.js";
  import { expiryFor, messageRefs, pinnedOf, rowKey, sameRow, splitChatKey, type ChatPlace } from "../chat-rules.js";
  import { threadView } from "../thread-rules.js";
  import type { ChatEvent, ChatMessage, FileConv, FileRef, Forwarded } from "../types.js";
  import { fetchFile, fileLimits, sendFile } from "../files.js";
  import { linkFacts, mentionNames as mentionNamesOf, plainText } from "../markdown.js";
  import { rosterOf } from "../roster-rules.js";
  import { prepare } from "../image-prep.js";
  import { sealedLen } from "../file-rules.js";
  import {
    addDmMessage,
    applyDmEvent,
    dmConversations,
    activeDmUserId,
    activeDmUsername,
    closeDm,
    forgetClearedBefore,
    joinedTextChannelIds,
    unreadPerChannel,
    clearChannelChat,
    clearDmChat,
    chatKey,
    dmKey,
    forgetNewMessages,
    newMessagesAt,
    channelMessages,
    dmMessages,
  } from "../stores/chat.js";
  import {
    channelMessageTtl,
    dmMessageTtl,
    endPreview,
    giveNsfwConsent,
    joinChannel,
    joinTextChannel,
    lastPostAt,
    leftTextChannelNames,
    me,
    notePost,
    messageJump,
    settingsAsk,
    showMessage,
    nsfwConsented,
    setDmMessageTtl,
  } from "../stores/channel-ui.js";
  import { canManage, needsNsfwConsent, postBlock, slowModeLabel } from "../channel-post-rules.js";
  import { currentChannelId } from "../stores/channels.js";
  import { displayChannelId, isPreviewing, shownMessages } from "../stores/roster.js";
  import { channelRosters } from "../stores/rosters.js";
  import Icon from "./Icons.svelte";
  import Composer from "./chat/Composer.svelte";
  import MessageList, { type MessageActions } from "./chat/MessageList.svelte";
  import ThreadPane from "./chat/ThreadPane.svelte";
  import SearchPane from "./chat/SearchPane.svelte";
  import type { Hit } from "../search-rules.js";
  import { shortName } from "../username.js";

  let messagesContainer = $state<HTMLDivElement | null>(null);

  // Links open a copy popup, never a browser (MessageList draws the buttons).
  // It shows, and copies, where the link goes as a browser would read it,
  // with its host on its own line and a word for what is no web address
  // (R2-12).
  let linkPopupUrl = $state<string | null>(null);
  let linkInputEl = $state<HTMLInputElement | null>(null);
  const link = $derived(linkPopupUrl === null ? null : linkFacts(linkPopupUrl));

  $effect(() => {
    if (linkPopupUrl !== null && linkInputEl) {
      linkInputEl.focus();
      linkInputEl.select();
    }
  });

  async function copyLink() {
    if (link === null) return;
    let copied = false;
    try {
      await navigator.clipboard.writeText(link.shown);
      copied = true;
    } catch {
      linkInputEl?.focus();
      linkInputEl?.select();
      copied = document.execCommand("copy");
    }
    if (copied) {
      addNotification("Link copied", "info", 2500);
      linkPopupUrl = null;
    }
    // Not copied: leave the popup open with the URL selected for manual Ctrl+C
  }

  let isDmMode = $derived($activeDmUserId !== null);

  // The channel whose chat is on screen: a preview, then the text channel the
  // user opened, then the channel they stand in. `displayChannelId` and
  // `isPreviewing` come from stores/roster.ts, which the member lists read as
  // well — this pane deriving its own copy would be a second answer to "which
  // channel is being shown", and the pane and the member list are meant to be
  // showing the same one.
  let effectiveChannel = $derived(
    $channels.find((c) => c.channel_id === $displayChannelId)
  );
  let channelName = $derived(effectiveChannel?.name ?? "");
  /** How prose names it: `#` belongs to a text channel, never to a voice one. */
  let channelLabel = $derived(effectiveChannel && !effectiveChannel.text ? channelName : `#${channelName}`);
  let isPasswordProtected = $derived(effectiveChannel?.has_password ?? false);

  // The lobby: in no voice channel on this server, and no other channel open.
  // Nothing to read there — the server keeps no chat for it.
  let isLobby = $derived($displayChannelId === 0);

  // Can send messages only in a channel we are in: not a preview, not the
  // lobby, not a text channel we only have on screen, and not while a DM holds
  // the pane.
  let canSendChannelMessage = $derived(
    !$isPreviewing &&
      !isLobby &&
      !isDmMode &&
      (!effectiveChannel?.text || $joinedTextChannelIds.has($displayChannelId))
  );

  // An announcement channel, or slow mode still counting down: the server
  // would refuse the post, and the pane shows a sent message before it hears
  // back — so the composer asks first (channel-post-rules.ts).
  let isManager = $derived(effectiveChannel ? canManage(effectiveChannel, $me) : false);
  let slowModeSecs = $derived(effectiveChannel?.slow_mode_secs ?? 0);
  /** Ticks once a second while a slow-mode countdown is on screen. */
  let now = $state(Date.now());
  /** Bumped on every send, so the countdown starts without waiting for a tick. */
  let sentCount = $state(0);
  let block = $derived.by(() => {
    void sentCount;
    if (isDmMode || !effectiveChannel) return null;
    return postBlock(effectiveChannel, isManager, lastPostAt($serverAddress, $displayChannelId), now);
  });
  $effect(() => {
    if (slowModeSecs === 0 || isManager || isDmMode) return;
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  // A channel marked 18+ that this server has no consent for: its messages
  // stay hidden behind the question until the user answers it.
  let nsfwGated = $derived(!isDmMode && needsNsfwConsent(effectiveChannel, $nsfwConsented));
  /** The pane shows a gate, not the conversation: nothing of it opens, threads included. */
  const gated = $derived(nsfwGated || (!isDmMode && $isPreviewing && isPasswordProtected && !effectiveChannel?.text));

  // This server's channels: another server's unread is on its icon in the rail
  let totalUnreadChannels = $derived.by(() => {
    const prefix = `${serverKey($serverAddress)}/`;
    let total = 0;
    for (const [key, count] of $unreadPerChannel) {
      if (key.startsWith(prefix)) total += count;
    }
    return total;
  });

  // stores/roster.ts decides which conversation is on screen, for this pane
  // and for the stream view's unread dot alike.
  let displayMessages = $derived($shownMessages);

  // ── Replies and threads ──────────────────────────────────────────────────
  //
  // Answers carry the id of what they answer (thread-rules.ts); which of them
  // fold into a thread is worked out here, from this copy of the conversation.
  const view = $derived(threadView(displayMessages, { auto: $uiPrefs.group_threads }));
  /** Slow mode still counting: a send waits, and the button says how long. */
  let held = $derived(
    block?.kind === "slow"
      ? { label: slowModeLabel(block.remainingSecs), title: `Slow mode: one message every ${slowModeLabel(slowModeSecs)}` }
      : null,
  );
  /** Whether this conversation can be written in, answers included. */
  let canAnswer = $derived(isDmMode || (canSendChannelMessage && block?.kind !== "announce"));
  // Raw: a $state proxy of a message is never === the message itself, and
  // these are looked up in the conversation by identity
  let replyingTo = $state.raw<ChatMessage | null>(null);
  let threadRoot = $state.raw<ChatMessage | null>(null);
  /** A thread's answers as last seen, by its first message's id, for its unread dot. */
  let threadSeen = $state(new Map<string, number>());
  let composer = $state<{ focus: () => void; addFiles: (files: Iterable<File>) => void } | null>(null);
  let mainList = $state<{ jumpTo: (m: ChatMessage) => boolean } | null>(null);
  /** The thread on screen, while its first message is still here: as it is
   *  now, which a reaction or an edit may have made a new object of. */
  const openThread = $derived.by(() => {
    const was = threadRoot;
    const root = was && !gated ? displayMessages.find((m) => sameRow(m, was)) : undefined;
    if (!root) return null;
    return { root, answers: view.threads.get(root) ?? [] };
  });

  // Both belong to the conversation they were opened in
  $effect(() => {
    void $serverAddress;
    void $displayChannelId;
    void $activeDmUserId;
    replyingTo = null;
    threadRoot = null;
  });

  // An open thread's answers count as read, new ones included
  $effect(() => {
    const t = openThread;
    if (!t?.root.id) return;
    void t.answers.length;
    untrack(() => {
      threadSeen.set(t.root.id!, Date.now());
      threadSeen = new Map(threadSeen);
    });
  });

  function replyTo(m: ChatMessage) {
    replyingTo = m;
    composer?.focus();
  }

  /** Open the thread on `m`; `write`: to answer in it, so the box gets the cursor. */
  function openThreadOn(m: ChatMessage, write = false) {
    replyingTo = null;
    threadRoot = m;
    threadWrite = write;
  }
  let threadWrite = $state(false);

  // ── Mentions and "New" ───────────────────────────────────────────────────

  /** The conversation's key in the chat stores. */
  const currentKey = $derived(
    isDmMode ? dmKey($serverAddress, $activeDmUsername) : chatKey($serverAddress, channelName),
  );
  /** Where the unread part of this conversation began, until the reader moves on. */
  const newSince = $derived($newMessagesAt.get(currentKey));
  $effect(() => {
    const key = currentKey;
    return () => forgetNewMessages(key);
  });

  /**
   * Who an `@` can name: the people of the conversation on screen (the
   * channel's roster, not the voice room's; the other person in a direct
   * one). In an anonymous channel every member sees others under pseudonyms
   * of their own, so a name typed there means nothing to anyone else: no
   * mentions at all, ours included (R2-11).
   */
  const anonymousHere = $derived(!isDmMode && !!effectiveChannel?.anonymous);
  // Keyed by the names themselves: the user list is rebuilt for every mute
  // and join, and a new array here would parse every message on screen again
  const mentionKey = $derived(
    anonymousHere
      ? ""
      : (isDmMode
          ? [$activeDmUsername]
          : rosterOf($displayChannelId, $channelRosters, $currentChannelId, $users).map((u) => u.username)
        ).join("\n"),
  );
  const mentionable = $derived(mentionKey ? mentionKey.split("\n") : []);
  /** Full names, and short ones only where one person here goes by it. */
  const mentionNames = $derived(mentionNamesOf(mentionable));
  /** Our own names here, with the tag, and without it where that is ours alone. */
  const myNames = $derived(
    !$username || anonymousHere
      ? []
      : mentionNamesOf([...mentionable, $username]).filter((n) => n === $username || n === shortName($username)),
  );
  /** Who the message box offers after an `@`: everybody but us. */
  const mentionOthers = $derived(mentionable.filter((n) => n !== $username));

  // ── Search ───────────────────────────────────────────────────────────────

  let searching = $state(false);
  let panelEl = $state<HTMLDivElement | null>(null);
  type Conv = ChatPlace;
  const everywhere = $derived.by(() => {
    const out: { conv: Conv; messages: ChatMessage[] }[] = [];
    for (const [kind, map] of [["channel", $channelMessages], ["dm", $dmMessages]] as const) {
      for (const [key, messages] of map) {
        const at = splitChatKey(key);
        if (!at || (kind === "channel" && behindNsfwGate(at.server, at.name))) continue;
        out.push({ conv: { kind, key, ...at }, messages });
      }
    }
    return out;
  });
  /** Every open server's channels, for which of them are 18+. */
  const channelLists = channels.all();
  /** A channel marked 18+ that its server has no consent for: its messages
   *  are not shown, so they are not searched either (R2-15). `server` as chat
   *  keys name it. */
  function behindNsfwGate(server: string, name: string): boolean {
    for (const [address, list] of $channelLists) {
      if (serverKey(address) !== server) continue;
      return needsNsfwConsent(list.find((c) => c.name === name), $uiPrefs.nsfw_ok.includes(server));
    }
    return false;
  }
  function convLabel(c: Conv): string {
    const name = c.kind === "dm" ? `@${shortName(c.name)}` : c.name;
    return c.server === serverKey($serverAddress) ? name : `${name} · ${c.server}`;
  }

  function pickResult(hit: Hit<Conv | null>) {
    searching = false;
    if (hit.conv === null || hit.conv.key === currentKey) {
      tick().then(() => {
        if (!mainList?.jumpTo(hit.msg)) showElsewhere(hit.msg);
      });
      return;
    }
    showMessage(hit.conv, hit.msg, thisPane);
  }

  // The conversation of a message to show came on screen (a search result
  // here, a file in Settings): go to it, once, and only past its gate. A
  // result found here is this pane's to show, not another one's on screen.
  const thisPane = Symbol("chat pane");
  let jumped: { msg: ChatMessage } | null = null;
  $effect(() => {
    const jump = $messageJump;
    if (!jump || jump === jumped || (jump.from && jump.from !== thisPane) || gated || !displayMessages.includes(jump.msg)) return;
    jumped = jump;
    tick().then(() => {
      if (!mainList?.jumpTo(jump.msg)) showElsewhere(jump.msg);
    });
  });

  /** Ctrl+F (⌘F) while the chat has the focus, or nothing has (a click in
   *  the list focuses nothing, and WebView2's own find bar would open, D1-03):
   *  the browser's own find knows nothing of threads. With nothing focused,
   *  the first chat on screen takes it, so two panes never both open. */
  function onWindowKeydown(e: KeyboardEvent) {
    if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== "f" || !panelEl) return;
    const active = document.activeElement;
    const ours =
      panelEl.contains(active) ||
      ((!active || active === document.body) &&
        [...document.querySelectorAll<HTMLElement>(".chat-panel")].find((p) => p.getClientRects().length > 0) === panelEl);
    if (!ours) return;
    e.preventDefault();
    searching = true;
  }

  /** A quote led to a message not drawn in the main flow: it is in a thread. */
  function showElsewhere(m: ChatMessage) {
    for (const [root, answers] of view.threads) {
      if (answers.includes(m)) {
        threadRoot = root;
        return;
      }
    }
  }

  /** From the thread pane, to a message in the conversation itself. */
  function showInMain(m: ChatMessage) {
    threadRoot = null;
    tick().then(() => {
      if (!mainList?.jumpTo(m)) showElsewhere(m);
    });
  }

  // Who in this channel would answer a request for its recent chat. The
  // automatic ask happens once, when joining; this is what the user can do
  // afterwards — having cleared the channel by accident, or because somebody
  // who was away then is here now.
  let historySharers = $derived(
    ($channelRosters.get($displayChannelId) ?? []).filter(
      (u) => u.shares_history && u.user_id !== $userId,
    ),
  );
  let canResync = $derived(!$isPreviewing && !isLobby && !isDmMode && historySharers.length > 0);

  async function resyncHistory() {
    const server = $serverAddress;
    const names = historySharers.map((u) => shortName(u.username)).join(", ");
    try {
      // Deliberate, so it also takes back a deletion: asking is how you undo
      // having cleared a channel, and nothing else reopens that door.
      forgetClearedBefore(server, channelName);
      await invoke("request_channel_history", {
        server,
        channelId: $displayChannelId,
        targetUserIds: historySharers.map((u) => u.user_id),
      });
      addNotification(`Asked ${names} for #${channelName}'s recent chat`, "info", 3000);
    } catch (e) {
      addNotification(`Could not ask for history: ${e}`, "error");
    }
  }

  // Follow the conversation to its end — when it is another conversation, or
  // when this one grew and the reader was already at the end. Not on every
  // change of the list: it is rebuilt for a message on any channel of any
  // server, and following each of those pulled a reader out of the history
  // they were scrolled back into.
  //
  // "At the end" is kept from the reader's own scrolling, never measured when
  // a message comes: rows off screen are only estimated (`content-visibility`,
  // R2-05), so the height says little. And while they are at the end, the end
  // is held there as rows settle into their real size (`followEnd`).
  let atEnd = true;
  let followedConversation = "";
  let followedEnd = "";
  function toEnd() {
    if (messagesContainer) messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }
  $effect.pre(() => {
    const conversation = `${$serverAddress}|${$displayChannelId}|${$activeDmUserId}`;
    const last = displayMessages.at(-1);
    const end = `${displayMessages.length}|${last?.id ?? last?.timestamp ?? ""}`;
    const switched = conversation !== followedConversation;
    if (!switched && end === followedEnd) return;
    followedConversation = conversation;
    followedEnd = end;
    if (switched) atEnd = true;
    if (!atEnd) return;
    tick().then(toEnd);
  });

  /** Hold the end in view while the reader is there and the rows change size. */
  function followEnd(node: HTMLElement) {
    const ro = new ResizeObserver(() => {
      if (atEnd) toEnd();
    });
    ro.observe(node);
    return { destroy: () => ro.disconnect() };
  }

  // Scrolled back into the conversation: a way back down that does not need
  // a long fling (and says when something new arrived meanwhile)
  let scrolledUp = $state(false);
  function onMessagesScroll() {
    const el = messagesContainer;
    if (!el) return;
    const below = el.scrollHeight - el.scrollTop - el.clientHeight;
    atEnd = below < 40;
    scrolledUp = below > 200;
  }
  function jumpToLatest() {
    messagesContainer?.scrollTo({ top: messagesContainer.scrollHeight, behavior: "smooth" });
  }

  // ── Destruction timer ────────────────────────────────────────────────────
  //
  // A channel's is the channel's: the server advertises it, everyone in the
  // room sees the same number, and only its creator or an admin may change it
  // (the gear dialog). A direct message has no such object, so it is this
  // user's own answer for that person, and it travels with each message they
  // write. Either way what is shown here is what our messages will carry.

  const TTL_CHOICES: Array<{ secs: number; label: string }> = [
    { secs: 0, label: "Off" },
    { secs: 5 * 60, label: "5 minutes" },
    { secs: 60 * 60, label: "1 hour" },
    { secs: 8 * 60 * 60, label: "8 hours" },
    { secs: 24 * 60 * 60, label: "24 hours" },
    { secs: 7 * 24 * 60 * 60, label: "7 days" },
  ];

  function ttlLabel(secs: number): string {
    return TTL_CHOICES.find((c) => c.secs === secs)?.label ?? `${Math.round(secs / 60)} minutes`;
  }

  let showTtlPicker = $state(false);
  // Re-read whenever the conversation changes, or the prefs do: `$uiPrefs` and
  // `$channels` are the two stores those answers live in.
  const activeTtl = $derived.by(() => {
    void $uiPrefs;
    void $channels;
    return isDmMode
      ? dmMessageTtl($serverAddress, $activeDmUsername)
      : channelMessageTtl($serverAddress, $displayChannelId);
  });

  function chooseTtl(secs: number) {
    showTtlPicker = false;
    if (!isDmMode) return;
    setDmMessageTtl($serverAddress, $activeDmUsername, secs);
  }

  /**
   * Where what is written now goes: read once, when sending starts. A file
   * takes a while to upload, and the conversation on screen may change
   * meanwhile; its message must still go where its file went.
   */
  type Target =
    | { server: string; dm: { peer: number; name: string; away?: string } }
    | { server: string; channelId: number };
  function targetNow(): Target {
    const server = $serverAddress;
    if (isDmMode) {
      const peer = $activeDmUserId ?? 0;
      const away = peer < 0 ? $dmConversations.find((c) => c.user_id === peer) : undefined;
      return { server, dm: { peer, name: $activeDmUsername, away: away?.account } };
    }
    return { server, channelId: $displayChannelId };
  }

  /**
   * The conversation a file is posted in and fetched from, as the relay names
   * it: a channel by id; a direct one by the other's user id, the one its
   * words go to (a slot of this server run: a reconnect forgets it, see
   * `resetServer`), else by their account while they are away; null where
   * neither names them. Not `users`: that is our voice room, and the other
   * may well be talking elsewhere.
   */
  function fileConvOf(t: Target): FileConv | null {
    if (!("dm" in t)) return t.channelId ? { channel: t.channelId } : null;
    if (t.dm.peer > 0) return { direct: t.dm.peer };
    return t.dm.away ? { account: t.dm.away } : null;
  }
  const fileConv = $derived.by(() => fileConvOf(targetNow()));

  /**
   * The composer hands over what to send; a held one never gets here. `refs`
   * comes from the thread pane; the main composer's answer is `replyingTo`,
   * which joins the thread of what it answers, if that is in one.
   */
  async function sendMessage(content: string, refs?: { replyTo: string; thread: string }, file?: FileRef) {
    const answering = replyingTo;
    replyingTo = null;
    const replyTo = refs?.replyTo ?? answering?.id ?? null;
    const thread = refs?.thread ?? answering?.thread ?? null;
    await sendTo(targetNow(), content, replyTo, thread, file);
  }

  /** Send to `t`; false (and a notice) where it did not go. `more`: a
   *  forwarded message's label, or the event it is instead of a message;
   *  `ttlCap`, the most seconds it may live, whatever the conversation says. */
  async function sendTo(
    t: Target,
    content: string,
    replyTo: string | null,
    thread: string | null,
    file?: FileRef,
    more: { fwd?: Forwarded; event?: ChatEvent; ttlCap?: number } = {},
  ): Promise<boolean> {
    const { fwd, event, ttlCap } = more;
    const capped = (ttl: number) => (ttlCap === undefined ? ttl || null : Math.min(ttl || Infinity, ttlCap));
    const server = t.server;
    try {
      // The destruction timer this conversation carries, stamped inside the
      // ciphertext so every copy of the message dies at the same moment: the
      // channel's own, or for a direct message the one this user set for that
      // person. Zero is no timer, which the backend reads as none.
      if ("dm" in t) {
        const ttlSecs = capped(dmMessageTtl(server, t.dm.name));
        if (t.dm.away) {
          // They are away: the server's copy is the one way it reaches them,
          // and this is our own copy of it.
          const id = await invoke<string>("send_kept_dm", { server, account: t.dm.away, content, ttlSecs, replyTo, thread, file, fwd, event });
          const own = get(account.peek(server));
          const myId = get(userId.peek(server));
          const now = Date.now();
          const by = { user_id: myId, username: own?.name ?? "", account: own ? accountHex(own.info.id) : undefined };
          if (event) {
            applyDmEvent(server, myId, myId, by.username, t.dm.peer, { event, by, at: now, content });
            return true;
          }
          addDmMessage(server, myId, myId, own?.name ?? "", t.dm.peer, {
            user_id: myId,
            username: own?.name ?? "",
            content,
            timestamp: now,
            id,
            account: own ? accountHex(own.info.id) : undefined,
            expires_at: expiryFor(now, ttlSecs, ttlSecs),
            ...messageRefs({ reply_to: replyTo, thread, file, fwd }),
          });
        } else {
          await invoke("send_direct_message", { server, targetUserId: t.dm.peer, content, ttlSecs, replyTo, thread, file, fwd, event });
        }
      } else {
        const channelId = t.channelId;
        // The countdown of the channel written in, which a forward may not
        // be the one on screen
        const slow = get(channels.peek(server)).find((c) => c.channel_id === channelId)?.slow_mode_secs ?? 0;
        if (slow > 0) {
          notePost(server, channelId);
          now = Date.now();
          sentCount++;
        }
        await invoke("send_channel_message", {
          server,
          content,
          channelId,
          ttlSecs: capped(channelMessageTtl(server, channelId)),
          replyTo,
          thread,
          file,
          fwd,
          event,
        });
      }
    } catch (e) {
      console.error("Failed to send message:", e);
      addNotification(`Failed to send message: ${e}`, "error");
      return false;
    }
    return true;
  }

  /**
   * One file, as its own message with `caption`: made ready (a photo made
   * smaller unless `original`), sealed and stored on the relay (progress under
   * `op`), then the message, to where it was written. Throws for the composer
   * to show; `CannotClean` asks the person about sending the original.
   * `refs` come from the thread pane, else the main composer's answer counts.
   */
  async function sendFileMessage(file: File, original: boolean, caption: string, op: string, refs?: { replyTo: string; thread: string }): Promise<void> {
    const t = targetNow();
    const conv = fileConvOf(t);
    if (!conv) throw new Error("Files cannot be sent to them now");
    const answering = refs ? null : replyingTo;
    const ready = await prepare(file, original);
    const max = get(fileLimits.peek(t.server))?.max_bytes;
    // Deflate may shrink a file; what is compressed already will not
    if (max && !ready.compress && sealedLen(ready.bytes.length) > max) {
      throw new Error(`Larger than this server takes (${Math.floor(max / 1_000_000)} MB at most)`);
    }
    const blob = await sendFile(t.server, conv, ready.bytes, ready.compress, op);
    // The answer goes with the first file that goes; a failure keeps it
    if (answering && replyingTo === answering) replyingTo = null;
    const { bytes: _, compress: __, ...about } = ready;
    const replyTo = refs?.replyTo ?? answering?.id ?? null;
    const thread = refs?.thread ?? answering?.thread ?? null;
    if (!(await sendTo(t, caption, replyTo, thread, { ...blob, ...about }))) {
      throw new Error("Not sent");
    }
  }

  // ── Reactions, edits, deletes, pins, forwards ────────────────────────────
  //
  // Each is an event sent into this conversation like a message (an envelope
  // kind, protocol 13), so whatever stops a post stops it too: the relay
  // counts it against slow mode and refuses it in an announcement channel.
  // Who may do what is every reader's to check (chat-rules.ts `applyEvent`).

  /**
   * Send `event` about `m` into `t`, the conversation `m` is in. It lives no
   * longer than `m` does: in a stored log an edit's new text must not outlive
   * the message it changes (R3-06), so it takes what is left of `m`'s timer,
   * and goes not at all once that has run out.
   */
  function sendEvent(t: Target, event: ChatEvent, m: ChatMessage, content = "") {
    const left = m.expires_at === undefined ? undefined : Math.floor((m.expires_at - Date.now()) / 1000);
    if (left !== undefined && left < 1) return;
    void sendTo(t, content, null, null, undefined, { event, ttlCap: left });
  }

  /** What the message tools offer here. Forward is not a post here, and
   *  goes wherever the person may post. */
  const actions = $derived.by((): MessageActions => {
    // Not a member's copy: forwarded, its claimed writer would become a
    // "Forwarded from" label with no mark of hearsay (D-15)
    const forward = (m: ChatMessage) => {
      if (m.kind !== "shared") forwarding = { m, from: fileConv, server: $serverAddress };
    };
    if (!canAnswer || held) return { forward };
    // The conversation these messages are in, read now: a delete is sent
    // after its question is answered, by when another one may be on screen
    const t = targetNow();
    return {
      forward,
      react: (m, emoji, on) => sendEvent(t, { kind: "react", target: m.id!, emoji, on }, m),
      edit: (m, text) => sendEvent(t, { kind: "edit", target: m.id! }, m, text),
      remove: (m) => sendEvent(t, { kind: "delete", target: m.id! }, m),
      // A pin counts only from a manager, which every reader checks
      pin: !isDmMode && isManager ? (m, on) => sendEvent(t, { kind: "pin", target: m.id!, on }, m) : undefined,
    };
  });

  /** The message being forwarded, and where it is fetched from (its file). */
  let forwarding = $state.raw<{ m: ChatMessage; from: FileConv | null; server: string } | null>(null);

  interface Dest {
    key: string;
    label: string;
    target: Target;
    /** Why a post would be refused there now. */
    blocked?: string;
  }

  /** Where a message can be forwarded on this server: the channels we may
   *  write in, and our direct conversations. */
  const destinations = $derived.by((): Dest[] => {
    if (!forwarding) return [];
    const server = forwarding.server;
    const out: Dest[] = [];
    for (const ch of $channels) {
      const here = ch.text ? $joinedTextChannelIds.has(ch.channel_id) : ch.channel_id !== 0 && ch.channel_id === $currentChannelId;
      if (!here) continue;
      const b = postBlock(ch, canManage(ch, $me), lastPostAt(server, ch.channel_id), Date.now());
      out.push({
        key: `c${ch.channel_id}`,
        label: ch.text ? `#${ch.name}` : ch.name,
        target: { server, channelId: ch.channel_id },
        blocked: b?.kind === "announce" ? "Only moderators post here" : b?.kind === "slow" ? `Slow mode: ${slowModeLabel(b.remainingSecs)}` : undefined,
      });
    }
    for (const c of $dmConversations) {
      const away = c.user_id < 0 ? c.account : undefined;
      if (c.user_id < 0 && !away) continue;
      out.push({ key: `d${c.user_id}`, label: `@${shortName(c.username)}`, target: { server, dm: { peer: c.user_id, name: c.username, away } } });
    }
    return out;
  });

  /**
   * Forward the message as a new one of ours in `d`, labelled with who wrote it
   * first and when. Its file goes as it is: the same blob and key, posted
   * there too (`forward_file`), after loading it here if it is not.
   */
  async function forwardTo(d: Dest) {
    const f = forwarding;
    forwarding = null;
    if (!f) return;
    const { m } = f;
    const fwd = m.fwd ?? { name: m.username, at: m.timestamp };
    // A copy only ever dies sooner: a forward goes no later than the message
    // it copies, whatever timer its new conversation has
    const left = m.expires_at === undefined ? undefined : Math.floor((m.expires_at - Date.now()) / 1000);
    if (left !== undefined && left < 1) {
      addNotification("That message's timer has run out", "warning");
      return;
    }
    if (m.file) {
      try {
        const to = fileConvOf(d.target);
        if (!to) throw new Error("files cannot be sent to them now");
        if (f.from) await fetchFile(f.server, f.from, m.file);
        await invoke("forward_file", { server: d.target.server, conv: to, hash: m.file.hash });
      } catch (e) {
        addNotification(`Could not forward the file: ${e}`, "error");
        return;
      }
    }
    if (await sendTo(d.target, m.content, null, null, m.file, { fwd, ttlCap: left })) addNotification(`Forwarded to ${d.label}`, "info", 2500);
  }

  /** A message as one line: a pin's or a forward's. */
  function oneLine(m: ChatMessage): string {
    const text = plainText(m.content);
    return (text.length > 80 ? `${text.slice(0, 80)}…` : text) || m.file?.name || "…";
  }

  /** The channel's pinned messages, newest pin first. */
  const pinned = $derived(isDmMode || gated ? [] : pinnedOf(displayMessages));
  let showPins = $state(false);

  function goToPinned(m: ChatMessage) {
    showPins = false;
    tick().then(() => {
      if (!mainList?.jumpTo(m)) showElsewhere(m);
    });
  }

  /** Files dropped on the conversation go to its composer, which stages them. */
  function dropFiles(e: DragEvent) {
    if (!e.dataTransfer?.types.includes("Files") || !canSendFiles) return;
    e.preventDefault();
    if (e.type === "drop") composer?.addFiles(e.dataTransfer.files);
  }
  const canSendFiles = $derived(!!$fileLimits && fileConv !== null);

  function backToChannel() {
    closeDm($serverAddress);
  }

  /** The trash button with no server copy to think about: asks, then clears. */
  async function confirmClearHere() {
    const where = isDmMode ? `your conversation with ${shortName($activeDmUsername ?? "")}` : channelLabel;
    const ok = await confirmAction({
      title: "Clear this conversation?",
      body: `The messages in ${where} are removed from this device. Everyone else keeps theirs.`,
      confirm: "Clear",
      danger: true,
    });
    if (ok) clearCurrentChat();
  }

  function clearCurrentChat() {
    if (isDmMode) {
      clearDmChat($serverAddress, $activeDmUserId!, $activeDmUsername);
    } else {
      clearChannelChat($serverAddress, channelName);
    }
  }

  // The server's copy of this conversation, where this account keeps one:
  // clearing can delete what we wrote there too (1.0, A6)
  let showClearMenu = $state(false);
  let keptConv = $derived.by(() => {
    const me = $account;
    if (!me?.cloud) return null;
    if (!isDmMode) return effectiveChannel?.log || null;
    const peer =
      $dmConversations.find((c) => c.user_id === $activeDmUserId)?.account ??
      ((a) => (a ? accountHex(a) : undefined))($users.find((u) => u.user_id === $activeDmUserId)?.account);
    if (!peer) return null;
    const [lo, hi] = [accountHex(me.info.id), peer].sort();
    return `d:${lo}:${hi}`;
  });

  function clearAndPurge() {
    const [server, conv] = [$serverAddress, keptConv];
    clearCurrentChat();
    if (conv) invoke("account_purge", { server, conv }).catch((e) => addNotification(`Could not delete the server's copy: ${e}`, "error"));
  }

  function stopKeeping() {
    const [server, conv] = [$serverAddress, keptConv];
    if (conv) invoke("account_leave", { server, conv }).then(
      () => addNotification(`${channelLabel} is no longer kept for you, until you come back to it`, "info"),
      (e) => addNotification(String(e), "error"),
    );
  }
</script>

<!-- Any click elsewhere closes the header's pop-ups; Escape closes them too -->
<svelte:window
  onclick={() => { showClearMenu = false; showTtlPicker = false; showPins = false; }}
  onkeydown={(e) => {
    onWindowKeydown(e);
    if (e.key === "Escape" && (showClearMenu || showTtlPicker || showPins)) {
      showClearMenu = false;
      showTtlPicker = false;
      showPins = false;
    }
  }}
/>

<div class="chat-panel" bind:this={panelEl}>
  <div class="chat-header" class:custom={headerExtra}>
    {#if isDmMode}
      <button aria-label="Back to channel chat" class="back-btn" onclick={backToChannel} title="Back to channel chat"><Icon name="arrow-left" size={16} /></button>
      <span class="chat-title" title={$activeDmUsername}>DM with {shortName($activeDmUsername)}</span>
      {#if totalUnreadChannels > 0}
        <span class="unread-badge" title="Unread channel messages">{totalUnreadChannels}</span>
      {/if}
    {:else}
      {#if $isPreviewing}
        <button aria-label="Stop previewing" class="back-btn" onclick={endPreview} title="Stop previewing"><Icon name="arrow-left" size={16} /></button>
      {/if}
      {#if !isLobby}
        <!-- Channel 0 is "not in voice", not a channel: it has no name to show -->
        <!-- The channel's own kind: a voice channel's chat is not a # channel -->
        <span class="chat-title"
          ><Icon name={effectiveChannel && !effectiveChannel.text ? "volume" : "hash"} size={14} /> {channelName}</span
        >
      {/if}
      {#if $isPreviewing}
        <span class="preview-label">preview</span>
      {/if}
    {/if}
    {#if canResync}
      <button
        class="resync-btn"
        class:first={displayMessages.length === 0 || isLobby}
        onclick={resyncHistory}
        title="Ask {historySharers.map((u) => shortName(u.username)).join(', ')} for recent messages"
        aria-label="Ask for recent messages"
      ><Icon name="history" size={16} /></button>
    {/if}
    {#if activeTtl > 0}
      <span class="ttl-label" title="Every message written here is deleted for everyone once its timer runs out">
        <Icon name="clock" size={13} /> {ttlLabel(activeTtl)}
      </span>
    {/if}
    {#if !isDmMode && !isLobby && effectiveChannel?.text && effectiveChannel?.announce}
      <span class="ttl-label" title="Only the channel's moderators post here">
        <Icon name="megaphone" size={13} /> Announcements
      </span>
    {/if}
    {#if !isDmMode && !isLobby && slowModeSecs > 0}
      <span
        class="ttl-label"
        title="Slow mode: each member may post once every {slowModeLabel(slowModeSecs)}; moderators are exempt"
      >
        <Icon name="hourglass" size={13} /> {slowModeLabel(slowModeSecs)}
      </span>
    {/if}
    {#if !isDmMode && !isLobby && effectiveChannel?.nsfw}
      <span class="ttl-label nsfw-label" title="This channel is marked 18+">18+</span>
    {/if}
    {#if isDmMode}
      <button
        class="clear-chat-btn"
        onclick={(e) => { e.stopPropagation(); showTtlPicker = !showTtlPicker; }}
        title="Delete messages you send here after a while"
        aria-label="Message timer"
        aria-expanded={showTtlPicker}
      ><Icon name="clock" size={16} /></button>
      {#if showTtlPicker}
        <div class="ttl-picker">
          <p class="ttl-note">
            Messages you send {shortName($activeDmUsername)} are deleted on both sides once the timer runs
            out. What they send you carries theirs.
          </p>
          {#each TTL_CHOICES as choice (choice.secs)}
            <button
              class="ttl-choice"
              class:active={activeTtl === choice.secs}
              onclick={() => chooseTtl(choice.secs)}
            >{choice.label}</button>
          {/each}
        </div>
      {/if}
    {/if}
    {#if pinned.length > 0}
      <button
        class="clear-chat-btn pins-btn"
        onclick={(e) => { e.stopPropagation(); showPins = !showPins; }}
        title="Pinned messages"
        aria-label="Pinned messages ({pinned.length})"
        aria-expanded={showPins}
      ><Icon name="pin" size={16} /><span class="num">{pinned.length}</span></button>
      {#if showPins}
        <div class="ttl-picker pins-menu" role="presentation" onclick={(e) => e.stopPropagation()}>
          <p class="ttl-note">Pinned by the channel's moderators</p>
          {#each pinned as p (rowKey(p))}
            <button class="ttl-choice pin-row" onclick={() => goToPinned(p)}>
              <span class="pin-who">{shortName(p.username)}</span>
              <span class="pin-text">{oneLine(p)}</span>
            </button>
          {/each}
        </div>
      {/if}
    {/if}
    {#if !isLobby}
      <button
        class="clear-chat-btn search-btn"
        onclick={() => (searching = !searching)}
        title="Search messages (Ctrl+F)"
        aria-label="Search messages"
        aria-expanded={searching}
      ><Icon name="search" size={16} /></button>
    {/if}
    {#if displayMessages.some((m) => m.file) && !gated}
      <button
        class="clear-chat-btn"
        onclick={() => settingsAsk.set({ tab: "files", place: `${isDmMode ? "dm" : "channel"} ${currentKey}` })}
        title="Files in this conversation"
        aria-label="Files in this conversation"
      ><Icon name="paperclip" size={16} /></button>
    {/if}
    {#if displayMessages.length > 0 && !isLobby}
      <button
        class="clear-chat-btn"
        onclick={(e) => { if (keptConv) { e.stopPropagation(); showClearMenu = !showClearMenu; } else void confirmClearHere(); }}
        title="Clear chat history"
        aria-label="Clear chat history"
        aria-expanded={keptConv ? showClearMenu : undefined}
      ><Icon name="trash" size={16} /></button>
      {#if showClearMenu && keptConv}
        <div class="ttl-picker clear-menu" role="presentation" onclick={(e) => e.stopPropagation()}>
          <button class="ttl-choice" onclick={() => { showClearMenu = false; clearCurrentChat(); }}>Clear here</button>
          <button class="ttl-choice" onclick={() => { showClearMenu = false; clearAndPurge(); }}>
            Clear here, and delete what I wrote from the server's copy
          </button>
          {#if !isDmMode && !effectiveChannel?.text}
            <button class="ttl-choice" onclick={() => { showClearMenu = false; stopKeeping(); }}>Stop keeping this channel's messages for me</button>
          {/if}
          <p class="ttl-note">
            Other people's devices are asked to drop their copies of what you wrote; one that already read them
            may keep them.
          </p>
        </div>
      {/if}
    {/if}
    {#if headerExtra}
      <span class="header-extra">{@render headerExtra()}</span>
    {/if}
  </div>

  <div class="chat-body">
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="chat-main" ondragover={dropFiles} ondrop={dropFiles}>
  <div class="messages" bind:this={messagesContainer} onscroll={onMessagesScroll}>
    {#if !isDmMode && isLobby}
      <div class="empty-state">Open a text channel to chat</div>
    {:else if nsfwGated}
      <div class="empty-state nsfw-gate">
        <p>{channelLabel} is marked <strong>18+</strong>.</p>
        <p>Only open it if you are 18 or older. You will not be asked again on this server.</p>
        <button class="join-text-btn" onclick={() => giveNsfwConsent($serverAddress)}>
          I am 18 or older — show it
        </button>
      </div>
    {:else if !isDmMode && $isPreviewing && isPasswordProtected && !effectiveChannel?.text}
      <div class="empty-state">This channel is password protected. Join to view messages.</div>
    {:else if displayMessages.length === 0}
      <div class="empty-state">
        {#if isDmMode}
          No messages yet. Say hi!
        {:else}
          No messages yet.{#if $isPreviewing}&nbsp;Messages will appear here in real-time.{:else}&nbsp;Start the conversation!{/if}
        {/if}
      </div>
    {:else}
      <div class="message-rows" use:followEnd>
      <MessageList
        bind:this={mainList}
        messages={view.main}
        all={displayMessages}
        threads={view.threads}
        orphans={view.orphans}
        onlink={(url) => (linkPopupUrl = url)}
        onreply={canAnswer ? replyTo : undefined}
        onthread={canAnswer ? (m) => openThreadOn(m, true) : undefined}
        onopenthread={(m) => openThreadOn(m)}
        threadSeen={(root) => (root.id ? threadSeen.get(root.id) : undefined) ?? 0}
        onjumpelsewhere={showElsewhere}
        names={mentionNames}
        me={myNames}
        {newSince}
        server={$serverAddress}
        {fileConv}
        {actions}
      />
      </div>
      {#if scrolledUp}
        <button class="jump-latest" onclick={jumpToLatest}>
          <Icon name="chevron-down" size={14} /> Jump to latest
        </button>
      {/if}
    {/if}
  </div>

  {#if isDmMode}
    <Composer
      bind:this={composer}
      placeholder={`Message ${shortName($activeDmUsername)}...`}
      mentionables={mentionOthers}
      conversation={`${$serverAddress}|dm|${$activeDmUserId}`}
      onsend={sendMessage}
      onsendfile={canSendFiles ? sendFileMessage : undefined}
      replying={replyingTo?.username ?? null}
      oncancelreply={() => (replyingTo = null)}
    />
  {:else if canSendChannelMessage && block?.kind === "announce"}
    <div class="preview-footer post-block">
      <Icon name="megaphone" size={14} /> Only moderators can post in #{channelName}
    </div>
  {:else if canSendChannelMessage}
    <Composer
      bind:this={composer}
      placeholder={`Message ${channelLabel}…`}
      mentionables={mentionOthers}
      conversation={`${$serverAddress}|${$displayChannelId}`}
      {held}
      onsend={sendMessage}
      onsendfile={canSendFiles ? sendFileMessage : undefined}
      replying={replyingTo?.username ?? null}
      oncancelreply={() => (replyingTo = null)}
    />
  {:else if effectiveChannel?.text}
    <div class="preview-footer">
      <button class="join-text-btn" onclick={() => joinTextChannel(effectiveChannel!)}>
        {#if $leftTextChannelNames.has(channelName)}
          Rejoin #{channelName} — you left this channel
        {:else}
          Join #{channelName} to write here
        {/if}
      </button>
    </div>
  {:else if $isPreviewing && !isLobby}
    <!-- The way into a voice channel, next to the pane a click already opened.
         A double click on the row does the same, but there is no such gesture
         on a phone. Password-protected too: `joinChannel` opens the prompt. -->
    <div class="preview-footer">
      <button
        class="join-voice-btn"
        onclick={() => joinChannel($displayChannelId, isPasswordProtected)}
        title="Moves you into {channelName}, and takes your voice with you"
      >Join {channelName} to talk and chat</button>
    </div>
  {/if}
  </div>
  {#if searching}
    <SearchPane
      here={gated ? [] : displayMessages}
      {everywhere}
      labelOf={convLabel}
      onpick={pickResult}
      onclose={() => (searching = false)}
    />
  {:else if openThread}
    <ThreadPane
      root={openThread.root}
      focusComposer={threadWrite}
      answers={openThread.answers}
      all={displayMessages}
      {held}
      onsend={canAnswer ? sendMessage : undefined}
      onsendfile={canAnswer && canSendFiles ? sendFileMessage : undefined}
      onlink={(url) => (linkPopupUrl = url)}
      onclose={() => (threadRoot = null)}
      onjumpelsewhere={showInMain}
      names={mentionNames}
      me={myNames}
      mentionables={mentionOthers}
      server={$serverAddress}
      {fileConv}
      {actions}
    />
  {/if}
  </div>
</div>

{#if forwarding}
  {@const m = forwarding.m}
  <div class="link-overlay" role="presentation" onclick={backdrop(() => (forwarding = null))}>
    <div class="link-dialog forward-dialog" aria-label="Forward message" use:dialog={{ onclose: () => (forwarding = null) }}>
      <span class="link-title">Forward to…</span>
      <p class="forward-quote"><strong>{shortName(m.fwd?.name ?? m.username)}</strong> {oneLine(m)}</p>
      {#if destinations.length === 0}
        <p class="ttl-note">Join a channel, or open a conversation with someone, to forward this there.</p>
      {/if}
      <ul class="forward-list">
        {#each destinations as d (d.key)}
          <li>
            <button class="forward-dest" type="button" disabled={!!d.blocked} onclick={() => forwardTo(d)}>
              <span>{d.label}</span>
              {#if d.blocked}<span class="forward-why">{d.blocked}</span>{/if}
            </button>
          </li>
        {/each}
      </ul>
      <div class="link-actions">
        <button class="link-close-btn" onclick={() => (forwarding = null)}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

{#if linkPopupUrl !== null}
  <div class="link-overlay" role="presentation" onclick={backdrop(() => (linkPopupUrl = null))}>
    <div
      class="link-dialog"
      aria-label="Copy link"
      use:dialog={{ onclose: () => (linkPopupUrl = null) }}
    >
      <span class="link-title">Copy link</span>
      <input
        class="link-input"
        readonly
        aria-label="Where the link goes"
        bind:this={linkInputEl}
        value={link?.shown ?? ""}
        onfocus={(e) => e.currentTarget.select()}
      />
      {#if link?.web}
        <p class="link-host">Goes to <strong>{link.host}</strong></p>
      {:else}
        <p class="link-host not-web">Not a web address: check it before you paste it anywhere</p>
      {/if}
      <div class="link-actions">
        <button class="link-copy-btn" onclick={copyLink}>Copy</button>
        <button class="link-close-btn" onclick={() => (linkPopupUrl = null)}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .chat-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
    flex: 1;
    min-width: 0;
  }

  .ttl-label {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: 8px;
    font-size: var(--fs-sm);
    color: var(--text-muted);
    white-space: nowrap;
  }

  .ttl-picker {
    position: absolute;
    top: 100%;
    right: 8px;
    z-index: var(--z-sticky);
    display: flex;
    flex-direction: column;
    min-width: 200px;
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-secondary);
    box-shadow: var(--shadow-menu);
  }

  .ttl-note {
    margin: 4px 6px 8px;
    font-size: var(--fs-micro);
    line-height: 1.4;
    color: var(--text-muted);
  }

  .ttl-choice {
    padding: 6px 8px;
    border: none;
    border-radius: 4px;
    background: none;
    color: var(--text-primary);
    font-size: var(--fs-sm);
    text-align: left;
    cursor: pointer;
  }

  .ttl-choice:hover {
    background: var(--bg-hover, var(--bg-tertiary));
  }

  .ttl-choice.active {
    color: var(--text-primary);
    font-weight: 600;
  }

  .chat-header {
    display: flex;
    align-items: center;
    /* the timer picker hangs off it */
    position: relative;
    gap: 8px;
    padding: 12px 16px;
    /* A channel's name as its owner wrote it: shouted in tracked capitals it
       was neither (and "# LOUNGE" was a voice channel) */
    font-size: var(--fs-md);
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
  }

  .chat-title {
    color: var(--text-primary);
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .back-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .back-btn:hover {
    color: var(--text-primary);
  }

  /* The clear button sits at the right end unless the shell put controls
     there, in which case they take the margin and it stays beside the title. */
  .chat-header.custom .clear-chat-btn,
  .chat-header.custom .resync-btn.first {
    margin-left: 0;
  }

  /* Same quiet treatment as the clear button it sits beside */
  .resync-btn {
    display: flex;
    align-items: center;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    /* Quiet, not hidden: 0.35 left them invisible on a touch screen */
    opacity: 0.7;
    transition: opacity var(--dur-fast);
  }

  /* Takes the margin when it is the first of the two */
  .resync-btn.first {
    margin-left: auto;
  }

  .chat-header:hover .resync-btn,
  .resync-btn:focus-visible {
    opacity: 1;
  }

  .resync-btn:hover {
    color: var(--text-primary);
  }

  .header-extra {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-left: auto;
  }

  .clear-chat-btn {
    display: flex;
    align-items: center;
    margin-left: auto;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    /* Quiet, not hidden: 0.35 left them invisible on a touch screen */
    opacity: 0.7;
    transition: opacity var(--dur-fast);
  }

  .chat-header:hover .clear-chat-btn,
  .clear-chat-btn:focus-visible {
    opacity: 1;
  }

  .clear-chat-btn:hover {
    color: var(--danger);
  }

  .unread-badge {
    background: var(--text-primary);
    color: var(--bg-primary);
    font-size: var(--fs-micro);
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 600;
  }

  /* The conversation, and beside it (or over it, where there is no room) an
     open thread */
  .chat-body {
    flex: 1;
    min-height: 0;
    display: flex;
    position: relative;
    container-type: inline-size;
  }

  .chat-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .chat-body > :global(.thread-pane),
  .chat-body > :global(.search-pane) {
    width: min(380px, 45%);
    border-left: 1px solid var(--border);
  }

  @container (max-width: 700px) {
    .chat-body > :global(.thread-pane),
    .chat-body > :global(.search-pane) {
      position: absolute;
      inset: 0;
      width: auto;
      border-left: none;
      z-index: var(--z-pane);
    }
  }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 8px 16px;
  }

  /* Rides the bottom of the list while you read further up */
  .jump-latest {
    position: sticky;
    bottom: 8px;
    left: 100%;
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 8px 0 0 auto;
    padding: 6px 12px;
    border-radius: var(--r-pill);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-menu);
    font-size: var(--fs-sm);
  }

  .jump-latest:hover {
    background: var(--bg-hover);
  }

  .empty-state {
    color: var(--text-secondary);
    font-size: var(--fs-body);
    text-align: center;
    padding: 32px 16px;
    font-style: italic;
  }

  .link-overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-popover);
  }

  .link-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    width: 420px;
    max-width: 90vw;
    display: flex;
    flex-direction: column;
    gap: 12px;
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
  }

  .link-title {
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .link-host {
    margin: -4px 0 0;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    overflow-wrap: anywhere;
  }

  .link-host strong {
    color: var(--text-primary);
  }

  .link-host.not-web {
    color: var(--danger);
  }

  .link-input {
    width: 100%;
    font-size: var(--fs-body);
    padding: 8px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
  }

  .link-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .link-copy-btn {
    background: var(--accent);
    color: var(--on-accent);
    padding: 6px 16px;
    font-size: var(--fs-body);
    border-radius: 4px;
  }

  .link-close-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 6px 16px;
    font-size: var(--fs-body);
    border-radius: 4px;
  }

  .pins-btn {
    gap: 2px;
    font-size: var(--fs-sm);
  }

  .pins-btn:hover {
    color: var(--text-primary);
  }

  .pins-menu {
    max-width: min(360px, calc(100vw - 32px));
    max-height: 320px;
    overflow-y: auto;
  }

  .pin-row {
    display: flex;
    gap: 6px;
    min-width: 0;
  }

  .pin-who {
    flex-shrink: 0;
    font-weight: 600;
  }

  .pin-text {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-secondary);
  }

  .forward-quote {
    margin: 0;
    padding-left: 8px;
    border-left: 2px solid var(--border);
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    overflow-wrap: anywhere;
  }

  .forward-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
    max-height: 50vh;
    overflow-y: auto;
  }

  .forward-dest {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
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

  .forward-dest:hover:not(:disabled),
  .forward-dest:focus-visible {
    background: var(--bg-hover);
  }

  .forward-dest:disabled {
    color: var(--text-muted);
    cursor: default;
  }

  .forward-why {
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  .preview-label {
    font-size: var(--fs-micro);
    color: var(--text-muted);
    border: 1px solid var(--text-muted);
    padding: 1px 5px;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .preview-footer {
    padding: 10px 16px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
    font-style: italic;
  }

  .preview-footer.post-block {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }

  .nsfw-label {
    color: var(--danger);
    font-weight: 600;
  }

  .nsfw-gate p {
    margin: 0 0 10px;
    font-style: normal;
  }

  .join-text-btn,
  .join-voice-btn {
    min-height: var(--hit);
    padding: 4px 12px;
    background: var(--accent);
    color: var(--on-accent);
    border: none;
    border-radius: 4px;
    font-size: var(--fs-sm);
    font-style: normal;
  }
</style>
