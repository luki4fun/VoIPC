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
  import { openServers } from "../stores/servers.js";
  import { addNotification } from "../stores/notifications.js";
  import { confirmAction } from "../stores/confirm.js";
  import { get } from "svelte/store";
  import { account, accountHex } from "../stores/account.js";
  import { users } from "../stores/users.js";
  import { expiryFor, messageRefs } from "../chat-rules.js";
  import { threadView } from "../thread-rules.js";
  import type { ChatMessage } from "../types.js";
  import {
    addDmMessage,
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
    openDm,
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
    selectChannel,
    nsfwConsented,
    setDmMessageTtl,
  } from "../stores/channel-ui.js";
  import { canManage, needsNsfwConsent, postBlock, slowModeLabel } from "../channel-post-rules.js";
  import { displayChannelId, isPreviewing, shownMessages } from "../stores/roster.js";
  import { channelRosters } from "../stores/rosters.js";
  import Icon from "./Icons.svelte";
  import Composer from "./chat/Composer.svelte";
  import MessageList from "./chat/MessageList.svelte";
  import ThreadPane from "./chat/ThreadPane.svelte";
  import SearchPane from "./chat/SearchPane.svelte";
  import type { Hit } from "../search-rules.js";
  import { shortName } from "../username.js";

  let messagesContainer = $state<HTMLDivElement | null>(null);

  // Links open a copy popup, never a browser (MessageList draws the buttons)
  let linkPopupUrl = $state<string | null>(null);
  let linkInputEl = $state<HTMLInputElement | null>(null);

  $effect(() => {
    if (linkPopupUrl !== null && linkInputEl) {
      linkInputEl.focus();
      linkInputEl.select();
    }
  });

  async function copyLink() {
    if (linkPopupUrl === null) return;
    let copied = false;
    try {
      await navigator.clipboard.writeText(linkPopupUrl);
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
  let composer = $state<{ focus: () => void } | null>(null);
  let mainList = $state<{ jumpTo: (m: ChatMessage) => boolean } | null>(null);
  /** The thread on screen, while its first message is still here. */
  const openThread = $derived.by(() => {
    const root = threadRoot;
    if (!root || !displayMessages.includes(root)) return null;
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

  /** Our own name here, with its tag, and without. */
  const myNames = $derived($username ? [...new Set([$username, shortName($username)])] : []);
  /**
   * Who an `@` can name. In an anonymous channel every member sees others
   * under pseudonyms of their own, so a name typed there means nothing to
   * anyone else: no mentions at all.
   */
  // Keyed by the names themselves: the user list is rebuilt for every mute
  // and join, and a new array here would parse every message on screen again
  const mentionKey = $derived(
    !isDmMode && effectiveChannel?.anonymous ? "" : $users.map((u) => u.username).join("\n"),
  );
  const mentionable = $derived(mentionKey ? mentionKey.split("\n") : []);
  const mentionNames = $derived([...new Set(mentionable.flatMap((n) => [n, shortName(n)]))]);
  /** Who the message box offers after an `@`: everybody but us. */
  const mentionOthers = $derived(mentionable.filter((n) => !myNames.includes(n)));

  // ── Search ───────────────────────────────────────────────────────────────

  let searching = $state(false);
  let panelEl = $state<HTMLDivElement | null>(null);
  /** A result in another conversation: shown once that conversation is on screen. */
  let pendingJump = $state.raw<ChatMessage | null>(null);

  interface Conv {
    kind: "channel" | "dm";
    key: string;
    /** `host:port`, as chat keys carry it. */
    server: string;
    name: string;
  }
  /** `host:port/name`; a channel name may hold a slash of its own. */
  function splitChatKey(key: string): { server: string; name: string } | null {
    const m = /^([^/]+:\d+)\/(.*)$/s.exec(key);
    return m ? { server: m[1], name: m[2] } : null;
  }
  const everywhere = $derived.by(() => {
    const out: { conv: Conv; messages: ChatMessage[] }[] = [];
    for (const [kind, map] of [["channel", $channelMessages], ["dm", $dmMessages]] as const) {
      for (const [key, messages] of map) {
        const at = splitChatKey(key);
        if (at) out.push({ conv: { kind, key, ...at }, messages });
      }
    }
    return out;
  });
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
    const conv = hit.conv;
    const server = $openServers.find((s) => serverKey(s) === conv.server);
    if (!server) {
      addNotification(`${conv.server} is not connected: connect to read that conversation`, "info");
      return;
    }
    if (server !== $serverAddress) serverAddress.set(server);
    if (conv.kind === "dm") {
      const peer =
        get(dmConversations.peek(server)).find((c) => c.username === conv.name) ??
        get(users.peek(server)).find((u) => u.username === conv.name);
      if (!peer) {
        addNotification(`Your conversation with ${shortName(conv.name)} is not open now`, "info");
        return;
      }
      openDm(server, peer.user_id, peer.username);
    } else {
      const channel = get(channels.peek(server)).find((c) => c.name === conv.name);
      if (!channel) {
        addNotification(`${conv.name} is not on that server any more`, "info");
        return;
      }
      void selectChannel(channel);
    }
    pendingJump = hit.msg;
    setTimeout(() => (pendingJump = null), 3000);
  }

  // The conversation a result was in came on screen: go to the result
  $effect(() => {
    const m = pendingJump;
    if (!m || !displayMessages.includes(m)) return;
    pendingJump = null;
    tick().then(() => {
      if (!mainList?.jumpTo(m)) showElsewhere(m);
    });
  });

  /** Ctrl+F (⌘F) while the chat has the focus: the browser's own find knows nothing of threads. */
  function onWindowKeydown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f" && panelEl?.contains(document.activeElement)) {
      e.preventDefault();
      searching = true;
    }
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
  // they were scrolled back into. Measured before the DOM update (`.pre`),
  // which is the only moment "at the end" still describes what they saw.
  let followedConversation = "";
  let followedEnd = "";
  $effect.pre(() => {
    const conversation = `${$serverAddress}|${$displayChannelId}|${$activeDmUserId}`;
    const last = displayMessages.at(-1);
    const end = `${displayMessages.length}|${last?.id ?? last?.timestamp ?? ""}`;
    const switched = conversation !== followedConversation;
    if (!switched && end === followedEnd) return;
    followedConversation = conversation;
    followedEnd = end;
    const el = untrack(() => messagesContainer);
    const atEnd = !el || el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    if (!switched && !atEnd) return;
    tick().then(() => {
      if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      }
    });
  });

  // Scrolled back into the conversation: a way back down that does not need
  // a long fling (and says when something new arrived meanwhile)
  let scrolledUp = $state(false);
  function onMessagesScroll() {
    const el = messagesContainer;
    if (!el) return;
    scrolledUp = el.scrollHeight - el.scrollTop - el.clientHeight > 200;
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
   * The composer hands over what to send; a held one never gets here. `refs`
   * comes from the thread pane; the main composer's answer is `replyingTo`,
   * which joins the thread of what it answers, if that is in one.
   */
  async function sendMessage(content: string, refs?: { replyTo: string; thread: string }) {
    const server = $serverAddress;
    const answering = replyingTo;
    replyingTo = null;
    const replyTo = refs?.replyTo ?? answering?.id ?? null;
    const thread = refs?.thread ?? answering?.thread ?? null;

    try {
      // The destruction timer this conversation carries, stamped inside the
      // ciphertext so every copy of the message dies at the same moment: the
      // channel's own, or for a direct message the one this user set for that
      // person. Zero is no timer, which the backend reads as none.
      if (isDmMode) {
        const ttlSecs = dmMessageTtl(server, $activeDmUsername) || null;
        const away = ($activeDmUserId ?? 0) < 0 ? $dmConversations.find((c) => c.user_id === $activeDmUserId) : undefined;
        if (away?.account) {
          // They are away: the server's copy is the one way it reaches them,
          // and this is our own copy of it.
          const id = await invoke<string>("send_kept_dm", { server, account: away.account, content, ttlSecs, replyTo, thread });
          const own = get(account.peek(server));
          const myId = get(userId.peek(server));
          const now = Date.now();
          addDmMessage(server, myId, myId, own?.name ?? "", away.user_id, {
            user_id: myId,
            username: own?.name ?? "",
            content,
            timestamp: now,
            id,
            account: own ? accountHex(own.info.id) : undefined,
            expires_at: expiryFor(now, ttlSecs, ttlSecs),
            ...messageRefs({ reply_to: replyTo, thread }),
          });
        } else {
          await invoke("send_direct_message", { server, targetUserId: $activeDmUserId, content, ttlSecs, replyTo, thread });
        }
      } else {
        const channelId = $displayChannelId;
        if (slowModeSecs > 0) {
          notePost(server, channelId);
          now = Date.now();
          sentCount++;
        }
        await invoke("send_channel_message", {
          server,
          content,
          channelId,
          ttlSecs: channelMessageTtl(server, channelId) || null,
          replyTo,
          thread,
        });
      }
    } catch (e) {
      console.error("Failed to send message:", e);
      addNotification(`Failed to send message: ${e}`, "error");
    }
  }

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
  onclick={() => { showClearMenu = false; showTtlPicker = false; }}
  onkeydown={(e) => {
    onWindowKeydown(e);
    if (e.key === "Escape" && (showClearMenu || showTtlPicker)) {
      showClearMenu = false;
      showTtlPicker = false;
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
    {#if !isLobby}
      <button
        class="clear-chat-btn search-btn"
        onclick={() => (searching = !searching)}
        title="Search messages (Ctrl+F)"
        aria-label="Search messages"
        aria-expanded={searching}
      ><Icon name="search" size={16} /></button>
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
  <div class="chat-main">
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
      />
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
      here={displayMessages}
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
      onlink={(url) => (linkPopupUrl = url)}
      onclose={() => (threadRoot = null)}
      onjumpelsewhere={showInMain}
      names={mentionNames}
      me={myNames}
      mentionables={mentionOthers}
    />
  {/if}
  </div>
</div>

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
        bind:this={linkInputEl}
        value={linkPopupUrl}
        onfocus={(e) => e.currentTarget.select()}
      />
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
