<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, untrack } from "svelte";
  import { get } from "svelte/store";
  import { answerFileWanted, fileLimits, noteProgress, startFileRetain, type FileProgress } from "./lib/files";
  import type { FileConv } from "./lib/types";

  import ConnectDialog from "./lib/components/ConnectDialog.svelte";
  import ScreenShareSourcePicker from "./lib/components/ScreenShareSourcePicker.svelte";
  import SettingsPanel from "./lib/components/SettingsPanel.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import ConfirmDialog from "./lib/components/ConfirmDialog.svelte";
  import InvitePopup from "./lib/components/InvitePopup.svelte";
  import PokePopup from "./lib/components/PokePopup.svelte";
  import VoiceKeys from "./lib/components/VoiceKeys.svelte";
  import LayoutSetup from "./lib/components/LayoutSetup.svelte";
  import ModernShell from "./lib/components/modern/ModernShell.svelte";
  import StageShell from "./lib/components/stage/StageShell.svelte";
  import UserContextMenu from "./lib/components/UserContextMenu.svelte";
  import SharePreview from "./lib/components/SharePreview.svelte";
  import ChannelDialogs from "./lib/components/ChannelDialogs.svelte";
  import AccountPrompts from "./lib/components/AccountPrompts.svelte";
  import AdminDialogs from "./lib/components/AdminDialogs.svelte";

  import {
    connectionState,
    serverAddress,
    userId,
    username,
    latency,
    viaTcp,
    isMuted,
    isDeafened,
    isTransmitting,
    transmitHeldByGame,
    isAdmin,
    pendingInvite,
    pendingJoin,
    rememberChannelPassword,
    serverKey,
  } from "./lib/stores/connection.js";
  import {
    channelLayout,
    groupStyles,
    layoutArrived,
    channels,
    currentChannelId,
    previewChannelId,
    previewUsers,
    voice,
    voiceChannel,
    voiceServer,
    voiceUsers,
  } from "./lib/stores/channels.js";
  import { patchUser, users, speakingUsers } from "./lib/stores/users.js";
  import { account, accountHex, shareRight } from "./lib/stores/account.js";
  import { blocked } from "./lib/stores/blocks.js";
  import { isBlocked, silenceChanges } from "./lib/block-rules.js";
  import { addNotification, removeNotification } from "./lib/stores/notifications.js";
  import { availableUpdate, initUpdates } from "./lib/stores/updates.js";
  import { updateToast, type UpdateInfo } from "./lib/update-rules.js";
  import { pendingInvites } from "./lib/stores/invites.js";
  import { pendingPokes, createPoke, addPoke } from "./lib/stores/pokes.js";
  import {
    addChannelMessage,
    noteNeverOpened,
    addChannelLineAtTop,
    addDmMessage,
    detachDm,
    peerName,
    applyChannelEvent,
    applyDmEvent,
    fileStoredChannelMessage,
    activeDmUsername,
    startExpirySweep,
    activeDmUserId,
    activeTextChannelId,
    dmConversations,
    incrementChannelUnread,
    noteChannelUnseen,
    clearChannelUnread,
    markRead,
    dmKey,
    chatKey,
    chatUnlocked,
    authorsHere,
    channelMessages,
    joinedTextChannelIds,
    mergeChannelHistory,
    onPostsHidden,
    openTextChannel,
    flushChatSave,
    quietBlockedDms,
    receivedNow,
    noteChannelLogNames,
  } from "./lib/stores/chat.js";
  import ChatHistorySetup from "./lib/components/ChatHistorySetup.svelte";
  import AudioSetup from "./lib/components/AudioSetup.svelte";
  import type { ChannelInfo, ChatMessage, UserInfo } from "./lib/types.js";
  import { parseInviteFragment, parseJoinFragment } from "./lib/invite.js";
  import {
    channelListArrived,
    disconnectServer,
    fromServer,
    listenServer,
    reconnectAll,
    withReloadServers,
    serverId,
    resetServer,
    sayConnectionLost,
    showConnectDialog,
    startReconnect,
    updateNeeded,
    type UpdateNeeded,
  } from "./lib/connect.js";
  import { openServers, serverName } from "./lib/stores/servers.js";
  import {
    inputDevice,
    outputDevice,
    volume,
    pttKey,
    pttHoldMode,
    noiseSuppression,
    rememberConnection,
    lastHost,
    lastPort,
    lastUsername,
    lastAcceptSelfSigned,
    autoConnect,
    savedServers,
    soundSettings,
    inputGain,
    muteKey,
    deafenKey,
    chatHistoryDisabled,
    shareChannelHistory,
    maxConversations,
    screenShareCodec,
    spatialAudio,
    screenAudioSpatial,
    AUDIO_SETUP_VERSION,
    audioSetupVersion,
    audioSetupRequested,
    defaultServer,
  } from "./lib/stores/settings.js";
  import type { AppConfig, SavedServer } from "./lib/stores/settings.js";
  import {
    hydrateUiPrefs,
    layoutAskedVersion,
    uiLayout,
    uiPrefs,
    uiPrefsReady,
  } from "./lib/stores/ui-prefs.js";
  import {
    addToRoster,
    channelRosters,
    exchangedKey,
    goneFrom,
    noteJoin,
    noteLeft,
    currentRosterOf,
    onlineById,
    patchRosters,
    requestAllRosters,
    requestRoster,
    forgetUser,
    rosterAccount,
    setRoster,
    textSeats,
  } from "./lib/stores/rosters.js";
  import { emoteLimits, metered, setEmotes, type EmoteLimits, type EmoteSet } from "./lib/stores/emotes.js";
  import { UNOPENED_LINE, answersHandOff, clampedLine, spendServe, type ServeBudget } from "./lib/history-rules.js";
  import { olderRelay } from "./lib/stores/relay.js";
  import { community, livePath } from "./lib/relay-rules.js";
  import { askArchiveChannels } from "./lib/stores/imported.js";
  import { noteMemberGone, onSweepPage, startSweeps, sweepForAsker } from "./lib/stores/sweep.js";
  import { afterJoin, joinedNow } from "./lib/stores/join-wait.js";
  import { goesByList, marksChannel } from "./lib/follow-rules.js";
  import { gateNoted, noteReaders, relayWentBack, type NamedReader } from "./lib/stores/noticing.js";
  import { forgetHandOff, handOffAnswered } from "./lib/stores/handoff.js";
  import { clearRing, flushMarks, moveRead, noteLastPost, ringBack, ringForPost } from "./lib/stores/marks.js";
  import { networkChanged } from "./lib/stores/quiet.js";
  import { confirmAction } from "./lib/stores/confirm.js";
  import {
    askNsfwConsent,
    autoJoinTextChannels,
    channelMessageTtl,
    dmMessageTtl,
    forgetLeft,
    isTextChannel,
    listenOnly,
    hideCheck,
    managesChannel,
    openJoinedTextChannel,
    previewChannel,
    settingsAsk,
    channelNotify,
    channelRenamed,
    channelsListed,
    firstVisit,
    forgetAutoJoinAsk,
    markKicked,
    type PostFlags,
    selectChannel,
  } from "./lib/stores/channel-ui.js";
  import { arrival, pageInView } from "./lib/notify-rules.js";
  import { cleanLayout, type ChannelLayout } from "./lib/channel-groups.js";
  import type { GroupStyle } from "./lib/member-sections.js";
  import type { WireProfile } from "./lib/profile-rules.js";
  import { callsOn, hasPower, ownMentionNames, powerTokens, tokensForMe } from "./lib/mention-rules.js";
  import { chatMods, mentionPower, myBadges, onChatMods, onMentionPower, onReportTakers, reportTakers } from "./lib/stores/powers.js";
  import { onRestrictions, restrictions, voiceRestriction } from "./lib/stores/restrictions.js";
  import { heldNotice, type RestrictionRow } from "./lib/restrict-rules.js";
  import { writerTag } from "./lib/profile-rules.js";
  import { askProfile, askProfiles, onPicture, onProfiles, onServerProfile } from "./lib/stores/profiles.js";
  type ServerProfileEvent = Parameters<typeof onServerProfile>[1];
  import {
    chatEvent,
    expiryFor,
    handOffOf,
    MAX_CONVERSATIONS,
    messageRefs,
    notificationBody,
    receivedText,
  } from "./lib/chat-rules.js";
  import { LAYOUT_PICKER_VERSION } from "./lib/ui-prefs.js";
  import { stopTransmit, voiceMode, vadThreshold } from "./lib/stores/voice.js";
  import {
    playChannelSwitchSound,
    playUserJoinedSound,
    playUserLeftSound,
    playDisconnectedSound,
    playDirectMessageSound,
    playChannelMessageSound,
    playPokeSound,
  } from "./lib/sounds.js";
  import { isMobile, isWeb } from "./lib/stores/platform.js";
  import {
    audibleIds,
    centreView,
    clearRoom,
    currentProximity,
    drivenBy,
    positions,
    selectedUserId,
    syncing,
  } from "./lib/stores/room.js";
  import { eachOnce, upsertById } from "./lib/stores/upsert.js";
  import { shortName } from "./lib/username.js";
  import { mentionsName, parse } from "./lib/markdown.js";
  import { findTarget, isOwn } from "./lib/thread-rules.js";
  import { cleanLane, micLane, silenceUser, silencedIds } from "./lib/stores/mixer.js";
  import {
    addScreenShare,
    removeScreenShare,
    watchingUserId,
    isSharingScreen,
    viewerCount,
    currentFrame,
    shareResolution,
    shareFps,
    showSourcePicker,
    resetScreenShareState,
    screenAudioSending,
    screenAudioReceiving,
    poppedOut,
    getPopoutWindow,
    setPopoutWindow,
    senderFps,
    senderBitrate,
    receiverFps,
    receiverBitrate,
    receiverResolution,
    receiverFramesDropped,
    previewFrame,
    previewShown,
    streamStage,
  } from "./lib/stores/screenshare.js";

  // Look up channel name by numeric ID (stable key for chat history). Per
  // server: an id is a slot in one server's list and means nothing on another.
  function channelNameById(server: string, channelId: number): string {
    return get(channels.peek(server)).find((c) => c.channel_id === channelId)?.name ?? "";
  }

  /**
   * The name a channel knows us by. Our own messages are echoed locally under
   * the name we connected with, which in an anonymous channel is not the one
   * anyone else sees; the roster carries the right one.
   *
   * Per channel, because a pseudonym belongs to the channel that minted it,
   * and a message names the channel it was sent in. Only a voice channel can
   * be anonymous, so in practice this is the roster of the channel we stand
   * in — but reading the name off the roster the message belongs to is what
   * keeps it true if that ever changes.
   */
  function ownDisplayName(server: string, fallback: string, channelId?: number): string {
    const own = get(users.peek(server));
    const roster =
      channelId === undefined || channelId === get(currentChannelId.peek(server))
        ? own
        : (get(channelRosters.peek(server)).get(channelId) ?? own);
    const me = get(userId.peek(server));
    return roster.find((u) => u.user_id === me)?.username ?? fallback;
  }

  let showSettings = $state(false);
  $effect(() => {
    if ($settingsAsk) showSettings = true;
  });

  // Deferred auto-connect: waits for chat history to be unlocked first
  let pendingAutoConnect = $state<SavedServer[] | null>(null);
  /** The "waiting for the channel's key" warning, and the server it is about. */
  let mediaKeyToast: { server: string; id: number } | null = null;
  // The warning is about the call, and the call can move without either event
  // above ever arriving: to another server, or out of voice. Wherever it went,
  // the old server's missing key is not what the user is waiting on any more.
  $effect(() => {
    const at = $voiceServer;
    if (mediaKeyToast && mediaKeyToast.server !== at) {
      removeNotification(mediaKeyToast.id);
      mediaKeyToast = null;
    }
  });
  /** game/resource/channel of the last "a game is placing people" toast, so a
   *  bridge that reconnects every two seconds cannot paper the screen. */
  let lastSdkToast: string | null = null;
  /** The same for "a game could not place you", which a mod retries. */
  let lastSdkRefusal: string | null = null;
  /** The background-keys warning is sticky; one is enough per run. */
  let keysToastShown = false;
  /** The update a toast already announced: the daily check finds it again. */
  let announcedUpdate = "";
  /** Channels we have already explained the `routed` flag for this session,
   *  as `server/channel id`. */
  const routedNoticeShown = new Set<string>();
  type HandOffAskEvent = { channel_id: number; from_user_id: number; sealed?: boolean };
  /** What this device has left for answering hand-offs, per server. */
  const serveBudgets = new Map<string, ServeBudget>();
  /** Channels already told nobody else is there, this run. */
  const nobodyHereSaid = new Set<string>();

  // Every server's state and list at once, for what runs per server
  const connectionStates = connectionState.all();
  const channelLists = channels.all();
  // The call's, for what follows voice rather than the view
  const voiceState = connectionState.at(voiceServer);

  // ── First-run audio setup ──────────────────────────────────────────────
  //
  // Shown on the first connection this install has ever made, from Settings on
  // demand, and — as a single step — when a device somebody chose is no longer
  // there. Never on Android, which has one microphone and one earpiece and no
  // mic test to drive.
  let missingDevice = $state<"input" | "output" | null>(null);
  let audioSetupDone = $state(false);
  const audioSetupOnly = $derived(
    $audioSetupVersion >= AUDIO_SETUP_VERSION && !$audioSetupRequested
      ? (missingDevice ?? undefined)
      : undefined,
  );
  const showAudioSetup = $derived(
    $connectionState === "connected" &&
      !($isMobile && !isWeb) &&
      !audioSetupDone &&
      ($audioSetupVersion < AUDIO_SETUP_VERSION || $audioSetupRequested || missingDevice !== null),
  );

  // ── First-run layout choice ────────────────────────────────────────────
  //
  // After the audio setup, and for the same reason it is where it is: they are
  // connected, in no voice channel yet, and expecting to be asked things. Audio first, because a microphone nobody can hear is what
  // ruins a call and a layout is not.
  let layoutPickerDone = $state(false);
  const showLayoutSetup = $derived(
    $connectionState === "connected" &&
      !showAudioSetup &&
      !layoutPickerDone &&
      $layoutAskedVersion < LAYOUT_PICKER_VERSION,
  );

  function closeLayoutSetup() {
    // Skipping writes nothing, so the offer stands next time — but not again
    // this session, which is how a helpful thing becomes an obstacle.
    layoutPickerDone = true;
  }

  function closeAudioSetup() {
    audioSetupRequested.set(false);
    missingDevice = null;
    // Skipping leaves the version at 0 so the offer stands next time, but not
    // for the rest of *this* session: being asked again on every reconnect is
    // how a helpful thing becomes an obstacle.
    audioSetupDone = true;
    invoke<AppConfig>("load_config")
      .then((c) => audioSetupVersion.set(c.audio_setup_version ?? 0))
      .catch(() => {});
  }

  // A block silences someone in the call, whichever server is on screen: only the
  // voice server's roster may drive this, since `set_user_volume` has no server and
  // an id on another one is a stranger. By volume alone, which the relay never sees.
  const voiceBlocked = blocked.at(voiceServer);
  $effect(() => {
    const changes = silenceChanges($voiceUsers, $voiceBlocked, !!$voiceChannel?.anonymous, silencedIds());
    untrack(() => {
      for (const { id, on } of changes) void silenceUser(id, on);
    });
  });

  // What someone newly blocked had waiting stops counting, on every open server
  const everyBlocked = blocked.all();
  $effect(() => {
    const servers = [...$everyBlocked.keys()];
    untrack(() => servers.forEach(quietBlockedDms));
  });

  // A server can ask every client into a text channel; the ones this user
  // walked out of are skipped. Every open server, not just the one on screen.
  //
  // Driven from both the list and the connection rather than from the
  // `channel-list` event, because the event arrives first: the server sends the
  // channel list as part of logging in, while the command that would join is
  // refused with "Not connected" until `connect` has finished storing the
  // session. Joining is idempotent, so running this again costs nothing.
  $effect(() => {
    for (const [server, state] of $connectionStates) {
      if (state === "connected") autoJoinTextChannels(server, $channelLists.get(server) ?? []);
    }
  });

  // The names of everyone on this device for that server, once a connection and in pages of
  // their own: drawn later they cost nothing, where asking then would say which channel is
  // on screen. An archive unlocked after connecting brings more of them.
  $effect(() => {
    void $chatUnlocked;
    for (const [server, state] of $connectionStates) {
      if (state === "connected") untrack(() => {
        if (community(get(olderRelay.peek(server))?.protocol ?? null)) askProfiles(server, authorsHere(server));
      });
    }
  });

  // Only once the layout that names it has come, which is a frame of its own behind
  // the sign-in: deciding earlier would use up this device's one welcome on nothing.
  // And only for the server on screen: one coming up in the background must not
  // pull the view to it.
  $effect(() => {
    const server = $serverAddress;
    if (!server || !$layoutArrived || $connectionStates.get(server) !== "connected") return;
    if (($channelLists.get(server) ?? []).length > 0) untrack(() => welcomeOnce(server));
  });

  /** The first time on this server on this device, with nothing else open: its
   *  welcome channel, if it has one. */
  function welcomeOnce(server: string) {
    if (server !== get(serverAddress) || get(activeTextChannelId) !== null || get(activeDmUserId) !== null) return;
    const channel = firstVisit(server);
    if (channel) selectChannel(channel);
  }

  // A saved device that is no longer plugged in: the name is all we store
  // (cpal has no stable id, and a browser's deviceId is wiped with site data),
  // so a name that is not in the list is a device that went away.
  $effect(() => {
    if ($connectionState !== "connected" || ($isMobile && !isWeb)) return;
    void (async () => {
      try {
        const wanted = { input: get(inputDevice), output: get(outputDevice) };
        if (!wanted.input && !wanted.output) return;
        const [ins, outs] = await Promise.all([
          invoke<{ name: string }[]>("get_input_devices"),
          invoke<{ name: string }[]>("get_output_devices"),
        ]);
        if (wanted.input && !ins.some((d) => d.name === wanted.input)) missingDevice = "input";
        else if (wanted.output && !outs.some((d) => d.name === wanted.output))
          missingDevice = "output";
      } catch {
        // Enumeration failing is its own toast elsewhere; do not stack another
      }
    })();
  });
  // Invite link: join the named channel once its server is connected and its
  // channel list is known (set from the URL fragment in onMount or by the
  // connect dialog). An invite that does not name its server yet — the URL's
  // — is for the first server on screen, the one the page came from.
  $effect(() => {
    const inv = $pendingInvite;
    const server = inv?.server ?? $serverAddress;
    if (!inv || !server) return;
    const list = $channelLists.get(server) ?? [];
    if ($connectionStates.get(server) !== "connected" || list.length === 0) return;
    const ch = list.find((c) => c.name === inv.channel);
    pendingInvite.set(null);
    if (!ch) {
      addNotification(`The invite's channel "${inv.channel}" does not exist on this server`, "warning");
      return;
    }
    if (inv.password) {
      rememberChannelPassword(server, ch.name, inv.password);
    }
    const join = () =>
      invoke("join_channel", { server, channelId: ch.channel_id, password: inv.password }).then(
        // A text channel the link names is the one to show (V-01), and
        // following it undoes having left it, as Join does
        () => {
          if (!ch.text) return;
          forgetLeft(server, ch.channel_id);
          if (server === get(serverAddress)) openJoinedTextChannel(server, ch.channel_id, ch.name);
        },
        (e: unknown) => {
          addNotification(`Could not join #${ch.name}: ${e}`, "error");
        },
      );
    // A link is somebody else's idea: an 18+ channel still asks first
    const joinAsked = () => {
      if (askNsfwConsent(server, ch.channel_id, () => void join())) void join();
    };
    if (ch.text) {
      // A text channel seats nobody: open it
      joinAsked();
      return;
    }
    // A voice channel is a seat with a microphone, and a seat needs an ask
    // (0.10.0): the link shows the channel, then asks (S-048)
    if (ch.channel_id === get(currentChannelId.peek(server))) return;
    if (server === get(serverAddress)) previewChannel(ch.channel_id);
    void confirmAction({
      title: `Join voice in ${ch.name}?`,
      body: "An invite link opened this channel. Joining puts you in its call, with your microphone as you have it set.",
      confirm: "Join voice",
    }).then((ok) => {
      if (ok) joinAsked();
    });
  });

  // What a connection held — admin, the channel list, rosters, the chat's
  // subscriptions and conversations — is forgotten with it, per server, by
  // `resetServer` in connect.ts: on a Disconnect, and when the connection is
  // lost. The call's state goes when voice leaves a server (voice.ts).

  // OS notification when the window is not focused (DMs and pokes)
  // At most one system notification every two seconds: a peer's DMs or
  // pokes at the relay's full rate would otherwise stack dozens a second on
  // the desktop. The unread counts still say what arrived.
  let lastNotifyAt = -Infinity;

  /** Our own account on `server` (hex), which names what we wrote across connects. */
  function ownAccount(server: string): string | undefined {
    const own = get(account.peek(server));
    return own ? accountHex(own.info.id) : undefined;
  }

  /** Whether `content` names us with an `@`. Never in an anonymous channel, where names are pseudonyms;
   *  by our short name only where nobody else in the channel goes by it (R2-11). */
  function mentionsUs(server: string, channelId: number, content: string): boolean {
    if (!content.includes("@")) return false;
    const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
    if (channel?.anonymous) return false;
    const own = get(username.peek(server));
    if (!own) return false;
    const names = ownMentionNames(
      own,
      currentRosterOf(server, channelId).map((u) => u.username),
      !!channel?.text && livePath(get(olderRelay.peek(server))?.protocol ?? null),
    );
    const tree = parse(content, { names });
    return names.some((n) => mentionsName(tree, n));
  }

  /** Whether someone here is blocked: by their account where a list we see has
   *  it, else by the name. */
  function blockedSender(server: string, uid: number, name: string): boolean {
    const known = get(users.peek(server)).find((u) => u.user_id === uid)?.account ?? rosterAccount(server, uid);
    return isBlocked(get(blocked.peek(server)), { account: known, username: name }, false);
  }

  /** Whether this message came with its sender's power to call on everybody. A post on the
   *  live path says itself whether its writer is an admin; no list may hold them. */
  function arrivedWithPower(server: string, channelId: number, uid: number, content: string, post?: PostFlags): boolean {
    if (!community(get(olderRelay.peek(server))?.protocol ?? null)) return false;
    const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
    const row = post ?? currentRosterOf(server, channelId).find((u) => u.user_id === uid);
    return hasPower(
      content,
      { holder: get(mentionPower.peek(server)).has(uid), isAdmin: !!row?.is_admin },
      { anonymous: !!channel?.anonymous },
      powerTokens(get(groupStyles.peek(server))),
    );
  }

  /**
   * Someone asks for a channel's recent chat. The request reaches us through the server, and the
   * server is the adversary this whole layer is built against: it can invent one, for any
   * channel and from any name, and forty-eight kilobytes of our plaintext would go straight back
   * out. A sealed one the relay could not even look at. So one rule for both, here on the device.
   *
   * A relay can still put a stranger *in* a list, as it is the one who sends it. In a gated
   * channel that is a name on screen, and answering names them to us too; in an open one it
   * reads no more than anyone on the server may. Off the live path every channel goes by its
   * list. `mayWait`: a stranger to the last list moves the next sweep up, and is looked at once
   * more when it is in.
   */
  function answerHandOff(server: string, data: HandOffAskEvent, mayWait: boolean): void {
    const channelId = data.channel_id;
    const chName = channelNameById(server, channelId);
    if (!chName) return;
    let msgs: ChatMessage[] = handOffOf($channelMessages.get(chatKey(server, chName)) ?? []);
    if (msgs.length === 0) return;
    const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
    const seat = get(textSeats.peek(server)).get(channelId);
    const asker = currentRosterOf(server, channelId).find((u) => u.user_id === data.from_user_id);
    const hold = get(restrictions.peek(server)).get(get(userId.peek(server)));
    const live = livePath(get(olderRelay.peek(server))?.protocol ?? null);
    const swept = !live || goesByList(channel, seat?.gated);
    const right = $shareChannelHistory && get(shareRight.peek(server));
    const gone = !!get(goneFrom.peek(server)).get(channelId)?.has(data.from_user_id);
    if (mayWait && live && swept && right && !asker && !gone && seat) {
      sweepForAsker(server, () => answerHandOff(server, data, false));
      return;
    }
    const ours = channelId === get(currentChannelId.peek(server)) || get(joinedTextChannelIds.peek(server)).has(channelId);
    // Before its join: on a one-page account the relay answers the page first, so a held ask
    // always came early and was dropped with no word. It goes on at the join (device pass)
    if (mayWait && right && !ours && channel?.text) {
      afterJoin(server, channelId, () => answerHandOff(server, data, true));
      return;
    }
    const answer = answersHandOff({
      switchOn: $shareChannelHistory,
      right: get(shareRight.peek(server)),
      anonymous: !!channel?.anonymous,
      listenOnly: get(listenOnly.peek(server)).has(channelId),
      held: !!hold?.text || !!hold?.direct,
      ours,
      swept,
      askerOnline: onlineById(server).has(data.from_user_id),
      askerOnSweep: !!asker,
      askerGone: gone,
      askerGuest: !!seat?.gated && !asker?.account,
      metered: metered(),
      spend: () => {
        let budget = serveBudgets.get(server);
        if (!budget) serveBudgets.set(server, (budget = { spent: 0, at: Date.now() }));
        return spendServe(budget, Date.now());
      },
    });
    if (!answer) return;
    // Stay well under the 64 KiB control-message cap (Signal envelope + framing)
    const bytes = (list: ChatMessage[]) => new TextEncoder().encode(JSON.stringify(list)).length;
    while (msgs.length > 0 && bytes(msgs) > 48 * 1024) msgs = msgs.slice(1);
    if (msgs.length === 0) return;
    // They can read this now: on the same line as a key, where who reads is what matters
    if (live && asker) noteReaders(server, channelId, [{ account: asker.account, name: asker.username }]);
    invoke("send_channel_history", {
      server,
      channelId,
      targetUserId: data.from_user_id,
      messages: msgs,
      sealed: data.sealed ?? false,
    }).catch((e: unknown) => console.warn("channel history hand-off failed:", e));
  }

  async function notifyUnfocused(title: string, body: string) {
    if (pageInView(document)) return;
    const now = performance.now();
    if (now - lastNotifyAt < 2000) return;
    lastNotifyAt = now;
    try {
      const notif = await import("@tauri-apps/plugin-notification");
      let granted = await notif.isPermissionGranted();
      // A browser grants it only from a click: Settings asks (H5-13)
      if (!granted && !isWeb) {
        granted = (await notif.requestPermission()) === "granted";
      }
      // Freedesktop daemons render the body as markup; peers must not be
      // able to inject links or styling into a system notification. Nothing
      // else does, and there "<3" would arrive as "&lt;3".
      const markup = !isWeb && /Linux/.test(navigator.userAgent) && !/Android/.test(navigator.userAgent);
      const esc = (s: string) =>
        markup ? s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : s;
      if (granted) notif.sendNotification({ title: esc(title), body: esc(body) });
    } catch (e) {
      console.error("Desktop notification failed:", e);
    }
  }

  // Trigger auto-connect only after chat history password has been entered
  // (or the vault was skipped — then there is nothing to unlock)
  $effect(() => {
    if (pendingAutoConnect && ($chatUnlocked || $chatHistoryDisabled)) {
      const list = pendingAutoConnect;
      pendingAutoConnect = null;
      reconnectAll(list);
    }
  });

  // ── Our share's capture ──
  //
  // Native capture runs while anybody watches, or while our own preview is on
  // screen — then with nothing encoded or sent until a viewer arrives
  // (FrameProcessor::process). The browser previews straight from its
  // MediaStream, so there only viewers start the encoder. No "capturing" flag
  // here: Rust also stops capture by itself (stop, a channel move, a failed
  // source switch), and both commands are safe to repeat.
  const captureWanted = $derived(
    $isSharingScreen && ($viewerCount > 0 || (!isWeb && $previewShown)),
  );
  $effect(() => {
    if (captureWanted) {
      const [resolution, fps] = untrack(() => [$shareResolution, $shareFps]);
      invoke("start_screen_capture", { resolution, fps }).catch((e: any) => {
        console.error("Failed to start capture:", e);
        addNotification(`Failed to start screen capture: ${e}`, "error");
      });
    } else if (untrack(() => $isSharingScreen)) {
      invoke("stop_screen_capture").catch((e: any) => console.error("Failed to stop capture:", e));
    }
  });

  // The capture task renders the preview only while it is on screen
  $effect(() => {
    if (isWeb) return;
    invoke("set_share_preview", { on: $previewShown }).catch(() => {});
  });

  // Close pop-out window when watching stops
  $effect(() => {
    if ($watchingUserId === null) {
      const win = getPopoutWindow();
      if (win) {
        win.destroy().catch(() => {});
        setPopoutWindow(null);
        poppedOut.set(false);
      }
    }
  });

  // Proximity switched off under us (an admin or the creator changed it):
  // close the room and forget the layout.
  $effect(() => {
    if ($currentProximity === "off") {
      // Only the room is proximity-gated; the mixer works in any channel
      if ($centreView === "room") centreView.set("chat");
      if ($positions.size > 0 || $syncing) clearRoom();
    }
  });

  // Clear unread for the channel the pane is actually showing, when returning
  // from DM view. Not `$currentChannelId`: with a text channel open, that one
  // is the voice room next door, whose badge is the user's to keep.
  $effect(() => {
    if ($activeDmUserId === null) {
      const channel = $channels.find(
        (c) => c.channel_id === ($activeTextChannelId ?? $currentChannelId),
      );
      if (channel) clearChannelUnread($serverAddress, channel.name);
    } else if ($serverAddress) {
      // Back on a server whose DM was left open: what arrived there meanwhile
      // counted as unread (chat.ts addDmMessage), and it is on screen now.
      const peer = $activeDmUserId;
      const server = $serverAddress;
      dmConversations.of(server).update((cs) => {
        const read = cs.find((c) => c.user_id === peer && c.unread > 0);
        if (!read) return cs;
        markRead(dmKey(server, read.username));
        return cs.map((c) => (c === read ? { ...c, unread: 0 } : c));
      });
    }
  });

  // Android: start/stop foreground voice service when joining/leaving voice,
  // on whichever server — the service is the call's. Only when the call or
  // its channel's name changes: the voice store changes with every roster
  // and share update, and each start re-applies the call's audio route (D1-07).
  const voiceServiceName = $derived(
    $voiceState === "connected" && $voice !== null ? $voiceChannel?.name || "voice channel" : null,
  );
  $effect(() => {
    if (!$isMobile) return;
    const bridge = (window as any).__VoIPC;
    if (!bridge) return;

    let timer: ReturnType<typeof setTimeout> | null = null;

    const name = voiceServiceName;
    if (name !== null) {
      timer = setTimeout(() => {
        bridge.startVoiceService(name);
      }, 300);
    } else {
      bridge.stopVoiceService();
    }

    return () => { if (timer) clearTimeout(timer); };
  });

  /** A live post is here. It moves where they read to it, ends a ring if they are looking,
   *  and in a channel that goes by a list its writer is on the list from now on: this app has
   *  a key from them. */
  function noteArrival(server: string, channelId: number, uid: number, name: string, at: number, post: PostFlags | undefined, writer: number[] | null | undefined): void {
    const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
    if (!channel?.text) return;
    moveRead(server, channel, at);
    if (uid === get(userId.peek(server))) return;
    if (viewingChannel(server, channelId)) clearRing(server, channelId);
    if (!post) return;
    if (!goesByList(channel, get(textSeats.peek(server)).get(channelId)?.gated)) return;
    exchangedKey(server, channelId, bareRow(channelId, uid, name, writer, post));
  }

  /** A person a frame named, as a row of a list. */
  function bareRow(channelId: number, uid: number, name: string, account: number[] | null | undefined, post?: PostFlags): UserInfo {
    return {
      user_id: uid,
      username: name,
      channel_id: channelId,
      is_muted: false,
      is_deafened: false,
      is_screen_sharing: false,
      is_admin: !!post?.is_admin,
      is_moderator: post?.is_moderator,
      shares_history: false,
      account,
    };
  }

  /** That channel's chat is on screen: this server, no DM over the pane,
   *  and this channel in it. */
  function viewingChannel(server: string, channelId: number): boolean {
    return (
      server === get(serverAddress) &&
      get(activeDmUserId.peek(server)) === null &&
      channelId === (get(activeTextChannelId.peek(server)) ?? get(currentChannelId.peek(server)))
    );
  }

  // Svelte calls the cleanup only when onMount returns it synchronously
  onMount(() => {
    const cleanup = (async () => {
    // Messages with a destruction timer go when their moment comes, whether or
    // not anybody is looking at them. One sweep for the whole app.
    startExpirySweep();
    // ...and the file cache follows what the chat still refers to
    const stopFileRetain = startFileRetain();
    // A reload, or a window closed under us: the debounced chat save goes now
    window.addEventListener("beforeunload", () => {
      void flushChatSave();
      flushMarks();
    });
    // What a key job may cost, and what asking and answering may: the backend asks only on this
    const sayMetered = () => {
      void invoke("set_metered", { metered: metered() }).catch(() => {});
      networkChanged(() => [...get(connectionStates).keys()]);
    };
    sayMetered();
    (navigator as { connection?: EventTarget }).connection?.addEventListener?.("change", sayMetered);
    // A file dropped where nothing takes it (the member list, a chat that
    // cannot send files) must not open in the window in place of the app:
    // the desktop page sees drops itself since 1.3 (R3-07). A chat that takes
    // it has staged it already, below this.
    window.addEventListener("dragover", (e) => {
      if (!e.dataTransfer?.types.includes("Files")) return;
      if (!e.defaultPrevented) e.dataTransfer.dropEffect = "none";
      e.preventDefault();
    });
    window.addEventListener("drop", (e) => {
      if (e.dataTransfer?.types.includes("Files")) e.preventDefault();
    });

    // Invite link in the URL fragment (web client): keep it, then drop it from
    // the address bar so it is neither kept in history nor re-applied on reload
    if (window.location.hash.length > 1) {
      // For the server that served this page, which is the one the link names:
      // with several open, "whichever is on screen" could be another one.
      const inv = parseInviteFragment(window.location.hash);
      const join = parseJoinFragment(window.location.hash);
      if (join) {
        pendingJoin.set({
          code: join.code,
          host: window.location.hostname.replace(/^\[|\]$/g, ""),
          port: Number(window.location.port) || 443,
        });
      }
      if (inv) {
        pendingInvite.set({
          ...inv,
          server: serverId(window.location.hostname, Number(window.location.port) || 443),
        });
      }
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }

    // Connections the backend still holds belong to a page that is gone — a
    // reload, or Android recreating the activity — and this one cannot see
    // them, let alone close them. It starts from none.
    await invoke("disconnect_all").catch(() => {});

    // Load persisted config and hydrate all stores
    try {
      const config = await invoke<AppConfig>("load_config");
      pttKey.set(config.ptt_key);
      pttHoldMode.set(config.ptt_hold_mode);
      volume.set(config.volume);
      voiceMode.set(config.voice_mode as any);
      vadThreshold.set(config.vad_threshold_db);
      noiseSuppression.set(config.noise_suppression);
      isMuted.set(config.muted);
      isDeafened.set(config.deafened);
      soundSettings.set(config.sounds);
      autoConnect.set(config.auto_connect);
      savedServers.set(config.saved_servers ?? []);
      inputGain.set(config.input_gain ?? 1.0);
      muteKey.set(config.mute_key ?? "");
      deafenKey.set(config.deafen_key ?? "");
      chatHistoryDisabled.set(config.chat_history_disabled ?? false);
      shareChannelHistory.set(config.share_channel_history ?? false);
      if (config.share_off_notice) {
        addNotification("Sharing with newcomers is off now, until you turn it on: it used to start on. Settings → Privacy & data.", "info", 15000);
        invoke("set_config_bool", { key: "share_off_notice", value: false }).catch(() => {});
      }
      maxConversations.set(config.max_conversations ?? MAX_CONVERSATIONS);
      screenShareCodec.set(config.screen_share_codec ?? "h264");
      spatialAudio.set(config.spatial_audio ?? true);
      screenAudioSpatial.set(config.screen_audio_spatial ?? true);
      audioSetupVersion.set(config.audio_setup_version ?? 0);
      // Layout, palette, panel sizes. One blob rather than a field each — see
      // the `ui_prefs` field in config.rs for why this one is allowed to be.
      hydrateUiPrefs(config.ui_prefs);
      // Our own lane, as the backend has already seeded it from the same file
      micLane.set(
        cleanLane({
          effect: config.mic_effect ?? "none",
          muffle: config.mic_muffle ?? 0,
          reverb: config.mic_reverb ?? 0,
          water: config.mic_water ?? 0,
        }),
      );
      if (config.input_device) inputDevice.set(config.input_device);
      if (config.output_device) outputDevice.set(config.output_device);
      rememberConnection.set(config.remember_connection);
      if (config.remember_connection) {
        // A build-time default (VITE_DEFAULT_SERVER) fills in for a config
        // written before there was one.
        lastHost.set(config.last_host ?? defaultServer().host);
        lastPort.set(config.last_port ?? defaultServer().port);
        lastUsername.set(config.last_username ?? "");
        lastAcceptSelfSigned.set(config.last_accept_self_signed ?? false);
      }

      // Schedule auto-connect — will trigger after chat history is unlocked.
      // Every server that was open, or, in a config written before there was
      // a list, the one server it remembered.
      let list: SavedServer[] = [];
      if (config.auto_connect) {
        const open = config.open_servers ?? [];
        list =
          open.length > 0
            ? open
            : config.last_host && config.last_username
              ? [
                  {
                    name: config.last_host,
                    host: config.last_host,
                    port: config.last_port ?? 9987,
                    username: config.last_username,
                    accept_self_signed: config.last_accept_self_signed ?? false,
                  },
                ]
              : [];
      }
      list = withReloadServers(list);
      if (list.length > 0) pendingAutoConnect = list;
    } catch (e) {
      console.error("Failed to load config:", e);
    } finally {
      // Render even if the config could not be read: the defaults are a working
      // app, and a window that never paints is not. Saving stays blocked.
      uiPrefsReady.set(true);
    }

    // Listen for events from the backend. Everything one connection says
    // arrives through `listenServer` with the server it came from, and is
    // written to that server's stores — never to "whichever server is on
    // screen", which is another server as often as not. What only makes sense
    // for the call (sounds, the room, shares) is judged against the server
    // carrying voice. The rest — the game SDK, audio devices, the keys — is
    // the app's, and arrives bare.
    const inVoice = (server: string) => get(voice)?.server === server;

    const unlisteners = [
      // Refused for another protocol: ConnectDialog shows which side updates
      listenServer<Omit<UpdateNeeded, "server">>("update-needed", (server, d) => updateNeeded.set({ server, ...d })),
      // The relay asks for a file this device holds (a re-seed): silent
      listenServer<{ conv: FileConv; hash: string }>("file-wanted", (server, d) => answerFileWanted(server, d.conv, d.hash)),
      listenServer<{ max_bytes: number } | null>("file-limits", (server, d) => fileLimits.of(server).set(d)),
      listenServer<EmoteSet>("emote-list", (server, d) => setEmotes(server, d)),
      listenServer<EmoteLimits | null>("emote-limits", (server, d) => emoteLimits.of(server).set(d)),
      // An older relay's protocol and version: the banner, and what the app holds back there
      listenServer<{ protocol: number; version: string | null }>("relay-version", (server, d) => {
        olderRelay.of(server).set(d.version === null ? null : { protocol: d.protocol, version: d.version });
        if (relayWentBack(server, d.protocol)) {
          addNotification(
            `${fromServer(server)}this server spoke a newer protocol before. On the older one your app does not check its gates and hand-offs as it did. If nobody said it would go back, someone may be between you and it.`,
            "warning",
            0,
          );
        }
      }),
      listenServer<{ name: string; reason: string }>("emote-error", (server, d) =>
        addNotification(`${fromServer(server)}${d.name ? `:${d.name}: — ` : ""}${d.reason}`, "error"),
      ),
      listenServer<FileProgress>("file-progress", (_server, d) => noteProgress(d)),
      // First meeting with a self-signed server: what was pinned, to compare
      listenServer<{ fingerprint: string }>("tofu-pinned", (server, d) =>
        addNotification(
          `${serverName(server, get(savedServers))} uses its own certificate, and this app now trusts it. ` +
            `Its fingerprint is ${d.fingerprint}. Compare it with the one the server's operator gives you ` +
            `(voipc-server cert fingerprint). If it differs, disconnect, use "Forget pinned certificate", and do not use this server.`,
          "warning",
          0,
        ),
      ),
      listenServer<ChannelInfo[]>("channel-list", (server, raw) => {
        const list = eachOnce(raw, (c) => c.channel_id);
        channels.of(server).set(list);
        // Renamed while this device was away: what it keeps by name follows
        channelsListed(server, list);
        // A reconnect waits for this before deciding where to put the user back
        channelListArrived(server, list);
        // The sidebar draws the people under every channel, and the names for
        // any channel but our own have to be asked for — a UserJoined broadcast
        // deliberately carries no username to outsiders.
        requestAllRosters(server);
      }),

      listenServer<{ channel_id: number; users: UserInfo[] }>("user-list", (server, raw) => {
        const data = { ...raw, users: eachOnce(raw.users, (u) => u.user_id) };
        const oldChannelId = get(currentChannelId.peek(server));
        const newChannelId = data.channel_id;
        // A join: whether we may only listen there comes right after
        listenOnly.of(server).update((s) => {
          if (!s.has(newChannelId)) return s;
          const next = new Set(s);
          next.delete(newChannelId);
          return next;
        });

        // A text channel is a subscription: we did not move, so none of the
        // channel-switch work below applies, and the chat pane stays where the
        // user put it.
        if (isTextChannel(server, newChannelId)) {
          joinedTextChannelIds.of(server).update((s) => new Set(s).add(newChannelId));
          // setRoster settles the row's member count from this same list
          setRoster(server, newChannelId, data.users);
          if (get(activeTextChannelId.peek(server)) === newChannelId) {
            const name = channelNameById(server, newChannelId);
            if (name) clearChannelUnread(server, name);
          }
          return;
        }

        // We are excluded from the UserJoined/UserLeft broadcasts about our own
        // movement, so the channel we left loses us here. The one we joined is
        // counted from the list below, by setRoster.
        if (oldChannelId !== newChannelId) {
          channels.of(server).update((chs) =>
            chs.map((ch) =>
              ch.channel_id === oldChannelId
                ? { ...ch, user_count: Math.max(0, ch.user_count - 1) }
                : ch,
            ),
          );
        }

        currentChannelId.of(server).set(newChannelId);
        users.of(server).set(data.users);
        setRoster(server, newChannelId, data.users);
        // A room can hold an archive too, and the relay is what moved us
        if (newChannelId !== 0 && livePath(get(olderRelay.peek(server))?.protocol ?? null)) askArchiveChannels(server);
        // We just left one, and the channel we joined may have been listed with
        // a roster we fetched before joining.
        if (oldChannelId !== newChannelId) {
          requestRoster(server, oldChannelId);
          requestAllRosters(server);
        }
        const joinedName = channelNameById(server, newChannelId);
        if (joinedName) clearChannelUnread(server, joinedName);

        // Where voice is, mirrored from the backend: a voice channel confirmed
        // here makes this the voice server, whatever held it before — the
        // backend has already taken voice off that one and asked it to leave —
        // and the lobby confirmed here ends voice if it was here. The lobby
        // confirmed by a server that no longer holds voice is that leave
        // arriving, and is not the call's business.
        const heldVoice = inVoice(server);
        if (newChannelId !== 0) {
          // A repeat of the same seat is not a move: every change of this
          // store reads as one (recent speakers, for a start)
          if (!heldVoice || get(voice)?.channelId !== newChannelId) {
            voice.set({ server, channelId: newChannelId });
          }
        } else if (heldVoice) {
          voice.set(null);
        }

        // Clear screenshare state and play channel switch sound
        if (oldChannelId !== newChannelId && (heldVoice || newChannelId !== 0)) {
          // A room layout belongs to the channel it was made in
          clearRoom();
          // The backend disarms the game SDK per channel: its player ids mean
          // nothing here, and its next update is refused until it says hello
          // again. Without this the room view and the mixer's incoming lanes
          // stay locked in every channel once any game has ever connected.
          drivenBy.set(null);
          audibleIds.set(null);
          resetScreenShareState();
          playChannelSwitchSound();
          // A routed channel is the one place the server is told anything
          // about who hears whom. Say so on the way in, once per channel per
          // session, in the words the README uses.
          const joined = get(channels.peek(server)).find((c) => c.channel_id === newChannelId);
          const noticeKey = `${server}/${newChannelId}`;
          if (joined?.routed && !routedNoticeShown.has(noticeKey)) {
            routedNoticeShown.add(noticeKey);
            addNotification(
              `#${joined.name} is a routed channel: the server is told which members you want ` +
                `to hear, so it forwards only their voice, and a game server connected to it ` +
                `may narrow that further. It still never receives positions, or audio it can read.`,
              "info",
              0,
            );
          }
        }

        // Clear preview when we actually join a channel
        previewChannelId.of(server).set(null);
        previewUsers.of(server).set([]);
      }),

      // Badges or the channel-manager mark changed (1.7): in place, no count
      listenServer<UserInfo>("user-updated", (server, u) => {
        const patch = { badges: u.badges ?? [], is_moderator: u.is_moderator };
        users.of(server).update((all) => patchUser(all, u.user_id, patch));
        patchRosters(server, u.user_id, patch);
      }),

      listenServer<{ channel_id: number; on: boolean }>("listen-only", (server, d) => {
        listenOnly.of(server).update((s) => {
          const next = new Set(s);
          if (d.on) next.add(d.channel_id);
          else next.delete(d.channel_id);
          return next;
        });
        const name = channelNameById(server, d.channel_id);
        // A gate letting us speak again means nothing while we are held on the whole server
        if (!d.on && get(restrictions.peek(server)).get(get(userId.peek(server)))?.voice) return;
        addNotification(
          `${fromServer(server)}${d.on ? `You can only listen and read in ${name}` : `You may speak in ${name} again`}`,
          "info",
        );
      }),

      listenServer<{ list: RestrictionRow[] }>("restrictions", (server, d) => {
        const me = get(userId.peek(server));
        const before = get(restrictions.peek(server)).get(me) ?? null;
        onRestrictions(server, d.list);
        const after = get(restrictions.peek(server)).get(me) ?? null;
        const notice = heldNotice(before, after, Date.now());
        if (notice) addNotification(`${fromServer(server)}${notice}`, after ? "warning" : "info");
        // Not through the mute, which goes across every server, is kept and is
        // announced: this is one server's. A lift re-arms voice activation (VoiceKeys)
        if (after?.voice && !before?.voice && inVoice(server)) void stopTransmit();
      }),

      listenServer<UserInfo>("user-joined", (server, joiner) => {
        // The user list snapshot and this broadcast are built separately on
        // the server, so a user we already have can arrive again (two joins
        // at once). Replacing is idempotent; appending twice would throw
        // each_key_duplicate and wedge the UI.
        const current = get(currentChannelId.peek(server));
        if (joiner.channel_id === current) {
          let isNew = true;
          users.of(server).update((u) => {
            const next = upsertById(u, joiner, (x) => x.user_id);
            isNew = next.added;
            return next.list;
          });
          // Play join sound: only in the call — not the lobby, not a server
          // we are only reading — and not for ourselves
          if (
            isNew &&
            current !== 0 &&
            inVoice(server) &&
            joiner.user_id !== get(userId.peek(server))
          ) {
            playUserJoinedSound();
          }
        }
        // The row's count and its list, with the next ones. The broadcast told us somebody
        // joined but maybe not who, and then it is asked, as one question, not ten.
        noteJoin(server, joiner);
      }),

      listenServer<{ user_id: number; channel_id: number }>("user-left", (server, data) => {
        const self = get(userId.peek(server));
        // Our own departure from a text channel is how we learn a leave (or a
        // kick from one) went through.
        if (data.user_id === self && isTextChannel(server, data.channel_id)) {
          joinedTextChannelIds.of(server).update((s) => {
            const next = new Set(s);
            next.delete(data.channel_id);
            return next;
          });
          if (get(activeTextChannelId.peek(server)) === data.channel_id) openTextChannel(server, null);
          forgetHandOff(server, data.channel_id);
        }

        // Only remove from local user list if they left our channel
        const current = get(currentChannelId.peek(server));
        if (data.channel_id === current) {
          const inCall = current !== 0 && inVoice(server);
          // Play leave sound before removing (only in the call, not for ourselves)
          if (inCall && data.user_id !== self) {
            playUserLeftSound();
          }
          users.of(server).update((u) => u.filter((user) => user.user_id !== data.user_id));
          if (inCall) {
            // Forget where they stood: the id belongs to the next joiner
            positions.update((m) => {
              if (!m.has(data.user_id)) return m;
              const next = new Map(m);
              next.delete(data.user_id);
              return next;
            });
            // A selection pointing at nobody would move a ghost on the next click
            selectedUserId.update((id) => (id === data.user_id ? null : id));
          }
        }
        noteLeft(server, data.channel_id, data.user_id);
      }),

      listenServer<{ user_id: number; muted: boolean }>("user-muted", (server, data) => {
        users.of(server).update((u) =>
          u.map((user) =>
            user.user_id === data.user_id ? { ...user, is_muted: data.muted } : user,
          ),
        );
        patchRosters(server, data.user_id, { is_muted: data.muted });
      }),

      listenServer<{ user_id: number; enabled: boolean }>("user-history-sharing", (server, data) => {
        users.of(server).update((u) =>
          u.map((user) =>
            user.user_id === data.user_id ? { ...user, shares_history: data.enabled } : user,
          ),
        );
        patchRosters(server, data.user_id, { shares_history: data.enabled });
      }),

      listenServer<{ user_id: number; deafened: boolean }>("user-deafened", (server, data) => {
        users.of(server).update((u) =>
          u.map((user) =>
            user.user_id === data.user_id ? { ...user, is_deafened: data.deafened } : user,
          ),
        );
        patchRosters(server, data.user_id, { is_deafened: data.deafened });
      }),

      // A member of a proximity channel shared where they stand
      listenServer<{ user_id: number; x: number; y: number; z: number }>(
        "user-position",
        (server, data) => {
          if (!inVoice(server)) return;
          const { user_id, x, y, z } = data;
          positions.update((m) => new Map(m).set(user_id, { x, y, z }));
        },
      ),

      // A game took over the positions (or gave them back): the room shows
      // them but stops accepting drags, and our own sharing is off — the
      // backend already cleared it when the game said hello.
      listen<{
        connected?: boolean;
        game?: string;
        resource?: string;
        channel?: string;
        beacon?: boolean;
        transmit?: boolean;
        refused?: string;
      }>(
        "sdk-status",
        (event) => {
          const { connected, game, resource, channel, beacon, transmit, refused } = event.payload;
          // The game is told only "wrong_server", whatever the cause, so the
          // player is the one who learns which (once per cause, not per retry).
          if (refused) {
            const key = `${game}/${resource}/${refused}`;
            if (key !== lastSdkRefusal) {
              lastSdkRefusal = key;
              const who = resource ? `${game} (${resource})` : game || "A game";
              addNotification(`${who} could not place you: ${refused}`, "warning");
            }
            return;
          }
          if (connected === undefined) return; // a listener-status update
          drivenBy.set(connected ? game || "a game" : null);
          if (!connected) {
            audibleIds.set(null);
            return;
          }
          syncing.set(false);
          positions.set(new Map());
          selectedUserId.set(null);
          // Say it out loud, once per game and channel. A game placing people
          // also moves the user into the channel it named, and until now the
          // only sign of either was a line in a settings panel nobody has
          // open. The strings are capped and stripped backend-side.
          const key = `${game}/${resource}/${channel}/${beacon}/${transmit}`;
          if (key !== lastSdkToast) {
            lastSdkToast = key;
            const who = resource ? `${game} (${resource})` : game || "A game";
            const where = channel ? ` in #${channel}` : "";
            // …and what it is allowed to do *to* them, not just for them. A
            // switch ticked once months ago is not consent anybody remembers
            // giving, so it is named every time a game takes over.
            const also = [
              beacon ? "broadcasting your position to the channel" : null,
              transmit ? "allowed to press your push-to-talk" : null,
            ].filter(Boolean);
            const tail = also.length ? `, and is ${also.join(" and ")}` : "";
            addNotification(`${who} is placing people for you${where}${tail}`, "info");
          }
        },
      ),

      // Who the game currently lets us hear. Everyone else is greyed out in
      // the member list and the mixer: leaving somebody out is how a game
      // culls by distance, and also how one would silence a person.
      listen<{ ids: number[] | null }>("sdk-audible", (event) => {
        // null is "nobody is culling any more" — the game let go — and is a
        // different thing from an empty list, which is a game saying nobody
        // is in earshot.
        audibleIds.set(event.payload.ids ? new Set(event.payload.ids) : null);
      }),

      listenServer<{ user_id: number; speaking: boolean }>("user-speaking", (server, data) => {
        // Only the voice connection plays audio; anything else is a straggler
        // from the one voice just left, and its ids are another server's.
        if (!inVoice(server)) return;
        // A new set wakes every member list; only when the answer moved
        if (get(speakingUsers).has(data.user_id) === data.speaking) return;
        speakingUsers.update((set) => {
          const next = new Set(set);
          if (data.speaking) {
            next.add(data.user_id);
          } else {
            next.delete(data.user_id);
          }
          return next;
        });
      }),

      listenServer<{ ms: number; tcp?: boolean }>("latency-update", (server, data) => {
        latency.of(server).set(data.ms);
        viaTcp.of(server).set(data.tcp === true);
      }),

      listenServer<{ reason: string }>("connection-lost", (server, data) => {
        const reason = data.reason;
        console.error(`Connection to ${server} lost:`, reason);
        sayConnectionLost(server, reason);

        // Session-scoped warnings die with the session
        if (mediaKeyToast?.server === server) {
          removeNotification(mediaKeyToast.id);
          mediaKeyToast = null;
        }

        // Its ids go with the connection: a restarted relay numbers from 1 again,
        // and whoever gets a holder's old id must not call on everybody. The relay
        // says who holds it again at sign-in.
        mentionPower.of(server).set(new Set());
        chatMods.of(server).set(new Map());
        restrictions.of(server).set(new Map());
        reportTakers.of(server).set(null);

        // A second connection-lost during a reconnect (ServerShutdown is
        // followed by the socket closing) is the loop's business, not a
        // second loop's; neither is one while the first connect is running.
        if (get(connectionState.peek(server)) !== "connected") return;

        // Play disconnected sound on initial loss (not during reconnect retries)
        playDisconnectedSound();
        // By name, both of them, and read here because this runs while the
        // channel list is still ours: the reconnect may land on a restarted
        // server, where the ids are new but the channels people were in are
        // the same ones they would recognise. The voice channel only if the
        // call was on this server.
        const seat = get(voice);
        const prevVoice = seat?.server === server ? channelNameById(server, seat.channelId) : "";
        const prevText = [...get(joinedTextChannelIds.peek(server))]
          .map((id) => channelNameById(server, id))
          .filter((n) => n !== "");
        const shownText = get(activeDmUserId.peek(server)) === null ? get(activeTextChannelId.peek(server)) : null;
        const prevOpen = shownText === null ? "" : channelNameById(server, shownText);
        // What the connection held goes now, the call with it if it was this
        // server's: a channel id is a slot in one server's run, and the
        // reconnect may land on a restarted server that hands them out again.
        resetServer(server);
        void startReconnect(server, { voice: prevVoice, text: prevText, open: prevOpen }, reason);
      }),

      listen<{ error: string; retrying?: boolean }>("audio-device-error", (event) => {
        addNotification(
          `Audio device error: ${event.payload.error}${event.payload.retrying ? " — retrying…" : ""}`,
          "error",
        );
      }),

      listen("audio-device-restored", () => {
        addNotification("Audio device restored", "info");
      }),

      // Push-to-talk that only works while the window is focused is the kind of
      // thing you find out about in a call. Sticky, because it is the setting
      // they have to change, and it is said once per run.
      listen<{ reason: string }>("global-keys-unavailable", (event) => {
        if (keysToastShown) return;
        keysToastShown = true;
        addNotification(`Push-to-talk outside the window: ${event.payload.reason}`, "warning", 0);
      }),

      // Quitting (the tray, or closing the window without one): hand the
      // backend the chat the debounce still holds, then let it exit and write
      // the archive. It does not wait for us for long.
      listen("quit-requested", async () => {
        await flushChatSave();
        flushMarks();
        await invoke("quit_app");
      }),

      // A newer VoIPC (updater.rs looks once a day): said once, and Settings
      // has the button
      listen<UpdateInfo>("update-available", (event) => {
        availableUpdate.set(event.payload);
        // An update on another protocol gets no toast: Settings says what it
        // would cost (design input 5)
        const connected = [...get(connectionStates)]
          .filter(([, s]) => s === "connected")
          .map(([id]) => ({ name: id, protocol: get(olderRelay.peek(id))?.protocol ?? null }));
        const toast = updateToast(event.payload, connected);
        if (toast && announcedUpdate !== event.payload.version) {
          announcedUpdate = event.payload.version;
          addNotification(toast, "info", 10000);
        }
      }),

      listenServer("media-key-missing", (server) => {
        if (mediaKeyToast === null) {
          mediaKeyToast = {
            server,
            id: addNotification(
              "Waiting for the channel's encryption key — voice and screen share are held back until a member sends it",
              "error",
              0,
            ),
          };
        }
      }),

      listenServer("media-key-installed", (server) => {
        if (mediaKeyToast?.server === server) {
          removeNotification(mediaKeyToast.id);
          mediaKeyToast = null;
        }
      }),

      // `name` comes with an account's change, which may be somebody away.
      // `as_guest`: a name first met as an account turned up without one.
      listenServer<{ user_id?: number | null; name?: string; as_guest?: boolean; replaced?: boolean }>("identity-key-changed", (server, data) => {
        const uid = data.user_id;
        const name =
          (uid != null ? get(users.peek(server)).find((u) => u.user_id === uid)?.username : undefined) ??
          data.name ??
          `User ${uid}`;
        addNotification(
          data.as_guest
            ? `${fromServer(server)}Security warning: ${name} is not signed in as the account you know by that name. ` +
                `Do not trust it to be them until you have checked.`
            : data.replaced
            ? `${fromServer(server)}${name} is another account now: the one you knew by that name was deleted, or this ` +
                `server gave the name to someone else. Verify them before trusting messages.`
            : `${fromServer(server)}Security warning: ${name}'s encryption identity changed. ` +
                `Verify with them out-of-band before trusting messages.`,
          "error",
          0,
        );
      }),

      // ── Moderation ──
      listenServer<{ user_id: number; is_admin: boolean; own: boolean }>("admin-status", (server, data) => {
        const { user_id: uid, is_admin } = data;
        // The backend says whether it is ours: a role admin's comes before
        // `connect` has answered with our id here
        if (data.own) {
          isAdmin.of(server).set(is_admin);
          if (is_admin) {
            addNotification(`${fromServer(server)}You are now a server admin`, "info");
            // An admin is answered about channels that refused us a moment ago,
            // and gets real names where we were given pseudonyms.
            requestAllRosters(server);
          }
        }
        const mark = (list: UserInfo[]) =>
          list.map((u) => (u.user_id === uid ? { ...u, is_admin } : u));
        users.of(server).update(mark);
        previewUsers.of(server).update(mark);
      }),

      listenServer<{ reason: string }>("admin-error", (server, data) => {
        addNotification(`${fromServer(server)}Admin: ${data.reason}`, "error");
      }),

      listenServer<{ reason: string }>("server-disconnected", (server, data) => {
        addNotification(`${fromServer(server)}${data.reason}`, "error", 0);
        // This server only, and closed before the socket is: the
        // connection-lost that follows is then for a server that is not open,
        // and is dropped before it can start the 5-minute reconnect loop. Not
        // written to the open list — like a lost connection, it was not the
        // user's choice, and the next start tries again.
        void disconnectServer(server, { save: false });
      }),

      // Another tab of this browser moved the switch
      listen<boolean>("share-switch", (event) => shareChannelHistory.set(event.payload)),

      // ── Channel history hand-off (E2E, member → newcomer) ──
      listenServer<HandOffAskEvent>("channel-history-requested", (server, data) => answerHandOff(server, data, true)),

      listenServer<{
        channel_id: number;
        from_user_id: number;
        from_username: string;
        messages: unknown[];
      }>("channel-history-received", (server, data) => {
        const chName = channelNameById(server, data.channel_id);
        handOffAnswered(server, data.channel_id);
        // Not from someone blocked. Read and dropped here: the sharer never knows
        const anonymous = !!get(channels.peek(server)).find((c) => c.channel_id === data.channel_id)?.anonymous;
        if (!anonymous && blockedSender(server, data.from_user_id, data.from_username)) return;
        // Something was read: the ring's work is done
        if (data.messages.length > 0) clearRing(server, data.channel_id);
        if (chName) {
          mergeChannelHistory(
            server,
            chName,
            data.messages,
            shortName(data.from_username),
            // What the channel says now. A sharer's claim is clamped by it,
            // and a message arriving with no claim at all takes it — which is
            // what stops somebody keeping a message alive by dropping the
            // field on the way through.
            channelMessageTtl(server, data.channel_id),
          );
        }
      }),

      listenServer<ChannelInfo>("channel-created", (server, created) => {
        // Idempotent: the channel list snapshot may already contain it
        channels.of(server).update((chs) => upsertById(chs, created, (c) => c.channel_id).list);
      }),

      listenServer<{ channel_id: number }>("channel-deleted", (server, data) => {
        const goneId = data.channel_id;
        // Read before the list loses it: the name is the key to everything the
        // channel owns here, and the list is the only place it exists.
        const goneName = channelNameById(server, goneId);
        forgetAutoJoinAsk(server, goneId);
        // The badge goes with the channel. What the user *deleted* there does
        // not: `clearedBefore` outlives the channel on purpose, so a channel
        // recreated under the same name cannot be used to hand the messages
        // they threw away straight back to them.
        if (goneName) clearChannelUnread(server, goneName);
        channels.of(server).update((chs) => chs.filter((ch) => ch.channel_id !== goneId));
        // Nobody is in a channel that does not exist, and the id will be handed
        // out again — a roster left here would be drawn under whatever gets it.
        channelRosters.of(server).update((m) => {
          if (!m.has(goneId)) return m;
          const next = new Map(m);
          next.delete(goneId);
          return next;
        });
        joinedTextChannelIds.of(server).update((s) => {
          if (!s.has(goneId)) return s;
          const next = new Set(s);
          next.delete(goneId);
          return next;
        });
        if (get(activeTextChannelId.peek(server)) === goneId) openTextChannel(server, null);
        // Nothing to do about the voice channel: the server deletes only an
        // empty one, so it was never the one we stand in.
        // Clear preview if previewing the deleted channel
        if (get(previewChannelId.peek(server)) === goneId) {
          previewChannelId.of(server).set(null);
          previewUsers.of(server).set([]);
        }
      }),

      listenServer<{ reason: string }>("channel-error", (server, data) => {
        addNotification(`${fromServer(server)}${data.reason}`, "error");
      }),

      listenServer<ChannelLayout>("channel-layout", (server, layout) => {
        channelLayout.of(server).set(cleanLayout(layout));
        layoutArrived.of(server).set(true);
        // An import's end comes as this, to everybody at once, so asking names no channel
        if (livePath(get(olderRelay.peek(server))?.protocol ?? null)) askArchiveChannels(server);
      }),

      listenServer<WireProfile[]>("profiles", (server, list) => onProfiles(server, list)),

      listenServer<{ hash: number[]; image: number[] }>("profile-picture", (server, p) => {
        void onPicture(server, p.hash, p.image);
      }),

      listenServer<ServerProfileEvent>("server-profile", (server, p) => onServerProfile(server, p)),

      listenServer<{ user_ids: number[]; on: boolean }>("mention-power", (server, p) =>
        onMentionPower(server, p.user_ids, p.on),
      ),

      listenServer<{ mods: { account: number[]; hide: boolean; admin: boolean }[] }>("chat-mods", (server, d) =>
        onChatMods(server, d.mods),
      ),

      listenServer<{ marks: Parameters<typeof onPostsHidden>[1] }>("posts-hidden", (server, d) => onPostsHidden(server, d.marks)),
      listenServer<{ takers: Parameters<typeof onReportTakers>[1] }>("report-takers", (server, d) => onReportTakers(server, d.takers)),
      listenServer<string[]>("my-badges", (server, badges) => {
        myBadges.of(server).set(badges);
      }),

      listenServer<GroupStyle[]>("group-styles", (server, styles) => {
        groupStyles.of(server).set(styles);
      }),

      listenServer<ChannelInfo>("channel-updated", (server, updated) => {
        const before = get(channels.peek(server)).find((c) => c.channel_id === updated.channel_id);
        if (before && before.name !== updated.name) channelRenamed(server, before.name, updated.name);
        noteChannelLogNames(server, [updated]);
        channels.of(server).update((chs) =>
          chs.map((ch) => (ch.channel_id === updated.channel_id ? updated : ch)),
        );
      }),

      listenServer<{ channel_id: number; reason: string }>("kicked", (server, data) => {
        // From a voice channel the server moves us to its lobby, which is no
        // voice channel at all, and the user-list for it follows — that is
        // what ends voice here. From a text channel we only lose it.
        const name = channelNameById(server, data.channel_id);
        const from =
          name && isTextChannel(server, data.channel_id) ? `#${name}` : "the voice channel";
        addNotification(
          `${fromServer(server)}You were removed from ${from}: ${data.reason}`,
          "warning",
        );
        markKicked(server, data.channel_id);
      }),

      // Out of a channel we may not enter any more: no mark, we follow it again if we may
      listenServer<{ channel_id: number; reason: string }>("evicted", (server, data) => {
        const name = channelNameById(server, data.channel_id);
        if (name) addNotification(`${fromServer(server)}You were removed from #${name}: ${data.reason}`, "warning");
      }),

      // On the live path a text channel is followed with no roster: this is the join, and a
      // gate that came or went on one we hold.
      listenServer<{
        joined: { channel_id: number; listen_only: boolean; gated: boolean; last_post_ms: number }[];
        refused: number[];
      }>("text-joined", (server, data) => {
        const ids = data.joined.map((row) => row.channel_id);
        joinedTextChannelIds.of(server).update((had) => new Set([...had, ...ids]));
        joinedNow(server, ids);
        textSeats.of(server).update((had) => {
          const next = new Map(had);
          for (const row of data.joined) next.set(row.channel_id, { gated: row.gated, lastPost: row.last_post_ms });
          return next;
        });
        const list = get(channels.peek(server));
        const seen = get(uiPrefs).opened_channels[serverKey(server)] ?? [];
        for (const row of data.joined) {
          const channel = list.find((c) => c.channel_id === row.channel_id);
          if (!channel) continue;
          if (gateNoted(server, channel, row.gated)) {
            addNotification(`${fromServer(server)}#${channel.name} no longer has a gate.`, "warning");
          }
          noteLastPost(server, row.channel_id, row.last_post_ms);
          ringBack(server, channel);
          if (!marksChannel(seen, channel)) noteNeverOpened(server, channel.name, true);
        }
        listenOnly.of(server).update((had) => {
          const next = new Set(had);
          for (const row of data.joined) {
            if (row.listen_only) next.add(row.channel_id);
            else next.delete(row.channel_id);
          }
          return next;
        });
        // What they are reading stays on screen: a preview ends as its channel is followed,
        // and the pane would go back to the text channel open before it
        const previewed = get(previewChannelId.peek(server));
        if (previewed !== null && ids.includes(previewed)) {
          activeTextChannelId.of(server).set(previewed);
          previewChannelId.of(server).set(null);
          previewUsers.of(server).set([]);
        }
        const active = get(activeTextChannelId.peek(server));
        if (active !== null && ids.includes(active)) {
          const name = channelNameById(server, active);
          if (name) clearChannelUnread(server, name);
        }
        askArchiveChannels(server);
        startSweeps(server);
      }),

      listenServer<{ channel_id: number; user_id: number }>("member-gone", (server, data) => {
        noteMemberGone(server, data.channel_id, data.user_id);
      }),

      // This device just handed these its key: said where who reads is what matters
      listenServer<{ channel_id: number; readers: NamedReader[] }>("key-readers", (server, data) => {
        noteReaders(server, data.channel_id, data.readers);
        const channel = get(channels.peek(server)).find((c) => c.channel_id === data.channel_id);
        if (!goesByList(channel, get(textSeats.peek(server)).get(data.channel_id)?.gated)) return;
        for (const r of data.readers) {
          if (r.user_id) exchangedKey(server, data.channel_id, bareRow(data.channel_id, r.user_id, r.name, r.account));
        }
      }),

      // Marks for channels followed quietly
      listenServer<{ marks: { channel_id: number; last_post_ms: number }[] }>("channel-marks", (server, data) => {
        textSeats.of(server).update((had) => {
          const next = new Map(had);
          for (const m of data.marks) {
            const seat = next.get(m.channel_id);
            if (seat) next.set(m.channel_id, { ...seat, lastPost: m.last_post_ms });
          }
          return next;
        });
        for (const m of data.marks) if (!viewingChannel(server, m.channel_id)) noteLastPost(server, m.channel_id, m.last_post_ms);
      }),

      // A post that will never open here: all a row can honestly say is that someone wrote
      listenServer<{ channel_id: number; timestamp: number }>("channel-ring", (server, data) => {
        ringForPost(server, data.channel_id, data.timestamp);
      }),

      // On mobile data past what is fair to spend unasked: a person says whether it goes
      listenServer<{ channel_id: number; people: number; bytes: number }>("key-job-ask", async (server, data) => {
        const where = channelNameById(server, data.channel_id);
        const megabytes = (data.bytes / 1_000_000).toFixed(1);
        const go = await confirmAction({
          title: "Use mobile data?",
          body: `${data.people} people are online in #${where}, so sending this uses about ${megabytes} MB of mobile data.`,
          confirm: "Send",
        });
        invoke("key_job_answer", { server, channelId: data.channel_id, go }).catch((e: unknown) =>
          console.warn("could not answer about the key job:", e),
        );
      }),

      // A first post with nobody to hand a key to: once a connection, and only if it is true
      listenServer<{ channel_id: number }>("nobody-here", (server, data) => {
        const channel = get(channels.peek(server)).find((c) => c.channel_id === data.channel_id);
        if (!channel || (channel.log && get(account.peek(server))?.cloud)) return;
        const said = `${server}/${data.channel_id}`;
        if (nobodyHereSaid.has(said)) return;
        nobodyHereSaid.add(said);
        addChannelMessage(server, channel.name, {
          user_id: 0,
          username: "",
          content: "Nobody else is here now, and no copy is kept: only you hold this.",
          timestamp: Date.now(),
          kind: "notice",
        });
      }),

      // A page of a sweep, or the rest of a roster too long for one frame
      listenServer<{ channel_id: number; ids?: number[]; rows: UserInfo[]; next: number }>("channel-page", (server, data) => {
        if (!onSweepPage(server, data)) addToRoster(server, data.channel_id, eachOnce(data.rows, (u) => u.user_id));
      }),

      // What a writer's device would not do, or could not: said once each. A gate gone is said
      // by `gateNoted`, which remembers it across connections.
      listenServer<{ kind: "gate-gone" | "guest-in-gate" | "unlisted"; channel_id: number }>("key-warning", (server, data) => {
        const where = channelNameById(server, data.channel_id);
        const channel = where ? `#${where}` : "this channel";
        const said = {
          "gate-gone": null,
          "guest-in-gate": `The server named a guest as a reader of ${channel}, which has a gate. They got no key.`,
          unlisted: `The server named someone as a reader of ${channel} whom it has never listed. They got no key.`,
        }[data.kind];
        if (said) addNotification(`${fromServer(server)}${said}`, "warning");
      }),

      // Channel preview response
      listenServer<{ channel_id: number; users: UserInfo[] }>("channel-users", (server, raw) => {
        const data = { ...raw, users: eachOnce(raw.users, (u) => u.user_id) };
        setRoster(server, data.channel_id, data.users);
        if (data.channel_id === get(previewChannelId.peek(server))) {
          previewUsers.of(server).set(data.users);
        }
      }),

      // Invite events
      listenServer<{ channel_id: number; channel_name: string; invited_by: string }>(
        "invite-received",
        (server, data) => {
          // Dropped, never declined: a decline would tell them. An invite has
          // only the name to go by.
          if (isBlocked(get(blocked.peek(server)), { username: data.invited_by }, false)) return;
          pendingInvites.update((inv) => [
            ...inv.filter((i) => !(i.server === server && i.channel_id === data.channel_id)),
            {
              server,
              channel_id: data.channel_id,
              channel_name: data.channel_name,
              invited_by: data.invited_by,
            },
          ]);
        },
      ),

      listenServer<{ channel_id: number; user_id: number }>("invite-accepted", (server, data) => {
        const userName =
          get(users.peek(server)).find((u) => u.user_id === data.user_id)?.username ?? "User";
        addNotification(`${fromServer(server)}${shortName(userName)} accepted your invite`, "info");
      }),

      listenServer<{ channel_id: number; user_id: number }>("invite-declined", (server) => {
        addNotification(`${fromServer(server)}Your invite was declined`, "warning");
      }),

      // Poke events
      listenServer<{ from_user_id: number; from_username: string; message: string }>(
        "poke-received",
        (server, data) => {
          if (blockedSender(server, data.from_user_id, data.from_username)) return;
          const poke = createPoke(server, data.from_user_id, data.from_username, data.message);
          let fresh = false;
          pendingPokes.update((p) => {
            const added = addPoke(p, poke);
            fresh = added.fresh;
            return added.list;
          });
          // A sender poking again only refreshes their popup
          if (!fresh) return;
          playPokeSound();
          notifyUnfocused(`${fromServer(server)}Poke from ${shortName(data.from_username)}`, data.message || "");
        },
      ),

      // Chat events
      listenServer<{
        channel_id: number;
        user_id: number;
        username: string;
        content: string;
        timestamp: number;
        message_id?: string | null;
        ttl_secs?: number | null;
        reply_to?: string | null;
        thread?: string | null;
        event?: unknown;
        decryption_failed?: boolean;
        /** Past here only on the live path: the post's own word, for want of a list. */
        account?: number[] | null;
        is_admin?: boolean;
        is_moderator?: boolean;
        /** It waited for its key. */
        held?: boolean;
      }>("channel-chat-message", (server, data) => {
        const { channel_id, user_id: uid, username, timestamp, message_id } = data;
        // Cut where it arrives (D-7): what follows parses it, for a mention
        const content = receivedText(data.content);
        const chName = channelNameById(server, channel_id);
        if (chName) {
          // The moment this message is to be deleted, worked out once, here:
          // the shorter of what its sender put inside the ciphertext and what
          // the channel itself says now. Every copy of it — ours, the sender's,
          // and any archive it is shared into later — names the same instant.
          const expires_at = expiryFor(timestamp, data.ttl_secs, channelMessageTtl(server, channel_id));
          // Our own messages are echoed locally under the name we connected
          // with; in an anonymous channel that is not the name anyone else
          // sees, so use the one the channel knows us by.
          const self = get(userId.peek(server));
          const uname = uid === self ? ownDisplayName(server, username, channel_id) : username;
          // Tagged with the writer's account, so the same message read from
          // the channel's stored log is recognised (sameMessage).
          const post: PostFlags | undefined =
            data.is_admin === undefined ? undefined : { user_id: uid, is_admin: data.is_admin, is_moderator: data.is_moderator };
          const writer = writerTag(
            uid === self,
            !!get(channels.peek(server)).find((c) => c.channel_id === channel_id)?.anonymous,
            get(account.peek(server))?.info.id,
            () =>
              post
                ? (data.account ?? undefined)
                : (currentRosterOf(server, channel_id).find((u) => u.user_id === uid)?.account ??
                  get(users.peek(server)).find((u) => u.user_id === uid)?.account),
          );
          // Their chosen name, on arrival: so drawing the row later says nothing of what is
          // on screen, which asking then would
          if (post && writer && uid !== self) askProfile(server, accountHex(writer));
          // An edit, delete, reaction, pin or hide: done to an earlier message
          // here, never a message itself. A pin counts only from one of the
          // channel's managers, as the roster has the sender now; a hide only from
          // a holder of its privilege.
          if (data.event != null) {
            const event = chatEvent(data.event);
            const by = { user_id: uid, username: uname, account: writer ? accountHex(writer) : undefined };
            const mayPin = event?.kind === "pin" && managesChannel(server, channel_id, uid, post);
            const mayHide = event?.kind === "hide" ? hideCheck(server, channel_id, by, post) : undefined;
            if (event) applyChannelEvent(server, chName, { event, by, at: timestamp, content }, mayPin, mayHide);
            return;
          }
          // A forward only repeats what somebody else said, as a quote does
          const power = !messageRefs(data).fwd && arrivedWithPower(server, channel_id, uid, content, post);
          const added = addChannelMessage(
            server,
            chName,
            {
              user_id: uid,
              username: uname,
              content,
              timestamp,
              ...(power ? { power: true } : {}),
              id: message_id ?? undefined,
              expires_at,
              // Marked, so it is never handed on as history: a placeholder is
              // not what the sender wrote, and passing it to the next person to
              // join spreads one member's missing key to everybody after them.
              kind: data.decryption_failed ? "undecryptable" : undefined,
              account: writer ? accountHex(writer) : undefined,
              ...messageRefs(data),
            },
            !!data.held,
          );
          noteArrival(server, channel_id, uid, uname, timestamp, post, writer);
          // Kept, and nothing more: no count, no sound, no notification, whoever
          // they call on. The channel's own anonymity decides, not the tag.
          const anonymous = !!get(channels.peek(server)).find((c) => c.channel_id === channel_id)?.anonymous;
          const quiet = uid !== self && isBlocked(get(blocked.peek(server)), { account: writer, username: uname }, anonymous);
          if (added && !quiet) {
            // An answer to something we wrote, or our name after an @, reaches
            // us like a direct message does
            const mine = uid === self;
            const target =
              !mine && data.reply_to
                ? findTarget(get(channelMessages).get(chatKey(server, chName)) ?? [], data.reply_to, timestamp)
                : undefined;
            const me = { account: ownAccount(server), user_id: self };
            const answered = !!target && isOwn(target, me, (m) => receivedNow(server, m));
            const called = power && callsOn(content, tokensForMe(get(myBadges.peek(server))), powerTokens(get(groupStyles.peek(server))));
            const named = !mine && !answered && (called || mentionsUs(server, channel_id, content));
            const onScreen = viewingChannel(server, channel_id);
            const here = get(channels.peek(server)).find((c) => c.channel_id === channel_id);
            const does = arrival(here ? channelNotify(server, here) : "mentions", { mine, onScreen, forMe: answered || named });
            if (does.count) incrementChannelUnread(server, chName, timestamp);
            else if (!onScreen) noteChannelUnseen(server, chName, timestamp);
            if (does.sound) playChannelMessageSound();
            if (does.os) {
              notifyUnfocused(
                `${fromServer(server)}${shortName(uname)} ${answered ? "replied to you" : "mentioned you"}`,
                notificationBody({ ...messageRefs(data), content, expires_at }),
              );
            }
          }
        }
      }),

      // A channel's stored log: what was written while we were away (or that
      // nobody was here to receive live), filed like the channel's chat.
      listenServer<{
        conv: string;
        sender_account: string;
        sender_name: string;
        from_me: boolean;
        message_id: string | null;
        content: string;
        ttl_secs: number | null;
        timestamp: number;
        /** When the relay filed it: where it stands when read back. */
        server_at?: number;
        reply_to?: string | null;
        thread?: string | null;
        replay?: boolean;
      }>("stored-channel-message", (server, m) => {
        const ch = get(channels.peek(server)).find((c) => c.log === m.conv);
        if (!ch) return;
        // As with a post: the read named this log already, and a draw later says nothing
        if (!m.from_me) askProfile(server, m.sender_account);
        const self = get(userId.peek(server));
        const online = m.from_me ? undefined : get(users.peek(server)).find((u) => u.username === m.sender_name);
        const added = fileStoredChannelMessage(server, ch.name, {
          user_id: m.from_me ? self : (online?.user_id ?? 0),
          username: m.sender_name,
          content: m.content,
          timestamp: m.timestamp,
          id: m.message_id ?? undefined,
          account: m.sender_account,
          expires_at: expiryFor(m.timestamp, m.ttl_secs, channelMessageTtl(server, ch.channel_id)),
          ...(typeof m.server_at === "number" ? { relay_at: m.server_at } : {}),
          ...messageRefs(m),
        });
        const quiet = isBlocked(get(blocked.peek(server)), { account: m.sender_account, username: m.sender_name }, !!ch.anonymous);
        // The words a ring only hinted at are here, or some of them are. One's own too: after an
        // exit with no save it reads back, and may be all the ring was about.
        if (added && !m.replay) {
          moveRead(server, ch, m.timestamp);
          clearRing(server, ch.channel_id);
        }
        if (added && !quiet && !m.from_me && !m.replay && !viewingChannel(server, ch.channel_id)) {
          const forMe = mentionsUs(server, ch.channel_id, m.content);
          const does = arrival(channelNotify(server, ch), { mine: false, onScreen: false, forMe });
          if (does.count) incrementChannelUnread(server, ch.name, m.timestamp);
          else noteChannelUnseen(server, ch.name, m.timestamp);
        }
      }),

      // Who can read what we write in a channel's stored log, said where it
      // happens: nobody gets our keys without the user seeing their name.
      listenServer<{ conv: string; names: string[]; history: boolean }>("log-readers", (server, d) => {
        const ch = get(channels.peek(server)).find((c) => c.log === d.conv);
        if (!ch || d.names.length === 0) return;
        const names = d.names.map((n) => shortName(n) || "someone").join(", ");
        addChannelMessage(server, ch.name, {
          user_id: 0,
          username: "",
          content: d.history
            ? `${names} can now read your kept messages here, earlier ones included`
            : `Your kept messages here can be read by ${names}`,
          timestamp: Date.now(),
          kind: "notice",
        });
      }),

      // What a read could not bring, in a quiet line above what it did: no toast, no mark
      listenServer<{ conv: string }>("stored-unopened", (server, d) => {
        const ch = get(channels.peek(server)).find((c) => c.log === d.conv);
        if (ch) addChannelLineAtTop(server, ch.name, UNOPENED_LINE);
      }),
      listenServer<{ conv: string; window: number }>("stored-clamped", (server, d) => {
        const ch = get(channels.peek(server)).find((c) => c.log === d.conv);
        if (ch) addChannelLineAtTop(server, ch.name, clampedLine(d.window));
      }),

      listenServer<{
        from_user_id: number;
        from_username: string;
        to_user_id: number;
        content: string;
        timestamp: number;
        message_id?: string | null;
        ttl_secs?: number | null;
        reply_to?: string | null;
        thread?: string | null;
        event?: unknown;
      }>("direct-chat-message", (server, data) => {
        const { from_user_id, to_user_id, timestamp } = data;
        const content = receivedText(data.content);
        const myId = get(userId.peek(server));
        const from_username =
          from_user_id === myId ? ownDisplayName(server, data.from_username) : data.from_username;
        // A direct message has no channel to take a policy from, so the two
        // answers are the sender's timer and this user's own for that person,
        // and the shorter wins. Their name is how the conversation is filed.
        const peer = from_user_id === myId ? get(activeDmUsername.peek(server)) : from_username;
        const expires_at = expiryFor(timestamp, data.ttl_secs, dmMessageTtl(server, peer));
        // Tagged with the sender's account, so the same message read back from
        // the stored log later is recognised (sameMessage).
        const sender = from_user_id === myId
          ? get(account.peek(server))?.info.id
          : (get(users.peek(server)).find((u) => u.user_id === from_user_id)?.account ?? rosterAccount(server, from_user_id));
        // Done to an earlier message of the conversation: no message, no sound
        if (data.event != null) {
          const event = chatEvent(data.event);
          const by = { user_id: from_user_id, username: from_username, account: sender ? accountHex(sender) : undefined };
          if (event) applyDmEvent(server, myId, from_user_id, from_username, to_user_id, { event, by, at: timestamp, content });
          return;
        }
        addDmMessage(server, myId, from_user_id, from_username, to_user_id, {
          user_id: from_user_id,
          username: from_username,
          content,
          timestamp,
          id: data.message_id ?? undefined,
          expires_at,
          account: sender ? accountHex(sender) : undefined,
          ...messageRefs(data),
        });
        if (from_user_id !== myId && !isBlocked(get(blocked.peek(server)), { account: sender, username: from_username }, false)) {
          playDirectMessageSound();
          // Never the text of a message with a timer (R2-14), nor of a report
          const body = notificationBody({ ...messageRefs(data), content, expires_at });
          notifyUnfocused(`${fromServer(server)}${shortName(from_username)}`, body || "New message");
        }
      }),

      // A direct message found nobody: the person it was for has left. Said
      // in the conversation, under the message, which is where it was missed.
      // `expired`: it waited for a secure session with them and none came up,
      // so it was never sent at all. That says nothing about where they are;
      // the rest says their id is gone, which is what ends writing to it.
      listenServer<{ user_id: number; kept?: boolean; expired?: number }>(
        "dm-undelivered",
        (server, { user_id, kept, expired }) => {
          const myId = get(userId.peek(server));
          const peer = peerName(server, user_id, "");
          const who = peer ? shortName(peer) : "they";
          addDmMessage(server, myId, myId, "", user_id, {
            user_id: 0,
            username: "",
            content: expired
              ? kept
                ? `No secure session with ${peer ? who : "them"} — kept on the server for them`
                : `Not delivered — no secure session with ${peer ? who : "them"}`
              : kept
                ? `${who} left the server — kept there for when they are back`
                : `Not delivered — ${who} left the server`,
            timestamp: Date.now(),
            kind: "notice",
          });
          if (!expired) {
            detachDm(server, user_id);
            forgetUser(server, user_id);
          }
        },
      ),

      // The channel's keys did not get out, so what was written then was never
      // sent, though it showed as sent.
      // A connection's end says which channel by name: its ids have gone from the stores by then,
      // and if the person is the one who closed it, the server has too. It goes in that chat.
      listen<{ server: string; data: { channel_id: number; expired: number; name?: string | null } }>("channel-undelivered", ({ payload: { server, data: d } }) => {
        const name = d.name ?? get(channels.peek(server)).find((c) => c.channel_id === d.channel_id)?.name;
        if (!name) return;
        addChannelMessage(server, name, {
          user_id: 0,
          username: "",
          content: `Not delivered — the channel's keys could not be sent (${d.expired} ${d.expired === 1 ? "message" : "messages"})`,
          timestamp: Date.now(),
          kind: "notice",
        });
      }),

      // Screen share events. Shares ride on the voice connection; another
      // server's flags still mark its member rows.
      listenServer<{ user_id: number; username: string; resolution: number }>(
        "screenshare-started",
        (server, data) => {
          if (inVoice(server)) addScreenShare(data);
          // Update user list to reflect screen sharing status
          users.of(server).update((u) =>
            u.map((user) =>
              user.user_id === data.user_id ? { ...user, is_screen_sharing: true } : user,
            ),
          );
          patchRosters(server, data.user_id, { is_screen_sharing: true });
        },
      ),

      listenServer<{ user_id: number }>("screenshare-stopped", (server, data) => {
        // Update user list
        users.of(server).update((u) =>
          u.map((user) =>
            user.user_id === data.user_id ? { ...user, is_screen_sharing: false } : user,
          ),
        );
        patchRosters(server, data.user_id, { is_screen_sharing: false });
        if (!inVoice(server)) return;
        removeScreenShare(data.user_id);
        // If we were watching this user, clear viewer state
        if ($watchingUserId === data.user_id) {
          watchingUserId.set(null);
          currentFrame.set(null);
        }
      }),

      listenServer<{ sharer_user_id: number }>("watching-screenshare", (server, data) => {
        if (!inVoice(server)) return;
        watchingUserId.set(data.sharer_user_id);
        currentFrame.set(null);
      }),

      listenServer<{ reason: string }>("stopped-watching-screenshare", (server, data) => {
        if (!inVoice(server)) return;
        watchingUserId.set(null);
        currentFrame.set(null);
        if (data.reason !== "requested") {
          addNotification("Screen share ended: " + data.reason, "info");
        }
      }),

      listenServer<{ viewer_count: number }>("viewer-count-changed", (server, data) => {
        if (!inVoice(server)) return;
        // Capture follows this (captureWanted, above)
        viewerCount.set(data.viewer_count);
      }),

      listenServer<{ reason: string }>("screenshare-error", (server, data) => {
        addNotification(`${fromServer(server)}Screen share error: ${data.reason}`, "error");
        // A share we watch that this device cannot decode comes the same way
        // (the browser's and the desktop's decoders say "cannot decode"), and
        // is no reason to end a share of our own (B1-N1)
        const watchedOne = $watchingUserId !== null && /cannot decode/i.test(data.reason);
        // The server refused or ended our share (a channel can switch sharing
        // off under us): stop capturing rather than sending into the void.
        if (inVoice(server) && $isSharingScreen && !watchedOne) {
          isSharingScreen.set(false);
          viewerCount.set(0);
          invoke("stop_screen_capture").catch(() => {});
        }
      }),

      listen<string>("screenshare-frame", (event) => {
        currentFrame.set(event.payload);
      }),

      // What our own share sends, for the preview (native only)
      listen<string>("screenshare-preview", (event) => {
        if ($isSharingScreen) previewFrame.set(event.payload);
      }),

      // Screen share force-stopped by server (channel change, kick, etc.)
      listenServer("screen-share-force-stopped", (server) => {
        if (!inVoice(server)) return;
        isSharingScreen.set(false);
        viewerCount.set(0);
        watchingUserId.set(null);
        currentFrame.set(null);
        invoke("stop_screen_capture").catch(() => {});
      }),

      // A game pressing push-to-talk for us, so the voice bar can say so
      listen<{ held: boolean }>("sdk-transmit", (event) => {
        transmitHeldByGame.set(event.payload.held);
      }),

      // Global PTT shortcut events from Rust backend
      listen("ptt-global-pressed", () => {
        isTransmitting.set(true);
        // The hotkey opens the capture in Rust and only then says so
        if (get(voiceRestriction)?.voice) void stopTransmit();
      }),
      listen("ptt-global-released", () => {
        isTransmitting.set(false);
      }),
    ];
    void initUpdates();

    // Periodic ping for latency measurement, on every server that is up
    const pingInterval = setInterval(() => {
      for (const server of get(openServers)) {
        if (get(connectionState.peek(server)) === "connected") {
          invoke("ping", { server }).catch(() => {});
        }
      }
    }, 5000);

    // Poll screen audio + video stats every 500ms, while a share is being
    // sent or watched: four calls a second for the length of every call, with
    // nothing to show for them, was battery on a phone for nothing
    let lastSendCount = 0;
    let lastRecvCount = 0;
    let lastFramesSent = 0;
    let lastBytesSent = 0;
    let lastFramesRecv = 0;
    let lastBytesRecv = 0;
    const statsInterval = setInterval(() => {
      if ($voiceState === "connected" && ($isSharingScreen || $watchingUserId !== null)) {
        invoke<[number, number]>("get_screen_audio_status")
          .then(([sendCount, recvCount]) => {
            screenAudioSending.set(sendCount !== lastSendCount);
            screenAudioReceiving.set(recvCount !== lastRecvCount);
            lastSendCount = sendCount;
            lastRecvCount = recvCount;
          })
          .catch(() => {});

        invoke<[number, number, number, number, number, number]>("get_screen_share_stats")
          .then(([framesSent, bytesSent, framesRecv, framesDropped, bytesRecv, resPacked]) => {
            const dt = 0.5; // 500ms poll interval

            // A restarted share resets the counters: never report a negative rate
            const sentDelta = Math.max(0, framesSent - lastFramesSent);
            senderFps.set(Math.round(sentDelta / dt));
            lastFramesSent = framesSent;

            const sentBytesDelta = Math.max(0, bytesSent - lastBytesSent);
            senderBitrate.set(Math.round((sentBytesDelta * 8) / (dt * 1000)));
            lastBytesSent = bytesSent;

            const recvDelta = Math.max(0, framesRecv - lastFramesRecv);
            receiverFps.set(Math.round(recvDelta / dt));
            lastFramesRecv = framesRecv;

            const recvBytesDelta = Math.max(0, bytesRecv - lastBytesRecv);
            receiverBitrate.set(Math.round((recvBytesDelta * 8) / (dt * 1000)));
            lastBytesRecv = bytesRecv;

            if (resPacked > 0) {
              const w = (resPacked >> 16) & 0xFFFF;
              const h = resPacked & 0xFFFF;
              receiverResolution.set(`${w}x${h}`);
            }

            receiverFramesDropped.set(framesDropped);
          })
          .catch(() => {});
      } else {
        // Nothing shared or watched: the audio flags must not stay lit from
        // the share that just ended until the next one starts
        screenAudioSending.set(false);
        screenAudioReceiving.set(false);
      }
    }, 500);

    return () => {
      clearInterval(pingInterval);
      clearInterval(statsInterval);
      stopFileRetain();
      unlisteners.forEach((p) => p.then((unlisten) => unlisten()));
    };
    })();
    return () => void cleanup.then((c) => c());
  });
</script>

<!-- Both wait for the config, which says whether there is history to unlock
     and what to fill in: before it, a start with history off flashed "Set up
     chat history", and the connect dialog showed empty fields first -->
{#if $uiPrefsReady && !$chatUnlocked && !$chatHistoryDisabled}
  <ChatHistorySetup />
{/if}

<!-- Up by itself while no server is on screen, and from the rail's "+". A
     server that is connecting or reconnecting says so in its own pane
     (ReconnectOverlay, mounted by each shell), not here. -->
{#if $uiPrefsReady && ($showConnectDialog || !$serverAddress)}
  <ConnectDialog />
{/if}

<!-- Audio, once, while they are still in no voice channel, where the
     microphone is off anyway. After Connect on purpose: that click is the
     browser gesture the audio graph needs, and it is the moment the user is
     expecting to be asked things. A device that has since vanished re-opens
     just its own step. -->
{#if showAudioSetup}
  <AudioSetup only={audioSetupOnly} onclose={closeAudioSetup} />
{/if}

{#if showLayoutSetup}
  <LayoutSetup onclose={closeLayoutSetup} />
{/if}

<!-- Push-to-talk, Ctrl+M/Ctrl+D, the tray's toggles and the voice-activation
     polling. Mounted here rather than inside a layout on purpose: a layout is a
     subtree that gets destroyed and rebuilt when it is switched, and doing that
     to the key handlers mid-call would either lose push-to-talk or leave two
     copies racing each other. -->
<VoiceKeys />

<!-- The layout itself. Both shells read the same stores; App.svelte stays
     the event bus and the modal stack above them. -->
{#if $uiPrefsReady}
  {#if $uiLayout === "stage"}
    <StageShell onopensettings={() => (showSettings = true)} />
  {:else}
    <ModernShell onopensettings={() => (showSettings = true)} />
  {/if}
{/if}


{#if showSettings}
  <SettingsPanel onclose={() => (showSettings = false)} />
{/if}

{#if !$isMobile && $showSourcePicker}
  <ScreenShareSourcePicker />
{/if}

<!-- The member menu and the channel dialogs, shared by every list there is. -->
<UserContextMenu />

<!-- Our own share, small; the stream view shows it big instead -->
{#if $isSharingScreen && $uiPrefs.share_preview && $streamStage !== "preview" && !showSettings}
  <SharePreview />
{/if}
<ChannelDialogs />
<AccountPrompts />
<AdminDialogs />

<ConfirmDialog />
<Toast />
<InvitePopup />
<PokePopup />

