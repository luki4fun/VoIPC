<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, untrack } from "svelte";
  import { get } from "svelte/store";

  import ConnectDialog from "./lib/components/ConnectDialog.svelte";
  import ScreenShareSourcePicker from "./lib/components/ScreenShareSourcePicker.svelte";
  import SettingsPanel from "./lib/components/SettingsPanel.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import ConfirmDialog from "./lib/components/ConfirmDialog.svelte";
  import InvitePopup from "./lib/components/InvitePopup.svelte";
  import PokePopup from "./lib/components/PokePopup.svelte";
  import VoiceKeys from "./lib/components/VoiceKeys.svelte";
  import LayoutSetup from "./lib/components/LayoutSetup.svelte";
  import ClassicShell from "./lib/components/shell/ClassicShell.svelte";
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
    rememberChannelPassword,
  } from "./lib/stores/connection.js";
  import {
    channels,
    currentChannelId,
    previewChannelId,
    previewUsers,
    voice,
    voiceChannel,
    voiceServer,
  } from "./lib/stores/channels.js";
  import { users, speakingUsers } from "./lib/stores/users.js";
  import { account, accountHex } from "./lib/stores/account.js";
  import { addNotification, removeNotification } from "./lib/stores/notifications.js";
  import { availableUpdate, initUpdates } from "./lib/stores/updates.js";
  import type { UpdateInfo } from "./lib/update-rules.js";
  import { pendingInvites } from "./lib/stores/invites.js";
  import { pendingPokes, createPoke, addPoke } from "./lib/stores/pokes.js";
  import {
    addChannelMessage,
    addDmMessage,
    fileStoredChannelMessage,
    activeDmUsername,
    startExpirySweep,
    activeDmUserId,
    activeTextChannelId,
    dmConversations,
    incrementChannelUnread,
    clearChannelUnread,
    markRead,
    dmKey,
    chatKey,
    chatUnlocked,
    channelMessages,
    joinedTextChannelIds,
    mergeChannelHistory,
    openTextChannel,
    flushChatSave,
  } from "./lib/stores/chat.js";
  import ChatHistorySetup from "./lib/components/ChatHistorySetup.svelte";
  import AudioSetup from "./lib/components/AudioSetup.svelte";
  import type { ChannelInfo, ChatMessage, UserInfo } from "./lib/types.js";
  import { parseInviteFragment } from "./lib/invite.js";
  import {
    channelListArrived,
    disconnectServer,
    fromServer,
    listenServer,
    reconnectAll,
    serverId,
    resetServer,
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
    channelRosters,
    currentRosterOf,
    patchRosters,
    requestAllRosters,
    requestRoster,
    setRoster,
  } from "./lib/stores/rosters.js";
  import {
    askNsfwConsent,
    autoJoinTextChannels,
    channelMessageTtl,
    dmMessageTtl,
    isTextChannel,
  } from "./lib/stores/channel-ui.js";
  import { expiryFor, HISTORY_MAX_MESSAGES, MAX_CONVERSATIONS, messageRefs } from "./lib/chat-rules.js";
  import { LAYOUT_PICKER_VERSION } from "./lib/ui-prefs.js";
  import { voiceMode, vadThreshold } from "./lib/stores/voice.js";
  import {
    playChannelSwitchSound,
    playUserJoinedSound,
    playUserLeftSound,
    playDisconnectedSound,
    playDirectMessageSound,
    playChannelMessageSound,
    playPokeSound,
  } from "./lib/sounds.js";
  import { isMobile, isWeb, mobileTab } from "./lib/stores/platform.js";
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
  import { upsertById } from "./lib/stores/upsert.js";
  import { shortName } from "./lib/username.js";
  import { mentionsName, parse, plainText } from "./lib/markdown.js";
  import { findTarget } from "./lib/thread-rules.js";
  import { cleanLane, micLane } from "./lib/stores/mixer.js";
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
      invoke("join_channel", { server, channelId: ch.channel_id, password: inv.password }).catch(
        (e: unknown) => {
          addNotification(`Could not join #${ch.name}: ${e}`, "error");
        },
      );
    // A link is somebody else's idea: an 18+ channel still asks first
    if (askNsfwConsent(server, ch.channel_id, () => void join())) void join();
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

  /** Whether `content` names us with an `@`. Never in an anonymous channel, where names are pseudonyms. */
  function mentionsUs(server: string, channelId: number, content: string): boolean {
    if (!content.includes("@")) return false;
    if (get(channels.peek(server)).find((c) => c.channel_id === channelId)?.anonymous) return false;
    const own = get(username.peek(server));
    if (!own) return false;
    const names = [...new Set([own, shortName(own)])];
    const tree = parse(content, { names });
    return names.some((n) => mentionsName(tree, n));
  }

  async function notifyUnfocused(title: string, body: string) {
    if (document.hasFocus()) return;
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
      if ($mobileTab === "room") mobileTab.set("chat");
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
  // on whichever server — the service is the call's
  $effect(() => {
    if (!$isMobile) return;
    const bridge = (window as any).__VoIPC;
    if (!bridge) return;

    let timer: ReturnType<typeof setTimeout> | null = null;

    if ($voiceState === 'connected' && $voice !== null) {
      const name = $voiceChannel?.name ?? "";
      timer = setTimeout(() => {
        bridge.startVoiceService(name || 'voice channel');
      }, 300);
    } else {
      bridge.stopVoiceService();
    }

    return () => { if (timer) clearTimeout(timer); };
  });

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
    // A reload, or a window closed under us: the debounced chat save goes now
    window.addEventListener("beforeunload", () => void flushChatSave());

    // Invite link in the URL fragment (web client): keep it, then drop it from
    // the address bar so it is neither kept in history nor re-applied on reload
    if (window.location.hash.length > 1) {
      // For the server that served this page, which is the one the link names:
      // with several open, "whichever is on screen" could be another one.
      const inv = parseInviteFragment(window.location.hash);
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
      shareChannelHistory.set(config.share_channel_history ?? true);
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
      if (config.auto_connect && config.remember_connection) {
        const open = config.open_servers ?? [];
        const list: SavedServer[] =
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
        if (list.length > 0) pendingAutoConnect = list;
      }
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
      listenServer<ChannelInfo[]>("channel-list", (server, list) => {
        channels.of(server).set(list);
        // A reconnect waits for this before deciding where to put the user back
        channelListArrived(server, list);
        // The sidebar draws the people under every channel, and the names for
        // any channel but our own have to be asked for — a UserJoined broadcast
        // deliberately carries no username to outsiders.
        requestAllRosters(server);
      }),

      listenServer<{ channel_id: number; users: UserInfo[] }>("user-list", (server, data) => {
        const oldChannelId = get(currentChannelId.peek(server));
        const newChannelId = data.channel_id;

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

      listenServer<UserInfo>("user-joined", (server, joiner) => {
        // The user list snapshot and this broadcast are built separately on
        // the server, so a user we already have can arrive again (two joins
        // at once). Replacing is idempotent; appending twice would throw
        // each_key_duplicate and wedge the UI.
        let isNew = true;
        const current = get(currentChannelId.peek(server));
        if (joiner.channel_id === current) {
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
        // Always update channel user count (broadcast to all)
        if (isNew) {
          channels.of(server).update((chs) =>
            chs.map((ch) =>
              ch.channel_id === joiner.channel_id ? { ...ch, user_count: ch.user_count + 1 } : ch,
            ),
          );
        }
        // The broadcast told us somebody joined but not who, if it is not our
        // channel. Coalesced, so a filling channel is one question, not ten.
        requestRoster(server, joiner.channel_id);
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
        // Always update channel count
        channels.of(server).update((chs) =>
          chs.map((ch) =>
            ch.channel_id === data.channel_id
              ? { ...ch, user_count: Math.max(0, ch.user_count - 1) }
              : ch,
          ),
        );
        requestRoster(server, data.channel_id);
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
        addNotification(`${fromServer(server)}Connection lost: ${reason}`, "error");

        // Session-scoped warnings die with the session
        if (mediaKeyToast?.server === server) {
          removeNotification(mediaKeyToast.id);
          mediaKeyToast = null;
        }

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
        // What the connection held goes now, the call with it if it was this
        // server's: a channel id is a slot in one server's run, and the
        // reconnect may land on a restarted server that hands them out again.
        resetServer(server);
        void startReconnect(server, { voice: prevVoice, text: prevText }, reason);
      }),

      listen<{ error: string }>("audio-device-error", (event) => {
        addNotification(
          `Audio device error: ${event.payload.error} — retrying…`,
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
        await invoke("quit_app");
      }),

      // A newer VoIPC (updater.rs looks once a day): said once, and Settings
      // has the button
      listen<UpdateInfo>("update-available", (event) => {
        availableUpdate.set(event.payload);
        if (announcedUpdate !== event.payload.version) {
          announcedUpdate = event.payload.version;
          addNotification(`VoIPC ${event.payload.version} is available: Settings, Updates.`, "info", 10000);
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
      listenServer<{ user_id: number; is_admin: boolean }>("admin-status", (server, data) => {
        const { user_id: uid, is_admin } = data;
        if (uid === get(userId.peek(server))) {
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

      // ── Channel history hand-off (E2E, member → newcomer) ──
      listenServer<{ channel_id: number; from_user_id: number }>(
        "channel-history-requested",
        (server, data) => {
          if (!$shareChannelHistory) return;
          const channelId = data.channel_id;
          const chName = channelNameById(server, channelId);
          if (!chName) return;
          // The request reaches us through the server, and the server is the
          // adversary this whole layer is built against: it can invent one, for
          // any channel and from any name, and forty-eight kilobytes of our
          // plaintext would go straight back out. So: a channel we are actually
          // in, and somebody the roster of that channel holds.
          //
          // A relay can still put a stranger *in* that roster — it is the one who
          // sends the member list. But then the stranger is on screen in the
          // channel, which is the difference between a silent harvest and a
          // visible one.
          if (
            channelId !== get(currentChannelId.peek(server)) &&
            !get(joinedTextChannelIds.peek(server)).has(channelId)
          )
            return;
          if (!currentRosterOf(server, channelId).some((u) => u.user_id === data.from_user_id)) {
            return;
          }
          // Second-hand messages go on: a conversation should outlive the last
          // person who was there for it, and it stays marked as hearsay all the
          // way down the chain — sanitizeHistory re-stamps whatever it is handed.
          const now = Date.now();
          const text = ($channelMessages.get(chatKey(server, chName)) ?? []).filter(
            (m) =>
              (!m.kind || m.kind === "text" || m.kind === "shared") &&
              // A message whose destruction timer has run out is not history. The
              // sweep takes it off our own screen within seconds; handing it over
              // in the meantime would put it back into somebody else's archive
              // with a fresh copy of the same deadline.
              !(m.expires_at !== undefined && m.expires_at <= now),
          );
          let msgs: ChatMessage[] = text.slice(-HISTORY_MAX_MESSAGES);
          // Stay well under the 64 KiB control-message cap (Signal envelope + framing)
          const bytes = (list: ChatMessage[]) =>
            new TextEncoder().encode(JSON.stringify(list)).length;
          while (msgs.length > 0 && bytes(msgs) > 48 * 1024) msgs = msgs.slice(1);
          if (msgs.length === 0) return;
          invoke("send_channel_history", {
            server,
            channelId,
            targetUserId: data.from_user_id,
            messages: msgs,
          }).catch((e: unknown) => console.warn("channel history hand-off failed:", e));
        },
      ),

      listenServer<{
        channel_id: number;
        from_user_id: number;
        from_username: string;
        messages: unknown[];
      }>("channel-history-received", (server, data) => {
        const chName = channelNameById(server, data.channel_id);
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

      listenServer<ChannelInfo>("channel-updated", (server, updated) => {
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
      }),

      // Channel preview response
      listenServer<{ channel_id: number; users: UserInfo[] }>("channel-users", (server, data) => {
        setRoster(server, data.channel_id, data.users);
        if (data.channel_id === get(previewChannelId.peek(server))) {
          previewUsers.of(server).set(data.users);
        }
      }),

      // Invite events
      listenServer<{ channel_id: number; channel_name: string; invited_by: string }>(
        "invite-received",
        (server, data) => {
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
        decryption_failed?: boolean;
      }>("channel-chat-message", (server, data) => {
        const { channel_id, user_id: uid, username, content, timestamp, message_id } = data;
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
          const writer = uid === self
            ? get(account.peek(server))?.info.id
            : get(users.peek(server)).find((u) => u.user_id === uid)?.account;
          const added = addChannelMessage(server, chName, {
            user_id: uid,
            username: uname,
            content,
            timestamp,
            id: message_id ?? undefined,
            expires_at,
            // Marked, so it is never handed on as history: a placeholder is
            // not what the sender wrote, and passing it to the next person to
            // join spreads one member's missing key to everybody after them.
            kind: data.decryption_failed ? "undecryptable" : undefined,
            account: writer ? accountHex(writer) : undefined,
            ...messageRefs(data),
          });
          if (added && !viewingChannel(server, channel_id)) {
            incrementChannelUnread(server, chName, timestamp);
            if (uid !== self) playChannelMessageSound();
          }
          // An answer to something we wrote, or our name after an @, reaches
          // us like a direct message does
          if (added && uid !== self) {
            const target = data.reply_to
              ? findTarget(get(channelMessages).get(chatKey(server, chName)) ?? [], data.reply_to)
              : undefined;
            const me = ownAccount(server);
            const answered = !!target && (target.user_id === self || (me !== undefined && target.account === me));
            const named = !answered && mentionsUs(server, channel_id, content);
            if (answered || named) {
              notifyUnfocused(
                `${fromServer(server)}${shortName(uname)} ${answered ? "replied to you" : "mentioned you"}`,
                plainText(content).slice(0, 140),
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
        reply_to?: string | null;
        thread?: string | null;
      }>("stored-channel-message", (server, m) => {
        const ch = get(channels.peek(server)).find((c) => c.log === m.conv);
        if (!ch) return;
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
          ...messageRefs(m),
        });
        if (added && !m.from_me && !viewingChannel(server, ch.channel_id)) incrementChannelUnread(server, ch.name, m.timestamp);
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
      }>("direct-chat-message", (server, data) => {
        const { from_user_id, to_user_id, content, timestamp } = data;
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
          : get(users.peek(server)).find((u) => u.user_id === from_user_id)?.account;
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
        if (from_user_id !== myId) {
          playDirectMessageSound();
          notifyUnfocused(`${fromServer(server)}${shortName(from_username)}`, plainText(content).slice(0, 140));
        }
      }),

      // A direct message found nobody: the person it was for has left. Said
      // in the conversation, under the message, which is where it was missed.
      // `expired`: it waited a minute for a secure session with them and none
      // came up, so it was never sent at all.
      listenServer<{ user_id: number; kept?: boolean; expired?: number }>(
        "dm-undelivered",
        (server, { user_id, kept, expired }) => {
          const myId = get(userId.peek(server));
          const peer = get(dmConversations.peek(server)).find((c) => c.user_id === user_id)?.username;
          const who = peer ? shortName(peer) : "they";
          addDmMessage(server, myId, myId, "", user_id, {
            user_id: 0,
            username: "",
            content: expired
              ? `Not delivered — no secure session with ${peer ? who : "them"} within a minute`
              : kept
                ? `${who} left the server — kept there for when they are back`
                : `Not delivered — ${who} left the server`,
            timestamp: Date.now(),
            kind: "notice",
          });
        },
      ),

      // The channel's keys did not arrive within a minute of writing, so what
      // was written then was never sent, though it showed as sent.
      listenServer<{ channel_id: number; expired: number }>("channel-undelivered", (server, d) => {
        const ch = get(channels.peek(server)).find((c) => c.channel_id === d.channel_id);
        if (!ch) return;
        addChannelMessage(server, ch.name, {
          user_id: 0,
          username: "",
          content: `Not delivered — the channel's keys did not arrive within a minute (${d.expired} ${d.expired === 1 ? "message" : "messages"})`,
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

      listenServer("keyframe-requested", (server) => {
        if (!inVoice(server)) return;
        invoke("set_keyframe_requested").catch(() => {});
      }),

      listenServer<{ reason: string }>("screenshare-error", (server, data) => {
        addNotification(`${fromServer(server)}Screen share error: ${data.reason}`, "error");
        // The server refused or ended our share (a channel can switch sharing
        // off under us): stop capturing rather than sending into the void.
        if (inVoice(server) && $isSharingScreen) {
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

<!-- The layout itself. All three shells read the same stores; App.svelte
     stays the event bus and the modal stack above them. -->
{#if $uiPrefsReady}
  {#if $uiLayout === "modern"}
    <ModernShell onopensettings={() => (showSettings = true)} />
  {:else if $uiLayout === "stage"}
    <StageShell onopensettings={() => (showSettings = true)} />
  {:else}
    <ClassicShell onopensettings={() => (showSettings = true)} />
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

