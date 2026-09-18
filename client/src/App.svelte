<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";
  import { get } from "svelte/store";

  import ConnectDialog from "./lib/components/ConnectDialog.svelte";
  import ScreenShareSourcePicker from "./lib/components/ScreenShareSourcePicker.svelte";
  import SettingsPanel from "./lib/components/SettingsPanel.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import ReconnectOverlay from "./lib/components/ReconnectOverlay.svelte";
  import InvitePopup from "./lib/components/InvitePopup.svelte";
  import PokePopup from "./lib/components/PokePopup.svelte";
  import VoiceKeys from "./lib/components/VoiceKeys.svelte";
  import LayoutSetup from "./lib/components/LayoutSetup.svelte";
  import ClassicShell from "./lib/components/shell/ClassicShell.svelte";
  import ModernShell from "./lib/components/modern/ModernShell.svelte";
  import UserContextMenu from "./lib/components/UserContextMenu.svelte";
  import ChannelDialogs from "./lib/components/ChannelDialogs.svelte";
  import AdminDialogs from "./lib/components/AdminDialogs.svelte";

  import {
    connectionState,
    serverAddress,
    username,
    userId,
    latency,
    acceptSelfSigned,
    isMuted,
    isDeafened,
    isTransmitting,
    transmitHeldByGame,
    isAdmin,
    pendingInvite,
    channelPassword,
    rememberChannelPassword,
  } from "./lib/stores/connection.js";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "./lib/stores/channels.js";
  import { users, speakingUsers } from "./lib/stores/users.js";
  import { addNotification, removeNotification } from "./lib/stores/notifications.js";
  import { pendingInvites } from "./lib/stores/invites.js";
  import { pendingPokes, createPoke } from "./lib/stores/pokes.js";
  import {
    addChannelMessage,
    addDmMessage,
    activeDmUsername,
    startExpirySweep,
    activeDmUserId,
    activeTextChannelId,
    clearDmState,
    clearTextChannels,
    incrementChannelUnread,
    clearChannelUnread,
    chatKey,
    chatUnlocked,
    channelMessages,
    joinedTextChannelIds,
    mergeChannelHistory,
    openTextChannel,
  } from "./lib/stores/chat.js";
  import ChatHistorySetup from "./lib/components/ChatHistorySetup.svelte";
  import AudioSetup from "./lib/components/AudioSetup.svelte";
  import type { ChannelInfo, ChatMessage, UserInfo } from "./lib/types.js";
  import { parseInviteFragment } from "./lib/invite.js";
  import { connectTo } from "./lib/connect.js";
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
  import type { AppConfig } from "./lib/stores/settings.js";
  import { hydrateUiPrefs, layoutAskedVersion, uiLayout, uiPrefsReady } from "./lib/stores/ui-prefs.js";
  import {
    channelRosters,
    clearRosters,
    currentRosterOf,
    patchRosters,
    requestAllRosters,
    requestRoster,
    setRoster,
  } from "./lib/stores/rosters.js";
  import { clearRecentSpeakers } from "./lib/stores/roster.js";
  import {
    autoJoinTextChannels,
    channelMessageTtl,
    clearAutoJoined,
    dmMessageTtl,
    isTextChannel,
  } from "./lib/stores/channel-ui.js";
  import { expiryFor, HISTORY_MAX_MESSAGES, MAX_CONVERSATIONS } from "./lib/chat-rules.js";
  import { resolveRejoin } from "./lib/rejoin-rules.js";
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
    resetRoom,
    selectedUserId,
    syncing,
  } from "./lib/stores/room.js";
  import { upsertById } from "./lib/stores/upsert.js";
  import { clearMixer, cleanLane, micLane } from "./lib/stores/mixer.js";
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
  } from "./lib/stores/screenshare.js";

  // Look up channel name by numeric ID (stable key for chat history)
  function channelNameById(channelId: number): string {
    return $channels.find((c) => c.channel_id === channelId)?.name ?? "";
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
  function ownDisplayName(fallback: string, channelId?: number): string {
    const roster =
      channelId === undefined || channelId === $currentChannelId
        ? $users
        : ($channelRosters.get(channelId) ?? $users);
    return roster.find((u) => u.user_id === $userId)?.username ?? fallback;
  }

  let showSettings = $state(false);
  let reconnectAttempt = $state(0);
  let reconnectCancelled = $state(false);
  let reconnectError = $state("");

  // Deferred auto-connect: waits for chat history to be unlocked first
  let pendingAutoConnect = $state<AppConfig | null>(null);
  let mediaKeyToastId: number | null = null;
  /** game/resource/channel of the last "a game is placing people" toast, so a
   *  bridge that reconnects every two seconds cannot paper the screen. */
  let lastSdkToast: string | null = null;
  /** Channels we have already explained the `routed` flag for this session. */
  const routedNoticeShown = new Set<number>();

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
  // connected, sitting in the lobby where voice is off, and expecting to be
  // asked things. Audio first, because a microphone nobody can hear is what
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
  // walked out of are skipped.
  //
  // Driven from both the list and the connection rather than from the
  // `channel-list` event, because the event arrives first: the server sends the
  // channel list as part of logging in, while the command that would join is
  // refused with "Not connected" until `connect` has finished storing the
  // session. Joining is idempotent, so running this again costs nothing.
  $effect(() => {
    if ($connectionState !== "connected") return;
    autoJoinTextChannels($channels);
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
  // Invite link: join the named channel once connected and the channel list
  // is known (set from the URL fragment in onMount or by the connect dialog)
  $effect(() => {
    const inv = $pendingInvite;
    if (!inv || $connectionState !== "connected" || $channels.length === 0) return;
    const ch = $channels.find((c) => c.name === inv.channel);
    pendingInvite.set(null);
    if (!ch) {
      addNotification(`The invite's channel "${inv.channel}" does not exist on this server`, "warning");
      return;
    }
    if (inv.password) {
      rememberChannelPassword(ch.name, inv.password);
    }
    invoke("join_channel", { channelId: ch.channel_id, password: inv.password }).catch((e: unknown) => {
      addNotification(`Could not join #${ch.name}: ${e}`, "error");
    });
  });

  // Admin status and the room live and die with the connection
  $effect(() => {
    if ($connectionState !== "connected") {
      isAdmin.set(false);
      resetRoom();
      clearMixer();
      clearRosters();
      clearTextChannels();
      // The conversation list is this connection's user ids; the messages
      // behind it are filed by server and name and stay.
      clearDmState();
      clearRecentSpeakers();
      clearAutoJoined();
      // The channel list too. A channel id is a slot in one server's run — the
      // reconnect may land on a restarted server where the numbers have been
      // handed out again — so keeping the old list around is keeping a map of
      // somewhere that no longer exists. Anything that needs a name from it
      // takes one before the connection goes; see the `connection-lost`
      // handler, which runs first and captures the channels to come back to.
      channels.set([]);
    }
  });

  // OS notification when the window is not focused (DMs and pokes)
  async function notifyUnfocused(title: string, body: string) {
    if (document.hasFocus()) return;
    try {
      const notif = await import("@tauri-apps/plugin-notification");
      let granted = await notif.isPermissionGranted();
      if (!granted) {
        granted = (await notif.requestPermission()) === "granted";
      }
      // Freedesktop daemons render the body as markup; peers must not be
      // able to inject links or styling into a system notification
      const esc = (s: string) =>
        s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      if (granted) notif.sendNotification({ title: esc(title), body: esc(body) });
    } catch (e) {
      console.error("Desktop notification failed:", e);
    }
  }

  async function performAutoConnect(config: AppConfig) {
    const result = await connectTo({
      host: config.last_host!,
      port: config.last_port ?? 9987,
      username: config.last_username!,
      acceptSelfSigned: config.last_accept_self_signed ?? false,
    });
    if (!result.ok) {
      console.error("Auto-connect failed:", result.error);
      addNotification("Auto-connect failed: " + result.error, "warning");
    }
  }

  // Trigger auto-connect only after chat history password has been entered
  // (or the vault was skipped — then there is nothing to unlock)
  $effect(() => {
    if (pendingAutoConnect && ($chatUnlocked || $chatHistoryDisabled)) {
      const config = pendingAutoConnect;
      pendingAutoConnect = null;
      performAutoConnect(config);
    }
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
      const name = channelNameById($activeTextChannelId ?? $currentChannelId);
      if (name) clearChannelUnread(name);
    }
  });

  // Android: start/stop foreground voice service when joining/leaving channels
  $effect(() => {
    if (!$isMobile) return;
    const bridge = (window as any).__VoIPC;
    if (!bridge) return;

    let timer: ReturnType<typeof setTimeout> | null = null;

    if ($connectionState === 'connected' && $currentChannelId !== 0) {
      const name = channelNameById($currentChannelId);
      timer = setTimeout(() => {
        bridge.startVoiceService(name || 'voice channel');
      }, 300);
    } else {
      bridge.stopVoiceService();
    }

    return () => { if (timer) clearTimeout(timer); };
  });

  /**
   * Whoever is waiting for the channel list a fresh connection pushes.
   *
   * The list arrives as part of logging in, so it can land either side of
   * `invoke("connect")` resolving — which is why a caller registers the wait
   * *before* connecting rather than after.
   */
  let channelListWaiters: Array<(list: ChannelInfo[]) => void> = [];

  function nextChannelList(timeoutMs = 5000): Promise<ChannelInfo[]> {
    return new Promise((resolve) => {
      const waiter = (list: ChannelInfo[]) => {
        clearTimeout(timer);
        resolve(list);
      };
      // No list, no rejoin: with nothing to resolve names against, the honest
      // answer is to leave the user where the server put them and let them
      // click. Guessing from a list we held before the drop is the bug.
      const timer = setTimeout(() => {
        channelListWaiters = channelListWaiters.filter((w) => w !== waiter);
        resolve([]);
      }, timeoutMs);
      channelListWaiters.push(waiter);
    });
  }

  async function startReconnect(
    address: string,
    name: string,
    previousVoiceChannel: string,
    previousTextChannels: string[],
    initialError = "",
  ) {
    reconnectAttempt = 0;
    reconnectCancelled = false;
    reconnectError = initialError;
    connectionState.set("reconnecting");

    const startTime = Date.now();
    // Generous budget: a Wi-Fi roam, VPN flap, or laptop lid-close should
    // not end the session. The overlay has a Cancel button for giving up.
    const RECONNECT_TIMEOUT_MS = 300_000;

    while (!reconnectCancelled) {
      reconnectAttempt++;
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempt - 1), 10000);

      // Wait before retrying
      await new Promise((resolve) => setTimeout(resolve, delay));
      if (reconnectCancelled) break;

      // Give up after the reconnect budget
      if (Date.now() - startTime > RECONNECT_TIMEOUT_MS) {
        addNotification("Reconnection timed out. Please reconnect manually.", "error");
        reconnectError = "";
        connectionState.set("disconnected");
        return;
      }

      // Clean up stale connection state
      try {
        await invoke("disconnect");
      } catch {
        // Ignore — may already be cleaned up
      }

      try {
        // Registered before connecting: the server sends the channel list while
        // logging us in, so it can be here before `connect` has resolved.
        const listArrived = nextChannelList();
        const id = await invoke<number>("connect", {
          address,
          username: name,
          acceptInvalidCerts: $acceptSelfSigned,
        });
        if (reconnectCancelled) {
          // Cancelled while this attempt was in flight (possibly after a
          // manual connect elsewhere) — don't adopt its result
          invoke("disconnect").catch(() => {});
          return;
        }
        // Success!
        userId.set(id);
        connectionState.set("connected");
        reconnectError = "";
        addNotification("Reconnected to server", "info");

        // Where to go back to is decided against the list *this* connection
        // pushed, by name and by kind — see rejoin-rules.ts. Resolving a
        // remembered name against the ids we held before the drop is how a
        // reconnect ends up walking somebody into a voice channel.
        const list = await listArrived;

        // The room they were standing in
        const [voice] = resolveRejoin(
          previousVoiceChannel ? [previousVoiceChannel] : [],
          list,
          "voice",
        );
        if (voice) {
          try {
            // With the password, where this session knows one: a password room
            // is exactly the room a reconnect must not silently drop you out
            // of, and the text rejoin below has always carried it.
            await invoke("join_channel", {
              channelId: voice.channel_id,
              password: voice.has_password ? channelPassword(voice.name) : null,
            });
          } catch {
            // Password changed, full, gone — stay in the lobby
          }
        }
        // ...and the text channels that were open. An auto-join one comes back
        // on its own with the channel list; this is for the ones joined by
        // hand, which nothing else would bring back.
        for (const ch of resolveRejoin(previousTextChannels, list, "text")) {
          // An `auto_join` one without a password is the effect's to re-join
          // (channel-ui.ts autoJoinTextChannels), which fires on the channel
          // list this connection just pushed. Asking for it here as well spends
          // two of the server's join tokens on one channel, and a connect that
          // runs out of them is a text channel that silently never opens. A
          // password one the effect skips, so it stays ours.
          if (ch.auto_join && !ch.has_password) continue;
          // A password one comes back too, when this session knows the password
          const password = ch.has_password ? channelPassword(ch.name) : null;
          if (ch.has_password && password === null) continue;
          invoke("join_channel", { channelId: ch.channel_id, password }).catch(() => {
            // Gone with the server restart — the user can join it again
          });
        }
        return;
      } catch (e: any) {
        const errMsg = typeof e === "string" ? e : e?.message ?? "Unknown error";
        if (errMsg.includes("username already taken")) {
          reconnectError = "Username still held by server, waiting...";
        } else if (errMsg.includes("version mismatch")) {
          addNotification(errMsg, "error");
          reconnectError = "";
          connectionState.set("disconnected");
          return;
        } else {
          reconnectError = errMsg;
        }
      }
    }

    // User cancelled
    reconnectError = "";
    connectionState.set("disconnected");
  }

  function cancelReconnect() {
    reconnectCancelled = true;
    connectionState.set("disconnected");
  }

  onMount(async () => {
    // Messages with a destruction timer go when their moment comes, whether or
    // not anybody is looking at them. One sweep for the whole app.
    startExpirySweep();

    // Invite link in the URL fragment (web client): keep it, then drop it from
    // the address bar so it is neither kept in history nor re-applied on reload
    if (window.location.hash.length > 1) {
      const inv = parseInviteFragment(window.location.hash);
      if (inv) pendingInvite.set(inv);
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }

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

      // Schedule auto-connect — will trigger after chat history is unlocked
      if (config.auto_connect && config.remember_connection && config.last_host && config.last_username) {
        pendingAutoConnect = config;
      }
    } catch (e) {
      console.error("Failed to load config:", e);
    } finally {
      // Render even if the config could not be read: the defaults are a working
      // app, and a window that never paints is not. Saving stays blocked.
      uiPrefsReady.set(true);
    }

    // Listen for events from the Rust backend
    const unlisteners = [
      listen<ChannelInfo[]>("channel-list", (event) => {
        channels.set(event.payload);
        // A reconnect waits for this before deciding where to put the user back
        const waiting = channelListWaiters;
        channelListWaiters = [];
        for (const waiter of waiting) waiter(event.payload);
        // The sidebar draws the people under every channel, and the names for
        // any channel but our own have to be asked for — a UserJoined broadcast
        // deliberately carries no username to outsiders.
        requestAllRosters();
      }),

      listen<{ channel_id: number; users: UserInfo[] }>("user-list", (event) => {
        const oldChannelId = $currentChannelId;
        const newChannelId = event.payload.channel_id;

        // A text channel is a subscription: we did not move, so none of the
        // channel-switch work below applies, and the chat pane stays where the
        // user put it.
        if (isTextChannel(newChannelId)) {
          joinedTextChannelIds.update((s) => new Set(s).add(newChannelId));
          // setRoster settles the row's member count from this same list
          setRoster(newChannelId, event.payload.users);
          if ($activeTextChannelId === newChannelId) {
            const name = channelNameById(newChannelId);
            if (name) clearChannelUnread(name);
          }
          return;
        }

        // We are excluded from the UserJoined/UserLeft broadcasts about our own
        // movement, so the channel we left loses us here. The one we joined is
        // counted from the list below, by setRoster.
        if (oldChannelId !== newChannelId) {
          channels.update((chs) =>
            chs.map((ch) =>
              ch.channel_id === oldChannelId
                ? { ...ch, user_count: Math.max(0, ch.user_count - 1) }
                : ch,
            )
          );
        }

        currentChannelId.set(newChannelId);
        users.set(event.payload.users);
        setRoster(newChannelId, event.payload.users);
        // We just left one, and the channel we joined may have been listed with
        // a roster we fetched before joining.
        if (oldChannelId !== newChannelId) {
          requestRoster(oldChannelId);
          requestAllRosters();
        }
        const joinedName = channelNameById(newChannelId);
        if (joinedName) clearChannelUnread(joinedName);

        // Clear screenshare state and play channel switch sound
        if (oldChannelId !== newChannelId) {
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
          const joined = $channels.find((c) => c.channel_id === newChannelId);
          if (joined?.routed && !routedNoticeShown.has(newChannelId)) {
            routedNoticeShown.add(newChannelId);
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
        previewChannelId.set(null);
        previewUsers.set([]);
      }),

      listen<UserInfo>("user-joined", (event) => {
        // The user list snapshot and this broadcast are built separately on
        // the server, so a user we already have can arrive again (two joins
        // at once). Replacing is idempotent; appending twice would throw
        // each_key_duplicate and wedge the UI.
        let isNew = true;
        if (event.payload.channel_id === $currentChannelId) {
          users.update((u) => {
            const next = upsertById(u, event.payload, (x) => x.user_id);
            isNew = next.added;
            return next.list;
          });
          // Play join sound (not for lobby, not for ourselves)
          if (isNew && $currentChannelId !== 0 && event.payload.user_id !== $userId) {
            playUserJoinedSound();
          }
        }
        // Always update channel user count (broadcast to all)
        if (isNew) {
          channels.update((chs) =>
            chs.map((ch) =>
              ch.channel_id === event.payload.channel_id
                ? { ...ch, user_count: ch.user_count + 1 }
                : ch
            )
          );
        }
        // The broadcast told us somebody joined but not who, if it is not our
        // channel. Coalesced, so a filling channel is one question, not ten.
        requestRoster(event.payload.channel_id);
      }),

      listen<{ user_id: number; channel_id: number }>("user-left", (event) => {
        // Our own departure from a text channel is how we learn a leave (or a
        // kick from one) went through.
        if (
          event.payload.user_id === $userId &&
          isTextChannel(event.payload.channel_id)
        ) {
          joinedTextChannelIds.update((s) => {
            const next = new Set(s);
            next.delete(event.payload.channel_id);
            return next;
          });
          if ($activeTextChannelId === event.payload.channel_id) openTextChannel(null);
        }

        // Only remove from local user list if they left our channel
        if (event.payload.channel_id === $currentChannelId) {
          // Play leave sound before removing (not for lobby, not for ourselves)
          if ($currentChannelId !== 0 && event.payload.user_id !== $userId) {
            playUserLeftSound();
          }
          users.update((u) =>
            u.filter((user) => user.user_id !== event.payload.user_id)
          );
          // Forget where they stood: the id belongs to the next joiner
          positions.update((m) => {
            if (!m.has(event.payload.user_id)) return m;
            const next = new Map(m);
            next.delete(event.payload.user_id);
            return next;
          });
          // A selection pointing at nobody would move a ghost on the next click
          selectedUserId.update((id) => (id === event.payload.user_id ? null : id));
        }
        // Always update channel count
        channels.update((chs) =>
          chs.map((ch) =>
            ch.channel_id === event.payload.channel_id
              ? { ...ch, user_count: Math.max(0, ch.user_count - 1) }
              : ch
          )
        );
        requestRoster(event.payload.channel_id);
      }),

      listen<{ user_id: number; muted: boolean }>("user-muted", (event) => {
        users.update((u) =>
          u.map((user) =>
            user.user_id === event.payload.user_id
              ? { ...user, is_muted: event.payload.muted }
              : user
          )
        );
        patchRosters(event.payload.user_id, { is_muted: event.payload.muted });
      }),

      listen<{ user_id: number; enabled: boolean }>("user-history-sharing", (event) => {
        users.update((u) =>
          u.map((user) =>
            user.user_id === event.payload.user_id
              ? { ...user, shares_history: event.payload.enabled }
              : user
          )
        );
        patchRosters(event.payload.user_id, { shares_history: event.payload.enabled });
      }),

      listen<{ user_id: number; deafened: boolean }>("user-deafened", (event) => {
        users.update((u) =>
          u.map((user) =>
            user.user_id === event.payload.user_id
              ? { ...user, is_deafened: event.payload.deafened }
              : user
          )
        );
        patchRosters(event.payload.user_id, { is_deafened: event.payload.deafened });
      }),

      // A member of a proximity channel shared where they stand
      listen<{ user_id: number; x: number; y: number; z: number }>(
        "user-position",
        (event) => {
          const { user_id, x, y, z } = event.payload;
          positions.update((m) => new Map(m).set(user_id, { x, y, z }));
        }
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
      }>(
        "sdk-status",
        (event) => {
          const { connected, game, resource, channel, beacon, transmit } = event.payload;
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

      listen<{ user_id: number; speaking: boolean }>(
        "user-speaking",
        (event) => {
          speakingUsers.update((set) => {
            const next = new Set(set);
            if (event.payload.speaking) {
              next.add(event.payload.user_id);
            } else {
              next.delete(event.payload.user_id);
            }
            return next;
          });
        }
      ),

      listen<{ ms: number }>("latency-update", (event) => {
        latency.set(event.payload.ms);
      }),

      listen<{ reason: string }>("connection-lost", (event) => {
        const reason = event.payload.reason;
        console.error("Connection lost:", reason);
        addNotification(`Connection lost: ${reason}`, "error");

        // Clear screenshare state
        resetScreenShareState();

        // Session-scoped warnings die with the session
        if (mediaKeyToastId !== null) {
          removeNotification(mediaKeyToastId);
          mediaKeyToastId = null;
        }

        // Play disconnected sound on initial loss (not during reconnect retries)
        if ($connectionState === "connected") {
          playDisconnectedSound();
        }

        // If we were connected, start auto-reconnect
        if ($connectionState === "connected") {
          const addr = $serverAddress;
          const name = $username;
          // By name, both of them, and read here because this runs while the
          // channel list is still ours: the reconnect may land on a restarted
          // server, where the ids are new but the channels people were in are
          // the same ones they would recognise.
          const prevVoice = $currentChannelId !== 0 ? channelNameById($currentChannelId) : "";
          const prevText = [...$joinedTextChannelIds]
            .map((id) => channelNameById(id))
            .filter((n) => n !== "");
          startReconnect(addr, name, prevVoice, prevText, reason);
        } else if ($connectionState !== "reconnecting") {
          // A second connection-lost during a reconnect (ServerShutdown is
          // followed by the socket closing) must not hide the overlay while
          // the retry loop is still running
          connectionState.set("disconnected");
        }
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
        addNotification(`Push-to-talk outside the window: ${event.payload.reason}`, "warning", 0);
      }),

      listen("media-key-missing", () => {
        if (mediaKeyToastId === null) {
          mediaKeyToastId = addNotification(
            "Waiting for the channel's encryption key — voice and screen share are held back until a member sends it",
            "error",
            0,
          );
        }
      }),

      listen("media-key-installed", () => {
        if (mediaKeyToastId !== null) {
          removeNotification(mediaKeyToastId);
          mediaKeyToastId = null;
        }
      }),

      listen<{ user_id: number }>("identity-key-changed", (event) => {
        const uid = event.payload.user_id;
        const name =
          $users.find((u) => u.user_id === uid)?.username ?? `User ${uid}`;
        addNotification(
          `Security warning: ${name}'s encryption identity changed. ` +
            `Verify with them out-of-band before trusting messages.`,
          "error",
          0,
        );
      }),

      // ── Moderation ──
      listen<{ user_id: number; is_admin: boolean }>("admin-status", (event) => {
        const { user_id: uid, is_admin } = event.payload;
        if (uid === $userId) {
          isAdmin.set(is_admin);
          if (is_admin) {
            addNotification("You are now a server admin", "info");
            // An admin is answered about channels that refused us a moment ago,
            // and gets real names where we were given pseudonyms.
            requestAllRosters();
          }
        }
        const mark = (list: UserInfo[]) =>
          list.map((u) => (u.user_id === uid ? { ...u, is_admin } : u));
        users.update(mark);
        previewUsers.update(mark);
      }),

      listen<{ reason: string }>("admin-error", (event) => {
        addNotification(`Admin: ${event.payload.reason}`, "error");
      }),

      listen<{ reason: string }>("server-disconnected", (event) => {
        // Set synchronously, before the socket closes: the connection-lost
        // that follows must not start the 5-minute reconnect loop
        connectionState.set("disconnected");
        isAdmin.set(false);
        addNotification(event.payload.reason, "error", 0);
        invoke("disconnect").catch(() => {});
      }),

      // ── Channel history hand-off (E2E, member → newcomer) ──
      listen<{ channel_id: number; from_user_id: number }>("channel-history-requested", (event) => {
        if (!$shareChannelHistory) return;
        const channelId = event.payload.channel_id;
        const chName = channelNameById(channelId);
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
        if (channelId !== $currentChannelId && !$joinedTextChannelIds.has(channelId)) return;
        if (!currentRosterOf(channelId).some((u) => u.user_id === event.payload.from_user_id)) {
          return;
        }
        // Second-hand messages go on: a conversation should outlive the last
        // person who was there for it, and it stays marked as hearsay all the
        // way down the chain — sanitizeHistory re-stamps whatever it is handed.
        const now = Date.now();
        const text = ($channelMessages.get(chatKey(chName)) ?? []).filter(
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
        const bytes = (list: ChatMessage[]) => new TextEncoder().encode(JSON.stringify(list)).length;
        while (msgs.length > 0 && bytes(msgs) > 48 * 1024) msgs = msgs.slice(1);
        if (msgs.length === 0) return;
        invoke("send_channel_history", {
          channelId,
          targetUserId: event.payload.from_user_id,
          messages: msgs,
        }).catch((e: unknown) => console.warn("channel history hand-off failed:", e));
      }),

      listen<{ channel_id: number; from_user_id: number; from_username: string; messages: unknown[] }>(
        "channel-history-received",
        (event) => {
          const chName = channelNameById(event.payload.channel_id);
          if (chName) {
            mergeChannelHistory(
              chName,
              event.payload.messages,
              event.payload.from_username,
              // What the channel says now. A sharer's claim is clamped by it,
              // and a message arriving with no claim at all takes it — which is
              // what stops somebody keeping a message alive by dropping the
              // field on the way through.
              channelMessageTtl(event.payload.channel_id),
            );
          }
        },
      ),

      listen<ChannelInfo>("channel-created", (event) => {
        // Idempotent: the channel list snapshot may already contain it
        channels.update(
          (chs) => upsertById(chs, event.payload, (c) => c.channel_id).list
        );
      }),

      listen<{ channel_id: number }>("channel-deleted", (event) => {
        // Read before the list loses it: the name is the key to everything the
        // channel owns here, and the list is the only place it exists.
        const goneName = channelNameById(event.payload.channel_id);
        // The badge goes with the channel. What the user *deleted* there does
        // not: `clearedBefore` outlives the channel on purpose, so a channel
        // recreated under the same name cannot be used to hand the messages
        // they threw away straight back to them.
        if (goneName) clearChannelUnread(goneName);
        channels.update((chs) =>
          chs.filter((ch) => ch.channel_id !== event.payload.channel_id)
        );
        // Nobody is in a channel that does not exist, and the id will be handed
        // out again — a roster left here would be drawn under whatever gets it.
        channelRosters.update((m) => {
          if (!m.has(event.payload.channel_id)) return m;
          const next = new Map(m);
          next.delete(event.payload.channel_id);
          return next;
        });
        joinedTextChannelIds.update((s) => {
          if (!s.has(event.payload.channel_id)) return s;
          const next = new Set(s);
          next.delete(event.payload.channel_id);
          return next;
        });
        if ($activeTextChannelId === event.payload.channel_id) openTextChannel(null);
        // If we were in the deleted channel, switch to General
        currentChannelId.update((id) => {
          if (id === event.payload.channel_id) {
            invoke("join_channel", { channelId: 0, password: null });
            return 0;
          }
          return id;
        });
        // Clear preview if previewing the deleted channel
        if ($previewChannelId === event.payload.channel_id) {
          previewChannelId.set(null);
          previewUsers.set([]);
        }
      }),

      listen<{ reason: string }>("channel-error", (event) => {
        addNotification(event.payload.reason, "error");
      }),

      listen<ChannelInfo>("channel-updated", (event) => {
        channels.update((chs) =>
          chs.map((ch) =>
            ch.channel_id === event.payload.channel_id ? event.payload : ch
          )
        );
      }),

      listen<{ channel_id: number; reason: string }>("kicked", (event) => {
        addNotification("You were kicked: " + event.payload.reason, "warning");
        // The server already moved us to General and will send a user-list event
      }),

      // Channel preview response
      listen<{ channel_id: number; users: UserInfo[] }>("channel-users", (event) => {
        setRoster(event.payload.channel_id, event.payload.users);
        if (event.payload.channel_id === $previewChannelId) {
          previewUsers.set(event.payload.users);
        }
      }),

      // Invite events
      listen<{ channel_id: number; channel_name: string; invited_by: string }>(
        "invite-received",
        (event) => {
          pendingInvites.update((inv) => [
            ...inv.filter((i) => i.channel_id !== event.payload.channel_id),
            {
              channel_id: event.payload.channel_id,
              channel_name: event.payload.channel_name,
              invited_by: event.payload.invited_by,
            },
          ]);
        }
      ),

      listen<{ channel_id: number; user_id: number }>("invite-accepted", (event) => {
        const userName = $users.find((u) => u.user_id === event.payload.user_id)?.username ?? "User";
        addNotification(`${userName} accepted your invite`, "info");
      }),

      listen<{ channel_id: number; user_id: number }>("invite-declined", () => {
        addNotification("Your invite was declined", "warning");
      }),

      // Poke events
      listen<{ from_user_id: number; from_username: string; message: string }>(
        "poke-received",
        (event) => {
          pendingPokes.update((p) => [
            ...p,
            createPoke(
              event.payload.from_user_id,
              event.payload.from_username,
              event.payload.message,
            ),
          ]);
          playPokeSound();
          notifyUnfocused(
            `Poke from ${event.payload.from_username}`,
            event.payload.message || "",
          );
        }
      ),

      // Chat events
      listen<{
        channel_id: number;
        user_id: number;
        username: string;
        content: string;
        timestamp: number;
        message_id?: string | null;
        decryption_failed?: boolean;
      }>("channel-chat-message", (event) => {
        const { channel_id, user_id: uid, username, content, timestamp, message_id } = event.payload;
        const chName = channelNameById(channel_id);
        if (chName) {
          // The moment this message is to be deleted, worked out once, here:
          // the shorter of what its sender put inside the ciphertext and what
          // the channel itself says now. Every copy of it — ours, the sender's,
          // and any archive it is shared into later — names the same instant.
          const expires_at = expiryFor(
            timestamp,
            event.payload.ttl_secs,
            channelMessageTtl(channel_id),
          );
          // Our own messages are echoed locally under the name we connected
          // with; in an anonymous channel that is not the name anyone else
          // sees, so use the one the channel knows us by.
          const uname = uid === $userId ? ownDisplayName(username, channel_id) : username;
          addChannelMessage(chName, {
            user_id: uid,
            username: uname,
            content,
            timestamp,
            id: message_id ?? undefined,
            expires_at,
            // Marked, so it is never handed on as history: a placeholder is
            // not what the sender wrote, and passing it to the next person to
            // join spreads one member's missing key to everybody after them.
            kind: event.payload.decryption_failed ? "undecryptable" : undefined,
          });
          // Track unread if not currently viewing this channel's chat
          const viewingThisChannel =
            $activeDmUserId === null &&
            channel_id === ($activeTextChannelId ?? $currentChannelId);
          if (!viewingThisChannel) {
            incrementChannelUnread(chName);
            if (uid !== $userId) playChannelMessageSound();
          }
        }
      }),

      listen<{
        from_user_id: number;
        from_username: string;
        to_user_id: number;
        content: string;
        timestamp: number;
        message_id?: string | null;
        ttl_secs?: number | null;
      }>("direct-chat-message", (event) => {
        const { from_user_id, to_user_id, content, timestamp } = event.payload;
        const myId = $userId;
        const from_username =
          from_user_id === myId
            ? ownDisplayName(event.payload.from_username)
            : event.payload.from_username;
        // A direct message has no channel to take a policy from, so the two
        // answers are the sender's timer and this user's own for that person,
        // and the shorter wins. Their name is how the conversation is filed.
        const peer = from_user_id === myId ? $activeDmUsername : from_username;
        const expires_at = expiryFor(timestamp, event.payload.ttl_secs, dmMessageTtl(peer));
        addDmMessage(myId, from_user_id, from_username, to_user_id, {
          user_id: from_user_id,
          username: from_username,
          content,
          timestamp,
          id: event.payload.message_id ?? undefined,
          expires_at,
        });
        if (from_user_id !== myId) {
          playDirectMessageSound();
          notifyUnfocused(from_username, content.slice(0, 140));
        }
      }),

      // Screen share events
      listen<{ user_id: number; username: string; resolution: number }>(
        "screenshare-started",
        (event) => {
          addScreenShare(event.payload);
          // Update user list to reflect screen sharing status
          users.update((u) =>
            u.map((user) =>
              user.user_id === event.payload.user_id
                ? { ...user, is_screen_sharing: true }
                : user
            )
          );
          patchRosters(event.payload.user_id, { is_screen_sharing: true });
        }
      ),

      listen<{ user_id: number }>("screenshare-stopped", (event) => {
        removeScreenShare(event.payload.user_id);
        // Update user list
        users.update((u) =>
          u.map((user) =>
            user.user_id === event.payload.user_id
              ? { ...user, is_screen_sharing: false }
              : user
          )
        );
        patchRosters(event.payload.user_id, { is_screen_sharing: false });
        // If we were watching this user, clear viewer state
        if ($watchingUserId === event.payload.user_id) {
          watchingUserId.set(null);
          currentFrame.set(null);
        }
      }),

      listen<{ sharer_user_id: number }>("watching-screenshare", (event) => {
        watchingUserId.set(event.payload.sharer_user_id);
        currentFrame.set(null);
      }),

      listen<{ reason: string }>("stopped-watching-screenshare", (event) => {
        watchingUserId.set(null);
        currentFrame.set(null);
        if (event.payload.reason !== "requested") {
          addNotification("Screen share ended: " + event.payload.reason, "info");
        }
      }),

      listen<{ viewer_count: number }>("viewer-count-changed", (event) => {
        const count = event.payload.viewer_count;
        const prevCount = $viewerCount;
        viewerCount.set(count);

        // Start/stop capture based on viewer count
        if (prevCount === 0 && count > 0 && $isSharingScreen) {
          invoke("start_screen_capture", {
            resolution: $shareResolution,
            fps: $shareFps,
          }).catch((e: any) => {
            console.error("Failed to start capture:", e);
            addNotification(`Failed to start screen capture: ${e}`, "error");
          });
        } else if (count === 0 && prevCount > 0) {
          invoke("stop_screen_capture").catch((e: any) =>
            console.error("Failed to stop capture:", e)
          );
        }
      }),

      listen("keyframe-requested", () => {
        invoke("set_keyframe_requested").catch(() => {});
      }),

      listen<{ reason: string }>("screenshare-error", (event) => {
        addNotification("Screen share error: " + event.payload.reason, "error");
        // The server refused or ended our share (a channel can switch sharing
        // off under us): stop capturing rather than sending into the void.
        if ($isSharingScreen) {
          isSharingScreen.set(false);
          invoke("stop_screen_capture").catch(() => {});
        }
      }),

      listen<string>("screenshare-frame", (event) => {
        currentFrame.set(event.payload);
      }),

      // Screen share force-stopped by server (channel change, kick, etc.)
      listen("screen-share-force-stopped", () => {
        isSharingScreen.set(false);
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

    // Periodic ping for latency measurement
    const pingInterval = setInterval(() => {
      if ($connectionState === "connected") {
        invoke("ping").catch(() => {});
      }
    }, 5000);

    // Poll screen audio + video stats every 500ms
    let lastSendCount = 0;
    let lastRecvCount = 0;
    let lastFramesSent = 0;
    let lastBytesSent = 0;
    let lastFramesRecv = 0;
    let lastBytesRecv = 0;
    const statsInterval = setInterval(() => {
      if ($connectionState === "connected") {
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

            const sentBytesDelta = bytesSent - lastBytesSent;
            senderBitrate.set(Math.round((sentBytesDelta * 8) / (dt * 1000)));
            lastBytesSent = bytesSent;

            const recvDelta = framesRecv - lastFramesRecv;
            receiverFps.set(Math.round(recvDelta / dt));
            lastFramesRecv = framesRecv;

            const recvBytesDelta = bytesRecv - lastBytesRecv;
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
      }
    }, 500);

    return () => {
      clearInterval(pingInterval);
      clearInterval(statsInterval);
      unlisteners.forEach((p) => p.then((unlisten) => unlisten()));
    };
  });
</script>

{#if !$chatUnlocked && !$chatHistoryDisabled}
  <ChatHistorySetup />
{/if}

{#if $connectionState === "disconnected" || $connectionState === "connecting"}
  <ConnectDialog />
{/if}

{#if $connectionState === "reconnecting"}
  <ReconnectOverlay attempt={reconnectAttempt} error={reconnectError} oncancel={cancelReconnect} />
{/if}

<!-- Audio, once, while they are still in the lobby where voice is off anyway.
     After Connect on purpose: that click is the browser gesture the audio
     graph needs, and it is the moment the user is expecting to be asked
     things. A device that has since vanished re-opens just its own step. -->
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

<!-- The layout itself. Both shells read the same stores; App.svelte stays the
     event bus and the modal stack above them. -->
{#if $uiPrefsReady}
  {#if $uiLayout === "modern"}
    <ModernShell onopensettings={() => (showSettings = true)} />
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
<ChannelDialogs />
<AdminDialogs />

<Toast />
<InvitePopup />
<PokePopup />

