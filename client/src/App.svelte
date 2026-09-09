<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";

  import ConnectDialog from "./lib/components/ConnectDialog.svelte";
  import ChannelList from "./lib/components/ChannelList.svelte";
  import ChatPanel from "./lib/components/ChatPanel.svelte";
  import UserList from "./lib/components/UserList.svelte";
  import VoiceControls from "./lib/components/VoiceControls.svelte";
  import ScreenShareSourcePicker from "./lib/components/ScreenShareSourcePicker.svelte";
  import ScreenShareViewer from "./lib/components/ScreenShareViewer.svelte";
  import RoomView from "./lib/components/RoomView.svelte";
  import StatusBar from "./lib/components/StatusBar.svelte";
  import SettingsPanel from "./lib/components/SettingsPanel.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import ReconnectOverlay from "./lib/components/ReconnectOverlay.svelte";
  import InvitePopup from "./lib/components/InvitePopup.svelte";
  import PokePopup from "./lib/components/PokePopup.svelte";
  import Icon from "./lib/components/Icons.svelte";

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
    isAdmin,
    pendingInvite,
    channelPasswords,
  } from "./lib/stores/connection.js";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "./lib/stores/channels.js";
  import { users, speakingUsers } from "./lib/stores/users.js";
  import { addNotification, removeNotification } from "./lib/stores/notifications.js";
  import { pendingInvites } from "./lib/stores/invites.js";
  import { pendingPokes, createPoke } from "./lib/stores/pokes.js";
  import {
    addChannelMessage,
    addDmMessage,
    activeDmUserId,
    incrementChannelUnread,
    clearChannelUnread,
    chatUnlocked,
    unreadPerChannel,
    channelMessages,
    mergeChannelHistory,
  } from "./lib/stores/chat.js";
  import ChatHistorySetup from "./lib/components/ChatHistorySetup.svelte";
  import type { ChannelInfo, ChatMessage, UserInfo } from "./lib/types.js";
  import { parseInviteFragment } from "./lib/invite.js";
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
    screenShareCodec,
    spatialAudio,
    screenAudioSpatial,
    defaultServer,
  } from "./lib/stores/settings.js";
  import type { AppConfig } from "./lib/stores/settings.js";
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
  import type { MobileTab } from "./lib/stores/platform.js";
  import {
    clearRoom,
    currentProximity,
    drivenBy,
    positions,
    resetRoom,
    roomOpen,
    selectedUserId,
    syncing,
  } from "./lib/stores/room.js";
  import { upsertById } from "./lib/stores/upsert.js";
  import MobilePTT from "./lib/components/MobilePTT.svelte";
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
   * The name the current channel knows us by. Our own messages are echoed
   * locally under the name we connected with, which in an anonymous channel
   * is not the one anyone else sees; the member list carries the right one.
   */
  function ownDisplayName(fallback: string): string {
    return $users.find((u) => u.user_id === $userId)?.username ?? fallback;
  }

  let showSettings = $state(false);
  let reconnectAttempt = $state(0);
  let reconnectCancelled = $state(false);
  let reconnectError = $state("");

  // Deferred auto-connect: waits for chat history to be unlocked first
  let pendingAutoConnect = $state<AppConfig | null>(null);
  let mediaKeyToastId: number | null = null;
  // Chat pane below the screen-share viewer (desktop)
  let viewerChatOpen = $state(true);

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
      channelPasswords.update((m) => new Map(m).set(ch.name, inv.password!));
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
    connectionState.set("connecting");
    try {
      const address = `${config.last_host}:${config.last_port ?? 9987}`;
      const id = await invoke<number>("connect", {
        address,
        username: config.last_username!,
        acceptInvalidCerts: config.last_accept_self_signed ?? false,
      });
      userId.set(id);
      serverAddress.set(address);
      username.set(config.last_username!);
      acceptSelfSigned.set(config.last_accept_self_signed ?? false);
      connectionState.set("connected");
    } catch (e) {
      console.error("Auto-connect failed:", e);
      connectionState.set("disconnected");
      addNotification("Auto-connect failed: " + String(e), "warning");
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
      roomOpen.set(false);
      if ($mobileTab === "room") mobileTab.set("chat");
      if ($positions.size > 0 || $syncing) clearRoom();
    }
  });

  // Clear unread for current channel when returning from DM view
  $effect(() => {
    if ($activeDmUserId === null) {
      const name = channelNameById($currentChannelId);
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

  async function startReconnect(
    address: string,
    name: string,
    previousChannelId: number,
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

        // Try to rejoin previous channel
        if (previousChannelId !== 0) {
          try {
            await invoke("join_channel", { channelId: previousChannelId, password: null });
          } catch {
            // Channel may no longer exist — stay in General
          }
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
      screenShareCodec.set(config.screen_share_codec ?? "h264");
      spatialAudio.set(config.spatial_audio ?? true);
      screenAudioSpatial.set(config.screen_audio_spatial ?? true);
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
    }

    // Listen for events from the Rust backend
    const unlisteners = [
      listen<ChannelInfo[]>("channel-list", (event) => {
        channels.set(event.payload);
      }),

      listen<{ channel_id: number; users: UserInfo[] }>("user-list", (event) => {
        const oldChannelId = $currentChannelId;
        const newChannelId = event.payload.channel_id;

        // Update channel counts for our own movement (we're excluded from
        // UserJoined/UserLeft broadcasts, so we must adjust counts here)
        if (oldChannelId !== newChannelId) {
          channels.update((chs) =>
            chs.map((ch) => {
              if (ch.channel_id === oldChannelId) {
                return { ...ch, user_count: Math.max(0, ch.user_count - 1) };
              }
              if (ch.channel_id === newChannelId) {
                return { ...ch, user_count: event.payload.users.length };
              }
              return ch;
            })
          );
        }

        currentChannelId.set(newChannelId);
        users.set(event.payload.users);
        const joinedName = channelNameById(newChannelId);
        if (joinedName) clearChannelUnread(joinedName);

        // Clear screenshare state and play channel switch sound
        if (oldChannelId !== newChannelId) {
          // A room layout belongs to the channel it was made in
          clearRoom();
          resetScreenShareState();
          playChannelSwitchSound();
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
      }),

      listen<{ user_id: number; channel_id: number }>("user-left", (event) => {
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
      }),

      listen<{ user_id: number; muted: boolean }>("user-muted", (event) => {
        users.update((u) =>
          u.map((user) =>
            user.user_id === event.payload.user_id
              ? { ...user, is_muted: event.payload.muted }
              : user
          )
        );
      }),

      listen<{ user_id: number; deafened: boolean }>("user-deafened", (event) => {
        users.update((u) =>
          u.map((user) =>
            user.user_id === event.payload.user_id
              ? { ...user, is_deafened: event.payload.deafened }
              : user
          )
        );
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
      listen<{ connected: boolean; game: string }>("sdk-status", (event) => {
        drivenBy.set(event.payload.connected ? event.payload.game || "a game" : null);
        if (event.payload.connected) {
          syncing.set(false);
          positions.set(new Map());
          selectedUserId.set(null);
        }
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
          const prevChannel = $currentChannelId;
          startReconnect(addr, name, prevChannel, reason);
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
          if (is_admin) addNotification("You are now a server admin", "info");
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
        const chName = channelNameById(event.payload.channel_id);
        if (!chName) return;
        const text = ($channelMessages.get(chName) ?? []).filter((m) => !m.kind || m.kind === "text");
        let msgs: ChatMessage[] = text.slice(-50);
        // Stay well under the 64 KiB control-message cap (Signal envelope + framing)
        const bytes = (list: ChatMessage[]) => new TextEncoder().encode(JSON.stringify(list)).length;
        while (msgs.length > 0 && bytes(msgs) > 48 * 1024) msgs = msgs.slice(1);
        if (msgs.length === 0) return;
        invoke("send_channel_history", {
          channelId: event.payload.channel_id,
          targetUserId: event.payload.from_user_id,
          messages: msgs,
        }).catch((e: unknown) => console.warn("channel history hand-off failed:", e));
      }),

      listen<{ channel_id: number; from_user_id: number; from_username: string; messages: unknown[] }>(
        "channel-history-received",
        (event) => {
          const chName = channelNameById(event.payload.channel_id);
          if (chName) mergeChannelHistory(chName, event.payload.messages, event.payload.from_username);
        },
      ),

      listen<ChannelInfo>("channel-created", (event) => {
        // Idempotent: the channel list snapshot may already contain it
        channels.update(
          (chs) => upsertById(chs, event.payload, (c) => c.channel_id).list
        );
      }),

      listen<{ channel_id: number }>("channel-deleted", (event) => {
        channels.update((chs) =>
          chs.filter((ch) => ch.channel_id !== event.payload.channel_id)
        );
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
      }>("channel-chat-message", (event) => {
        const { channel_id, user_id: uid, username, content, timestamp } = event.payload;
        const chName = channelNameById(channel_id);
        if (chName) {
          // Our own messages are echoed locally under the name we connected
          // with; in an anonymous channel that is not the name anyone else
          // sees, so use the one the channel knows us by.
          const uname = uid === $userId ? ownDisplayName(username) : username;
          addChannelMessage(chName, { user_id: uid, username: uname, content, timestamp });
          // Track unread if not currently viewing this channel's chat
          const viewingThisChannel = $activeDmUserId === null && channel_id === $currentChannelId;
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
      }>("direct-chat-message", (event) => {
        const { from_user_id, to_user_id, content, timestamp } = event.payload;
        const myId = $userId;
        const from_username =
          from_user_id === myId
            ? ownDisplayName(event.payload.from_username)
            : event.payload.from_username;
        addDmMessage(myId, from_user_id, from_username, to_user_id, {
          user_id: from_user_id,
          username: from_username,
          content,
          timestamp,
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

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="app-layout" class:mobile={$isMobile} oncontextmenu={(e) => e.preventDefault()}>
  <div class="titlebar">
    <span class="title">VoIPC</span>
    <button class="settings-btn" onclick={() => (showSettings = true)} title="Settings">
      <Icon name="settings" size={18} />
    </button>
  </div>

  {#if $isMobile}
    <!-- Mobile: single-column tabbed layout -->
    <div class="main-content mobile-main">
      {#if $watchingUserId !== null}
        <ScreenShareViewer />
      {:else if $mobileTab === 'channels'}
        <ChannelList />
      {:else if $mobileTab === 'chat'}
        <ChatPanel />
      {:else if $mobileTab === 'room'}
        <RoomView />
      {:else}
        <UserList />
      {/if}
    </div>

    <MobilePTT />
    <VoiceControls />
    <StatusBar />

    <!-- Bottom tab bar -->
    <nav class="mobile-tabs">
      <button
        class="tab-btn"
        class:active={$mobileTab === 'channels'}
        onclick={() => mobileTab.set('channels')}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 12h4l3-9 4 18 3-9h4"/>
        </svg>
        <span>Channels</span>
      </button>
      <button
        class="tab-btn"
        class:active={$mobileTab === 'chat'}
        onclick={() => mobileTab.set('chat')}
      >
        <div class="tab-icon-wrap">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          {#if Array.from($unreadPerChannel.values()).reduce((a, b) => a + b, 0) > 0}
            <span class="tab-badge"></span>
          {/if}
        </div>
        <span>Chat</span>
      </button>
      {#if $currentProximity !== 'off'}
        <button
          class="tab-btn"
          class:active={$mobileTab === 'room'}
          onclick={() => mobileTab.set('room')}
        >
          <Icon name="room" size={20} />
          <span>Room</span>
        </button>
      {/if}
      <button
        class="tab-btn"
        class:active={$mobileTab === 'users'}
        onclick={() => mobileTab.set('users')}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
        </svg>
        <span>Users</span>
      </button>
    </nav>
  {:else}
    <!-- Desktop: 3-column layout -->
    <div class="main-content">
      <ChannelList />
      {#if $watchingUserId !== null && !$poppedOut}
        <div class="viewer-with-chat">
          <ScreenShareViewer />
          <button
            class="chat-collapse"
            onclick={() => (viewerChatOpen = !viewerChatOpen)}
          >{viewerChatOpen ? "Hide chat ▾" : "Show chat ▴"}</button>
          {#if viewerChatOpen}
            <div class="viewer-chat-pane">
              <ChatPanel />
            </div>
          {/if}
        </div>
      {:else if $roomOpen && $currentProximity !== 'off'}
        <RoomView />
      {:else}
        <ChatPanel />
      {/if}
      <UserList />
    </div>

    <VoiceControls />
    <StatusBar />
  {/if}
</div>

{#if showSettings}
  <SettingsPanel onclose={() => (showSettings = false)} />
{/if}

{#if !$isMobile && $showSourcePicker}
  <ScreenShareSourcePicker />
{/if}

<Toast />
<InvitePopup />
<PokePopup />

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .titlebar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 16px;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
  }

  .title {
    font-size: 16px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 1px;
  }

  .settings-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: var(--icon-btn-size);
    height: var(--icon-btn-size);
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid transparent;
    border-radius: var(--icon-btn-radius);
    transition: color 0.15s, background-color 0.15s;
  }

  .settings-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .main-content {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  /* Screen-share viewer with the chat pane stacked below it */
  .viewer-with-chat {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }

  .viewer-with-chat > :global(.viewer) {
    flex: 1;
    min-height: 0;
  }

  .chat-collapse {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: none;
    border-top: 1px solid var(--border);
    padding: 3px 0;
    font-size: 11px;
    cursor: pointer;
  }

  .chat-collapse:hover {
    color: var(--text-primary);
  }

  .viewer-chat-pane {
    height: 280px;
    flex-shrink: 0;
    display: flex;
    min-height: 0;
  }

  .viewer-chat-pane > :global(*) {
    flex: 1;
    min-width: 0;
  }

  /* ── Mobile layout ── */
  .app-layout.mobile {
    height: 100vh;
    height: 100dvh; /* dynamic viewport height (respects on-screen keyboard) */
  }

  .app-layout.mobile .titlebar {
    padding-top: max(8px, env(safe-area-inset-top));
  }

  .mobile-main {
    flex-direction: column;
  }

  /* Mobile: each child fills the full width */
  .mobile-main > :global(*) {
    width: 100%;
    flex: 1;
    min-height: 0;
  }

  .mobile-tabs {
    display: flex;
    background: var(--bg-primary);
    border-top: 1px solid var(--border);
    padding: 4px 0;
    padding-bottom: max(4px, env(safe-area-inset-bottom));
    flex-shrink: 0;
  }

  .tab-btn {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    padding: 6px 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 0;
    font-size: 10px;
    transition: color 0.15s;
  }

  .tab-btn:active {
    transform: none;
  }

  .tab-btn.active {
    color: var(--accent);
  }

  .tab-btn span {
    font-size: 10px;
    line-height: 1;
  }

  .tab-icon-wrap {
    position: relative;
    display: inline-flex;
  }

  .tab-badge {
    position: absolute;
    top: -3px;
    right: -5px;
    width: 8px;
    height: 8px;
    background: var(--error, #e53935);
    border-radius: 50%;
    border: 1.5px solid var(--bg-primary);
  }

  /* Mobile: override scoped child component widths */
  .app-layout.mobile :global(.channel-list) {
    width: 100%;
    min-width: 0;
    border-right: none;
  }

  .app-layout.mobile :global(.user-list) {
    width: 100%;
    min-width: 0;
    border-left: none;
  }

  .app-layout.mobile :global(.chat-panel) {
    width: 100%;
  }

  .app-layout.mobile :global(.voice-controls) {
    flex-wrap: wrap;
    padding: 6px 12px;
  }

  .app-layout.mobile :global(.status-bar) {
    padding: 4px 12px;
  }
</style>
