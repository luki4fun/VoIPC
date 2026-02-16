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
  } from "./lib/stores/connection.js";
  import { channels, currentChannelId, previewChannelId, previewUsers } from "./lib/stores/channels.js";
  import { users, speakingUsers } from "./lib/stores/users.js";
  import { addNotification } from "./lib/stores/notifications.js";
  import { pendingInvites } from "./lib/stores/invites.js";
  import { pendingPokes, createPoke } from "./lib/stores/pokes.js";
  import {
    addChannelMessage,
    addDmMessage,
    activeDmUserId,
    incrementChannelUnread,
    clearChannelUnread,
    chatUnlocked,
  } from "./lib/stores/chat.js";
  import ChatHistorySetup from "./lib/components/ChatHistorySetup.svelte";
  import type { ChannelInfo, UserInfo } from "./lib/types.js";
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
    soundSettings,
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

  let showSettings = $state(false);
  let reconnectAttempt = $state(0);
  let reconnectCancelled = $state(false);
  let reconnectError = $state("");

  // Deferred auto-connect: waits for chat history to be unlocked first
  let pendingAutoConnect = $state<AppConfig | null>(null);

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
  $effect(() => {
    if (pendingAutoConnect && $chatUnlocked) {
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

  // Clear unread for current channel when returning from DM view
  $effect(() => {
    if ($activeDmUserId === null) {
      const name = channelNameById($currentChannelId);
      if (name) clearChannelUnread(name);
    }
  });

  async function startReconnect(address: string, name: string, previousChannelId: number) {
    reconnectAttempt = 0;
    reconnectCancelled = false;
    reconnectError = "";
    connectionState.set("reconnecting");

    const startTime = Date.now();
    const RECONNECT_TIMEOUT_MS = 30_000;

    while (!reconnectCancelled) {
      reconnectAttempt++;
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempt - 1), 10000);

      // Wait before retrying
      await new Promise((resolve) => setTimeout(resolve, delay));
      if (reconnectCancelled) break;

      // Give up after 30 seconds
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
      if (config.input_device) inputDevice.set(config.input_device);
      if (config.output_device) outputDevice.set(config.output_device);
      rememberConnection.set(config.remember_connection);
      if (config.remember_connection) {
        lastHost.set(config.last_host ?? "localhost");
        lastPort.set(config.last_port ?? 9987);
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
          resetScreenShareState();
          playChannelSwitchSound();
        }

        // Clear preview when we actually join a channel
        previewChannelId.set(null);
        previewUsers.set([]);
      }),

      listen<UserInfo>("user-joined", (event) => {
        // Only add to local user list if they joined our channel
        if (event.payload.channel_id === $currentChannelId) {
          users.update((u) => [...u, event.payload]);
          // Play join sound (not for lobby, not for ourselves)
          if ($currentChannelId !== 0 && event.payload.user_id !== $userId) {
            playUserJoinedSound();
          }
        }
        // Always update channel user count (broadcast to all)
        channels.update((chs) =>
          chs.map((ch) =>
            ch.channel_id === event.payload.channel_id
              ? { ...ch, user_count: ch.user_count + 1 }
              : ch
          )
        );
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
        console.error("Connection lost:", event.payload.reason);

        // Clear screenshare state
        resetScreenShareState();

        // Play disconnected sound on initial loss (not during reconnect retries)
        if ($connectionState === "connected") {
          playDisconnectedSound();
        }

        // If we were connected, start auto-reconnect
        if ($connectionState === "connected") {
          const addr = $serverAddress;
          const name = $username;
          const prevChannel = $currentChannelId;
          startReconnect(addr, name, prevChannel);
        } else {
          connectionState.set("disconnected");
        }
      }),

      listen<ChannelInfo>("channel-created", (event) => {
        channels.update((chs) => [...chs, event.payload]);
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
        const { channel_id, user_id: uid, username: uname, content, timestamp } = event.payload;
        const chName = channelNameById(channel_id);
        if (chName) {
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
        const { from_user_id, from_username, to_user_id, content, timestamp } = event.payload;
        const myId = $userId;
        addDmMessage(myId, from_user_id, from_username, to_user_id, {
          user_id: from_user_id,
          username: from_username,
          content,
          timestamp,
        });
        if (from_user_id !== myId) playDirectMessageSound();
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
          }).catch((e: any) => console.error("Failed to start capture:", e));
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

            const sentDelta = framesSent - lastFramesSent;
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

{#if !$chatUnlocked}
  <ChatHistorySetup />
{/if}

{#if $connectionState === "disconnected" || $connectionState === "connecting"}
  <ConnectDialog />
{/if}

{#if $connectionState === "reconnecting"}
  <ReconnectOverlay attempt={reconnectAttempt} error={reconnectError} oncancel={cancelReconnect} />
{/if}

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="app-layout" oncontextmenu={(e) => e.preventDefault()}>
  <div class="titlebar">
    <span class="title">VoIPC</span>
    <button class="settings-btn" onclick={() => (showSettings = true)} title="Settings">
      <Icon name="settings" size={18} />
    </button>
  </div>

  <div class="main-content">
    <ChannelList />
    {#if $watchingUserId !== null && !$poppedOut}
      <ScreenShareViewer />
    {:else}
      <ChatPanel />
    {/if}
    <UserList />
  </div>

  <VoiceControls />
  <StatusBar />
</div>

{#if showSettings}
  <SettingsPanel onclose={() => (showSettings = false)} />
{/if}

{#if $showSourcePicker}
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
</style>
