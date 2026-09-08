// Headless end-to-end self-test for the web client, driven by test-web.sh.
// Loaded instead of the UI when the page URL carries ?selftest=1. It exercises
// the same invoke()/listen() surface the Svelte components use and reports
// through console.log lines prefixed with "SELFTEST", which the driver parses.
//
// Query parameters:
//   name=<username>      required
//   channel=<name>       channel to create or join (default "e2e"); an invite
//                        fragment (#channel=<name>) takes precedence
//   role=talker|listener talker transmits a PTT burst, listener reports stats
//   dm=<username>        send a direct message to this user once seen
//   duration=<ms>        main phase before the wrap-up (default 15000)
//   admin=<token>        wrap-up: log in as admin and kick the user in `kick`
//   kick=<username>      the user the admin kicks
//   expect_kick=1        wrap-up: wait (up to 10 s) to be kicked
//   share=1              share a screen (a synthetic canvas stands in for the
//                        display, so headless browsers need no real capture)
//   watch=1              watch the first peer that starts sharing

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { parseInviteFragment } from "../lib/invite";

interface ChannelInfo { channel_id: number; name: string }
interface UserInfo { user_id: number; username: string; channel_id: number; is_screen_sharing?: boolean }

/**
 * Stand-in for a display: an animated canvas as a MediaStream. Headless
 * browsers have no screen to capture and no picker to click, so the sharer role
 * replaces getDisplayMedia with this. Product code is untouched — the override
 * lives on the navigator.mediaDevices instance and shadows the prototype method.
 */
function fakeDisplayCapture(fps: number): void {
  const canvas = document.createElement("canvas");
  canvas.width = 854;
  canvas.height = 480;
  const ctx = canvas.getContext("2d")!;
  let frame = 0;
  setInterval(() => {
    frame++;
    // Moving content: a static image would encode to almost nothing and hide
    // a broken pipeline behind a plausible byte count.
    ctx.fillStyle = `hsl(${(frame * 7) % 360}, 70%, 45%)`;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#fff";
    ctx.fillRect((frame * 13) % canvas.width, 120, 160, 160);
    ctx.font = "48px sans-serif";
    ctx.fillText(`frame ${frame}`, 40, 400);
  }, Math.round(1000 / fps));
  const stream = canvas.captureStream(fps);
  navigator.mediaDevices.getDisplayMedia = async () => stream;
}

// Wall clock, not a page-relative one: the two sides run in separate browsers
// and the only interesting question about a failed run is the order of events
// *between* them ("did alice send before bob asked?"). The suffix goes last so
// the checks in test-web.sh, which match on the message and its payload, are
// unaffected — as is Firefox's `", source: …"` tail, stripped by the same sed.
function log(line: string, data?: unknown) {
  console.log(
    `SELFTEST ${line}${data === undefined ? "" : " " + JSON.stringify(data, (_k, v) => (typeof v === "bigint" ? Number(v) : v))} @${Date.now()}`,
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function run(params: URLSearchParams): Promise<void> {
  const name = params.get("name") ?? `web${Math.floor(Math.random() * 1000)}`;
  const invite = parseInviteFragment(window.location.hash);
  const channelName = invite?.channel ?? params.get("channel") ?? "e2e";
  const role = params.get("role") ?? "listener";
  const dmTarget = params.get("dm");
  const duration = Number(params.get("duration") ?? 15000);
  const adminToken = params.get("admin");
  const kickTarget = params.get("kick");
  const expectKick = params.has("expect_kick");
  const doShare = params.has("share");
  const doWatch = params.has("watch");

  window.addEventListener("error", (e) => log("error", { message: e.message }));
  window.addEventListener("unhandledrejection", (e) => log("error", { message: String(e.reason) }));

  let channels: ChannelInfo[] = [];
  const users = new Map<number, UserInfo>();
  let myUserId = 0;
  let joinedChannelId = 0;
  let dmSent = false;
  let chatSent = false;
  let earlySent = false;
  let isAdmin = false;
  let kicked = false;
  let sharing = false;
  let watching = false;
  let sharerUserId = 0;
  let framesDrawn = 0;
  // What App.svelte would hand to a newcomer: the channel messages we have seen
  const channelHistory: { user_id: number; username: string; content: string; timestamp: number }[] = [];

  const watched = [
    "channel-list", "user-list", "user-joined", "user-left", "media-key-installed",
    "media-key-missing", "user-speaking", "channel-chat-message", "direct-chat-message",
    "latency-update", "connection-lost", "channel-error", "audio-device-error",
    "identity-key-changed", "poke-received", "admin-status", "admin-error",
    "server-disconnected", "channel-history-requested", "channel-history-received",
    "screenshare-started", "screenshare-stopped", "watching-screenshare",
    "stopped-watching-screenshare", "screenshare-error", "screenshare-frame",
    "viewer-count-changed", "keyframe-requested",
  ];
  for (const ev of watched) {
    await listen(ev, (e: { payload: unknown }) => {
      if (ev !== "latency-update") log(`event ${ev}`, e.payload);
      if (ev === "channel-list") channels = e.payload as ChannelInfo[];
      if (ev === "user-list") {
        const p = e.payload as { channel_id: number; users: UserInfo[] };
        for (const u of p.users) users.set(u.user_id, u);
      }
      if (ev === "user-joined") {
        const u = e.payload as UserInfo;
        users.set(u.user_id, u);
      }
      if (ev === "admin-status") {
        const p = e.payload as { user_id: number; is_admin: boolean };
        if (p.user_id === myUserId) isAdmin = p.is_admin;
      }
      if (ev === "server-disconnected") kicked = true;
      if (ev === "screenshare-started") {
        const p = e.payload as { user_id: number };
        if (p.user_id !== myUserId) sharerUserId = p.user_id;
      }
      if (ev === "screenshare-frame") framesDrawn++;
      // What App.svelte does for a sharer: encode only while someone watches,
      // and force a keyframe when a viewer asks for one.
      if (ev === "viewer-count-changed") {
        const p = e.payload as { viewer_count: number };
        const cmd = p.viewer_count > 0 ? "start_screen_capture" : "stop_screen_capture";
        invoke(cmd, { resolution: 480, fps: 15 }).catch((err) =>
          log("error", { message: `${cmd}: ${String(err)}` }),
        );
      }
      if (ev === "keyframe-requested") {
        invoke("set_keyframe_requested").catch(() => {});
      }
      if (ev === "channel-chat-message") {
        const m = e.payload as { user_id: number; username: string; content: string; timestamp: number };
        channelHistory.push({ user_id: m.user_id, username: m.username, content: m.content, timestamp: m.timestamp });
      }
      if (ev === "channel-history-requested") {
        // The UI's job in the real app: answer with the recent channel chat
        const p = e.payload as { channel_id: number; from_user_id: number };
        invoke("send_channel_history", {
          channelId: p.channel_id,
          targetUserId: p.from_user_id,
          messages: channelHistory.slice(-50),
        }).catch((err) => log("error", { message: `history: ${String(err)}` }));
      }
    });
  }

  try {
    const userId = await invoke<number>("connect", {
      address: window.location.host,
      username: name,
      acceptInvalidCerts: false,
    });
    myUserId = userId;
    log("connected", { user_id: userId, name });
  } catch (e) {
    log("connect-failed", { error: String(e) });
    log("done");
    return;
  }

  // Wait for the channel list, then create or join the test channel
  for (let i = 0; i < 50 && channels.length === 0; i++) await sleep(100);
  const existing = channels.find((c) => c.name === channelName);
  try {
    if (existing) {
      await invoke("join_channel", { channelId: existing.channel_id, password: invite?.password ?? null });
      joinedChannelId = existing.channel_id;
    } else {
      await invoke("create_channel", { name: channelName, password: null });
    }
    log("channel-requested", { channel: channelName, existing: !!existing, source: invite ? "invite" : "param" });
  } catch (e) {
    log("error", { message: `channel: ${String(e)}` });
  }

  // The message alice types while alone, sent before the loop rather than on
  // its first tick: a peer that joins in between asks for the channel history
  // straight away, and she can only hand over what she already has.
  if (role === "talker") {
    // No fixed budget: test-web.sh holds the second browser until the line
    // below appears, so taking longer here costs time but never correctness.
    for (let i = 0; i < 200 && joinedChannelId === 0; i++) {
      await sleep(50);
      const me = users.get(myUserId);
      if (me && me.channel_id !== 0) joinedChannelId = me.channel_id;
    }
    if (joinedChannelId === 0) {
      log("error", { message: "no channel after 10s, skipping the early message" });
    } else {
      earlySent = true;
      const early = `early from ${name}`;
      const inHistory = () => channelHistory.some((m) => m.content === early);
      try {
        await invoke("send_channel_message", { content: early });
        // "Sent" is not the state the next peer depends on: the message reaches
        // channelHistory — the list handed to a newcomer — only when the server
        // echoes it back. Log the line the harness waits for once it is there.
        for (let i = 0; i < 100 && !inHistory(); i++) await sleep(50);
        log("early-chat-sent", { in_history: inHistory() });
      } catch (e) {
        log("error", { message: `early chat: ${String(e)}` });
      }
    }
  }

  const started = Date.now();
  let talked = false;
  while (Date.now() - started < duration) {
    await sleep(500);
    const me = users.get(myUserId);
    if (me && me.channel_id !== 0) joinedChannelId = me.channel_id;
    const peers = [...users.values()].filter((u) => u.user_id !== myUserId && u.channel_id === joinedChannelId && joinedChannelId !== 0);

    // A message typed while alone: queued until a peer arrives, and part of
    // the channel history handed to that peer
    if (role === "talker" && !earlySent && joinedChannelId !== 0) {
      earlySent = true;
      try {
        await invoke("send_channel_message", { content: `early from ${name}` });
        log("early-chat-sent");
      } catch (e) {
        log("error", { message: `early chat: ${String(e)}` });
      }
    }
    // Give the Signal handshake + sender-key exchange a moment, then chat once
    if (!chatSent && peers.length > 0 && Date.now() - started > 4000) {
      chatSent = true;
      try {
        await invoke("send_channel_message", { content: `hello from ${name}` });
        log("chat-sent");
      } catch (e) {
        log("error", { message: `chat: ${String(e)}` });
      }
    }
    if (!dmSent && dmTarget) {
      const target = [...users.values()].find((u) => u.username === dmTarget);
      if (target && Date.now() - started > 4000) {
        dmSent = true;
        try {
          await invoke("send_direct_message", { targetUserId: target.user_id, content: `dm from ${name}` });
          log("dm-sent", { to: target.user_id });
        } catch (e) {
          log("error", { message: `dm: ${String(e)}` });
        }
      }
    }
    if (doShare && !sharing && peers.length > 0 && Date.now() - started > 3000) {
      sharing = true;
      try {
        fakeDisplayCapture(15);
        await invoke("start_screen_share", {
          sourceType: "display",
          sourceId: "0",
          resolution: 480,
          fps: 15,
        });
        log("share-started");
      } catch (e) {
        log("error", { message: `share: ${String(e)}` });
      }
    }
    // A peer's share shows up as ScreenShareStarted, or (for a late joiner) as
    // is_screen_sharing in the user list.
    if (doWatch && !watching && Date.now() - started > 4000) {
      const target =
        sharerUserId || peers.find((u) => u.is_screen_sharing)?.user_id || 0;
      if (target !== 0) {
        watching = true;
        try {
          // The viewer component's job: hand the canvas to the web backend
          const canvas = document.createElement("canvas");
          document.body.appendChild(canvas);
          (window as any).__voipc_web?.setVideoCanvas(canvas);
          await invoke("watch_screen_share", { sharerUserId: target });
          log("watch-requested", { sharer: target });
        } catch (e) {
          log("error", { message: `watch: ${String(e)}` });
        }
      }
    }
    if (role === "talker" && !talked && peers.length > 0 && Date.now() - started > 5000) {
      talked = true;
      try {
        await invoke("start_transmit");
        log("transmit-started");
        await sleep(4000);
        await invoke("stop_transmit");
        log("transmit-stopped");
      } catch (e) {
        log("error", { message: `transmit: ${String(e)}` });
      }
    }
  }

  try {
    const [played, lost] = await invoke<[number, number]>("get_voice_stats");
    log("voice-stats", { played, lost });
  } catch (e) {
    log("error", { message: `voice-stats: ${String(e)}` });
  }

  if (doShare || doWatch) {
    try {
      const [sent, bytesSent, recv, dropped, bytesRecv, resolution] =
        await invoke<[number, number, number, number, number, number]>("get_screen_share_stats");
      log("screenshare-stats", {
        frames_sent: sent,
        bytes_sent: bytesSent,
        frames_recv: recv,
        frames_dropped: dropped,
        bytes_recv: bytesRecv,
        width: resolution >>> 16,
        height: resolution & 0xffff,
        frames_drawn: framesDrawn,
      });
    } catch (e) {
      log("error", { message: `screenshare-stats: ${String(e)}` });
    }
    if (doShare) await invoke("stop_screen_share").catch(() => {});
  }

  // "My measurements are in." The two browsers do not start together — the
  // harness holds the second one until the first has its message in the channel
  // history — so the admin cannot assume the other side is as far along as she
  // is. Without this the kick lands mid-run and the kicked side never reports
  // its voice and video stats.
  await invoke("send_channel_message", { content: `wrap-up from ${name}` }).catch(() => {});
  log("wrap-up-sent");

  // Wrap-up: moderation
  if (adminToken && kickTarget) {
    const peerWrapped = () =>
      channelHistory.some((m) => m.username === kickTarget && m.content === `wrap-up from ${kickTarget}`);
    for (let i = 0; i < 400 && !peerWrapped(); i++) await sleep(50);
    log("peer-wrap-up", { seen: peerWrapped() });
    await sleep(500);
    try {
      await invoke("admin_login", { token: adminToken });
      for (let i = 0; i < 50 && !isAdmin; i++) await sleep(100);
      log("admin-login", { ok: isAdmin });
      const target = [...users.values()].find((u) => u.username === kickTarget);
      if (isAdmin && target) {
        await invoke("admin_kick", { userId: target.user_id, reason: "e2e kick" });
        log("admin-kicked", { user_id: target.user_id });
        await sleep(1000);
      }
    } catch (e) {
      log("error", { message: `admin: ${String(e)}` });
    }
  } else if (expectKick) {
    for (let i = 0; i < 100 && !kicked; i++) await sleep(100);
    log("kick-observed", { kicked });
  }

  try {
    await invoke("disconnect");
  } catch {
    // ignore
  }
  log("done");
}
