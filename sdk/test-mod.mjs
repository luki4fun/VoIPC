// A fake game mod, in one file with no dependencies: it speaks the SDK's
// WebSocket subset over a raw socket, drives the whole pipeline against a
// running VoIPC client, and says what worked.
//
// `test-page.html` is the version you watch and drag sliders in. This one is
// the version you run:
//
//   node sdk/test-mod.mjs --server rp.example.com:9987 --channel Ingame \
//                         [--password s3cret] [--port 39987]
//
// It needs a VoIPC client that is **connected to that server**, with Settings →
// Game Integration switched on. It sends no Origin header, which makes it a
// native client — the class the SDK allows without configuration, exactly like
// a C# plugin or curl. Nothing it does is written to disk, and it hands the mix
// back when it is finished.
//
// What it checks, in order: the handshake; that a mod naming the wrong server
// is refused without being told who is at the keyboard; that `hello` joins the
// named channel and answers `ingame`; that an update placing people is
// accepted; that a layered player (a radio and a phone in one ear) is accepted;
// that listing one id twice is refused; that `transmit` opens and closes the
// microphone when the player has allowed it; and that a second origin cannot
// take the mix while this one holds it.

import net from "node:net";
import crypto from "node:crypto";

const args = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
};
const PORT = Number(arg("port", 39987));
const SERVER = arg("server", "127.0.0.1:9987");
const CHANNEL = arg("channel", "Ingame");
const PASSWORD = arg("password", undefined);

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
function check(ok, what, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${what}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

// ── The WebSocket subset the SDK speaks ──────────────────────────────────

function frame(text) {
  const body = Buffer.from(text, "utf8");
  const mask = crypto.randomBytes(4);
  let head;
  if (body.length < 126) {
    head = Buffer.from([0x81, 0x80 | body.length]);
  } else {
    head = Buffer.alloc(4);
    head[0] = 0x81;
    head[1] = 0x80 | 126;
    head.writeUInt16BE(body.length, 2);
  }
  const masked = Buffer.alloc(body.length);
  for (let i = 0; i < body.length; i++) masked[i] = body[i] ^ mask[i % 4];
  return Buffer.concat([head, mask, masked]);
}

function parse(buf) {
  const frames = [];
  let i = 0;
  while (i + 2 <= buf.length) {
    const opcode = buf[i] & 0x0f;
    let len = buf[i + 1] & 0x7f;
    let at = i + 2;
    if (len === 126) {
      if (buf.length < at + 2) break;
      len = buf.readUInt16BE(at);
      at += 2;
    }
    if (at + len > buf.length) break;
    const payload = buf.subarray(at, at + len);
    if (opcode === 0x1) frames.push({ text: payload.toString("utf8") });
    else if (opcode === 0x8) frames.push({ closed: len >= 2 ? payload.readUInt16BE(0) : null });
    i = at + len;
  }
  return { frames, used: i };
}

/** One socket to the SDK. `origin` of `null` sends no Origin header at all. */
function connect(origin = null) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(PORT, "127.0.0.1");
    let buf = Buffer.alloc(0);
    let upgraded = false;
    const messages = [];
    const waiters = [];
    const api = {
      status: null,
      messages,
      send: (o) => sock.write(frame(JSON.stringify(o))),
      next: () =>
        new Promise((res) => (messages.length ? res(messages.shift()) : waiters.push(res))),
      close: () => sock.destroy(),
    };
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (!upgraded) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        api.status = buf.subarray(0, end).toString().split("\r\n")[0];
        buf = buf.subarray(end + 4);
        upgraded = true;
        resolve(api);
      }
      const { frames, used } = parse(buf);
      buf = buf.subarray(used);
      for (const f of frames) {
        const m = f.closed !== undefined ? { closed: f.closed } : JSON.parse(f.text);
        waiters.length ? waiters.shift()(m) : messages.push(m);
      }
    });
    sock.on("error", (e) =>
      reject(
        new Error(
          `${e.message} — is VoIPC running with Settings → Game Integration on, and is the port ${PORT}?`,
        ),
      ),
    );
    sock.on("close", () => waiters.length && waiters.shift()({ socketClosed: true }));
    sock.write(
      `GET / HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n` +
        (origin === null ? "" : `Origin: ${origin}\r\n`) +
        "\r\n",
    );
  });
}

// ── The run ──────────────────────────────────────────────────────────────

const hello = (extra = {}) => ({
  type: "hello",
  sdk: 1,
  game: "test-mod",
  resource: "sdk/test-mod.mjs",
  server: SERVER,
  channel: CHANNEL,
  password: PASSWORD,
  ...extra,
});

const mod = await connect();
check(mod.status.includes("101"), `the socket is upgraded (${mod.status})`);

mod.send(hello({ server: "not.this.server.example:9987" }));
const wrong = await mod.next();
if (wrong.state === "disconnected") {
  console.log("\nVoIPC is not connected to a server — connect it first, then run this again.");
  process.exit(1);
}
check(wrong.state === "wrong_server", "a mod naming another server is refused", wrong.state);
check(
  !("user_id" in wrong) && !("username" in wrong),
  "and the refusal says nothing about the player",
);

await wait(1100); // one hello per second
mod.send(hello());
const state = await mod.next();
check(state.state === "ingame", "hello joins the channel", state.reason ?? state.state);
if (state.state !== "ingame") {
  console.log(`\nsdk/test-mod.mjs: ${failures} FAILED`);
  process.exit(1);
}
const me = state.user_id;
console.log(
  `     in #${state.channel} as ${state.username} (user ${me}), proximity ${state.proximity}, ` +
    `${state.modes.length} modes`,
);
check(state.capabilities.includes("layers"), "this build renders layers");

mod.send({
  type: "update",
  self: { pos: [0, 0, 0], yaw: 90, reverb: 2, underwater: 0 },
  players: [
    { id: me + 1, pos: [5, 0, 0], range: 8, muffle: 0 },
    {
      id: me + 2,
      pos: [40, 0, 0],
      range: 8,
      muffle: 4,
      layers: [
        { mode: "walkie", volume: 0.9 },
        { mode: "mobile", pan: -0.9, delay: 40 },
      ],
    },
  ],
});
await wait(300);
check(
  !mod.messages.some((m) => m.type === "error"),
  "an update with positions and layers is accepted",
  JSON.stringify(mod.messages.filter((m) => m.type === "error")).slice(0, 120),
);

mod.messages.length = 0;
mod.send({
  type: "update",
  self: { pos: [0, 0, 0] },
  players: [
    { id: me + 1, pos: [1, 0, 0] },
    { id: me + 1, pos: [9, 9, 9] },
  ],
});
const dup = await mod.next();
check(/twice/.test(dup.reason ?? ""), "one player listed twice is refused", dup.reason);

mod.messages.length = 0;
mod.send({ type: "transmit", on: true });
await wait(700);
const pressed = mod.messages.find((m) => m.type === "self");
const refusal = mod.messages.find((m) => m.type === "error");
if (refusal) {
  console.log(`SKIP the game pressing push-to-talk — ${refusal.reason}`);
} else {
  check(pressed?.speaking === true, "the game opens the microphone");
  mod.messages.length = 0;
  mod.send({ type: "transmit", on: false });
  await wait(700);
  check(
    mod.messages.find((m) => m.type === "self")?.speaking === false,
    "and lets it go again",
  );
}

const second = await connect("http://localhost:3000");
second.send(hello({ game: "another" }));
const taken = await second.next();
check(
  /another game/.test(taken.reason ?? ""),
  "a second origin cannot take the mix",
  taken.reason ?? taken.state,
);
second.close();

mod.messages.length = 0;
mod.send({ type: "ping" });
let pong = false;
for (let i = 0; i < 6 && !pong; i++) pong = (await mod.next()).type === "pong";
check(pong, "the socket is still healthy");

mod.send({ type: "bye" });
await wait(300);
mod.close();

console.log(
  failures === 0
    ? "\nsdk/test-mod.mjs: all checks passed — the mix is handed back"
    : `\nsdk/test-mod.mjs: ${failures} FAILED`,
);
process.exit(failures === 0 ? 0 : 1);
