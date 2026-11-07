#!/usr/bin/env node
// The move from Discord (1.11), in real browsers against a real relay. Nothing here calls
// Discord: `import_replay` runs the importer's real driver over real QUIC against the stand-in
// in testkit/6-mock-discord, and a local port stands in for Discord's sign-in. What a browser
// cannot run, the wizard's commands, answers from the same stand-in in a test build. The rules
// are in session_tests.rs (`providers::import`) and crates/voipc-import.
//
// The cast: annika holds `*` (an account with codes), bobby the moderator group. rita holds `*`
// too, and is who `import_replay` signs in as: that ends her tab, and spends her codes, of which
// each account has five in fifteen minutes. dan, eva and cal come through the stand-in Discord as
// the people they are in the fixture. gus is a guest. A second relay, with no accounts and a
// thousand bans, is what the token admin's list is on.
//
//   VOIPC_SELFTEST=1 npm run web
//   cargo build --release --locked -p voipc-server --example import_replay
//   node test-move.mjs [port]
//   MOVE_DATABASE=postgres://... node test-move.mjs [port]   # another database, a new one each run
//
// No dependencies. Needs openssl and chromium (CHROME=/path/to/chrome).

import { spawn, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] ?? 49993);
const CHROME = process.env.CHROME ?? "chromium";
const ORIGIN = `https://127.0.0.1:${PORT}`;
const WORK = mkdtempSync(join(tmpdir(), "voipc-move-"));
const TOKEN = "e2e-admin-token-0001";
const PASSWORD = "correct-horse-battery-1";
const SERVER = join(ROOT, "target/release/voipc-server");
const REPLAY = join(ROOT, "target/release/examples/import_replay");
const POSTGRES = !!process.env.MOVE_DATABASE;
const children = [];

// The fixture's ids
const STAFF = "1190000000000000212";
const AFTER_DARK = "1190000000000000217"; // 18+, and gated: it denied a role, and eva holds another
const DAN = "1190000000000001001";
const EVA = "1190000000000001002";
const CAL = "1190000000000001004";
const FRANK = "1190000000000001005";
/** A row's element, by its Discord id. */
const rowOf = (id) => `#archive-${id}`;
const WELCOME = rowOf("1200000000000005001"); // dan's, pinned, what v2/resend.json sends again

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
function check(what, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${what}${!ok && detail ? ` — ${String(detail).slice(0, 600)}` : ""}`);
  if (!ok) failures++;
}

async function stop(code) {
  for (const c of children) c.kill("SIGKILL");
  await sleep(1000);
  try {
    rmSync(WORK, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch (e) {
    console.log(`(left ${WORK}: ${e.code})`);
  }
  process.exit(code);
}
// How test-web.sh stops a lane it runs side by side: the relay and browsers go with it.
process.on("SIGTERM", () => stop(1));

/** A program to its end, without stopping this one's clock or its SIGTERM. */
function run(file, args, options = {}) {
  return new Promise((resolve) => {
    const c = spawn(file, args, { cwd: WORK, stdio: ["ignore", "pipe", "pipe"], ...options });
    children.push(c);
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => c.kill("SIGKILL"), 240_000);
    c.on("close", (status) => {
      clearTimeout(timer);
      children.splice(children.indexOf(c), 1);
      resolve({ status, stdout, stderr });
    });
  });
}

// ── The stand-in Discord sign-in ──────────────────────────────────────────

let subject = DAN;
let username = "dan_d";
const provider = createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    res.end(
      req.method === "POST"
        ? JSON.stringify({ access_token: "at", token_type: "Bearer" })
        : JSON.stringify({ id: subject, username, global_name: username }),
    );
  });
});
await new Promise((r) => provider.listen(0, "127.0.0.1", r));
children.push({ kill: () => provider.close() });
const providerBase = `http://127.0.0.1:${provider.address().port}`;

// ── The relays ────────────────────────────────────────────────────────────

spawnSync(
  "openssl",
  ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
   "-keyout", join(WORK, "server.key"), "-out", join(WORK, "server.crt"), "-subj", "/CN=voipc-test",
   "-addext", "subjectAltName=IP:127.0.0.1"],
  { stdio: "ignore" },
);
writeFileSync(
  join(WORK, "server.toml"),
  `host = "127.0.0.1"
tcp_port = ${PORT}
udp_port = ${PORT}
cert_path = "server.crt"
key_path = "server.key"
[accounts]
mode = "optional"
registration = "open"
public_url = "${ORIGIN}"
${POSTGRES ? `database = "${process.env.MOVE_DATABASE}"` : ""}
`,
);
writeFileSync(join(WORK, "channels.json"), JSON.stringify([{ name: "lobby-chat", text: true, auto_join: true }]));
const env = { ...process.env, VOIPC_OAUTH_DISCORD_ID: "client", VOIPC_OAUTH_DISCORD_SECRET: "secret", VOIPC_OAUTH_TEST_BASE: providerBase };
let relay = null;
function startRelay() {
  relay = spawn(SERVER, ["-c", "server.toml", "--channels", "channels.json"], { cwd: WORK, env, stdio: ["ignore", "ignore", "inherit"] });
  children.push(relay);
}
startRelay();
/** A cut: the relay shuts down, which it says on the wire so that nobody waits for a timeout, and comes back. */
async function cut() {
  const was = relay;
  const gone = new Promise((r) => was.once("exit", r));
  was.kill("SIGTERM");
  await Promise.race([gone, sleep(8000)]);
  was.kill("SIGKILL");
  await sleep(500);
  startRelay();
  await sleep(1500);
}

// A relay with no accounts keeps its bans in a file, which a person with a name was banned into,
// unlike a shell's address ban, whose rows all read "(from the server shell)". Past a frame's
// worth, as one answer would be: the old list's silent failure at this size is `a_large_ban_list_
// arrives_in_pages`. Newest first, so person-0990 is far down.
const BANS = 1000;
mkdirSync(join(WORK, "s2"));
writeFileSync(
  join(WORK, "s2", "bans.json"),
  JSON.stringify({
    format: 1,
    bans: Array.from({ length: BANS }, (_, n) => ({
      id: n + 1,
      label: `person-${String(n).padStart(4, "0")}`,
      reason: "spam",
      by: "server shell",
      created_at: 1_800_000_000 - n,
      expires_at: null,
      addr: `10.${n >> 8}.${n & 255}.1`,
    })),
  }),
  { mode: 0o600 },
);
children.push(
  spawn(
    SERVER,
    ["--host", "127.0.0.1", "--tcp-port", String(PORT + 1), "--udp-port", String(PORT + 1), "--cert", join(WORK, "server.crt"), "--key", join(WORK, "server.key"), "--admin-token", TOKEN],
    { cwd: join(WORK, "s2"), stdio: ["ignore", "ignore", "inherit"] },
  ),
);
await sleep(2000);

// ── Browsers, each its own device ─────────────────────────────────────────

const browsers = new Map();
async function browser(cdpPort) {
  const c = spawn(
    CHROME,
    ["--headless=new", "--no-sandbox", "--ignore-certificate-errors", `--remote-debugging-port=${cdpPort}`,
     "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", `--user-data-dir=${join(WORK, `profile-${cdpPort}`)}`, "about:blank"],
    { stdio: "ignore" },
  );
  children.push(c);
  browsers.set(cdpPort, c);
  for (let i = 0; i < 60; i++) {
    if (await fetch(`http://127.0.0.1:${cdpPort}/json/version`).then((r) => r.ok, () => false)) return cdpPort;
    await sleep(250);
  }
  throw new Error("chromium did not come up");
}

// What every page does on the control stream, seen from outside the app. `__sent` holds which
// AccountRequest each frame was (a ClientMessage::Account is index 41), so that "nothing was
// fetched" is counted and not assumed; `__heard` is what came back, as text; and `__control`
// lets a test write what no button sends, as a modified app could.
const WIRE = `(() => {
  window.__sent = [];
  window.__heard = "";
  const write = WritableStreamDefaultWriter.prototype.write;
  WritableStreamDefaultWriter.prototype.write = function (chunk) {
    if (chunk instanceof Uint8Array && chunk.length >= 5 && new DataView(chunk.buffer, chunk.byteOffset).getUint32(0) === chunk.length - 4) {
      window.__control = this;
      if (chunk[4] === 41) window.__sent.push(chunk[5]);
    }
    return write.call(this, chunk);
  };
  const read = ReadableStreamDefaultReader.prototype.read;
  ReadableStreamDefaultReader.prototype.read = function () {
    return read.call(this).then((r) => {
      if (r.value instanceof Uint8Array) window.__heard = (window.__heard + new TextDecoder().decode(r.value)).slice(-600000);
      return r;
    });
  };
})()`;
const ARCHIVE_FETCH = 28; // AccountRequest::ArchiveFetch
const fetchesSent = (tab) => tab.evaluate(`window.__sent.filter((i) => i === ${ARCHIVE_FETCH}).length`);

const varint = (n) => {
  const out = [];
  for (; n > 127; n = Math.floor(n / 128)) out.push((n & 127) | 128);
  return [...out, n];
};
/** An `ArchiveFetch` of a channel's flow, framed: what the relay must answer whoever asks. */
const archiveFetch = (channel) => {
  const body = [41, ARCHIVE_FETCH, ...varint(channel), 0, 0, 0];
  return [0, 0, 0, body.length, ...body];
};
/** Asks for every channel there could be, one at a time. A page's id is its relay's small number. */
async function forgeFetches(tab) {
  await tab.evaluate(`window.__heard = ""; 0`);
  for (let channel = 1; channel <= 30; channel++) {
    await tab.evaluate(`window.__control.write(new Uint8Array(${JSON.stringify(archiveFetch(channel))})).then(() => 0)`);
    await sleep(40);
  }
  await sleep(600);
  return tab.evaluate(`window.__heard`);
}

async function newTab(cdpPort) {
  const res = await fetch(`http://127.0.0.1:${cdpPort}/json/new?about:blank`, { method: "PUT" });
  const target = await res.json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let id = 0;
  const pending = new Map();
  const errors = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    } else if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      errors.push(`${d.text} ${d.exception?.description ?? ""}`);
    } else if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      errors.push(`console: ${msg.params.args.map((a) => a.value ?? a.description).join(" ")}`);
    }
  };
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const i = ++id;
      const timer = setTimeout(() => reject(new Error(`CDP timed out: ${method}`)), 30_000);
      pending.set(i, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(`evaluate: ${JSON.stringify(r.result.exceptionDetails).slice(0, 300)}`);
    return r.result?.result?.value;
  };
  await send("Runtime.enable");
  await send("Page.enable");
  await send("DOM.enable");
  await send("Page.addScriptToEvaluateOnNewDocument", { source: WIRE });
  await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  return { send, evaluate, errors, activate: () => fetch(`http://127.0.0.1:${cdpPort}/json/activate/${target.id}`) };
}

async function waitFor(tab, expression, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return;
    await sleep(150);
  }
  const text = await tab.evaluate(`document.body?.innerText?.slice(0, 900) ?? ""`).catch(() => "");
  throw new Error(`timed out waiting for ${expression}\n--- page: ${text.replace(/\s+/g, " ")}`);
}
const seen = (tab, expression, timeoutMs = 15_000) => waitFor(tab, expression, timeoutMs).then(() => true, () => false);

const setInput = (selector, value) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`;
const byText = (selector, text) => `[...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim().startsWith(${JSON.stringify(text)}))`;
const dialogOf = (kind) => `.account-dialog[data-kind="${kind}"]`;
const q = (s) => `document.querySelector(${JSON.stringify(s)})`;

const totpAt = (b32, step) => {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of b32.replace(/[\s=-]/g, "").toUpperCase()) bits += abc.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
};

// ── Real input ────────────────────────────────────────────────────────────

/** A trusted click at the element's centre, after making sure nothing lies over it. */
async function mouse(tab, expr, name = expr, button = "left") {
  await tab.activate?.();
  const at = await tab.evaluate(`(() => { const el = (${expr}); if (!el) return null; el.scrollIntoView({ block: "nearest" });
    const r = el.getBoundingClientRect(); const x = r.left + r.width / 2, y = r.top + r.height / 2;
    const top = document.elementFromPoint(x, y);
    return { x, y, hit: !!top && (el === top || el.contains(top) || top.contains(el) && top.tagName === "LABEL"), over: top ? (top.className || top.tagName) : "none" }; })()`);
  if (!at) throw new Error(`nothing to click: ${name}\n--- ${(await tab.evaluate(`document.body.innerText`)).replace(/\s+/g, " ").slice(0, 900)}`);
  if (!at.hit) {
    // A toast passes, but not under a pointer left on it: it stays while it is hovered
    if (String(at.over).includes("toast")) {
      await tab.evaluate(`document.querySelectorAll(".toast .toast-close").forEach((c) => c.click()); 0`);
      await sleep(300);
      return mouse(tab, expr, name, button);
    }
    check(`nothing lies over ${name}`, false, `under the pointer: ${at.over}`);
  }
  const base = { x: at.x, y: at.y, button, clickCount: 1 };
  const buttons = button === "left" ? 1 : 2;
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0 });
  await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons });
  await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons });
  await sleep(120);
}
const click = (tab, selector) => mouse(tab, q(selector), selector);
const clickText = (tab, selector, text) => mouse(tab, byText(selector, text), `${selector} "${text}"`);
async function type(tab, selector, text) {
  await click(tab, selector);
  await tab.send("Input.insertText", { text });
  await sleep(60);
}
async function key(tab, k, code) {
  await tab.activate?.();
  const base = { key: k, code: k, windowsVirtualKeyCode: code, nativeVirtualKeyCode: code };
  await tab.send("Input.dispatchKeyEvent", { type: "keyDown", ...base, ...(k === "Enter" ? { text: "\r" } : {}) });
  await tab.send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  await sleep(120);
}
/** A `<select>` cannot be opened by a mouse headless: by script, with its `change`. */
const pickIn = (tab, selector, label) =>
  tab.evaluate(`(() => { const s = document.querySelector(${JSON.stringify(selector)});
    s.selectedIndex = [...s.options].findIndex((o) => o.textContent.trim() === ${JSON.stringify(label)});
    s.dispatchEvent(new Event("change", { bubbles: true })); })()`);

const pickBy = (tab, selector, value) =>
  tab.evaluate(`(() => { const s = document.querySelector(${JSON.stringify(selector)}); s.value = ${JSON.stringify(value)}; s.dispatchEvent(new Event("change", { bubbles: true })); })()`);

// ── Coming in ─────────────────────────────────────────────────────────────

/** The relay's page, up to the sign-in form: a browser just started can take two goes. */
async function reachDialog(tab, path = "/", port = PORT) {
  const shown = `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`;
  const before = tab.errors.length;
  await tab.send("Page.navigate", { url: `https://127.0.0.1:${port}${path}` });
  if (await seen(tab, shown, 25_000)) return;
  await tab.send("Page.navigate", { url: `https://127.0.0.1:${port}${path}` });
  // The load given up on dies mid-fetch, and says so: that is this lane's doing, not the page's
  tab.errors.splice(before);
  await waitFor(tab, shown, 60_000);
}
async function pastAudioStep(tab) {
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(`document.querySelector(".skip-link").click()`);
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
}
async function prepare(tab) {
  await pastAudioStep(tab);
  await tab.evaluate(`window.open = (url) => { window.__opened = url; return null; }; 0`);
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await tab.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(tab, `document.querySelector("#account-name")`);
}
async function openDialog(cdpPort) {
  const tab = await newTab(cdpPort);
  await reachDialog(tab);
  await prepare(tab);
  return tab;
}
/** What a first connect asks after the sign-in: answered. */
async function settle(tab) {
  const end = Date.now() + 40_000;
  while (Date.now() < end) {
    await tab.evaluate(`document.querySelector('${dialogOf("cloud")} .submit-btn')?.click(); 0`);
    await tab.evaluate(`document.querySelector(".audio-setup .skip-link")?.click(); 0`);
    await tab.evaluate(`document.querySelector('.layout-setup .layout-choice[data-layout="modern"]')?.click(); document.querySelector(".layout-setup .submit-btn")?.click(); 0`);
    const quiet = `!document.querySelector(".connect-btn") && !document.querySelector(".account-dialog") && !document.querySelector(".audio-setup") && !document.querySelector(".layout-setup")`;
    if (await tab.evaluate(quiet)) {
      await sleep(800);
      if (await tab.evaluate(quiet)) return;
    }
    await sleep(200);
  }
  const up = await tab.evaluate(`[...document.querySelectorAll(".account-dialog, .connect-btn, .audio-setup, .layout-setup")].map((e) => e.dataset.kind ?? e.className).join(", ")`);
  throw new Error(`the first-connect questions did not end: ${up}\n--- page: ${(await tab.evaluate(`document.body.innerText`)).replace(/\s+/g, " ").slice(0, 800)}`);
}
async function createAccount(tab, name) {
  await tab.evaluate(`document.querySelector(".mode-switch.small button:nth-child(2)").click()`);
  await waitFor(tab, `document.querySelector("#account-password2")`);
  await tab.evaluate(setInput("#account-name", name));
  await tab.evaluate(setInput("#account-password", PASSWORD));
  await tab.evaluate(setInput("#account-password2", PASSWORD));
  await tab.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("recovery")}')`, 60_000);
  await tab.evaluate(`document.querySelector('${dialogOf("recovery")} .submit-btn').click()`);
  await settle(tab);
}
async function connectGuest(tab, name, port = PORT) {
  await reachDialog(tab, "/", port);
  await pastAudioStep(tab);
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(port)));
  await tab.evaluate(setInput('input[placeholder="Your name"]', name));
  await tab.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(tab, `document.querySelector(".channel-list")`);
  await settle(tab);
}
async function serverMenu(tab, label) {
  await tab.evaluate(`document.querySelector(".server-header .menu") || document.querySelector(".server-header .header-btn").click(); 0`);
  await waitFor(tab, byText(".server-header .menu > button", label));
  await tab.evaluate(`${byText(".server-header .menu > button", label)}.click()`);
}
async function turnOnCodes(tab) {
  await serverMenu(tab, "Your account");
  await waitFor(tab, `document.querySelector('${dialogOf("account")}')`);
  await tab.evaluate(`[...document.querySelectorAll('${dialogOf("account")} .secondary')].find((e) => e.textContent.includes("Set up")).click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("totp-setup")} .secret')`);
  const secret = (await tab.evaluate(`document.querySelector('${dialogOf("totp-setup")} .secret').textContent`)).trim();
  await tab.evaluate(setInput("#acct-setup-code", totpAt(secret, Math.floor(Date.now() / 30_000))));
  await tab.evaluate(`document.querySelector('${dialogOf("totp-setup")} .submit-btn').click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("recovery-codes")}') || document.querySelector('${dialogOf("account")}')`);
  await sleep(500);
  await tab.evaluate(`document.querySelector('${dialogOf("recovery-codes")} .submit-btn')?.click(); 0`);
  await sleep(300);
  await tab.evaluate(`document.querySelector('${dialogOf("account")} .submit-btn')?.click(); 0`);
  await sleep(300);
  return secret;
}

/** The last 30-second step of annika's secret anyone has used. The relay takes a code once,
 *  none older than the last, and one step either side of now. */
let codeStepUsed = 0;
async function nextCode() {
  for (;;) {
    const now = Math.floor(Date.now() / 30_000);
    const step = Math.max(codeStepUsed + 1, now - 1);
    if (step <= now + 1) {
      codeStepUsed = step;
      return step;
    }
    await sleep(500);
  }
}
/** A reload signs in by itself, by the remembered device: no fresh code, so a step asks for one. */
async function reloaded(tab) {
  await tab.send("Page.reload");
  await waitFor(tab, `document.querySelector(".channel-list")`, 60_000);
  await settle(tab);
  await sleep(800);
}
/** Another address of the page is a new visit, which signs in with the form. */
async function signIn(tab, name, secret, path) {
  await reachDialog(tab, path);
  await logInHere(tab, name, secret);
}
/** The sign-in form, on the page as it stands: what a page holds in RAM stays. */
async function logInHere(tab, name, secret) {
  await prepare(tab);
  await tab.evaluate(setInput("#account-name", name));
  await tab.evaluate(setInput("#account-password", PASSWORD));
  await tab.evaluate(`document.querySelector(".connect-btn").click()`);
  // A question that stays up after an answer is that answer, still on its way
  let answered = 0;
  for (const end = Date.now() + 100_000; Date.now() < end; await sleep(300)) {
    if (await tab.evaluate(`!document.querySelector(".connect-btn")`)) break;
    if (Date.now() - answered < 3000 || !(await tab.evaluate(`!!document.querySelector('${dialogOf("totp")} input')`))) continue;
    answered = Date.now();
    await tab.evaluate(setInput(`${dialogOf("totp")} input`, totpAt(secret, await nextCode())));
    await tab.evaluate(`document.querySelector('${dialogOf("totp")} .submit-btn').click()`);
  }
  await waitFor(tab, `document.querySelector(".channel-list")`, 60_000);
  await settle(tab);
  await sleep(800);
}
/** Answer the code question with a real mouse, wherever it was put. */
async function giveCode(tab, secret, expect = "") {
  const panelPrompt = `.admin-dialog input[aria-label="Two-factor code"]`;
  const dialogPrompt = `.step-up-dialog input`;
  await waitFor(tab, `${q(panelPrompt)} || ${q(dialogPrompt)}`, 15_000);
  const inPanel = await tab.evaluate(`!!${q(panelPrompt)}`);
  if (expect) {
    const says = await tab.evaluate(`(${inPanel ? q(".admin-dialog .callout .admin-hint") : q(".step-up-dialog .admin-hint")}).textContent`);
    check(`the code question says: ${expect}`, says.includes(expect), says);
  }
  await type(tab, inPanel ? panelPrompt : dialogPrompt, totpAt(secret, await nextCode()));
  if (inPanel) await mouse(tab, byText(".admin-dialog .callout button", "Confirm"), "Confirm");
  else await click(tab, ".step-up-dialog .poke-send-btn");
  await sleep(300);
}
/** The same, when the last code may still hold (ten minutes): whether it was asked. */
async function giveCodeIfAsked(tab, secret, expect = "") {
  const prompt = `${q(`.admin-dialog input[aria-label="Two-factor code"]`)} || ${q(".step-up-dialog input")}`;
  if (!(await seen(tab, prompt, 2500))) return false;
  await giveCode(tab, secret, expect);
  return true;
}
async function confirmDialog(tab, label) {
  await waitFor(tab, byText(".confirm-dialog button, [class*=confirm] button", label), 10_000);
  await mouse(tab, byText(".confirm-dialog button, [class*=confirm] button", label), `confirm ${label}`);
  await sleep(150);
}
async function throughProvider(tab, cdpPort) {
  await waitFor(tab, `document.querySelector(".connect-provider")`);
  await tab.evaluate(`${byText(".connect-provider", "Continue with Discord")}.click()`);
  await waitFor(tab, `document.querySelector(".provider-code")`);
  const code = await tab.evaluate(`document.querySelector(".provider-code").textContent.trim()`);
  await tab.evaluate(`${byText(".connect-provider", "Open Discord")}.click()`);
  await waitFor(tab, `window.__opened`);
  const opened = await tab.evaluate(`window.__opened`);
  const state = new URL(opened).searchParams.get("state");
  const page = await newTab(cdpPort);
  await page.send("Page.navigate", { url: `${ORIGIN}/account/oauth/discord/cb?state=${state}&code=abc` });
  await waitFor(page, `document.querySelector("button[name=pick]")`);
  await page.evaluate(`document.querySelector('button[name=pick][value="${code}"]').click()`);
  await waitFor(page, `document.body?.innerText.includes("go back to the app")`);
  await page.send("Page.close").catch(() => {});
}
/** A member of the fixture opens the account the move made them. `says` is checked on the
 *  way, as the name the screen starts with; `rename` is what they make of it. */
async function comeWithDiscord(cdpPort, id, name, { says = name, rename = "" } = {}) {
  subject = id;
  username = name;
  const tab = await openDialog(cdpPort);
  await throughProvider(tab, cdpPort);
  const nameBox = `${dialogOf("provider-name")} input`;
  await waitFor(tab, q(nameBox));
  const offered = await tab.evaluate(`${q(nameBox)}.value`);
  check(`the name screen starts with the name they had: ${says}`, offered === says, offered);
  if (rename) await tab.evaluate(setInput(nameBox, rename));
  await tab.evaluate(`document.querySelector('${dialogOf("provider-name")} .submit-btn').click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("provider-choice")}')`, 60_000);
  await tab.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("provider-choice")}')?.innerText.includes("used this account before")`);
  await tab.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  // Its yes goes live a moment after it shows
  await waitFor(tab, `document.querySelector('${dialogOf("provider-key")} .submit-btn:enabled')`, 60_000);
  check("a recovery key is shown", await tab.evaluate(`!!document.querySelector('${dialogOf("provider-key")} .secret')`));
  await tab.evaluate(`document.querySelector('${dialogOf("provider-key")} .submit-btn').click()`);
  await settle(tab);
  return tab;
}
/** A whole import by the real driver, as rita, who holds her own count of codes. */
const importer = { secret: "", step: 0 };
async function replay(args) {
  const r = await run(REPLAY, [`127.0.0.1:${PORT}`, "rita", PASSWORD, importer.secret, "--code-after", String(importer.step), ...args]);
  if (r.status !== 0) throw new Error(`import_replay: ${r.status}\n${r.stdout}\n${r.stderr}`);
  const out = JSON.parse(r.stdout.trim().split("\n").at(-1));
  if (out.code_step) importer.step = Math.max(importer.step, out.code_step);
  return out;
}
const pageText = (tab) => tab.evaluate(`document.body?.innerText ?? ""`);
const panelText = (tab) => tab.evaluate(`document.querySelector(".admin-dialog")?.innerText ?? ""`);
const paneText = (tab) => tab.evaluate(`document.querySelector(".archive-pane")?.innerText.slice(0, 500) ?? ""`);
const channelRow = (name) =>
  `[...document.querySelectorAll(".channel-list.modern .channels.text .channel")].find((c) => c.querySelector(".channel-name")?.textContent.trim() === ${JSON.stringify(name)})`;
const textChannels = (tab) => tab.evaluate(`[...document.querySelectorAll(".channel-list.modern .channels.text .channel-name")].map((c) => c.textContent.trim())`);
async function openChannel(tab, name) {
  await waitFor(tab, channelRow(name));
  await mouse(tab, channelRow(name), `#${name}`);
  await sleep(600);
  // A channel on the list is joined with its own button when not auto-joined
  if (await tab.evaluate(`!!${q(".join-text-btn:not(.archive-open)")}`)) await click(tab, ".join-text-btn:not(.archive-open)");
  await waitFor(tab, `document.querySelector(".input-bar .chat-input") || document.querySelector(".archive-btn")`);
}
async function openPanel(tab) {
  await serverMenu(tab, "Server admin");
  await waitFor(tab, `document.querySelector(".admin-tabs")`);
}
const tabTo = (tab, name) => mouse(tab, byText(".admin-tabs button", name), `tab ${name}`);
const memberRow = (name) => `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes(${JSON.stringify(name)}))`;
const scrollToTop = `(() => { const b = document.querySelector(".archive-rows"); b.scrollTop = -b.scrollHeight; })()`;
/** What this person's search finds of the archive of the channel on screen. */
async function searchHas(tab, words, row) {
  await tab.evaluate(setInput(".archive-input", ""));
  await tab.evaluate(`document.querySelector(".archive-search-clear")?.click(); 0`);
  await sleep(150);
  await type(tab, ".archive-input", words);
  await key(tab, "Enter", 13);
  await waitFor(tab, `/Looked at [\\d,]+ message/.test(document.querySelector(".archive-status")?.textContent ?? "")`);
  return tab.evaluate(`!!document.querySelector(".archive-results ${row}")`);
}
const noErrors = (who, tab) => check(`no page error on ${who}'s side`, tab.errors.length === 0, tab.errors.join(" | "));

async function lane() {
  // ── Before anything: the tab, on a page with no importer ────────────────
  const one = await browser(PORT + 100);
  const ann = await openDialog(one);
  await createAccount(ann, "annika");
  const secret = await turnOnCodes(ann);
  codeStepUsed = Math.floor(Date.now() / 30_000);
  const granted = await run(SERVER, ["-c", "server.toml", "admin", "grant", "annika", "admin"], { env });
  check("the shell gives annika the admin group", granted.status === 0, granted.stderr);
  await reloaded(ann);
  await openPanel(ann);
  await tabTo(ann, "Discord move");
  await waitFor(ann, q(".move-desktop-only"));
  check("the tab says the importer is the desktop app's", (await panelText(ann)).includes("Reading a Discord server runs in the desktop app"));
  check("and says why for a page", (await panelText(ann)).includes("would hand the token to whatever served it"));
  check("no token field in a browser", await ann.evaluate(`!document.querySelector(".wizard-token") && !document.querySelector(".wizard-start")`));
  check("the dashboard is empty and there", await seen(ann, byText(".move-status .move-line", "0 of 0 signed in")), await panelText(ann));
  check("no runs yet", (await panelText(ann)).includes("No import has run on this server."));

  const two = await browser(PORT + 101);
  const bob = await openDialog(two);
  await createAccount(bob, "bobby");
  await turnOnCodes(bob);
  const bobby = await run(SERVER, ["-c", "server.toml", "admin", "grant", "bobby", "moderator"], { env });
  check("the shell makes bobby a moderator", bobby.status === 0, bobby.stderr);
  await reloaded(bob);
  await openPanel(bob);
  check("a moderator's panel has their tabs", await seen(bob, byText(".admin-tabs button", "Moderation log")), await panelText(bob));
  check("and no Discord move", await bob.evaluate(`!${byText(".admin-tabs button", "Discord move")}`), await panelText(bob));
  await bob.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);

  const seven = await browser(PORT + 106);
  const rit = await openDialog(seven);
  await createAccount(rit, "rita");
  importer.secret = await turnOnCodes(rit);
  importer.step = Math.floor(Date.now() / 30_000);
  const rita = await run(SERVER, ["-c", "server.toml", "admin", "grant", "rita", "admin"], { env });
  check("the shell gives rita the admin group", rita.status === 0, rita.stderr);
  browsers.get(seven).kill("SIGKILL");

  // ── A real run, by the real driver ──────────────────────────────────────
  // More than a page can hold, so the pane's cap is met too. Its rows are the newest, and the
  // fixture's own are behind "Go further back".
  const first = await replay(["--top-up", "5300", "--tick", STAFF, "--tick", AFTER_DARK]);
  check("import_replay ran to the end", first.stopped == null && first.run > 0, JSON.stringify(first));
  check("over 5,000 rows came", first.counts.messages > 5000, JSON.stringify(first.counts));
  check("annika's list follows, with nothing pressed", await seen(ann, channelRow("lounge"), 30_000), (await textChannels(ann)).join());
  const annList = await textChannels(ann);
  check("channels in Discord's order, with the private ones for a holder of `*`",
    ["general", "lounge", "staff", "vault", "teams", "news", "old-logs", "after-dark"].join() ===
      annList.filter((n) => ["general", "lounge", "staff", "vault", "teams", "news", "old-logs", "after-dark"].includes(n)).join(),
    annList.join());
  const sections = await ann.evaluate(`[...document.querySelectorAll(".channel-list.modern .category-head")].map((c) => c.textContent.trim())`);
  const inOrder = sections.filter((s) => /^(talk|voice rooms|help)$/i.test(s));
  check("sections in Discord's order", inOrder.join().toLowerCase() === "talk,voice rooms,help", sections.join());
  check("a forum is a text channel here", annList.includes("help"), annList.join());
  await tabTo(ann, "Users");
  await waitFor(ann, q(".admin-dialog .move-filter"));
  await sleep(500);
  check("Users lists with chips", await seen(ann, `document.querySelector(".move-chip[data-state='Waiting']")`), await panelText(ann));
  await click(ann, ".admin-dialog .move-filter");
  await key(ann, "Escape", 27);
  await pickBy(ann, ".admin-dialog .move-filter", "Banned");
  check("the filter asks the relay: Banned", await seen(ann, `document.querySelector(".move-chip[data-state='Banned']") && !document.querySelector(".move-chip[data-state='Waiting']")`), await panelText(ann));
  await pickBy(ann, ".admin-dialog .move-filter", "All");
  await waitFor(ann, `document.querySelector(".move-chip[data-state='Waiting']")`);
  await mouse(ann, `document.querySelector(".admin-dialog .list-row .move-chip[data-state='Waiting']").closest(".list-row")`, "a waiting row");
  check("a row opens the account", await seen(ann, byText(".admin-dialog .btn-back", "All accounts")));
  await clickText(ann, ".admin-dialog .btn-back", "All accounts");
  await tabTo(ann, "Bans");
  check("who was banned on Discord is not on the relay's own list", await seen(ann, q(".admin-hint.empty")) && (await panelText(ann)).includes("No active bans"), await panelText(ann));

  await tabTo(ann, "Discord move");
  check("the dashboard says who is left", await seen(ann, byText(".move-status .move-line", "0 of")), await panelText(ann));
  check("one greyed row on the OK list, with nothing to press", await seen(ann, `document.querySelector(".power-row.unclaimed") && !document.querySelector(".power-row.unclaimed .power-ok")`), await panelText(ann));
  check("it says so", (await panelText(ann)).includes("Has not signed in yet"));
  check("the run stands", await seen(ann, `document.querySelector(".run-row[data-run='${first.run}'] .run-undo")`));
  await clickText(ann, `.run-row[data-run='${first.run}'] .run-report`, "Report");
  check("its stored report opens", await seen(ann, q(".move-report")), await panelText(ann));
  check("and is about what came", (await panelText(ann)).includes("channels"), await panelText(ann));
  await mouse(ann, byText(".move-report button", "Close"), "report Close");

  // ── dan comes, through the stand-in Discord, and changes the name ───────
  const three = await browser(PORT + 102);
  const dan = await comeWithDiscord(three, DAN, "dan_d", { rename: "danny" });
  await sleep(500);
  check("he is in under the name he chose", await seen(dan, memberRow("danny")), await pageText(dan));
  const badgeOf = (name) => `${memberRow(name)}?.querySelector(".badge")`;
  check("with his badge, on his screen", await seen(dan, badgeOf("danny")), await pageText(dan));
  check("and annika's", await seen(ann, badgeOf("danny")), await ann.evaluate(`${memberRow("danny")}?.textContent ?? "(not there)"`));
  check("in the colour it had", await dan.evaluate(`!!${badgeOf("danny")}.getAttribute("style")`));
  check("and the name he went by, beside his own", await ann.evaluate(`${memberRow("danny")}?.textContent.includes("Dan D")`), await ann.evaluate(`${memberRow("danny")}?.textContent ?? ""`));
  const danList = await textChannels(dan);
  check("the gate passes him into #staff", danList.includes("staff"), danList.join());
  check("no one passes #vault", !danList.includes("vault"), danList.join());
  await mouse(ann, byText(".admin-tabs button", "Users"), "Users");
  await mouse(ann, byText(".admin-tabs button", "Discord move"), "back to Discord move");
  check("the dashboard says one has signed in", await seen(ann, `/^1 of/.test(document.querySelector(".move-status .move-line")?.textContent ?? "")`), await panelText(ann));
  check("dan's row can be answered now", await seen(ann, `[...document.querySelectorAll(".power-row")].find((r) => r.textContent.includes("danny") && r.querySelector(".power-ok"))`), await panelText(ann));
  check("the OK list warns", (await panelText(ann)).includes("Check with them outside Discord first"));
  check("and says what else waits", (await panelText(ann)).includes("or a group their account held before it was opened"), await panelText(ann));
  check("and that an archive's channel takes an admin to delete", (await panelText(ann)).includes("but not one holding what came from Discord"), await panelText(ann));
  // A touch screen has no tooltip: what an OK hands out is read whole, at a phone's width
  await ann.send("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(500);
  const onPhone = await ann.evaluate(`(() => {
    const rows = [...document.querySelectorAll(".power-row")].filter((r) => r.textContent.includes("danny") && r.querySelector(".power-ok"));
    if (!rows.length) return null;
    const row = rows.sort((a, b) => b.querySelector(".row-meta").title.length - a.querySelector(".row-meta").title.length)[0];
    const meta = row.querySelector(".row-meta");
    const look = getComputedStyle(meta);
    const ok = row.querySelector(".power-ok").getBoundingClientRect();
    return {
      fits: meta.scrollWidth <= meta.clientWidth,
      lines: meta.getBoundingClientRect().height / (parseFloat(look.lineHeight) || parseFloat(look.fontSize) * 1.2),
      labels: meta.textContent.split(",").length,
      scopes: meta.title.split(",").length,
      okInside: ok.left >= 0 && ok.right <= innerWidth,
    };
  })()`);
  check("the OK list shows a group's powers whole on a phone", !!onPhone && onPhone.fits && onPhone.labels === onPhone.scopes, JSON.stringify(onPhone));
  check("long enough to have been cut before", !!onPhone && onPhone.lines > 1.5, JSON.stringify(onPhone));
  check("and its OK stands on screen", !!onPhone && onPhone.okInside, JSON.stringify(onPhone));
  await ann.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(300);

  // ── Who cannot see what: eva, cal, a guest ──────────────────────────────
  const four = await browser(PORT + 103);
  const eva = await comeWithDiscord(four, EVA, "eva.e", { says: "eva_e" });
  const evaList = await textChannels(eva);
  check("eva, without its groups, has no #staff", !evaList.includes("staff"), evaList.join());
  check("and has the open channels", evaList.includes("lounge") && evaList.includes("general"), evaList.join());
  const five = await browser(PORT + 104);
  const gus = await newTab(five);
  await connectGuest(gus, "gus");
  const gusList = await textChannels(gus);
  check("a guest has no #staff", !gusList.includes("staff"), gusList.join());
  check("and has the open channels", gusList.includes("lounge"), gusList.join());
  const six = await browser(PORT + 105);
  const cal = await comeWithDiscord(six, CAL, "cal");

  // Moved text channels are followed with no click, but for a gate someone passes only as `*`
  const isFollowed = (name) => `(${channelRow(name)} && !${channelRow(name)}.classList.contains("unjoined"))`;
  check("a claimed member follows a moved channel with no click", await seen(cal, isFollowed("lounge")), await cal.evaluate(`${channelRow("lounge")}?.outerHTML ?? "no row"`));
  check("and through his gate, #staff", await seen(dan, isFollowed("staff")), await dan.evaluate(`${channelRow("staff")}?.outerHTML ?? "no row"`));
  check("annika, who passes it only as `*`, is not pulled in", await seen(ann, `${channelRow("staff")}?.classList.contains("unjoined")`), await ann.evaluate(`${channelRow("staff")}?.outerHTML ?? "no row"`));

  // And the row lights by itself: a dot for a post, with nothing asked and nothing clicked
  await openChannel(dan, "lounge");
  await openChannel(eva, "general");
  await sleep(2500);
  await type(eva, ".input-bar .chat-input", "a word in general");
  await key(eva, "Enter", 13);
  check("a post lights a followed channel's row, with no click", await seen(dan, `!!${channelRow("general")}?.querySelector(".channel-dot, .channel-unread")`, 60_000), await dan.evaluate(`${channelRow("general")}?.outerHTML ?? "no row"`));

  // A preview reads nothing: the button and the fetch both wait for standing in the channel.
  // So it takes having left one first.
  await waitFor(cal, channelRow("lounge"));
  await cal.evaluate(`${channelRow("lounge")}.parentElement.querySelector('.settings-icon[title^="Leave this channel"]').click(); 0`);
  await waitFor(cal, `${channelRow("lounge")}?.classList.contains("unjoined")`);
  const beforePreview = await fetchesSent(cal);
  await mouse(cal, channelRow("lounge"), "#lounge, a preview");
  check("a preview offers to join", await seen(cal, `document.querySelector(".join-text-btn:not(.archive-open)")`), await pageText(cal));
  await sleep(800);
  check("and offers no archive", await cal.evaluate(`!document.querySelector(".archive-btn") && !document.querySelector(".archive-open")`), await pageText(cal));
  check("having asked for none", (await fetchesSent(cal)) === beforePreview, await fetchesSent(cal));
  await click(cal, ".join-text-btn:not(.archive-open)");
  check("joined: the empty state's line and its button", await seen(cal, `document.querySelector(".archive-open")?.textContent.includes("History from Discord")`), await pageText(cal));
  check("and the header's", await cal.evaluate(`!!document.querySelector(".archive-btn")`));
  check("that took no fetch: the list of what holds one said so", (await fetchesSent(cal)) === beforePreview);

  // A modified app asks for all of it by number. What it stands in answers; a gate answers as
  // an unknown channel does. The first of these is what shows the rest are not vacuous
  const calHeard = await forgeFetches(cal);
  check("asked directly, the channel cal stands in answers", calHeard.includes("xxxxxxxxxxxx"), calHeard.slice(0, 300));
  check("and the others say to join first", calHeard.includes("Join the channel first."), calHeard.slice(0, 300));
  check("and #staff's rows never come", !calHeard.includes("Who has the rota?") && !calHeard.includes("Keep it in here"), calHeard.slice(0, 300));
  await openChannel(dan, "staff");
  await click(dan, ".archive-btn");
  check("dan, through the gate, reads #staff's rows: they are there to read", await seen(dan, `document.querySelector(".archive-rows")?.textContent.includes("Who has the rota?")`), await paneText(dan));
  await click(dan, ".archive-close");
  const gusFetches = await fetchesSent(gus);
  await waitFor(gus, channelRow("lounge"));
  await mouse(gus, channelRow("lounge"), "#lounge, as a guest");
  await sleep(600);
  if (await gus.evaluate(`!!${q(".join-text-btn:not(.archive-open)")}`)) await click(gus, ".join-text-btn:not(.archive-open)");
  await sleep(1000);
  check("a guest has no button, in a channel it stands in", await gus.evaluate(`!document.querySelector(".archive-btn") && !document.querySelector(".archive-open")`), await pageText(gus));
  check("and its app asked for nothing", (await fetchesSent(gus)) === gusFetches);
  const gusHeard = await forgeFetches(gus);
  check("asked directly, the relay says to sign in", gusHeard.includes("Sign in with an account first."), gusHeard.slice(0, 300));
  check("and sends no row", !gusHeard.includes("xxxxxxxxxxxx") && !gusHeard.includes("Who has the rota?"), gusHeard.slice(0, 300));

  // An 18+ channel: nothing goes before the yes
  const beforeGate = await fetchesSent(eva);
  await waitFor(eva, channelRow("after-dark"));
  await mouse(eva, channelRow("after-dark"), "#after-dark");
  await sleep(600);
  if (await eva.evaluate(`!document.querySelector(".nsfw-gate") && !!${q(".join-text-btn:not(.archive-open)")}`)) await click(eva, ".join-text-btn:not(.archive-open)");
  check("#after-dark asks first", await seen(eva, q(".nsfw-gate")), await pageText(eva));
  await sleep(800);
  check("no button yet", await eva.evaluate(`!document.querySelector(".archive-btn")`));
  check("and nothing was fetched", (await fetchesSent(eva)) === beforeGate);
  await click(eva, ".nsfw-gate .join-text-btn");
  await sleep(600);
  if (await eva.evaluate(`!!${q(".join-text-btn:not(.archive-open)")}`)) await click(eva, ".join-text-btn:not(.archive-open)");
  check("after the yes, its archive is offered", await seen(eva, q(".archive-btn")), await pageText(eva));
  await click(eva, ".archive-btn");
  check("and reads", await seen(eva, `document.querySelector(".archive-rows")?.textContent.includes("Late night talk.")`), await paneText(eva));
  await click(eva, ".archive-close");

  // ── The OK: power only when annika says, with a code ────────────────────
  const canKick = async (tab) => {
    await mouse(tab, memberRow("gus"), "gus on the list", "right");
    await waitFor(tab, q(".ctx-menu"));
    const has = await tab.evaluate(`!!${byText(".ctx-item", "Kick from server")}`);
    await tab.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);
    await sleep(150);
    return has;
  };
  check("dan holds no power yet", !(await canKick(dan)), await pageText(dan));
  await mouse(ann, `[...document.querySelectorAll(".power-row")].find((r) => r.textContent.includes("danny")).querySelector(".power-ok")`, "OK");
  await giveCode(ann, secret, "hands out power");
  check("the OK goes, and the row with it", await seen(ann, `![...document.querySelectorAll(".power-row")].find((r) => r.textContent.includes("danny"))`), await panelText(ann));
  check("no error in the panel", await ann.evaluate(`!document.querySelector(".admin-error")`), await panelText(ann));
  check("dan is asked for codes, now a group of his holds power", await seen(dan, `document.querySelector('${dialogOf("totp-setup")}')?.innerText.includes("needs a second factor")`, 10_000), await pageText(dan));
  await dan.evaluate(`${byText(".account-dialog button", "Later")}?.click(); 0`);
  await sleep(400);
  check("its rights wait for them", !(await canKick(dan)), await pageText(dan));
  await turnOnCodes(dan);
  await sleep(500);
  check("with codes on, dan can kick", await canKick(dan), await pageText(dan));

  // ── The pane, as dan ────────────────────────────────────────────────────
  await openChannel(dan, "lounge");
  check("the header has the archive's button", await seen(dan, q(".archive-btn")), await pageText(dan));
  await click(dan, ".archive-btn");
  check("the pane opens", await seen(dan, q(".archive-pane")));
  const label = await dan.evaluate(`${q(".archive-pane .archive-label")}?.textContent`);
  check("the label's exact words", label === "Imported from Discord, unverified. This server can read it.", label);
  check("role note", await dan.evaluate(`${q(".archive-pane .archive-label")}?.getAttribute("role") === "note"`));
  const place = await dan.evaluate(`${q(".archive-input")}?.placeholder`);
  check("the search says who sees it", place === "Search this archive. The server sees what you search.", place);
  check("no composer in it", await dan.evaluate(`!document.querySelector(".archive-pane textarea, .archive-pane .chat-input")`));
  check("rows come", await seen(dan, `document.querySelectorAll(".archive-rows .row").length > 50`), await paneText(dan));
  const before = await dan.evaluate(`document.querySelectorAll(".archive-rows .row").length`);
  check("the newest row is at the bottom", await dan.evaluate(`(() => { const box = document.querySelector(".archive-rows"); return box.scrollTop === 0 && getComputedStyle(box).flexDirection === "column-reverse"; })()`));
  // Scroll with a real wheel
  const box = await dan.evaluate(`(() => { const r = document.querySelector(".archive-rows").getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
  await dan.activate();
  for (let i = 0; i < 40; i++) {
    await dan.send("Input.dispatchMouseEvent", { type: "mouseWheel", x: box.x, y: box.y, deltaX: 0, deltaY: -1500 });
    await sleep(40);
  }
  check("older rows come on scrolling", await seen(dan, `document.querySelectorAll(".archive-rows .row").length > ${before}`), before);
  // The cap: at 5,000 rows it stops, and Go further back starts the list again from there
  for (let i = 0; i < 200 && (await dan.evaluate(`document.querySelectorAll(".archive-rows .row").length < 5000`)); i++) {
    await dan.evaluate(scrollToTop);
    await sleep(200);
  }
  const held = await dan.evaluate(`document.querySelectorAll(".archive-rows .row").length`);
  check("the list stops near the cap", held >= 5000 && held < 5300, held);
  await sleep(600);
  await dan.evaluate(scrollToTop);
  check("and offers to go further back", await seen(dan, q(".archive-further"), 5000), held);
  check("it held there", (await dan.evaluate(`document.querySelectorAll(".archive-rows .row").length`)) === held);
  await click(dan, ".archive-further");
  check("Go further back holds only what is older", await seen(dan, `document.querySelector(".archive-newest") && document.querySelectorAll(".archive-rows .row").length <= 200`, 15_000), await dan.evaluate(`document.querySelectorAll(".archive-rows .row").length`));
  for (let i = 0; i < 60 && !(await dan.evaluate(`!!document.querySelector("${WELCOME}")`)); i++) {
    await dan.evaluate(scrollToTop);
    await sleep(200);
  }

  const ids = await dan.evaluate(`[...document.querySelectorAll(".archive-rows .row")].map((r) => r.dataset.id)`);
  check("each row once", new Set(ids).size === ids.length);
  check("a real snowflake comes through whole", ids.includes("1200000000000005001"), ids.slice(-5).join());
  check("what is written shows", await dan.evaluate(`document.querySelector("${WELCOME}")?.textContent.includes("Welcome to the lounge")`));
  check("a pin mark", await dan.evaluate(`!!document.querySelector("${WELCOME} .pin-mark")`));
  check("reactions are chips, not buttons", await dan.evaluate(`(() => { const c = document.querySelector(".archive-rows .chip"); return !!c && !c.closest("button"); })()`));
  check("dan's own row offers Hide and Delete", await dan.evaluate(`!!document.querySelector("${WELCOME} .hide-mine") && !!document.querySelector("${WELCOME} .delete-mine")`));
  check("nobody else's does", await dan.evaluate(`!document.querySelector("${rowOf("1200000000000005002")} .hide-mine")`));
  const spoiler = rowOf("1200000000000005004");
  check("a spoiler and a long body are there", await dan.evaluate(`document.querySelector("${spoiler}")?.textContent.includes("the butler did it")`), await dan.evaluate(`document.querySelector("${spoiler}")?.textContent ?? "(none)"`));

  // Thread, with its back button
  const opener = `document.querySelector("${rowOf("1200000000000005005")} .thread-open")`;
  check("a thread shows on its row", await seen(dan, opener), await dan.evaluate(`document.querySelector("${rowOf("1200000000000005005")}")?.textContent`));
  await mouse(dan, opener, "thread opener");
  check("the thread opens in the pane, with a way back", await seen(dan, q(".archive-back")));
  await sleep(500);
  check("the header names the thread", (await dan.evaluate(`${q(".archive-title")}.textContent`)) === "movie night", await paneText(dan));
  await click(dan, ".archive-back");
  check("back at the list", await seen(dan, `!document.querySelector(".archive-back") && document.querySelectorAll(".archive-rows .row").length > 50`));

  // Pins
  await click(dan, ".archive-pins");
  check("only what was pinned", await seen(dan, `document.querySelector(".archive-pins")?.getAttribute("aria-pressed") === "true" && document.querySelector("${WELCOME}") && document.querySelectorAll(".archive-rows .row").length < 20`), await paneText(dan));
  check("a pin has Show here", await seen(dan, `document.querySelector("${WELCOME} .show-here")`));
  await click(dan, `${WELCOME} .show-here`);
  check("Show here loads the page ending at it", await seen(dan, `document.querySelector("${WELCOME}.focus") && document.querySelector(".archive-newest")`), await paneText(dan));
  await click(dan, ".archive-newest");
  check("Back to the newest", await seen(dan, `!document.querySelector(".archive-newest") && document.querySelectorAll(".archive-rows .row").length > 50 && document.querySelector(".archive-back")`), await paneText(dan));
  await sleep(300);
  while (await dan.evaluate(`!!document.querySelector(".archive-back")`)) await click(dan, ".archive-back");
  check("the way back ends at the list it came from", await seen(dan, `document.querySelector("${WELCOME}") && document.querySelector(".archive-pins")?.getAttribute("aria-pressed") === "false"`), await paneText(dan));

  // Search
  await type(dan, ".archive-input", "movie");
  await key(dan, "Enter", 13);
  check("the search finds across flow and thread", await seen(dan, `document.querySelectorAll(".archive-results .row").length >= 1`), await paneText(dan));
  check("says how far it looked", await seen(dan, `/Looked at [\\d,]+ message/.test(document.querySelector(".archive-status")?.textContent ?? "")`), await dan.evaluate(`document.querySelector(".archive-status")?.textContent`));
  await mouse(dan, `document.querySelector(".archive-results .show-here")`, "a hit's Show here");
  check("a hit shows where it stands", await seen(dan, `document.querySelector(".archive-rows .row.focus")`), await paneText(dan));
  await click(dan, ".archive-back");
  check("back at the results", await seen(dan, `document.querySelectorAll(".archive-results .row").length >= 1`));
  await click(dan, ".archive-search-clear");
  check("clearing goes back to the list", await seen(dan, `document.querySelectorAll(".archive-rows .row").length > 0 && !document.querySelector(".archive-results")`));

  // Look further: fifty hits wait to be asked for more
  await type(dan, ".archive-input", "xxxx");
  await key(dan, "Enter", 13);
  check("a search stops at fifty hits, and offers more", await seen(dan, `document.querySelectorAll(".archive-results .row").length >= 50 && document.querySelector(".archive-more")`, 20_000), await dan.evaluate(`document.querySelector(".archive-status")?.textContent`));
  const hits = await dan.evaluate(`document.querySelectorAll(".archive-results .row").length`);
  await click(dan, ".archive-more");
  check("Look further finds more", await seen(dan, `document.querySelectorAll(".archive-results .row").length > ${hits}`, 20_000));
  await click(dan, ".archive-search-clear");
  await sleep(500);

  // His own row: hidden from others at once, shown again, then deleted for good. cal and
  // annika look by searching, which is a fresh fetch each time
  await openChannel(cal, "lounge");
  await click(cal, ".archive-btn");
  await waitFor(cal, q(".archive-pane"));
  await closedPanel(ann);
  await openChannel(ann, "lounge");
  await click(ann, ".archive-btn");
  await waitFor(ann, q(".archive-pane"));
  check("cal finds dan's post", await searchHas(cal, "Welcome to the lounge", WELCOME), await paneText(cal));
  check("and annika", await searchHas(ann, "Welcome to the lounge", WELCOME), await paneText(ann));

  await dan.evaluate(`document.querySelector("${WELCOME}")?.scrollIntoView()`);
  await waitFor(dan, q(`${WELCOME} .hide-mine`));
  await click(dan, `${WELCOME} .hide-mine`);
  check("hidden: dimmed, and says who sees it", await seen(dan, `document.querySelector("${WELCOME}.hidden-row")?.textContent.includes("Only you see this. Whoever runs this server still has it.")`));
  check("cal no longer finds it", !(await searchHas(cal, "Welcome to the lounge", WELCOME)), await paneText(cal));
  check("nor annika", !(await searchHas(ann, "Welcome to the lounge", WELCOME)), await paneText(ann));
  await click(dan, `${WELCOME} .show-mine`);
  check("Show again", await seen(dan, `document.querySelector("${WELCOME}") && !document.querySelector("${WELCOME}.hidden-row")`));
  check("cal finds it again", await searchHas(cal, "Welcome to the lounge", WELCOME), await paneText(cal));
  await click(dan, `${WELCOME} .delete-mine`);
  await confirmDialog(dan, "Delete it");
  check("deleted: gone from the pane", await seen(dan, `!document.querySelector("${WELCOME}")`));
  check("gone for cal", !(await searchHas(cal, "Welcome to the lounge", WELCOME)), await paneText(cal));
  check("and for annika", !(await searchHas(ann, "Welcome to the lounge", WELCOME)), await paneText(ann));
  check("no JS errors on dan's page so far", dan.errors.length === 0, dan.errors.join(" | "));

  await key(dan, "Escape", 27);
  check("Escape closes the pane", await seen(dan, `!document.querySelector(".archive-pane")`));
  check("the keyboard goes back where it was", await dan.evaluate(`document.activeElement?.classList.contains("archive-btn")`), await dan.evaluate(`document.activeElement?.className ?? document.activeElement?.tagName`));
  await click(dan, ".archive-btn");
  await waitFor(dan, `document.querySelectorAll(".archive-rows .row").length > 0`);
  // At a phone's width it covers the chat, and its own close comes back
  await dan.send("Emulation.setDeviceMetricsOverride", { width: 600, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(500);
  const covers = await dan.evaluate(`(() => { const p = document.querySelector(".archive-pane"); const b = p?.parentElement?.getBoundingClientRect(); const r = p?.getBoundingClientRect(); return !!b && getComputedStyle(p).position === "absolute" && Math.abs(r.width - b.width) < 2; })()`);
  check("in a narrow chat the pane covers it", covers);
  await dan.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(500);

  // The back-stack's way out, and in again by the empty state's button
  await click(dan, ".archive-close");
  check("Close shuts it", await seen(dan, `!document.querySelector(".archive-pane")`));
  await mouse(dan, q(".archive-open"), "History from Discord is here");
  check("the empty state's button opens it", await seen(dan, `document.querySelector(".archive-pane") && document.querySelectorAll(".archive-rows .row").length > 0`));
  await click(dan, ".archive-btn");
  check("the header's button shuts it", await seen(dan, `!document.querySelector(".archive-pane")`));
  await click(dan, ".search-btn");
  await waitFor(dan, q(".search-pane"));
  await click(dan, ".archive-btn");
  check("one pane at a time: the archive takes the search's place", await seen(dan, `document.querySelector(".archive-pane") && !document.querySelector(".search-pane")`));
  await click(dan, ".search-btn");
  check("and the other way round", await seen(dan, `document.querySelector(".search-pane") && !document.querySelector(".archive-pane")`));
  await key(dan, "Escape", 27);

  // Settings: the section
  await openSettings(dan);
  const mineLine = `document.querySelector(".imported-mine")?.textContent.trim() ?? ""`;
  const toastSays = (words) => `[...document.querySelectorAll(".toast-message")].some((t) => t.textContent.includes(${JSON.stringify(words)}))`;
  check("Settings counts his posts", await seen(dan, `/\\d of your posts are here/.test(${mineLine})`), await dan.evaluate(mineLine));
  await click(dan, ".imported-hide");
  check("Hide all says so", await seen(dan, toastSays("of your posts hidden."), 5000), (await pageText(dan)).slice(-300));
  await click(dan, ".imported-show");
  check("Show all says so", await seen(dan, toastSays("of your posts shown again."), 5000), (await pageText(dan)).slice(-300));
  await click(dan, ".imported-delete");
  await confirmDialog(dan, "Delete them");
  check("Delete all says so", await seen(dan, toastSays("of your posts deleted."), 5000), (await pageText(dan)).slice(-300));
  // Straight away: the worker may not have been, and the count has only this one chance
  check("and the count follows", await seen(dan, `/None of your posts/.test(${mineLine})`), await dan.evaluate(mineLine));
  check("no JS errors after Settings", dan.errors.length === 0, dan.errors.join(" | "));
  await key(dan, "Escape", 27);
  await sleep(300);

  // annika has no Discord linked: one line
  await click(ann, ".archive-close");
  await openSettings(ann);
  check("no linked Discord: one line saying so", await seen(ann, `/Link your Discord account first/.test(document.querySelector(".imported-refused")?.textContent ?? "")`), await ann.evaluate(`document.querySelector(".imported-mine")?.textContent ?? "(none)"`));
  await key(ann, "Escape", 27);
  await sleep(300);

  // ── The operator's menu on a row, and its code ──────────────────────────
  // The panel-less prompt asks
  // Past `*`: a moderator who may read the list does not see who was banned on Discord, and deletes no archive
  if (!(await ann.evaluate(`!!document.querySelector(".admin-tabs")`))) await openPanel(ann);
  await tabTo(ann, "Groups");
  await waitFor(ann, byText(".admin-dialog button", "New group"));
  await mouse(ann, byText(".admin-dialog button", "New group"), "New group");
  await waitFor(ann, q('.admin-dialog input[aria-label="Group name"]'));
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Group name"]', "readers"));
  await ann.evaluate(`document.querySelector('.admin-dialog input[data-scope="users:read"]').click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await giveCodeIfAsked(ann, secret);
  await waitFor(ann, `[...document.querySelectorAll(".admin-dialog .list-row .row-name")].some((n) => n.textContent.startsWith("readers"))`);
  const readers = await run(SERVER, ["-c", "server.toml", "admin", "grant", "bobby", "readers"], { env });
  check("the shell gives bobby a group that reads the list", readers.status === 0, readers.stderr);
  const hugoWaits = await run(SERVER, ["-c", "server.toml", "admin", "grant", "hugo", "readers"], { env });
  check("the shell says it waits, on an account nobody opened", hugoWaits.status === 0 && hugoWaits.stdout.includes("It waits for an admin's OK once the account is opened."), hugoWaits.stdout + hugoWaits.stderr);
  await reloaded(bob);
  await openPanel(bob);
  await tabTo(bob, "Users");
  await waitFor(bob, q(".admin-dialog .move-filter"));
  check("a moderator is not offered the Banned filter", await bob.evaluate(`![...document.querySelectorAll(".admin-dialog .move-filter option")].some((o) => o.value === "Banned")`), await panelText(bob));
  check("nor shown who was banned", await seen(bob, `document.querySelector(".move-chip[data-state='Waiting']")`) && (await bob.evaluate(`!document.querySelector(".move-chip[data-state='Banned']")`)), await panelText(bob));
  await tabTo(bob, "Channels");
  const holdingRow = `document.querySelector('.admin-dialog .row[data-channel="general"]')`;
  await waitFor(bob, holdingRow);
  await mouse(bob, `[...${holdingRow}.querySelectorAll("button")].find((b) => b.textContent.trim() === "Delete")`, "Delete #general");
  await waitFor(bob, byText(".confirm-dialog button, [class*=confirm] button", "Delete it"), 10_000);
  check("the question says one holding what came takes an admin", (await pageText(bob)).includes("One holding what came from Discord takes an admin"), await pageText(bob));
  await confirmDialog(bob, "Delete it");
  check("the relay says no, and asks for no code", await seen(bob, `document.querySelector(".admin-error")?.textContent.includes("only an admin can delete it")`) && (await bob.evaluate(`!document.querySelector('.admin-dialog input[aria-label="Two-factor code"]') && !document.querySelector(".step-up-dialog input")`)), await panelText(bob));
  check("and the channel stands", await bob.evaluate(`!!${holdingRow}`), await panelText(bob));
  await bob.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await reloaded(ann);
  await openChannel(ann, "lounge");
  check("annika has the button too", await seen(ann, q(".archive-btn")));
  await click(ann, ".archive-btn");
  await waitFor(ann, `document.querySelector(".archive-rows .row")`);
  await sleep(400);
  const victim = rowOf("1200000000000005002");
  // Reach it through its own page
  for (let i = 0; i < 300 && !(await ann.evaluate(`!!document.querySelector("${victim}")`)); i++) {
    if (await ann.evaluate(`!!document.querySelector(".archive-further")`)) await click(ann, ".archive-further");
    await ann.evaluate(scrollToTop);
    await sleep(150);
  }
  check("annika reaches the row", await ann.evaluate(`!!document.querySelector("${victim}")`));
  await ann.evaluate(`document.querySelector("${victim}")?.scrollIntoView()`);
  await click(ann, `${victim} .row-menu-btn`);
  check("the menu has both", await seen(ann, `document.querySelector("${victim} .delete-this") && document.querySelector("${victim} .delete-author")`));
  await click(ann, `${victim} .delete-this`);
  await confirmDialog(ann, "Delete it");
  await giveCode(ann, secret, "imported posts go for good");
  check("the code takes it", await seen(ann, `!document.querySelector("${victim}")`));
  check("the toast says so", await seen(ann, `document.body.innerText.includes("1 imported post deleted")`, 4000), (await pageText(ann)).slice(-300));
  await sleep(300);
  const third = spoiler;
  await ann.evaluate(`document.querySelector("${third}")?.scrollIntoView()`);
  check("annika reaches bea's row", await ann.evaluate(`!!document.querySelector("${third}")`));
  await click(ann, `${third} .row-menu-btn`);
  await click(ann, `${third} .delete-author`);
  await confirmDialog(ann, "Delete it all");
  // Within the code's ten minutes
  check("everything by that author goes", await seen(ann, `!document.querySelector("${third}") && !document.querySelector("${rowOf("1200000000000005015")}")`), await paneText(ann));
  check("and nobody else's", await ann.evaluate(`!!document.querySelector("${rowOf("1200000000000005012")}")`), await paneText(ann));
  check("no JS errors on annika's page", ann.errors.length === 0, ann.errors.join(" | "));
  await click(ann, ".archive-close");

  // ── Left out, held, let back in, and delete by id ───────────────────────
  await openPanel(ann);
  await tabTo(ann, "Discord move");
  check("still to sign in, with its two actions", await seen(ann, `document.querySelector(".waiting-row .move-leave") && document.querySelector(".waiting-row .move-hold")`), await panelText(ann));
  const heldName = await ann.evaluate(`document.querySelector(".waiting-row .row-name").textContent`);
  await click(ann, ".waiting-row .move-hold");
  await confirmDialog(ann, "Hold for now");
  check("held: on the list, its posts staying", await seen(ann, byText(".excluded-row .row-meta", "Held for now")), await panelText(ann));
  check("gone from those still to sign in", await seen(ann, `![...document.querySelectorAll(".waiting-row .row-name")].some((n) => n.textContent === ${JSON.stringify(heldName)})`), heldName);
  await mouse(ann, `document.querySelector(".excluded-row .let-back")`, "Let back in");
  check("let back in", await seen(ann, `!document.querySelector(".excluded-row")`), await panelText(ann));
  // bea by her id: rows of one second stand in the order of their random account ids, and frank's posts are for further down.
  // If she was the one held, her row is back only once the list has come again.
  const beaRow = `[...document.querySelectorAll(".waiting-row")].find((r) => r.textContent.includes("1190000000000001003"))`;
  await waitFor(ann, `!!${beaRow}`, 30_000);
  await mouse(ann, `[...document.querySelectorAll(".waiting-row")].find((r) => r.textContent.includes("1190000000000001003")).querySelector(".move-leave")`, "bea's Leave out");
  await confirmDialog(ann, "Leave out and delete");
  check("left out: says their posts go", await seen(ann, byText(".excluded-row .row-meta", "Left out")), await panelText(ann));
  await mouse(ann, `document.querySelector(".excluded-row .let-back")`, "Let back in, after an erase");
  await waitFor(ann, byText(".confirm-dialog button, [class*=confirm] button", "Let back in"));
  check("letting back in says posts do not come back", (await pageText(ann)).includes("Posts already gone do not come back"));
  await confirmDialog(ann, "Let back in");
  await sleep(500);

  // ── Lifting a ban that came from Discord ────────────────────────────────
  await tabTo(ann, "Users");
  await waitFor(ann, q(".admin-dialog .move-filter"));
  await pickBy(ann, ".admin-dialog .move-filter", "Banned");
  check("a banned row offers the lift, and no other does", await seen(ann, `document.querySelector(".move-lift") && [...document.querySelectorAll(".admin-dialog .list > li")].every((li) => !!li.querySelector(".move-lift") === !!li.querySelector(".move-chip[data-state='Banned']"))`), await panelText(ann));
  const bannedRows = `document.querySelectorAll(".admin-dialog .move-chip[data-state='Banned']").length`;
  const bannedBefore = await ann.evaluate(bannedRows);
  const liftedRow = await ann.evaluate(`document.querySelector(".move-lift").closest("li").querySelector(".row-name").textContent`);
  check("a banned row goes by its Discord id", /^dc-\d+/.test(liftedRow), liftedRow);
  await mouse(ann, q(".move-lift"), "Lift ban");
  await waitFor(ann, byText(".confirm-dialog button, [class*=confirm] button", "Lift ban"));
  check("lifting says what stays", (await pageText(ann)).includes("what they wrote stays"));
  await confirmDialog(ann, "Lift ban");
  await giveCodeIfAsked(ann, secret);
  check("lifted: one fewer, and still the banned list", await seen(ann, `${bannedRows} === ${bannedBefore - 1} && !document.querySelector(".admin-dialog .move-chip[data-state='Waiting']")`, 15_000), await panelText(ann));
  check("the row itself has gone", await ann.evaluate(`![...document.querySelectorAll(".admin-dialog .row-name")].some((n) => n.textContent === ${JSON.stringify(liftedRow)})`), await panelText(ann));
  await pickBy(ann, ".admin-dialog .move-filter", "All");
  await tabTo(ann, "Discord move");
  check("lifted: held on the left-out list, its posts staying", await seen(ann, byText(".excluded-row .row-meta", "Held for now")), await panelText(ann));
  await mouse(ann, `document.querySelector(".excluded-row .let-back")`, "Let back in, after a lift");
  check("and back off it", await seen(ann, `!document.querySelector(".excluded-row")`), await panelText(ann));

  await type(ann, ".delete-id", "not an id");
  check("a bad id can't be sent", await ann.evaluate(`document.querySelector(".delete-id-go").disabled`));
  await ann.evaluate(setInput(".delete-id", ""));
  await type(ann, ".delete-id", FRANK);
  check("a good one can", await ann.evaluate(`!document.querySelector(".delete-id-go").disabled`));
  const franks = rowOf("1200000000000005012");
  check("frank's row is there to go", await searchHas(cal, "Looked it up for you", franks), await paneText(cal));
  await ann.evaluate(`document.querySelectorAll(".toast .toast-close").forEach((c) => c.click()); 0`);
  await click(ann, ".delete-id-go");
  await confirmDialog(ann, "Delete it all");
  check("delete by id says how many", await seen(ann, `[...document.querySelectorAll(".toast-message")].some((t) => /\\d imported posts deleted/.test(t.textContent))`, 5000), (await pageText(ann)).slice(-300));
  check("no error from delete by id", await ann.evaluate(`!document.querySelector(".admin-error")`), await panelText(ann));
  check("and frank's row has gone for a reader", !(await searchHas(cal, "Looked it up for you", franks)), await paneText(cal));
  await tabTo(ann, "Moderation log");
  const deleted = `document.querySelector('.modlog-row[data-action="archive_delete"]')`;
  check("the log reads in words", await seen(ann, `${deleted}?.textContent.includes("deleted posts imported from Discord")`), await panelText(ann));
  const logRows = await ann.evaluate(`[...document.querySelectorAll('.modlog-row[data-action="archive_delete"]')].map((r) => r.textContent).join(" | ")`);
  check("and names nobody it took", !/bea|1190000000000001/i.test(logRows), logRows);
  check("the run's row too", await ann.evaluate(`document.querySelector('.modlog-row[data-action="import"]')?.textContent.includes("began a move from Discord")`));
  check("the OK's row too", await ann.evaluate(`document.querySelector('.modlog-row[data-action="power_grant"]')?.textContent.includes("what they could do on Discord")`));

  // ── A later delta: what is new and nothing else ─────────────────────────
  await tabTo(ann, "Channels");
  const newsRow = `document.querySelector('.admin-dialog .row[data-channel="news"]')`;
  await waitFor(ann, newsRow);
  await mouse(ann, `[...${newsRow}.querySelectorAll("button")].find((b) => b.textContent.trim() === "Edit")`, "Edit #news");
  await waitFor(ann, q('.admin-dialog input[aria-label="Name"]'));
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Name"]', "notices"));
  await mouse(ann, byText(".admin-dialog button", "Save"), "Save");
  await giveCodeIfAsked(ann, secret);
  check("annika renames #news by hand", await seen(ann, channelRow("notices")), (await textChannels(ann)).join());

  const second = await replay(["--v2"]);
  check("the delta ran to the end", second.stopped == null && second.run > first.run, JSON.stringify(second));
  check("what dan deleted did not come back: the relay skipped it", JSON.stringify(second.resent) === "[0,1]", JSON.stringify(second.resent));
  await seen(ann, channelRow("new-room"), 30_000);
  const afterDelta = await textChannels(ann);
  check("a new channel came", afterDelta.includes("new-room"), afterDelta.join());
  check("annika's name for #news stands", afterDelta.includes("notices") && !afterDelta.includes("news"), afterDelta.join());
  check("nothing doubled on the list", new Set(afterDelta).size === afterDelta.length, afterDelta.join());

  // Dan is on the list, the pane is opened afresh and stays open for the ban below
  await dan.evaluate(`document.querySelector(".search-close, .search-pane .close-btn")?.click(); 0`);
  await key(dan, "Escape", 27);
  await sleep(300);
  await reloaded(dan);
  await openChannel(dan, "lounge");
  await click(dan, ".archive-btn");
  const newRow = (n) => rowOf(`331000000000000100${n}`);
  check("the delta's rows are on top", await seen(dan, `document.querySelector("${newRow(2)}")?.textContent.includes("A new message, number 2.")`), await paneText(dan));
  const flow = await dan.evaluate(`[...document.querySelectorAll(".archive-rows .row")].map((r) => r.dataset.id)`);
  check("no row twice after a second run", new Set(flow).size === flow.length);
  check("a deleted author's new posts stay out: all dan's", await dan.evaluate(`!document.querySelector("${newRow(1)}") && !document.querySelector("${newRow(5)}")`), await paneText(dan));
  check("and the rest of the delta came: cal's", await dan.evaluate(`!!document.querySelector("${newRow(4)}") && !!document.querySelector("${newRow(8)}")`), await paneText(dan));

  // ── A ban with removal: whoever has the pane open sees it go ────────────
  await tabTo(ann, "Bans");
  await waitFor(ann, q('.ban-add input[aria-label="Account to ban"]'));
  await ann.evaluate(setInput('.ban-add input[aria-label="Account to ban"]', "cal"));
  await ann.evaluate(setInput('.ban-add input[aria-label="Reason"]', "spam"));
  await pickIn(ann, ".ban-add-removal", "Remove posts: everything kept");
  await mouse(ann, q(".ban-add .admin-ok"), "Ban account");
  await giveCodeIfAsked(ann, secret, "");
  check("cal is out", await seen(cal, `document.body.innerText.includes("banned")`, 20_000), await pageText(cal));
  check("his rows leave dan's open pane, with nothing pressed", await seen(dan, `!document.querySelector("${newRow(4)}") && !document.querySelector("${newRow(8)}")`, 20_000), await paneText(dan));
  check("someone else's stay", await dan.evaluate(`!!document.querySelector("${newRow(2)}")`), await paneText(dan));
  await ann.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);

  // ── A reload: nothing of the archive in storage ─────────────────────────
  const leak = await dan.evaluate(`(async () => {
    const parts = [JSON.stringify({ ...localStorage })];
    for (const db of await indexedDB.databases()) {
      const open = await new Promise((done, fail) => { const r = indexedDB.open(db.name); r.onsuccess = () => done(r.result); r.onerror = fail; });
      for (const store of open.objectStoreNames) {
        const all = await new Promise((done) => { const q = open.transaction(store).objectStore(store).getAll(); q.onsuccess = () => done(q.result); q.onerror = () => done([]); });
        parts.push(JSON.stringify(all, (_, v) => typeof v === "bigint" ? String(v) : v));
      }
    }
    return parts.join(" ").includes("A new message, number") || parts.join(" ").includes("Movie night");
  })()`);
  check("nothing of the archive in localStorage or IndexedDB", leak === false);
  const stillRows = await dan.evaluate(`[...document.querySelectorAll(".archive-rows .row")].length`);
  check("and the pane did hold rows to leak", stillRows > 0, stillRows);
  noErrors("dan", dan);

  // ── Undo: preview, one question, a code, all the way, newest first ──────
  await openPanel(ann);
  await tabTo(ann, "Discord move");
  const undoOne = async (runId, words) => {
    await waitFor(ann, `document.querySelector(".run-row[data-run='${runId}'] .run-undo")`);
    await click(ann, `.run-row[data-run='${runId}'] .run-undo`);
    await waitFor(ann, byText(".confirm-dialog button, [class*=confirm] button", "Undo it"), 10_000);
    const said = await pageText(ann);
    check(`the question says what goes: ${words.source}`, words.test(said), said.slice(-800));
    await confirmDialog(ann, "Undo it");
    await giveCodeIfAsked(ann, secret, "goes for good");
    check("Undo goes on until it is done", await seen(ann, `document.querySelector(".move-undoing")?.textContent.startsWith("Undone.")`, 60_000), await panelText(ann));
    check("the run says it is undone or clearing", await seen(ann, `/Undone|Being undone/.test(document.querySelector(".run-row[data-run='${runId}'] .row-name")?.textContent ?? "")`), await panelText(ann));
    await clickText(ann, ".move-undoing button", "Done");
  };
  const groupNames = () => ann.evaluate(`[...document.querySelectorAll(".admin-dialog .list-row .row-name")].map((n) => n.textContent.trim().split(" ")[0])`);
  await tabTo(ann, "Groups");
  await waitFor(ann, `document.querySelector(".admin-dialog .list-row .row-name")`);
  const groupsBefore = await groupNames();
  check("the run's groups are there, and their twins", groupsBefore.includes("moderators") && groupsBefore.includes("moderators-power"), groupsBefore.join());
  await tabTo(ann, "Discord move");
  await undoOne(second.run, /This takes 2 channels and everything written in them/);
  check("the delta's channel went", await seen(ann, `!${channelRow("new-room")}`, 10_000), (await textChannels(ann)).join());
  check("the first run's still stand", await ann.evaluate(`!!${channelRow("lounge")}`));
  await undoOne(first.run, /This takes .*channels and everything written in them/);
  check("the channels went from the list", await seen(ann, `!${channelRow("lounge")}`, 10_000), (await textChannels(ann)).join());
  check("even the one renamed by hand: the run made it", await ann.evaluate(`!${channelRow("notices")}`), (await textChannels(ann)).join());
  await tabTo(ann, "Groups");
  await waitFor(ann, `document.querySelector(".admin-dialog .list-row .row-name")`);
  const groupsAfter = await groupNames();
  check("its groups went, and their twins", !groupsAfter.includes("moderators") && !groupsAfter.includes("moderators-power"), groupsAfter.join());
  check("the relay's own stayed", groupsAfter.includes("moderator"), groupsAfter.join());
  await tabTo(ann, "Users");
  await waitFor(ann, q(".admin-dialog .move-filter"));
  check("dan, who came, stays", await seen(ann, `[...document.querySelectorAll(".admin-dialog .list-row .row-name")].some((n) => n.textContent.includes("danny"))`), await panelText(ann));
  check("who never came, goes", await seen(ann, `![...document.querySelectorAll(".admin-dialog .list-row .row-name")].some((n) => n.textContent.includes("hugo"))`), await panelText(ann));
  check("and his tab is still connected", await dan.evaluate(`!!document.querySelector(".channel-list") && !document.querySelector(".connect-btn")`), await pageText(dan));
  check("no JS errors on annika's page after Undo", ann.errors.length === 0, ann.errors.join(" | "));
  check("no JS errors on dan's page after Undo", dan.errors.length === 0, dan.errors.join(" | "));

  // ── The wizard, on a test build's page ──────────────────────────────────
  await signIn(ann, "annika", secret, "/?wizard");
  await openPanel(ann);
  await tabTo(ann, "Discord move");
  await waitFor(ann, q(".wizard-start"));
  check("the wizard takes the card's place", await ann.evaluate(`!document.querySelector(".move-desktop-only")`));
  await click(ann, ".wizard-start");
  await waitFor(ann, q(".wizard-token"));
  check("Next stays shut with no token", await ann.evaluate(`document.querySelector(".wizard-open").disabled`));
  await type(ann, ".wizard-token", "wrong-token");
  await click(ann, ".wizard-open");
  check("a bad token is said, and the field is empty", await seen(ann, `document.querySelector(".wizard-error")?.textContent.includes("no longer works") && document.querySelector(".wizard-token")?.value === ""`), await panelText(ann));
  await type(ann, ".wizard-token", "fixture-token");
  await click(ann, ".wizard-open");
  check("it picks a server, two of one name fine", await seen(ann, `document.querySelectorAll(".wizard-guild option").length === 2`), await panelText(ann));
  check("the token left no trace on the page", !(await ann.evaluate(`document.documentElement.outerHTML`)).includes("fixture-token"));
  await click(ann, ".wizard-read");
  check("the dry-run comes", await seen(ann, q(".wizard-toggles")), await panelText(ann));
  const row = (name) => `[...document.querySelectorAll(".channel-row")].find((r) => r.dataset.channel === ${JSON.stringify(name)})`;
  check("a private channel's tick starts off", await ann.evaluate(`${row("staff")}.querySelector(".channel-messages").checked === false`));
  check("an open channel's starts on", await ann.evaluate(`${row("general")}.querySelector(".channel-messages").checked === true`));
  check("the sentence about a private name", (await panelText(ann)).includes("Its name and topic go regardless; Leave out to keep them off."));
  check("Run is shut until the tick", await ann.evaluate(`document.querySelector(".wizard-begin").disabled`));
  check("and says why", (await panelText(ann)).includes("Tick what copying messages means"));
  check("the acknowledgement's words", (await panelText(ann)).includes("scraping our services without our written consent"));
  // Toggles, each by mouse: messages off takes what needs it
  await click(ann, `input[data-toggle="messages"]`);
  check("messages off: threads say why", await seen(ann, `document.querySelector('input[data-toggle="threads"]').disabled && document.querySelector('input[data-toggle="threads"]').checked === false`));
  check("and the channel ticks with it", await ann.evaluate(`${row("general")}.querySelector(".channel-messages").disabled`));
  if (POSTGRES) await click(ann, ".wizard-backup input");
  check("no tick to give then: Run opens", await seen(ann, `!document.querySelector(".wizard-begin").disabled`), await panelText(ann));
  await click(ann, `input[data-toggle="messages"]`);
  await click(ann, `input[data-toggle="channels"]`);
  check("channels off takes messages too", await seen(ann, `document.querySelector('input[data-toggle="messages"]').disabled && document.querySelector('input[data-toggle="permissions"]').disabled`));
  await click(ann, `input[data-toggle="channels"]`);
  for (const k of ["roles", "members", "bans", "emotes", "pins", "reactions", "anonymise", "threads", "permissions"]) {
    await click(ann, `input[data-toggle="${k}"]`);
    const off = await ann.evaluate(`document.querySelector('input[data-toggle="${k}"]').checked === false`);
    await click(ann, `input[data-toggle="${k}"]`);
    const on = await ann.evaluate(`document.querySelector('input[data-toggle="${k}"]').checked === true`);
    check(`the ${k} toggle takes a click each way`, off && on);
  }
  await mouse(ann, `${row("staff")}.querySelector(".channel-messages")`, "staff's tick");
  check("a private channel can be ticked", await ann.evaluate(`${row("staff")}.querySelector(".channel-messages").checked`));
  await mouse(ann, `${row("vault")}.querySelector(".channel-out")`, "vault's Leave out");
  check("Leave out shuts its messages tick", await ann.evaluate(`${row("vault")}.querySelector(".channel-messages").disabled && ${row("vault")}.classList.contains("left-out")`));
  await mouse(ann, `document.querySelector(".wizard-lossy summary")`, "what does not come");
  check("what does not come opens", await ann.evaluate(`document.querySelector(".wizard-lossy").open`));
  await type(ann, ".wizard-ids", "dan#1234");
  check("a bad id says so, and the button stays shut", await seen(ann, `document.querySelector(".wizard-ids-go").disabled && document.querySelector(".wizard-error")?.textContent.includes("Not a Discord id")`));
  await ann.evaluate(setInput(".wizard-ids", ""));
  await type(ann, ".wizard-ids", "1190000000000001003\n1190000000000001006");
  await click(ann, ".wizard-ids-go");
  await giveCodeIfAsked(ann, secret, "keeps them out");
  check("both are on the left-out list", await seen(ann, `[...document.querySelectorAll(".excluded-row .row-name")].filter((n) => /100[36]$/.test(n.textContent)).length === 2`), await panelText(ann));
  await click(ann, ".wizard-ack input");
  check("the tick opens Run", await seen(ann, `!document.querySelector(".wizard-begin").disabled`), await panelText(ann));
  await ann.evaluate(`window.__waitSeen = false; window.__waitWatch = setInterval(() => { if (document.querySelector(".wizard-wait")) window.__waitSeen = true; }, 50); 0`);
  await click(ann, ".wizard-begin");
  await giveCodeIfAsked(ann, secret, "On SQLite the server makes a copy first");
  check("the run goes, with its progress", await seen(ann, q(".wizard-progress"), 30_000), await panelText(ann));
  if (!POSTGRES) check("the backup's path is shown, and that it stays until deleted", await seen(ann, `document.querySelector(".wizard-backup-path")?.textContent.includes("It stays until you delete it")`, 3000) || (await panelText(ann)).includes("It stays until you delete it"), await panelText(ann));
  check("Discord's wait shows", await seen(ann, `window.__waitSeen`, 8000), await panelText(ann));
  check("it ends", await seen(ann, byText(".wizard-ended", "Done."), 15_000), await panelText(ann));
  check("the end screen says to remove the bot", (await panelText(ann)).includes("Now remove the bot.") && (await panelText(ann)).includes("do not keep the new one"));
  check("a repeated note draws, as a keyed each could not", await ann.evaluate(`document.querySelectorAll(".wizard-notes li").length >= 2`));
  await click(ann, ".wizard-post-open");
  await waitFor(ann, q(".post-text"));
  const postText = await ann.evaluate(`document.querySelector(".post-text").value`);
  check("the post says what happened to the messages", postText.includes("Whoever runs that server can read it"), postText);
  check("the post names this server", postText.includes(ORIGIN), postText);
  await click(ann, ".post-link");
  check("a join link comes into it", await seen(ann, `document.querySelector(".post-text").value.includes("New here? https://")`), await ann.evaluate(`document.querySelector(".post-text").value`));
  await click(ann, ".post-everyone");
  await click(ann, ".post-go");
  check("Post goes once", await seen(ann, `document.querySelector(".post-done") && document.querySelector(".post-go").disabled`));
  const posts = await ann.evaluate(`JSON.stringify(window.__movePosts)`);
  check("with what was on screen", JSON.parse(posts).length === 1 && JSON.parse(posts)[0].everyone === true && JSON.parse(posts)[0].text.includes("New here?"), posts);
  await click(ann, ".post-go").catch(() => {});
  check("a second press posts nothing", (await ann.evaluate(`window.__movePosts.length`)) === 1);
  await click(ann, ".wizard-done");
  check("Done goes back to the start, saying Run again", await seen(ann, byText(".wizard-start", "Run again")), await panelText(ann));
  // Cancel at the first step, and Stop in a run
  await click(ann, ".wizard-start");
  await waitFor(ann, q(".wizard-token"));
  await clickText(ann, ".wizard button", "Cancel");
  check("Cancel goes back", await seen(ann, `document.querySelector(".wizard-start") && !document.querySelector(".wizard-token")`));
  await click(ann, ".wizard-start");
  await waitFor(ann, q(".wizard-token"));
  await type(ann, ".wizard-token", "fixture-token");
  await key(ann, "Enter", 13);
  await waitFor(ann, q(".wizard-read"));
  await click(ann, ".wizard-read");
  await waitFor(ann, q(".wizard-toggles"));
  check("a run after a run starts with no tick", await ann.evaluate(`document.querySelector(".wizard-ack input").checked === false`));
  await click(ann, ".wizard-ack input");
  if (POSTGRES) await click(ann, ".wizard-backup input");
  await click(ann, ".wizard-begin");
  await waitFor(ann, q(".wizard-stop"), 20_000);
  await click(ann, ".wizard-stop");
  check("Stop stops it, and says so", await seen(ann, byText(".wizard-ended", "Stopped"), 8000), await panelText(ann));
  check("no post offered after a stop", await ann.evaluate(`!document.querySelector(".wizard-post-open")`));
  await click(ann, ".wizard-go-on");
  check("Go on comes back to the choices, with the tick to give again", await seen(ann, `document.querySelector(".wizard-toggles") && document.querySelector(".wizard-ack input").checked === false`), await panelText(ann));
  await clickText(ann, ".wizard button", "Cancel");
  check("Cancel from there goes to the start", await seen(ann, q(".wizard-start")));
  check("the reminder stays until it is ticked", await seen(ann, q(".bot-reminder input"), 8000), await panelText(ann));
  await click(ann, ".bot-reminder input");
  check("and goes when it is", await seen(ann, `!document.querySelector(".bot-reminder")`));
  noErrors("annika", ann);

  // ── Active bans, a page at a time: a token admin, past a frame's worth ──
  const tess = await newTab(five);
  await connectGuest(tess, "tess", PORT + 1);
  await serverMenu(tess, "Admin login");
  await waitFor(tess, `document.querySelector(".admin-dialog .admin-input")`);
  await tess.evaluate(setInput('.admin-dialog input[type="password"]', TOKEN));
  await tess.evaluate(`document.querySelector(".admin-dialog .admin-ok").click()`);
  await sleep(1000);
  await serverMenu(tess, "Server admin");
  const banRows = `document.querySelectorAll(".ban-list .ban-label").length`;
  const banLabels = `[...document.querySelectorAll(".ban-list .ban-label")].map((b) => b.textContent)`;
  check("the list comes, a page of it", await seen(tess, `${banRows} === 100`), await panelText(tess));
  check("and says how many are left", await seen(tess, `document.querySelector(".ban-more")?.textContent.includes("${BANS - 100} left")`), await panelText(tess));
  check("newest first", (await tess.evaluate(banLabels))[0] === "person-0000");
  await click(tess, ".ban-more");
  check("Show more brings the next", await seen(tess, `${banRows} === 200`), await panelText(tess));
  const shown = await tess.evaluate(banLabels);
  check("each once, in order", new Set(shown).size === 200 && shown[199] === "person-0199", shown.slice(195).join());
  await type(tess, '.ban-search input[type="search"]', "PERSON-0990");
  await key(tess, "Enter", 13);
  check("a search finds a far one, in any case", await seen(tess, `${banRows} === 1 && document.querySelector(".ban-list .ban-label").textContent === "person-0990"`), await panelText(tess));
  check("and nothing more to show", await tess.evaluate(`!document.querySelector(".ban-more")`));
  await mouse(tess, `document.querySelector(".ban-list .admin-cancel")`, "Unban");
  check("lifting it keeps the search, which now finds nothing", await seen(tess, `document.querySelector(".admin-hint.empty")?.textContent.includes("person-0990".toUpperCase()) && ${banRows} === 0`), await panelText(tess));
  check("the box still says it", await tess.evaluate(`document.querySelector('.ban-search input[type="search"]').value === "PERSON-0990"`));
  await tess.evaluate(setInput('.ban-search input[type="search"]', ""));
  await click(tess, '.ban-search button[type="submit"]');
  check("clearing it brings the first page of what is left", await seen(tess, `${banRows} === 100 && document.querySelector(".ban-more")?.textContent.includes("${BANS - 1 - 100} left")`), await panelText(tess));
  noErrors("the token admin", tess);

  for (const [who, tab] of [["bobby", bob], ["eva", eva], ["gus", gus]]) noErrors(who, tab);

  // ── Stop, then a new dry-run: the run standing is annika's own ──────────
  const toChoices = async () => {
    await click(ann, ".wizard-start");
    await waitFor(ann, q(".wizard-token"));
    await type(ann, ".wizard-token", "fixture-token");
    await click(ann, ".wizard-open");
    await waitFor(ann, q(".wizard-read"));
    await click(ann, ".wizard-read");
    await waitFor(ann, q(".wizard-toggles"));
  };
  await toChoices();
  check("a new dry-run after her own Stop blames nobody", !(await panelText(ann)).includes("Another admin"), await panelText(ann));
  await click(ann, ".wizard-ack input");
  if (POSTGRES) await click(ann, ".wizard-backup input");
  check("and Run opens", await seen(ann, `!document.querySelector(".wizard-begin").disabled`, 5000), await panelText(ann));

  // ── A cut: the wizard outlives it, wherever it stood. The last thing here, as every page reconnects ──
  const wizardAt = (step) => `document.querySelector('.wizard[data-step="${step}"]')`;
  const codePrompt = q(`.admin-dialog input[aria-label="Two-factor code"]`);
  const backInPanel = async () => {
    await waitFor(ann, `document.querySelector(".channel-list") && !document.body.innerText.includes("attempt #")`, 60_000);
    await seen(ann, `!document.querySelector(".admin-dialog")`, 3000);
    await sleep(1500);
    await settle(ann);
    await openPanel(ann);
    await tabTo(ann, "Discord move");
  };
  await mouse(ann, `${row("lounge")}.querySelector(".channel-out")`, "lounge's Leave out");
  await cut();
  await backInPanel();
  check("a cut at the choices keeps them", await seen(ann, wizardAt("choose")), await panelText(ann));
  check("with what was ticked", await ann.evaluate(`${row("lounge")}.querySelector(".channel-out").checked && document.querySelector(".wizard-ack input").checked`), await panelText(ann));
  check("and no stale error", await ann.evaluate(`!document.querySelector(".admin-error")`), await panelText(ann));
  await click(ann, ".wizard-begin");
  check("a new connection asks for the code", await seen(ann, codePrompt), await panelText(ann));
  check("waiting on it", await ann.evaluate(`!!${wizardAt("beginning")}`), await panelText(ann));
  await cut();
  await backInPanel();
  check("a cut at the code goes back to the choices", await seen(ann, wizardAt("choose")), await panelText(ann));
  check("which says what to do", (await ann.evaluate(`document.querySelector(".wizard-error")?.textContent ?? ""`)).includes("Press Run again"), await panelText(ann));
  check("the question went with the connection", await ann.evaluate(`!${codePrompt}`), await panelText(ann));
  await click(ann, ".wizard-begin");
  await giveCode(ann, secret, "On SQLite the server makes a copy first");
  check("a run goes again", await seen(ann, q(".wizard-stop"), 20_000), await panelText(ann));
  await cut();
  await backInPanel();
  check("a run cut mid-way lands on its end screen", await seen(ann, byText(".wizard-ended", "Stopped:")), await panelText(ann));
  check("saying the connection went", (await ann.evaluate(`document.querySelector(".wizard-ended").textContent`)).includes("Go on takes it up from here"), await panelText(ann));
  await click(ann, ".wizard-go-on");
  check("Go on has its choices, and asks for the tick", await seen(ann, wizardAt("choose")) && (await ann.evaluate(`${row("lounge")}.querySelector(".channel-out").checked && !document.querySelector(".wizard-ack input").checked`)), await panelText(ann));
  check("and no error left over", await ann.evaluate(`!document.querySelector(".wizard-error")`), await panelText(ann));
  // The control: what the person closes goes, on the same page and with no reload
  await serverMenu(ann, "Disconnect");
  await waitFor(ann, `document.querySelector(".connect-btn") || document.querySelector(".skip-link")`, 15_000);
  await logInHere(ann, "annika", secret);
  await openPanel(ann);
  await tabTo(ann, "Discord move");
  check("a Disconnect drops the wizard", await seen(ann, `${q(".wizard-start")} && !${q(".wizard-toggles")}`), await panelText(ann));
  const hard = ann.errors.filter((e) => /state_unsafe|RangeError|TypeError|each_key|ReferenceError|Uncaught/.test(e));
  check("no hard JS errors through the cuts", hard.length === 0, hard.join(" | "));
}

async function closedPanel(tab) {
  await tab.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await sleep(300);
  return tab;
}
async function openSettings(tab) {
  await serverMenu(tab, "Settings").catch(() => {});
  await sleep(300);
  if (!(await tab.evaluate(`!!document.querySelector(".settings-panel, .settings-overlay, .settings")`))) {
    await tab.evaluate(`document.querySelector('[aria-label="Settings"], [title="Settings"]')?.click(); 0`);
  }
  await waitFor(tab, byText("button", "Privacy & data"), 8000);
  await mouse(tab, byText("button", "Privacy & data"), "Privacy & data");
}

try {
  await lane();
  console.log(failures ? `test-move: ${failures} failed` : "test-move: all checks passed");
  await stop(failures ? 1 : 0);
} catch (e) {
  console.log(`FAIL the lane stopped: ${e.stack ?? e}`);
  await stop(1);
}
