#!/usr/bin/env node
// Moderation and safety (1.10), in real browsers against a real relay. One section
// per tool, under the cast below; session_tests.rs has the rules, and what only a
// browser shows is here.
//
// The cast: annika holds `*` (an account with codes, and the token), bobby the
// moderator group with codes, carla the ban list and erin the moderation log and no
// more, dan the one they act on; fay blocks gus, hana is a guest beside them, and bobby
// times ivy out, and hides what she writes, as does mona, who then leaves. bobby bans
// ned, with what he wrote, and summons fay and ivy. carla, fay and ivy report what dan and
// fay wrote. Each comes in with the first section that needs them. A second server, with
// nobody on it, is what hana moves to with a report dialog open.
//
//   VOIPC_SELFTEST=1 npm run web
//   node test-moderation.mjs [port]
//   MODERATION_DATABASE=postgres://... node test-moderation.mjs [port]   # another database
//
// No dependencies. Needs openssl and chromium (CHROME=/path/to/chrome).

import { spawn, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] ?? 49992);
const CHROME = process.env.CHROME ?? "chromium";
const ORIGIN = `https://127.0.0.1:${PORT}`;
const WORK = mkdtempSync(join(tmpdir(), "voipc-moderation-"));
const TOKEN = "e2e-admin-token-0001";
const PASSWORD = "correct-horse-battery-1";
const children = [];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
function check(what, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${what}${!ok && detail ? ` — ${detail}` : ""}`);
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

// ── The relay ─────────────────────────────────────────────────────────────

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
${process.env.MODERATION_DATABASE ? `database = "${process.env.MODERATION_DATABASE}"` : ""}
`,
);
writeFileSync(
  join(WORK, "channels.json"),
  JSON.stringify([
    { name: "lobby-chat", text: true, auto_join: true },
    { name: "side-chat", text: true, auto_join: true },
    { name: "slow-chat", text: true, slow_mode_secs: 60 },
    { name: "quiet-chat", text: true, hide_members: true },
    { name: "masked-room", anonymous: true },
    { name: "locked-room", password: "room-secret" },
    { name: "crew-room" },
  ]),
);
const relay = spawn(
  join(ROOT, "target/release/voipc-server"),
  ["-c", "server.toml", "--admin-token", TOKEN, "--channels", "channels.json"],
  { cwd: WORK, stdio: ["ignore", "ignore", "inherit"] },
);
children.push(relay);
// A second, empty server: to a client two ports on one host are two servers. Its own
// directory, because a server keeps its state next to where it runs.
mkdirSync(join(WORK, "s2"));
children.push(
  spawn(
    join(ROOT, "target/release/voipc-server"),
    ["--host", "127.0.0.1", "--tcp-port", String(PORT + 1), "--udp-port", String(PORT + 1), "--cert", join(WORK, "server.crt"), "--key", join(WORK, "server.key")],
    { cwd: join(WORK, "s2"), stdio: ["ignore", "ignore", "inherit"] },
  ),
);
await sleep(1500);

// ── Browsers, each its own device ─────────────────────────────────────────

async function browser(cdpPort) {
  const c = spawn(
    CHROME,
    ["--headless=new", "--no-sandbox", "--ignore-certificate-errors", `--remote-debugging-port=${cdpPort}`,
     "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required",
     `--user-data-dir=${join(WORK, `profile-${cdpPort}`)}`, "about:blank"],
    { stdio: "ignore" },
  );
  children.push(c);
  for (let i = 0; i < 60; i++) {
    if (await fetch(`http://127.0.0.1:${cdpPort}/json/version`).then((r) => r.ok, () => false)) return cdpPort;
    await sleep(250);
  }
  throw new Error("chromium did not come up");
}

async function newTab(cdpPort) {
  const res = await fetch(`http://127.0.0.1:${cdpPort}/json/new?about:blank`, { method: "PUT" });
  const ws = new WebSocket((await res.json()).webSocketDebuggerUrl);
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
  await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  return { send, evaluate, errors };
}

async function waitFor(tab, expression, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return;
    await sleep(150);
  }
  const text = await tab.evaluate(`document.body?.innerText?.slice(0, 600) ?? ""`).catch(() => "");
  throw new Error(`timed out waiting for ${expression}\n--- page: ${text.replace(/\s+/g, " ")}`);
}

const seen = (tab, expression, timeoutMs = 15_000) =>
  waitFor(tab, expression, timeoutMs).then(() => true, () => false);

const setInput = (selector, value) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false;
    el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`;

const byText = (selector, text) =>
  `[...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.trim().startsWith(${JSON.stringify(text)}))`;

const dialogOf = (kind) => `.account-dialog[data-kind="${kind}"]`;

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

/** The relay's page up. A browser just started on a busy runner can leave its first page blank. */
async function reachDialog(tab) {
  const shown = `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`;
  const before = tab.errors.length;
  await tab.send("Page.navigate", { url: `${ORIGIN}/` });
  if (await waitFor(tab, shown).then(() => true, () => false)) return;
  await tab.send("Page.navigate", { url: `${ORIGIN}/` });
  // The load given up on dies mid-fetch, and says so: that is this lane's doing, not the page's
  tab.errors.splice(before);
  await waitFor(tab, shown, 60_000);
}

/** The connect dialog on the relay's own page, its Account tab open. */
async function openDialog(cdpPort) {
  const tab = await newTab(cdpPort);
  await reachDialog(tab);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(`document.querySelector(".skip-link").click()`);
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await tab.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(tab, `document.querySelector("#account-name")`);
  return tab;
}

/** The connect dialog on the relay's own page, as a guest. */
async function connectGuest(tab, name) {
  await reachDialog(tab);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(`document.querySelector(".skip-link").click()`);
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await tab.evaluate(setInput('input[placeholder="Your name"]', name));
  await tab.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(tab, `document.querySelector(".channel-list")`);
  await settle(tab);
}

/** What a first connect asks after the sign-in: answered. */
async function settle(tab) {
  const end = Date.now() + 40_000;
  while (Date.now() < end) {
    await tab.evaluate(`document.querySelector('${dialogOf("cloud")} .submit-btn')?.click(); 0`);
    await tab.evaluate(`document.querySelector(".audio-setup .skip-link")?.click(); 0`);
    await tab.evaluate(`document.querySelector('.layout-setup .layout-choice[data-layout="modern"]')?.click();
      document.querySelector(".layout-setup .submit-btn")?.click(); 0`);
    const quiet = `!document.querySelector(".connect-btn") && !document.querySelector(".account-dialog")
      && !document.querySelector(".audio-setup") && !document.querySelector(".layout-setup")`;
    if (await tab.evaluate(quiet)) {
      await sleep(800);
      if (await tab.evaluate(quiet)) return;
    }
    await sleep(200);
  }
  const up = await tab.evaluate(`[...document.querySelectorAll(".account-dialog, .connect-btn, .audio-setup, .layout-setup")].map((e) => e.dataset.kind ?? e.className).join(", ")`);
  throw new Error(`the first-connect questions did not end: ${up}\n--- page: ${(await tab.evaluate(`document.body.innerText`)).replace(/\s+/g, " ").slice(0, 600)}`);
}

/** Settings: the switch to share history, which starts off. */
async function turnOnSharing(tab) {
  const box = `[...document.querySelectorAll(".toggle-row")].find((r) => r.textContent.includes("Share recent channel chat"))?.querySelector("input")`;
  await tab.evaluate(`document.querySelector(".settings-btn").click()`);
  await waitFor(tab, byText(".tabs .tab", "Privacy"));
  await tab.evaluate(`${byText(".tabs .tab", "Privacy")}.click()`);
  await waitFor(tab, box);
  if (!(await tab.evaluate(`${box}.checked`))) await tab.evaluate(`${box}.click()`);
  await tab.evaluate(`document.querySelector(".panel .close-btn").click()`);
  await sleep(300);
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

/** The connect dialog again, for an account that exists: a tab sent away by a ban no
 *  longer has the server open, so a reload does not bring it back. `secret`: a code, for
 *  an account whose privileges ask for one. */
async function signIn(tab, name, secret) {
  await reachDialog(tab);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(`document.querySelector(".skip-link").click()`);
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await tab.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(tab, `document.querySelector("#account-name")`);
  await tab.evaluate(setInput("#account-name", name));
  await tab.evaluate(setInput("#account-password", PASSWORD));
  await tab.evaluate(`document.querySelector(".connect-btn").click()`);
  // A code is good once, and the ban's was one step ahead: it asks again until it is past
  let tried = 0;
  for (const end = Date.now() + 90_000; secret && Date.now() < end; await sleep(300)) {
    if (await tab.evaluate(`!document.querySelector(".connect-btn")`)) break;
    const step = Math.floor(Date.now() / 30_000);
    if (step <= tried || !(await tab.evaluate(`!!document.querySelector('${dialogOf("totp")} input')`))) continue;
    tried = step;
    await tab.evaluate(setInput(`${dialogOf("totp")} input`, totpAt(secret, step)));
    await tab.evaluate(`document.querySelector('${dialogOf("totp")} .submit-btn').click()`);
  }
  await waitFor(tab, `document.querySelector(".channel-list")`, 60_000);
  await settle(tab);
}

async function serverMenu(tab, label) {
  await tab.evaluate(`document.querySelector(".server-header .menu") || document.querySelector(".server-header .header-btn").click(); 0`);
  await waitFor(tab, byText(".server-header .menu > button", label));
  await tab.evaluate(`${byText(".server-header .menu > button", label)}.click()`);
}

async function openAccountPanel(tab) {
  await serverMenu(tab, "Your account");
  await waitFor(tab, `document.querySelector('${dialogOf("account")}')`);
}

async function closeAccountPanel(tab) {
  await tab.evaluate(`document.querySelector('${dialogOf("account")} .submit-btn')?.click(); 0`);
}

/** Two-factor codes on, from the account panel. Returns the authenticator's secret. */
async function turnOnCodes(tab) {
  await openAccountPanel(tab);
  await tab.evaluate(`[...document.querySelectorAll('${dialogOf("account")} .secondary')].find((e) => e.textContent.includes("Set up")).click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("totp-setup")} .secret')`);
  const secret = (await tab.evaluate(`document.querySelector('${dialogOf("totp-setup")} .secret').textContent`)).trim();
  await tab.evaluate(setInput("#acct-setup-code", totpAt(secret, Math.floor(Date.now() / 30_000))));
  await tab.evaluate(`document.querySelector('${dialogOf("totp-setup")} .submit-btn').click()`);
  await waitFor(tab, `document.querySelector('${dialogOf("recovery-codes")}')`);
  await tab.evaluate(`document.querySelector('${dialogOf("recovery-codes")} .submit-btn').click()`);
  await sleep(500);
  return secret;
}

/** The panel's step-up for `tab`: a code one step ahead each time, since a code is good once. */
function stepUpWith(tab, secret) {
  let codeStep = Math.floor(Date.now() / 30_000);
  return async () => {
    const asked = await seen(tab, `document.querySelector('.admin-dialog input[aria-label="Two-factor code"]')`, 3_000);
    if (!asked) return;
    codeStep += 1;
    await tab.evaluate(setInput('.admin-dialog input[aria-label="Two-factor code"]', totpAt(secret, codeStep)));
    await tab.evaluate(`${byText(".admin-dialog button", "Confirm")}.click()`);
  };
}

const say = (tab, text) =>
  tab.evaluate(`(() => { const input = document.querySelector(".input-bar .chat-input"); if (!input) return false;
    input.focus(); input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })); return true; })()`);

async function openChat(tab, name) {
  const row = byText(".channel-list.modern .channels.text .channel", name);
  await waitFor(tab, row);
  await tab.evaluate(`${row}.click()`);
  await waitFor(tab, `document.querySelector(".input-bar .chat-input")`);
}

const lastMessage = (text) => `[...document.querySelectorAll(".msg")].reverse().find((m) => m.textContent.includes(${JSON.stringify(text)}))`;

// ── The lane ──────────────────────────────────────────────────────────────

async function lane() {
  const one = await browser(PORT + 100);

  // An admin: an account with codes on, and the token.
  const ann = await openDialog(one);
  await createAccount(ann, "annika");
  const secret = await turnOnCodes(ann);
  await serverMenu(ann, "Admin login");
  await waitFor(ann, `document.querySelector(".admin-dialog .admin-input")`);
  await ann.evaluate(setInput('.admin-dialog input[type="password"]', TOKEN));
  await ann.evaluate(`document.querySelector(".admin-dialog .admin-ok").click()`);
  await sleep(1500);
  await serverMenu(ann, "Server admin");
  await waitFor(ann, `document.querySelector(".admin-tabs")`);

  const tabTo = (name) => ann.evaluate(`${byText(".admin-tabs button", name)}.click()`);
  const groupRow = (name) =>
    `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent.trim().startsWith(${JSON.stringify(name)}))`;
  const ticked = (scope) => `document.querySelector('.admin-dialog input[data-scope="${scope}"]')?.checked`;

  // The privileges: in the group editor, and held by a new server's moderator group.
  await tabTo("Groups");
  await waitFor(ann, groupRow("moderator"));
  await ann.evaluate(`${groupRow("moderator")}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[data-scope="voipc:kick"]')`);
  for (const scope of ["voipc:restrict", "voipc:hide", "voipc:reports", "voipc:modlog", "voipc:kick"]) {
    check(`a new moderator group holds ${scope}`, await ann.evaluate(`!!${ticked(scope)}`));
  }
  check(
    "and not what it never held",
    await ann.evaluate(`${ticked("voipc:bans")} === false`),
    await ann.evaluate(`document.querySelector(".group-form")?.innerText.slice(0, 500) ?? ""`),
  );

  // The moderation log. bobby moderates; carla holds the ban list and not the log;
  // erin the log and nothing else; dan is the one acted on.
  const stepUp = stepUpWith(ann, secret);

  // No group holds Share history until an admin gives it. Here every account gets it, and
  // whoever a section needs to hand something on then turns the switch on.
  check("nor Share history", await ann.evaluate(`${ticked("voipc:share_history")} === false`));
  await ann.evaluate(`${byText(".group-form button", "Cancel")}.click()`);
  await waitFor(ann, groupRow("user"));
  await ann.evaluate(`${groupRow("user")}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[data-scope="voipc:share_history"]')`);
  await ann.evaluate(`document.querySelector('.admin-dialog input[data-scope="voipc:share_history"]').click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  await waitFor(ann, groupRow("user"));
  const two = await browser(PORT + 101);
  const bob = await openDialog(two);
  await createAccount(bob, "bobby");
  const bobSecret = await turnOnCodes(bob);
  await closeAccountPanel(bob);
  const three = await browser(PORT + 102);
  const car = await openDialog(three);
  await createAccount(car, "carla");
  await turnOnCodes(car);
  await closeAccountPanel(car);
  const four = await browser(PORT + 103);
  const eri = await openDialog(four);
  await createAccount(eri, "erin");
  await turnOnCodes(eri);
  await closeAccountPanel(eri);
  const five = await browser(PORT + 104);
  const dan = await openDialog(five);
  await createAccount(dan, "dan");

  const makeGroup = async (name, scope) => {
    await tabTo("Groups");
    await ann.evaluate(`${byText(".group-form button", "Cancel")}?.click(); 0`);
    await waitFor(ann, byText(".admin-dialog button", "New group"));
    await ann.evaluate(`${byText(".admin-dialog button", "New group")}.click()`);
    await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Group name"]')`);
    await ann.evaluate(setInput('.admin-dialog input[aria-label="Group name"]', name));
    await ann.evaluate(`document.querySelector('.admin-dialog input[data-scope="${scope}"]').click()`);
    await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
    await stepUp();
    await waitFor(ann, groupRow(name));
  };
  const giveGroup = async (who, name) => {
    await tabTo("Users");
    await sleep(300);
    await ann.evaluate(`document.querySelector(".admin-dialog .btn-back")?.click(); 0`);
    await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Search accounts"]')`);
    await ann.evaluate(setInput('.admin-dialog input[aria-label="Search accounts"]', who));
    await ann.evaluate(`document.querySelector('.admin-dialog form[role="search"] button[type="submit"]').click()`);
    const row = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent === ${JSON.stringify(who)})`;
    await waitFor(ann, row);
    await ann.evaluate(`${row}.click()`);
    await waitFor(ann, `document.querySelector('.admin-dialog input[data-group="${name}"]')`);
    await ann.evaluate(`document.querySelector('.admin-dialog input[data-group="${name}"]').click()`);
    await stepUp();
    await waitFor(ann, `document.querySelector('.admin-dialog input[data-group="${name}"]')?.checked`);
  };
  await makeGroup("listers", "voipc:bans");
  await makeGroup("readers", "voipc:modlog");
  await giveGroup("carla", "listers");
  await giveGroup("erin", "readers");
  await giveGroup("bobby", "moderator");

  const panelOpens = (tab) =>
    seen(tab, `(document.querySelector(".server-header .menu") || document.querySelector(".server-header .header-btn").click(), ${byText(".server-header .menu > button", "Server admin")})`, 20_000);
  const openPanel = async (tab) => {
    await tab.evaluate(`${byText(".server-header .menu > button", "Server admin")}.click()`);
    await waitFor(tab, `document.querySelector(".admin-dialog")`);
  };
  const logRow = (action) => `document.querySelector('.modlog-row[data-action="${action}"]')`;
  const shownText = (tab) => tab.evaluate(`document.querySelector(".admin-dialog")?.innerText.slice(0, 600) ?? ""`);

  // bobby's kick, from the member list as anyone would do it
  await openChat(bob, "lobby-chat");
  const danRow = `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes("dan"))`;
  await waitFor(bob, danRow);
  await bob.evaluate(`${danRow}.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 }))`);
  await waitFor(bob, byText(".ctx-item", "Kick from server"));
  await bob.evaluate(`${byText(".ctx-item", "Kick from server")}.click()`);
  await waitFor(bob, `document.querySelector(".poke-input")`);
  await bob.evaluate(setInput(".poke-input", "spamming the lobby"));
  await bob.evaluate(`${byText(".poke-send-btn", "Kick")}.click()`);
  check("the kick went through", await seen(bob, `!${danRow}`), await bob.evaluate(`document.querySelector(".user-list.modern")?.innerText ?? ""`));

  // It shows in his log tab, and there is no way to delete it
  check("a moderator's menu opens the panel", await panelOpens(bob));
  await openPanel(bob);
  await waitFor(bob, `document.querySelector(".admin-tabs")`);
  check("a moderator has the Moderation log tab", await seen(bob, byText(".admin-tabs button", "Moderation log")), await shownText(bob));
  await bob.evaluate(`${byText(".admin-tabs button", "Moderation log")}.click()`);
  check("the kick is in the log", await seen(bob, logRow("kick")), await shownText(bob));
  const kickText = await bob.evaluate(`${logRow("kick")}?.innerText ?? ""`);
  check(
    "with who, whom and why",
    ["bobby", "dan", "spamming the lobby"].every((word) => kickText.includes(word)),
    kickText,
  );
  check(
    "and how long it stays, and that a hide is an app's word",
    await bob.evaluate(`document.querySelector(".modlog")?.innerText.includes("180 days") && document.querySelector(".modlog")?.innerText.includes("app's word")`),
    await shownText(bob),
  );
  check(
    "nothing in a row can be pressed",
    await bob.evaluate(`document.querySelectorAll(".modlog-row").length > 0 && document.querySelectorAll(".modlog-row button, .modlog-row a, .modlog-row input").length === 0`),
    await bob.evaluate(`document.querySelector(".modlog")?.innerHTML.slice(0, 500) ?? ""`),
  );
  check(
    "and nothing on the tab deletes",
    await bob.evaluate(`![...document.querySelectorAll(".modlog button")].some((b) => /delete|remove|clear|edit/i.test(b.textContent))`),
    await shownText(bob),
  );

  // annika, who holds everything, reads the same row. The negative control: carla's
  // panel opens, for the ban list, and has no log
  await tabTo("Moderation log");
  check("an admin has it too", await seen(ann, logRow("kick")), await shownText(ann));
  check("carla's menu opens the panel", await panelOpens(car));
  await openPanel(car);
  check("for the ban list", await seen(car, `document.querySelector(".admin-dialog")?.innerText.includes("Active bans")`), await shownText(car));
  check(
    "a holder without voipc:modlog has no tab",
    await car.evaluate(`!${byText(".admin-tabs button", "Moderation log")} && !document.querySelector(".modlog")`),
    await shownText(car),
  );

  // erin holds that one privilege: the panel opens, and on the log, the only tab
  check("the log alone opens the panel", await panelOpens(eri), await eri.evaluate(`document.querySelector(".server-header .menu")?.innerText ?? ""`));
  await openPanel(eri);
  check("on the log", await seen(eri, logRow("kick")), await shownText(eri));


  // ── Blocking ─────────────────────────────────────────────────────────────
  //
  // fay blocks gus. hana is a guest in the same channels, for whom nothing changes
  // until she blocks him too, and gus must never be able to tell.
  const six = await browser(PORT + 105);
  const fay = await openDialog(six);
  await createAccount(fay, "fay");
  const seven = await browser(PORT + 106);
  const gus = await openDialog(seven);
  await createAccount(gus, "gus");
  const eight = await browser(PORT + 107);
  const han = await newTab(eight);
  await connectGuest(han, "hana");
  for (const tab of [fay, gus, han]) {
    await tab.evaluate(`(() => { window.__toasts = [];
      new MutationObserver(() => { for (const e of document.querySelectorAll(".toast-message"))
        if (!window.__toasts.includes(e.textContent)) window.__toasts.push(e.textContent); })
        .observe(document.body, { childList: true, subtree: true, characterData: true }); })()`);
    await openChat(tab, "lobby-chat");
  }
  const toastSaid = (tab, words) => tab.evaluate(`window.__toasts.some((t) => t.includes(${JSON.stringify(words)}))`);
  const memberRow = (name) => `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes(${JSON.stringify(name)}))`;
  const menuItem = (label) => byText(".ctx-item", label);
  const openMenuOn = async (tab, name) => {
    await tab.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);
    await waitFor(tab, memberRow(name));
    await tab.evaluate(`${memberRow(name)}.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 }))`);
    await waitFor(tab, `document.querySelector(".ctx-menu")`);
  };
  const choose = async (tab, name, label) => {
    await openMenuOn(tab, name);
    await waitFor(tab, menuItem(label));
    await tab.evaluate(`${menuItem(label)}.click()`);
  };
  const marked = (name) => `${memberRow(name)}?.querySelector(".blocked-mark")`;
  const folds = `document.querySelectorAll(".msg-folded").length`;
  const unreadOn = (name) => `(() => { const row = ${byText(".channel-list.modern .channels.text .channel", name)}; return row?.querySelector(".channel-unread")?.textContent.trim() ?? (row?.querySelector(".channel-dot") ? "dot" : ""); })()`;
  const dmRow = (name) => `[...document.querySelectorAll(".dm-entry")].find((d) => d.textContent.includes(${JSON.stringify(name)}))`;
  const invited = `document.querySelector(".invite")`;
  const poked = `document.querySelector(".poke")`;
  const pageText = (tab) => tab.evaluate(`document.body.innerText`);
  const says = (tab, words) => tab.evaluate(`document.querySelector(".messages")?.innerText.includes(${JSON.stringify(words)}) ?? false`);

  // Before anything: what gus writes reaches fay as written
  await waitFor(gus, memberRow("fay"));
  await waitFor(fay, memberRow("gus"));
  await waitFor(han, memberRow("gus"));
  await say(gus, "gus says one");
  check("before a block, fay reads gus", await seen(fay, lastMessage("gus says one"), 60_000), await pageText(fay));
  check("and so does hana", await seen(han, lastMessage("gus says one"), 60_000));
  await openMenuOn(fay, "gus");
  check("a person's menu offers Block", await fay.evaluate(`!!${menuItem("Block")}`));
  await fay.evaluate(`${menuItem("Block")}.click()`);

  // fay's screen only
  check("the blocked person is marked", await seen(fay, marked("gus")), await pageText(fay));
  check("nobody else is", await fay.evaluate(`!${marked("hana")}`));
  check("their message folds for fay", await seen(fay, `(${folds}) === 1`));
  check("to one line", (await pageText(fay)).includes("Message from someone you blocked"));
  check("with none of what they wrote", !(await says(fay, "gus says one")), await pageText(fay));
  check("and the toast says they are not told", await seen(fay, `window.__toasts.some((t) => t.includes("They are not told"))`));
  check("hana still reads it", await says(han, "gus says one"));
  check("gus still sees it as sent", await says(gus, "gus says one"));
  check("and gus's page says nothing of it", await gus.evaluate(`!/blocked/i.test(document.body.innerText) && !document.querySelector(".msg-folded")`), await pageText(gus));

  // Show opens that one row; what comes later folds on its own
  await fay.evaluate(`document.querySelector(".folded-show").click()`);
  check("Show opens it", await seen(fay, lastMessage("gus says one")));
  await say(gus, "gus says two");
  check("hana gets the next one", await seen(han, lastMessage("gus says two"), 30_000));
  check("which folds for fay", await seen(fay, `(${folds}) === 1`));
  check("and stays folded", !(await says(fay, "gus says two")));

  // No count from gus in a channel fay is not reading. hana's message is the control
  await openChat(fay, "side-chat");
  await sleep(300);
  await say(gus, "gus says three");
  check("hana gets a third", await seen(han, lastMessage("gus says three"), 30_000));
  await sleep(1500);
  check("a blocked person's message counts for nothing", (await fay.evaluate(unreadOn("lobby-chat"))) === "", await fay.evaluate(unreadOn("lobby-chat")));
  await say(han, "hana says hello");
  // A dot: a channel the server asks everyone to follow counts only what is for you
  check("anyone else's does", await seen(fay, `${unreadOn("lobby-chat")} === "dot"`), await pageText(fay));
  await openChat(fay, "lobby-chat");

  // A direct message: delivered and kept, with no row, no count and no notice for gus
  await choose(gus, "fay", "Direct message");
  await waitFor(gus, `document.querySelector(".input-bar .chat-input")`);
  await sleep(500);
  await say(gus, "gus writes to fay");
  check("gus's message goes out", await seen(gus, lastMessage("gus writes to fay"), 30_000));
  await sleep(3000);
  check("no row for it at fay", await fay.evaluate(`!${dmRow("gus")}`), await fay.evaluate(`document.querySelector(".dm-section")?.innerText ?? ""`));
  check("no undelivered notice at gus", !/Not delivered|left the server/.test(await pageText(gus)), await pageText(gus));
  await choose(han, "fay", "Direct message");
  await waitFor(han, `document.querySelector(".input-bar .chat-input")`);
  await sleep(500);
  await say(han, "hana writes to fay");
  check("the control: hana's gets a row", await seen(fay, dmRow("hana"), 30_000), await pageText(fay));

  // A poke raises nothing. An invite neither, and gus hears no decline. gus's room
  // is voice, so fay stands outside it, in his Online list.
  await choose(gus, "fay", "Poke");
  await waitFor(gus, `document.querySelector(".poke-input")`);
  await gus.evaluate(`document.querySelector(".poke-send-btn").click()`);
  await gus.evaluate(`document.querySelector('button[title="Create channel"]').click()`);
  await waitFor(gus, `document.querySelector(".create-form")`);
  await gus.evaluate(setInput(".create-form input[type=text]", "gus-room"));
  await gus.evaluate(`document.querySelector(".create-form .create-btn").click()`);
  const inRoom = `[...document.querySelectorAll(".channels.voice .channel.active")].some((c) => c.textContent.includes("gus-room"))`;
  await waitFor(gus, inRoom);
  const roomRow = byText(".channel-list.modern .channels.voice .channel", "gus-room");
  await sleep(500);
  await gus.evaluate(`${roomRow}.click()`);
  await choose(gus, "fay", "Invite to Channel");
  await sleep(3000);
  check("a blocked person's poke raises nothing", await fay.evaluate(`!${poked}`));
  check("nor does their invite", await fay.evaluate(`!${invited}`), await pageText(fay));
  check("and gus hears no decline", !(await toastSaid(gus, "declined")), await gus.evaluate(`JSON.stringify(window.__toasts)`));
  check("gus sees no refusal of any kind", await gus.evaluate(`!/could not|refused|blocked/i.test(window.__toasts.join(" "))`), await gus.evaluate(`JSON.stringify(window.__toasts)`));

  // Unblocked, it is all back, and the same invite and poke do what they do. The
  // decline is the control for the silence above: gus would have heard one
  await choose(fay, "gus", "Unblock");
  check("unblocking takes the mark off", await seen(fay, `!${marked("gus")}`));
  check("and brings what they wrote back", await seen(fay, `!document.querySelector(".msg-folded")`));
  check("all of it", (await says(fay, "gus says two")) && (await says(fay, "gus says three")), await pageText(fay));
  check("their conversation is listed again, as it was kept", await seen(fay, dmRow("gus")), await pageText(fay));
  await fay.evaluate(`${dmRow("gus")}.click()`);
  check("with what they wrote in it", await seen(fay, lastMessage("gus writes to fay")), await pageText(fay));
  await fay.evaluate(`document.querySelector(".back-btn")?.click(); 0`);
  await openChat(fay, "lobby-chat");
  await choose(gus, "fay", "Invite to Channel");
  check("their invite raises the popup now", await seen(fay, invited), await pageText(fay));
  await fay.evaluate(`document.querySelector(".invite .decline-btn").click()`);
  check("and a decline does reach gus", await seen(gus, `window.__toasts.some((t) => t.includes("declined"))`), await gus.evaluate(`JSON.stringify(window.__toasts)`));
  await choose(gus, "fay", "Poke");
  await waitFor(gus, `document.querySelector(".poke-input")`);
  await gus.evaluate(`document.querySelector(".poke-send-btn").click()`);
  check("their poke too", await seen(fay, poked), await pageText(fay));
  await fay.evaluate(`document.querySelector(".poke .dismiss-btn").click()`);

  // Blocked again: the list is the account's, so a reload signs back in with it
  await choose(fay, "gus", "Block");
  await seen(fay, marked("gus"));
  await sleep(1000);
  await fay.send("Page.reload");
  await waitFor(fay, `document.querySelector(".channel-list")`, 60_000);
  await settle(fay);
  await openChat(fay, "lobby-chat");
  check("the vault's list comes back with the account", await seen(fay, marked("gus"), 30_000), await pageText(fay));

  // In a call: silenced by volume, again under a new id, and never for hana
  await fay.evaluate(`${roomRow}.click()`);
  await waitFor(fay, `document.querySelector(".join-voice-btn")`);
  await fay.evaluate(`document.querySelector(".join-voice-btn").click()`);
  await waitFor(fay, `(${inRoom}) && ${memberRow("gus")}`);
  const mutedInMenu = async (name) => {
    await openMenuOn(fay, name);
    await waitFor(fay, `document.querySelector(".ctx-mute-btn")`);
    const muted = await fay.evaluate(`document.querySelector(".ctx-mute-btn").classList.contains("muted")`);
    await fay.evaluate(`document.querySelector(".ctx-overlay").click()`);
    return muted;
  };
  check("in a call, somebody blocked is silenced", await mutedInMenu("gus"));
  await gus.send("Page.reload");
  await waitFor(gus, `document.querySelector(".channel-list")`, 60_000);
  await settle(gus);
  await waitFor(gus, roomRow);
  await gus.evaluate(`${roomRow}.click()`);
  await waitFor(gus, `document.querySelector(".join-voice-btn")`);
  await gus.evaluate(`document.querySelector(".join-voice-btn").click()`);
  await sleep(1500);
  await waitFor(fay, memberRow("gus"));
  check("and when they come back under a new id", await mutedInMenu("gus"));

  // Settings lists them, and unblocks from there
  await fay.evaluate(`document.querySelector(".settings-btn").click()`);
  await waitFor(fay, byText(".tabs .tab", "Privacy"));
  await fay.evaluate(`${byText(".tabs .tab", "Privacy")}.click()`);
  const blockedRow = `[...document.querySelectorAll(".blocked-row")].find((r) => r.textContent.includes("gus"))`;
  check("Settings lists who is blocked", await seen(fay, blockedRow), await pageText(fay));
  await fay.evaluate(`${blockedRow}.querySelector("button").click()`);
  check("and takes it back", await seen(fay, `!${blockedRow}`));
  await fay.evaluate(`document.querySelector(".panel .close-btn").click()`);
  check("the mark goes", await seen(fay, `!${marked("gus")}`));
  check("and they are heard again", !(await mutedInMenu("gus")));

  // A guest: on this device, and only here. A reload is a new connection, under the
  // same name, with the same list
  await openChat(han, "lobby-chat");
  await choose(han, "gus", "Block");
  check("a guest blocks too", await seen(han, marked("gus")), await pageText(han));
  check("what he wrote folds for her", await seen(han, `(${folds}) > 0`) && !(await says(han, "gus says one")), await pageText(han));
  check("and the toast says they are not told, here too", await seen(han, `window.__toasts.some((t) => t.includes("They are not told"))`));

  // What he shares of a channel's past is not taken, and he is not told. fay reads
  // gus-notes as he writes there and leaves, so only he holds it (written to nobody it
  // would wait, and go out live to the next to join). A guest has no kept copies: her
  // join asks him, and unblocked the same ask brings it
  await turnOnSharing(gus);
  await gus.evaluate(`document.querySelector('button[title="Create channel"]').click()`);
  await waitFor(gus, `document.querySelector(".create-form")`);
  await gus.evaluate(setInput(".create-form input[type=text]", "gus-notes"));
  await gus.evaluate(`document.querySelector('.create-form input[data-kind="text"]').click()`);
  await sleep(300);
  await gus.evaluate(`document.querySelector(".create-form .create-btn").click()`);
  const notesRow = byText(".channel-list.modern .channels.text .channel", "gus-notes");
  await waitFor(gus, notesRow);
  await gus.evaluate(`${notesRow}.click()`);
  await waitFor(gus, `document.querySelector(".input-bar .chat-input")`);
  await waitFor(fay, notesRow);
  await fay.evaluate(`${notesRow}.click()`);
  await waitFor(fay, `document.querySelector(".join-text-btn")`);
  await fay.evaluate(`document.querySelector(".join-text-btn").click()`);
  await waitFor(fay, `document.querySelector(".input-bar .chat-input")`);
  await sleep(500);
  await say(gus, "only gus holds this");
  await waitFor(fay, lastMessage("only gus holds this"), 30_000);
  await fay.evaluate(`${notesRow}.parentElement.querySelector('.settings-icon[title^="Leave this channel"]').click()`);
  await waitFor(gus, `!${memberRow("fay")}`);
  await waitFor(han, notesRow);
  await han.evaluate(`${notesRow}.click()`);
  await waitFor(han, `document.querySelector(".join-text-btn")`);
  await han.evaluate(`document.querySelector(".join-text-btn").click()`);
  await waitFor(han, `document.querySelector(".input-bar .chat-input")`);
  await sleep(3000);
  const noteRows = `document.querySelectorAll(".msg").length`;
  check("a blocked person's hand-off is not taken", (await han.evaluate(noteRows)) === 0, await pageText(han));
  await choose(han, "gus", "Unblock");
  await seen(han, `!${marked("gus")}`);
  await waitFor(han, `document.querySelector(".resync-btn")`);
  await han.evaluate(`document.querySelector(".resync-btn").click()`);
  check("the control: unblocked, the same ask brings it", await seen(han, lastMessage("only gus holds this"), 30_000), await pageText(han));
  check("as a member's copy", await han.evaluate(`!!document.querySelector(".shared-tag")`), await pageText(han));
  await choose(han, "gus", "Block");
  check("which folds again when he is blocked, by the name it gives", await seen(han, `(${folds}) === 1 && (${noteRows}) === 1`), await pageText(han));

  await sleep(800);
  const kept = await han.evaluate(`JSON.stringify(JSON.parse(localStorage.getItem("voipc.settings") ?? "{}").ui_prefs?.blocked ?? {})`);
  check("in this browser's settings", kept.includes("a:") && kept.includes("gus"), kept);
  await connectGuest(han, "hana");
  await openChat(han, "lobby-chat");
  check("which a new connection reads", await seen(han, marked("gus"), 30_000), await pageText(han));
  check("nobody's page broke", gus.errors.length + fay.errors.length + han.errors.length === 0, [...gus.errors, ...fay.errors, ...han.errors].join(" | ").slice(0, 400));

  // ── Mute and timeouts ────────────────────────────────────────────────────
  //
  // bobby times ivy out; hana, a guest, is there to see what everyone else sees, and
  // the reason is not part of it. What the relay holds is in session_tests.rs: here,
  // what each screen says about it, across a reload and after the lift.
  const nine = await browser(PORT + 108);
  const ivy = await openDialog(nine);
  await createAccount(ivy, "ivy");
  const keepToasts = (tab) => tab.evaluate(`(() => { window.__toasts = [];
    new MutationObserver(() => { for (const e of document.querySelectorAll(".toast-message"))
      if (!window.__toasts.includes(e.textContent)) window.__toasts.push(e.textContent); })
      .observe(document.body, { childList: true, subtree: true, characterData: true }); })()`);
  await keepToasts(ivy);
  await openChat(ivy, "lobby-chat");
  await bob.evaluate(`document.querySelector(".admin-dialog .admin-close").click()`);
  await waitFor(bob, `!document.querySelector(".admin-dialog")`);
  await openChat(bob, "lobby-chat");
  await openChat(han, "lobby-chat");
  const composer = `document.querySelector(".input-bar .chat-input")`;
  // Not openChat, which waits for a compose box: here there may be none
  const openRoom = (tab, name) => tab.evaluate(`${byText(".channel-list.modern .channels.text .channel", name)}.click()`);
  const heldFooter = `document.querySelector(".preview-footer.held-back")`;
  const restrictedMark = (name) => `${memberRow(name)}?.querySelector(".restricted-mark")`;
  const markTitleOf = (tab, name) => tab.evaluate(`${restrictedMark(name)}?.title ?? ""`);

  // The control: nothing marked and everyone writes, and the menu offers no lift yet
  await waitFor(bob, memberRow("ivy"));
  check("before anything, nobody is marked", await bob.evaluate(`!${restrictedMark("ivy")}`));
  check("and ivy can write", await ivy.evaluate(`!!${composer} && !${heldFooter}`));
  await openMenuOn(bob, "ivy");
  check("a moderator's menu offers a mute", await bob.evaluate(`!!${menuItem("Mute voice")}`), await pageText(bob));
  check("and a timeout", await bob.evaluate(`!!${menuItem("Time out")}`));
  check("and nothing to lift yet", await bob.evaluate(`!${menuItem("Lift mute or timeout")}`));
  await bob.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);
  await openMenuOn(han, "ivy");
  check("someone without the privilege is offered neither", await han.evaluate(`!${menuItem("Time out")} && !${menuItem("Mute voice")}`));
  await han.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);

  await choose(bob, "ivy", "Time out");
  await waitFor(bob, `document.querySelector(".restrict-duration")`);
  check("the dialog asks how long", await bob.evaluate(`document.querySelector(".restrict-duration").value === "3600"`));
  await bob.evaluate(setInput(".poke-input", "shouting in the lobby"));
  await bob.evaluate(`${byText(".poke-send-btn", "Time out")}.click()`);

  check("the compose box gives way on ivy's screen", await seen(ivy, heldFooter), await pageText(ivy));
  check("and it is gone", await ivy.evaluate(`!${composer}`));
  const footer = await ivy.evaluate(`${heldFooter}?.textContent ?? ""`);
  check("saying by whom, until when and why", /Timed out by @bobby until (\w+ \d+ )?\d/.test(footer) && footer.includes("shouting in the lobby"), footer);
  check("ivy is told", await seen(ivy, `window.__toasts.some((t) => t.includes("Timed out by @bobby"))`), await ivy.evaluate(`JSON.stringify(window.__toasts)`));
  check("the moderator sees the mark", await seen(bob, restrictedMark("ivy")), await pageText(bob));
  check("ivy sees it on her own row", await seen(ivy, restrictedMark("ivy")));
  check("and so does everyone else", await seen(han, restrictedMark("ivy")));
  check("nobody else is marked", await bob.evaluate(`!${restrictedMark("hana")}`));
  const seenBy = {
    bobby: await markTitleOf(bob, "ivy"),
    ivy: await markTitleOf(ivy, "ivy"),
    hana: await markTitleOf(han, "ivy"),
  };
  check("a moderator reads the reason", seenBy.bobby.includes("shouting in the lobby"), seenBy.bobby);
  check("the person does", seenBy.ivy.includes("shouting in the lobby"), seenBy.ivy);
  check("anyone else sees who and until when", /Timed out by @bobby until (\w+ \d+ )?\d/.test(seenBy.hana), seenBy.hana);
  check("and not why", !seenBy.hana.includes("shouting"), seenBy.hana);
  check("the moderator's compose box stays", await bob.evaluate(`!!${composer} && !${heldFooter}`));
  check("and hana's", await han.evaluate(`!!${composer} && !${heldFooter}`));

  // A direct message stays open, so a timed-out member can still appeal
  await choose(ivy, "bobby", "Direct message");
  check("a timeout leaves direct messages open", await seen(ivy, composer), await pageText(ivy));
  check("with no footer there", await ivy.evaluate(`!${heldFooter}`));
  await say(ivy, "may I speak again?");
  check("and bobby gets it", await seen(bob, dmRow("ivy"), 30_000), await pageText(bob));
  // Deleting from the server's copy ends with a message to the others' devices, so it
  // waits with everything else she cannot write. Here she can, and it is on offer
  const clearMenu = `document.querySelector(".clear-menu")`;
  const purgeItem = `[...document.querySelectorAll(".clear-menu .ttl-choice")].find((b) => b.textContent.includes("delete what I wrote"))`;
  const openClearMenu = async (tab) => {
    await waitFor(tab, `document.querySelector('.clear-chat-btn[aria-label="Clear chat history"]')`);
    await tab.evaluate(`document.querySelector('.clear-chat-btn[aria-label="Clear chat history"]').click()`);
    await waitFor(tab, clearMenu);
  };
  const shutClearMenu = async (tab) => {
    await tab.evaluate(`document.body.click(); 0`);
    await waitFor(tab, `!${clearMenu}`);
  };
  await openClearMenu(ivy);
  check("where she can write, the bin offers to delete what she wrote", await ivy.evaluate(`!!${purgeItem} && !document.querySelector(".clear-held")`), await pageText(ivy));
  await shutClearMenu(ivy);
  await ivy.evaluate(`document.querySelector(".back-btn")?.click(); 0`);
  await openRoom(ivy, "lobby-chat");
  check("back in the channel, held again", await seen(ivy, heldFooter), await pageText(ivy));
  // The bin is there only with something to clear, and nothing above promises her a row here
  await say(bob, "something for the bin");
  await waitFor(ivy, `[...document.querySelectorAll(".msg")].some((m) => m.textContent.includes("something for the bin"))`, 60_000);
  await openClearMenu(ivy);
  check("where she cannot, it does not", await ivy.evaluate(`!${purgeItem}`), await pageText(ivy));
  check("and says why", await ivy.evaluate(`document.querySelector(".clear-held")?.textContent.includes("until you can write here again")`), await pageText(ivy));
  check("clearing her own screen stays", await ivy.evaluate(`[...document.querySelectorAll(".clear-menu .ttl-choice")].some((b) => b.textContent.trim() === "Clear here")`));
  await shutClearMenu(ivy);

  // A reload is a new connection and a new id, and both screens keep it
  await ivy.send("Page.reload");
  await waitFor(ivy, `document.querySelector(".channel-list")`, 60_000);
  await settle(ivy);
  await keepToasts(ivy);
  await waitFor(ivy, byText(".channel-list.modern .channels.text .channel", "lobby-chat"));
  await openRoom(ivy, "lobby-chat");
  check("a reload keeps the compose box away", await seen(ivy, heldFooter, 30_000), await pageText(ivy));
  check("with the reason, for her", (await ivy.evaluate(`${heldFooter}?.textContent ?? ""`)).includes("shouting in the lobby"));
  check("and her mark", await seen(ivy, restrictedMark("ivy"), 30_000), await pageText(ivy));
  await waitFor(bob, memberRow("ivy"));
  check("under her new id, the moderator's screen keeps it", await seen(bob, restrictedMark("ivy"), 30_000), await pageText(bob));
  check("and hana's", await seen(han, restrictedMark("ivy"), 30_000));
  check("still without the reason", !(await markTitleOf(han, "ivy")).includes("shouting"));

  await openMenuOn(bob, "ivy");
  check("now there is something to lift", await seen(bob, menuItem("Lift mute or timeout")), await pageText(bob));
  await bob.evaluate(`${menuItem("Lift mute or timeout")}.click()`);
  check("a lift brings ivy's compose box back", await seen(ivy, composer), await pageText(ivy));
  check("without the footer", await seen(ivy, `!${heldFooter}`));
  check("she is told", await seen(ivy, `window.__toasts.some((t) => t.includes("again"))`), await ivy.evaluate(`JSON.stringify(window.__toasts)`));
  check("the mark goes on the moderator's screen", await seen(bob, `!${restrictedMark("ivy")}`));
  check("on hers", await seen(ivy, `!${restrictedMark("ivy")}`));
  check("and on everyone else's", await seen(han, `!${restrictedMark("ivy")}`));
  await openClearMenu(ivy);
  check("after the lift the bin offers it again", await ivy.evaluate(`!!${purgeItem}`), await pageText(ivy));
  await shutClearMenu(ivy);
  await say(ivy, "ivy is back");
  check("and what she writes arrives", await seen(bob, lastMessage("ivy is back"), 60_000), await pageText(bob));

  // A mute leaves her writing: the same relay, the other flag
  await choose(bob, "ivy", "Mute voice");
  await waitFor(bob, `document.querySelector(".restrict-duration")`);
  await bob.evaluate(`${byText(".poke-send-btn", "Mute")}.click()`);
  check("a mute marks her", await seen(ivy, restrictedMark("ivy")), await pageText(ivy));
  check("and leaves the compose box", await ivy.evaluate(`!!${composer} && !${heldFooter}`));
  check("saying so in the mark", /^Muted by @bobby/.test(await markTitleOf(han, "ivy")), await markTitleOf(han, "ivy"));
  await choose(bob, "ivy", "Lift mute or timeout");
  check("and lifts the same way", await seen(ivy, `!${restrictedMark("ivy")}`));

  // Both are in the log, which names no expiry and no wait
  await panelOpens(bob);
  await openPanel(bob);
  await waitFor(bob, byText(".admin-tabs button", "Moderation log"));
  await bob.evaluate(`${byText(".admin-tabs button", "Moderation log")}.click()`);
  check("the log has the timeout", await seen(bob, logRow("restrict")), await shownText(bob));
  const logged = await bob.evaluate(`${logRow("restrict")}?.innerText ?? ""`);
  check("in words, with who, whom and how long", ["bobby", "restricted", "ivy", "voice"].every((w) => logged.includes(w)), logged);
  const timedOut = await bob.evaluate(`[...document.querySelectorAll('.modlog-row[data-action="restrict"]')].map((r) => r.innerText).join(" | ")`);
  check("the reason and the length of the timeout", timedOut.includes("shouting in the lobby") && timedOut.includes("1 hour"), timedOut);
  check("and the lift", await seen(bob, logRow("unrestrict")), await shownText(bob));
  check("nobody's page broke on the way", ivy.errors.length === 0, ivy.errors.join(" | ").slice(0, 400));

  // ── Hiding messages ──────────────────────────────────────────────────────
  //
  // bobby hides what ivy wrote. fay has an account, so a reload reads it all back from
  // the stored log, the hide among it; hana is a guest and has only what happens while
  // she is here, and what members hand her. Who may and who is spared are in
  // chat-rules.test.ts and stores/hide.test.ts: here, what each screen shows of it.
  const ten = await browser(PORT + 109);
  const mon = await openDialog(ten);
  await createAccount(mon, "mona");
  await turnOnCodes(mon);
  await closeAccountPanel(mon);
  await giveGroup("mona", "moderator");
  for (const tab of [ann, bob]) await tab.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  for (const tab of [ann, bob, fay, han, ivy, mon]) await openChat(tab, "lobby-chat");
  await keepToasts(bob);

  // A fellow moderator shows on the roster as changing channels, and what bobby may do to
  // her is the relay's to say, so the menu offers it. On an admin it does not
  await openMenuOn(bob, "mona");
  check("the menu offers a mute on a fellow moderator", await seen(bob, menuItem("Mute voice")), await pageText(bob));
  check("and a timeout", await bob.evaluate(`!!${menuItem("Time out")}`));
  check("set off by a separator", await bob.evaluate(`${menuItem("Mute voice")}.previousElementSibling.classList.contains("ctx-separator")`));
  check("and still no kick", await bob.evaluate(`!${menuItem("Kick from server")}`));
  await choose(bob, "mona", "Time out");
  await waitFor(bob, `document.querySelector(".restrict-duration")`);
  await bob.evaluate(`${byText(".poke-send-btn", "Time out")}.click()`);
  check("the relay takes it: she holds no more than he does", await seen(mon, heldFooter), await pageText(mon));
  await choose(bob, "mona", "Lift mute or timeout");
  check("and the lift, from the same menu", await seen(mon, `!${heldFooter}`), await pageText(mon));
  await openMenuOn(bob, "annika");
  check("the control: an admin is offered none of it", await bob.evaluate(`!${menuItem("Mute voice")} && !${menuItem("Time out")}`), await pageText(bob));
  await bob.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);

  const reloaded = async (tab) => {
    await tab.send("Page.reload");
    await waitFor(tab, `document.querySelector(".channel-list")`, 60_000);
    await settle(tab);
    await openChat(tab, "lobby-chat");
  };
  const removedBy = (name) => byText(".folded-line", `Removed by ${name}`);
  // The row itself, not one that quotes it
  const rowWith = (words) => `[...document.querySelectorAll(".msg")].find((m) => m.querySelector(".msg-content")?.textContent.includes(${JSON.stringify(words)}))`;
  const removals = `[...document.querySelectorAll(".folded-line")].filter((e) => e.textContent.startsWith("Removed by")).length`;
  const offered = (label) => `[...document.querySelectorAll(".msg-menu button")].find((b) => b.textContent.trim() === ${JSON.stringify(label)})`;
  const shutMenu = (tab) => tab.evaluate(`window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true })); 0`);
  const messageMenu = async (tab, words) => {
    await shutMenu(tab);
    await waitFor(tab, rowWith(words), 60_000);
    await tab.evaluate(`${rowWith(words)}.querySelector('button[title="More"]').click()`);
    await waitFor(tab, `document.querySelector(".msg-menu")`);
  };
  const offeredOn = async (tab, words, label) => {
    await messageMenu(tab, words);
    const there = await tab.evaluate(`!!${offered(label)}`);
    await shutMenu(tab);
    return there;
  };
  const joinRoom = async (tab, name) => {
    const row = byText(".channel-list.modern .channels.text .channel", name);
    await waitFor(tab, row);
    await tab.evaluate(`${row}.click()`);
    await waitFor(tab, `document.querySelector(".join-text-btn")`);
    await tab.evaluate(`document.querySelector(".join-text-btn").click()`);
    await waitFor(tab, composer);
  };

  await say(ivy, "cheap pills here");
  for (const [who, tab] of [["bobby", bob], ["fay", fay], ["hana", han]]) {
    check(`before anything, ${who} reads it`, await seen(tab, rowWith("cheap pills"), 60_000), await pageText(tab));
  }
  // An answer quotes it, for now
  await fay.evaluate(`${rowWith("cheap pills")}.querySelector('button[title="Reply"]').click()`);
  await say(fay, "who asked for these");
  const quoted = `${lastMessage("who asked for these")}?.querySelector(".quote-text")?.textContent`;
  check("the control: a quote reads what it answers", await seen(han, `${quoted}?.includes("cheap pills")`, 60_000), await pageText(han));
  check("a guest is offered no Hide", !(await offeredOn(han, "cheap pills", "Hide")));
  check("a plain member neither", !(await offeredOn(fay, "cheap pills", "Hide")));
  check("nor who wrote it", !(await offeredOn(ivy, "cheap pills", "Hide")));
  await messageMenu(bob, "cheap pills");
  check("a moderator is, in those words where it will be kept", await bob.evaluate(`!!${offered("Hide")}`), await bob.evaluate(`document.querySelector(".msg-menu").innerText`));
  await bob.evaluate(`${offered("Hide")}.click()`);

  check("it collapses for a member", await seen(fay, removedBy("bobby")), await pageText(fay));
  check("for a guest, live", await seen(han, removedBy("bobby")), await pageText(han));
  check("for who wrote it", await seen(ivy, removedBy("bobby")), await pageText(ivy));
  check("and for the moderator", await seen(bob, removedBy("bobby")), await pageText(bob));
  check("with nothing of it left on screen", !(await says(fay, "cheap pills")), await pageText(fay));
  check("the quote says the same as the row", await seen(han, `${quoted}?.includes("Removed by bobby")`), await pageText(han));
  check("and names nobody", await han.evaluate(`!${lastMessage("who asked for these")}?.querySelector(".quote-name")`));
  check("and one Show anyway", await fay.evaluate(`!!${byText(".folded-show", "Show anyway")}`));
  check("only a holder may take it back", await seen(bob, `document.querySelector(".folded-restore")`) && (await fay.evaluate(`!document.querySelector(".folded-restore")`)));

  await say(fay, "fay says something fine");
  await waitFor(ivy, lastMessage("something fine"), 60_000);
  await messageMenu(fay, "something fine");
  check("a message anyone may forward", await fay.evaluate(`!!${offered("Forward")}`));
  check("and copy", await fay.evaluate(`!!${offered("Copy text")}`));
  await shutMenu(fay);
  await fay.evaluate(`${byText(".folded-show", "Show anyway")}.click()`);
  check("Show anyway brings it back", await seen(fay, rowWith("cheap pills")), await pageText(fay));
  check("still saying what was done", await fay.evaluate(`${rowWith("cheap pills")}?.querySelector(".hidden-tag")?.textContent.includes("Removed by bobby")`));
  await messageMenu(fay, "cheap pills");
  check("and goes no further from here: no Forward", await fay.evaluate(`!${offered("Forward")}`));
  check("no Copy text", await fay.evaluate(`!${offered("Copy text")}`));
  await shutMenu(fay);
  check("nobody else's screen changed", await han.evaluate(`(${removals}) === 1 && !${rowWith("cheap pills")}`), await pageText(han));

  // A plain member's hide is an event like any other, and asks for nothing the relay
  // could refuse. So her app is made to send one in place of a reaction, and the same
  // trick from bobby shows it does what it should go on to prove
  const sendsHide = async (tab, words) => {
    await tab.evaluate(`(() => { const real = JSON.stringify; window.__stringify = real;
      JSON.stringify = (v, ...rest) => real(v && v.kind === "react" ? { kind: "hide", target: v.target, on: true } : v, ...rest); })()`);
    await tab.evaluate(`${lastMessage(words)}.querySelector('button[title="React"]').click()`);
    await waitFor(tab, `document.querySelector(".react-item")`);
    await tab.evaluate(`document.querySelector(".react-item").click()`);
    await sleep(300);
    await tab.evaluate(`JSON.stringify = window.__stringify; 0`);
  };
  await sendsHide(ivy, "something fine");
  // Written after it, on the same line: whoever reads this has read that
  await say(ivy, "ivy after the forged hide");
  for (const [who, tab] of [["fay", fay], ["bobby", bob], ["hana", han]]) {
    await waitFor(tab, lastMessage("ivy after the forged hide"), 60_000);
    check(`a plain member's hide does nothing for ${who}`, await tab.evaluate(`!!${lastMessage("something fine")}`), await pageText(tab));
  }
  check("no line for it either", await bob.evaluate(`(${removals}) === 1`), await pageText(bob));

  // The stored log: the Show anyway is gone with the page, and the hide is not
  await reloaded(fay);
  check("a reload reads it back hidden", await seen(fay, removedBy("bobby"), 30_000), await pageText(fay));
  check("not as it was written", !(await says(fay, "cheap pills")), await pageText(fay));
  check("the plain member's stored hide still does nothing", await seen(fay, lastMessage("something fine"), 30_000), await pageText(fay));
  check("and what she wrote after it reads", await seen(fay, lastMessage("ivy after the forged hide"), 30_000), await pageText(fay));

  // A hide stands when its moderator has gone: the list is by account. mona hides one
  // thing and leaves, not to return in this run
  await say(ivy, "mona takes this down");
  await waitFor(mon, lastMessage("mona takes this down"), 60_000);
  await messageMenu(mon, "mona takes this down");
  await mon.evaluate(`${offered("Hide")}.click()`);
  check("another moderator's hide reads as theirs", await seen(fay, removedBy("mona")), await pageText(fay));
  await mon.send("Page.navigate", { url: "about:blank" });
  check("mona has left", await seen(fay, `!${memberRow("mona")}`, 30_000), await pageText(fay));
  await reloaded(fay);
  check("a moderator's stored hide counts with them away", await seen(fay, removedBy("mona"), 30_000), await pageText(fay));
  check("and the rest is back around it", await seen(fay, lastMessage("something fine"), 30_000) && !(await says(fay, "mona takes this down")), await pageText(fay));

  // The control: the same trick from a moderator hides
  await say(fay, "fay says something else");
  await waitFor(bob, lastMessage("something else"), 60_000);
  await sendsHide(bob, "something else");
  check("the forged event does hide, from a holder", await seen(fay, `(${removals}) === 3`), await pageText(fay));

  // Newest first: Restore takes them back one at a time
  const restoreLast = (tab) => tab.evaluate(`[...document.querySelectorAll(".folded-restore")].at(-1).click()`);
  await seen(ann, `(${removals}) === 3`);
  await restoreLast(ann);
  check("Restore brings it back for everyone", await seen(fay, lastMessage("something else")), await pageText(fay));
  // bobby's own screen never had that one as a hide: it went out as a reaction, here
  await restoreLast(bob);
  check("one moderator takes back another's", await seen(fay, lastMessage("mona takes this down")), await pageText(fay));
  await seen(bob, `(${removals}) === 1`);
  await restoreLast(bob);
  check("the first too", await seen(fay, rowWith("cheap pills")), await pageText(fay));
  check("for hana as well", await seen(han, rowWith("cheap pills")), await pageText(han));
  check("with no line left", await seen(fay, `(${removals}) === 0`) && (await han.evaluate(`!${rowWith("cheap pills")}?.querySelector(".hidden-tag")`)));
  await reloaded(fay);
  check("and a reload keeps it restored: the latest wins", await seen(fay, rowWith("cheap pills"), 30_000), await pageText(fay));
  check("in the stored log too", await fay.evaluate(`(${removals}) === 0`), await pageText(fay));

  // bobby's app told the log, in his own word
  await panelOpens(bob);
  await openPanel(bob);
  await waitFor(bob, byText(".admin-tabs button", "Moderation log"));
  await bob.evaluate(`${byText(".admin-tabs button", "Moderation log")}.click()`);
  check("the hide is in the log", await seen(bob, logRow("hide")), await shownText(bob));
  const hideRows = await bob.evaluate(`[...document.querySelectorAll('.modlog-row[data-action="hide"]')].map((r) => r.innerText)`);
  check("with who, whose and where", hideRows.some((r) => ["bobby", "ivy", "lobby-chat"].every((w) => r.includes(w))), hideRows.join(" | "));
  check("the restore too", await seen(bob, logRow("unhide")), await shownText(bob));
  await bob.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await waitFor(bob, `!document.querySelector(".admin-dialog")`);

  // A moderator acts on nobody who holds a privilege; annika alone does
  await say(ann, "annika says hello");
  check("a moderator is offered no Hide on an admin's message", !(await offeredOn(bob, "annika says hello", "Hide")));
  await say(bob, "bobby says hello");
  await messageMenu(ann, "bobby says hello");
  check("an admin is, on a moderator's", await ann.evaluate(`!!${offered("Hide")}`));
  await ann.evaluate(`${offered("Hide")}.click()`);
  check("which counts for everyone", await seen(fay, removedBy("annika")), await pageText(fay));
  await restoreLast(ann);
  check("and an admin takes it back", await seen(fay, lastMessage("bobby says hello")), await pageText(fay));

  // What a member hands a newcomer leaves out what was hidden: hana has no stored log,
  // so all she gets is what ivy and bobby answer with
  await turnOnSharing(ivy);
  await turnOnSharing(bob);
  await ivy.evaluate(`document.querySelector('button[title="Create channel"]').click()`);
  await waitFor(ivy, `document.querySelector(".create-form")`);
  await ivy.evaluate(setInput(".create-form input[type=text]", "ivy-notes"));
  await ivy.evaluate(`document.querySelector('.create-form input[data-kind="text"]').click()`);
  await sleep(300);
  await ivy.evaluate(`document.querySelector(".create-form .create-btn").click()`);
  const ivyNotes = byText(".channel-list.modern .channels.text .channel", "ivy-notes");
  await waitFor(ivy, ivyNotes);
  await ivy.evaluate(`${ivyNotes}.click()`);
  await waitFor(ivy, composer);
  await joinRoom(bob, "ivy-notes");
  await sleep(500);
  await say(ivy, "hand me on");
  await waitFor(bob, lastMessage("hand me on"), 60_000);
  await say(ivy, "take me down");
  await messageMenu(bob, "take me down");
  // A channel made in the app keeps no messages: only those here hear of it
  await bob.evaluate(`${offered("Hide for those online")}.click()`);
  await waitFor(ivy, removedBy("bobby"));
  await joinRoom(han, "ivy-notes");
  await waitFor(han, `document.querySelector(".resync-btn")`);
  await sleep(3000);
  await han.evaluate(`document.querySelector(".resync-btn").click()`);
  check("a newcomer is handed what is around it", await seen(han, lastMessage("hand me on"), 30_000), await pageText(han));
  check("as a member's copy", await han.evaluate(`!!${lastMessage("hand me on")}?.querySelector(".shared-tag")`));
  check("which cannot be reported: who wrote it is the member's word", !(await offeredOn(han, "hand me on", "Report")));
  check("and not what was hidden, in any form", !(await says(han, "take me down")) && (await han.evaluate(`(${removals}) === 0`)), await pageText(han));

  // A channel keeping no messages: the hide reaches only who is here, and says so
  for (const tab of [bob, ivy, han]) await joinRoom(tab, "quiet-chat");
  await sleep(500);
  await say(ivy, "quiet words");
  await messageMenu(bob, "quiet words");
  check("the action says it reaches only those online", await bob.evaluate(`!!${offered("Hide for those online")}`), await bob.evaluate(`document.querySelector(".msg-menu").innerText`));
  await bob.evaluate(`${offered("Hide for those online")}.click()`);
  check("and so does the moderator's toast", await seen(bob, `window.__toasts.some((t) => t.includes("only for people online"))`), await bob.evaluate(`JSON.stringify(window.__toasts)`));
  check("it still reaches who is here", await seen(han, removedBy("bobby"), 30_000), await pageText(han));

  // Slow mode does not hold back a moderator, whose hide is a post
  const held = `document.querySelector('.input-bar .send-btn[title^="Slow mode"]')`;
  for (const tab of [bob, ivy]) await joinRoom(tab, "slow-chat");
  await sleep(500);
  await say(ivy, "slow from ivy");
  check("the control: a member's post starts the wait", await seen(ivy, held), await pageText(ivy));
  await say(bob, "slow one from bobby");
  await say(bob, "slow two from bobby");
  check("a moderator's two posts both arrive", await seen(ivy, lastMessage("slow two from bobby"), 30_000) && (await ivy.evaluate(`!!${lastMessage("slow one from bobby")}`)), await pageText(ivy));
  check("with no wait on his side", await bob.evaluate(`!${held}`));
  await messageMenu(bob, "slow from ivy");
  check("and his Hide stays on offer", await bob.evaluate(`!!${offered("Hide")}`));
  await shutMenu(bob);
  await messageMenu(ivy, "slow one from bobby");
  check("a member still waiting is offered no such thing", await ivy.evaluate(`!${offered("Hide")}`));
  await shutMenu(ivy);

  // An anonymous room: a hide would unmask the moderator, so there is none
  const maskedRoom = byText(".channel-list.modern .channels.voice .channel", "masked-room");
  for (const tab of [bob, ivy]) {
    await waitFor(tab, maskedRoom);
    await tab.evaluate(`${maskedRoom}.click()`);
    await waitFor(tab, `document.querySelector(".join-voice-btn")`);
    await tab.evaluate(`document.querySelector(".join-voice-btn").click()`);
    await waitFor(tab, composer);
  }
  await sleep(500);
  await say(ivy, "masked words");
  await messageMenu(bob, "masked words");
  check("in an anonymous room the menu opens", await bob.evaluate(`!!${offered("Copy text")}`), await bob.evaluate(`document.querySelector(".msg-menu").innerText`));
  check("with no Hide", await bob.evaluate(`!${offered("Hide")} && !${offered("Hide for those online")}`));
  await shutMenu(bob);
  for (const tab of [bob, ivy]) await tab.evaluate(`document.querySelector(".voice-panel .leave-btn")?.click(); 0`);
  check("nobody's page broke on the way", [ann, bob, fay, han, ivy].every((t) => t.errors.length === 0), [ann, bob, fay, han, ivy].flatMap((t) => t.errors).join(" | ").slice(0, 400));

  // ── Banning with removal ─────────────────────────────────────────────────
  //
  // bobby bans ned and removes what he wrote. Everyone in this lane comes from one
  // address, and an address ban ends every session there holding no privilege, so it is
  // carla, holding the ban list, who reads it happen. The others are turned away until
  // annika lifts that ban below, and then reload. What the relay does and keeps is in
  // session_tests.rs, each way a copy arrives in stores/posts-hidden.test.ts.
  const eleven = await browser(PORT + 110);
  const ned = await openDialog(eleven);
  await createAccount(ned, "ned");
  await car.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await waitFor(car, `!document.querySelector(".admin-dialog")`);
  for (const tab of [bob, car, ned, ivy]) await openChat(tab, "lobby-chat");
  for (const tab of [ann, bob, car]) await keepToasts(tab);
  const stored = (tab, words) => seen(tab, rowWith(words), 30_000);

  // What he writes to carla directly is hers too, and stays
  await choose(ned, "carla", "Direct message");
  await waitFor(ned, composer);
  await sleep(500);
  await say(ned, "ned writes to carla directly");
  check("a direct message reaches her", await seen(car, dmRow("ned"), 30_000), await pageText(car));
  await openChat(ned, "lobby-chat");
  await say(ned, "ned sells pills here");
  await waitFor(ivy, rowWith("ned sells pills"), 60_000);
  await say(ivy, "ivy answers ned");
  await waitFor(car, rowWith("ivy answers ned"), 60_000);

  // The control: a reload reads both back from the stored log, so that their being
  // gone below is the removal
  await sleep(1500);
  await reloaded(car);
  check("before anything, a reload reads what he wrote", await stored(car, "ned sells pills"), await pageText(car));
  check("and what was answered", await stored(car, "ivy answers ned"), await pageText(car));
  await keepToasts(car);

  // The dialog, as a moderator and as an admin
  const pickIn = (tab, selector, label) =>
    tab.evaluate(`(() => { const s = document.querySelector(${JSON.stringify(selector)});
      s.selectedIndex = [...s.options].findIndex((o) => o.textContent.trim() === ${JSON.stringify(label)});
      s.dispatchEvent(new Event("change", { bubbles: true })); })()`);
  const optionIn = (selector, label) => `[...document.querySelectorAll(${JSON.stringify(`${selector} option`)})].some((o) => o.textContent.trim() === ${JSON.stringify(label)})`;
  const accountBox = `document.querySelector(".poke-dialog .admin-check input[type=checkbox]")`;
  await openChat(ann, "lobby-chat");
  await choose(ann, "ned", "Ban 1 hour");
  await waitFor(ann, `document.querySelector(".remove-posts")`);
  check("an admin may remove everything kept", await ann.evaluate(optionIn(".remove-posts", "Everything kept")));
  await ann.evaluate(`document.querySelector(".poke-cancel-btn").click()`);
  await waitFor(ann, `!document.querySelector(".remove-posts")`);
  await choose(bob, "ned", "Ban 1 hour");
  await waitFor(bob, `document.querySelector(".remove-posts")`);
  check("a moderator goes back seven days at most", await bob.evaluate(`${optionIn(".remove-posts", "Last 7 days")} && !${optionIn(".remove-posts", "Everything kept")}`), await pageText(bob));
  check("by default it removes nothing and says nothing of it", await bob.evaluate(`document.querySelector(".remove-posts").selectedIndex === 0 && !document.querySelector(".remove-posts-hint") && !${accountBox}.disabled`));
  await bob.evaluate(`${accountBox}.click()`);
  await pickIn(bob, ".remove-posts", "Last 24 hours");
  check("choosing to bans the account as well, whatever was unticked", await seen(bob, `${accountBox}.checked && ${accountBox}.disabled`), await pageText(bob));
  check("and says what it does and does not do", await bob.evaluate(`["not direct messages", "copies on people's devices", "does not undo"].every((w) => document.querySelector(".remove-posts-hint")?.textContent.includes(w))`), await pageText(bob));
  await bob.evaluate(setInput(".poke-input", "selling pills"));
  const beforeBan = Date.now();
  await bob.evaluate(`${byText(".poke-send-btn", "Ban")}.click()`);

  // A code, asked for here: bobby's panel is shut, and he may have none to open
  const stepDialog = `document.querySelector(".step-up-dialog")`;
  const banLine = byText(".folded-line", "This server says bobby removed this with a ban");
  const banRow = `${banLine}?.closest(".msg")`;
  check("the menu has its own prompt for a code", await seen(bob, stepDialog), await pageText(bob));
  check("with the panel shut", await bob.evaluate(`!document.querySelector(".admin-dialog")`));
  check("the ban is already made", await seen(car, `!${memberRow("ned")}`), await pageText(car));
  check("and nothing is hidden yet", await car.evaluate(`!!${rowWith("ned sells pills")} && !${banLine}`), await pageText(car));
  const toasts = await bob.evaluate(`window.__toasts.length`);
  await bob.evaluate(setInput(".step-up-dialog input", "000000"));
  await bob.evaluate(`document.querySelector('.step-up-dialog button[type="submit"]').click()`);
  check("a wrong code is told", await seen(bob, `window.__toasts.length > ${toasts}`), await pageText(bob));
  check("and asked for again, there being no other place to", await seen(bob, stepDialog), await pageText(bob));
  check("having hidden nothing", await car.evaluate(`!${banLine}`));
  await bob.evaluate(setInput(".step-up-dialog input", totpAt(bobSecret, Math.floor(Date.now() / 30_000) + 1)));
  await bob.evaluate(`document.querySelector('.step-up-dialog button[type="submit"]').click()`);

  check("a second browser sees the line", await seen(car, banLine), await pageText(car));
  check("so does the moderator", await seen(bob, banLine), await pageText(bob));
  check("the prompt has gone", await seen(bob, `!${stepDialog}`));
  check("with what he wrote off the screen", !(await says(car, "ned sells pills")), await pageText(car));
  check("and what others wrote still on it", await car.evaluate(`!!${rowWith("ivy answers ned")}`), await pageText(car));
  check("and Show anyway", await car.evaluate(`${banRow}?.querySelector(".folded-show")?.textContent === "Show anyway"`), await pageText(car));
  check("and no Restore, even for a moderator: it is not his to take back", await bob.evaluate(`!!${banRow} && !${banRow}.querySelector(".folded-restore")`), await pageText(bob));
  check("he is told what it came to", await seen(bob, `window.__toasts.some((t) => t.includes("1 kept message deleted") && t.includes("hidden, not erased"))`), await bob.evaluate(`window.__toasts.join(" | ")`));
  check("ned has been told why", await seen(ned, `document.body.innerText.includes("selling pills")`), await pageText(ned));

  await car.evaluate(`${banRow}.querySelector(".folded-show").click()`);
  check("Show anyway brings it back", await seen(car, rowWith("ned sells pills")), await pageText(car));
  check("still saying whose word it is", await car.evaluate(`${rowWith("ned sells pills")}?.querySelector(".hidden-tag")?.textContent.includes("This server says bobby")`), await pageText(car));

  // The stored log has none of it now, and no one hands it on
  await reloaded(car);
  check("after a reload the rest is read back", await stored(car, "ivy answers ned"), await pageText(car));
  await sleep(1500);
  check("and the rows do not return", !(await says(car, "ned sells pills")), await pageText(car));
  check("not even as a line", await car.evaluate(`!${banLine}`), await pageText(car));
  await waitFor(car, dmRow("ned"), 30_000);
  await car.evaluate(`${dmRow("ned")}.click()`);
  check("his direct message is still hers to read", await seen(car, lastMessage("ned writes to carla directly"), 30_000), await pageText(car));
  check("as he wrote it", await car.evaluate(`!document.querySelector(".msg-folded")`), await pageText(car));
  await openChat(car, "lobby-chat");

  // The log
  await panelOpens(bob);
  await openPanel(bob);
  await waitFor(bob, byText(".admin-tabs button", "Moderation log"));
  await bob.evaluate(`${byText(".admin-tabs button", "Moderation log")}.click()`);
  check("the log shows the row", await seen(bob, logRow("remove_posts")), await shownText(bob));
  const removedText = await bob.evaluate(`${logRow("remove_posts")}?.innerText ?? ""`);
  check("who, whom, why and how many", ["bobby", "removed the posts of", "ned", "selling pills", "1 kept message, last day"].every((w) => removedText.includes(w)), removedText);
  check("and nothing in it can be pressed", await bob.evaluate(`${logRow("remove_posts")}.querySelectorAll("button, a, input").length === 0`));
  await bob.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);

  // From the ban list, later and with the panel's own prompt. carla goes back a week at
  // most too, and annika takes all that is kept, of which nothing is left
  const nedBans = `[...document.querySelectorAll(".ban-list li")].filter((li) => li.querySelector(".ban-label")?.textContent === "ned")`;
  await panelOpens(car);
  await openPanel(car);
  await waitFor(car, `${nedBans}.length === 2`);
  await car.evaluate(`${nedBans}[0].querySelector(".ban-remove").click()`);
  await waitFor(car, `document.querySelector(".ban-removal")`);
  check("the ban list says it too", await car.evaluate(`document.querySelector(".ban-removal").textContent.includes("does not undo")`), await shownText(car));
  check("and goes no further for a holder of the list", await car.evaluate(`${optionIn(".ban-removal", "Last 7 days")} && !${optionIn(".ban-removal", "Everything kept")}`), await shownText(car));
  // The address row: the relay goes by the name, and this name has an account
  await car.evaluate(`${nedBans}[1].querySelector(".ban-remove").click()`);
  check("the row of his address says the same", await seen(car, `document.querySelector(".ban-removal").textContent.includes("does not undo")`, 3_000), await shownText(car));
  check("and not that a guest has nothing kept", await car.evaluate(`!document.querySelector(".ban-removal").textContent.includes("A guest has nothing kept")`), await shownText(car));
  await car.evaluate(`document.querySelector(".ban-removal .admin-cancel").click()`);
  await car.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await panelOpens(ann);
  await openPanel(ann);
  await tabTo("Bans");
  await waitFor(ann, `${nedBans}.length === 2`);
  await ann.evaluate(`${nedBans}[0].querySelector(".ban-remove").click()`);
  await waitFor(ann, `document.querySelector(".ban-removal")`);
  await pickIn(ann, ".ban-removal select", "Everything kept");
  await ann.evaluate(`document.querySelector('.ban-removal button[type="submit"]').click()`);
  await stepUp();
  check("from the ban list too", await seen(ann, `window.__toasts.some((t) => t.includes("Nothing kept to delete"))`), await ann.evaluate(`window.__toasts.join(" | ")`));
  await tabTo("Moderation log");
  check("each removal has its row", await seen(ann, `document.querySelectorAll('.modlog-row[data-action="remove_posts"]').length === 2`), await shownText(ann));

  // A lifted ban brings nothing back. The address is free again and everyone returns:
  // an account reads the stored log, a guest only what members hand her, which she holds
  // against what the relay told her as she connected
  await tabTo("Bans");
  await waitFor(ann, `${nedBans}.length === 2`);
  await ann.evaluate(`${nedBans}[1].querySelector(".admin-cancel").click()`);
  check("annika lifts the address ban", await seen(ann, `${nedBans}.length === 1`), await shownText(ann));
  await ann.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await signIn(ivy, "ivy");
  await openChat(ivy, "lobby-chat");
  await signIn(fay, "fay");
  await openChat(fay, "lobby-chat");
  check("a member back from it reads the rest", await stored(fay, "ivy answers ned"), await pageText(fay));
  check("not what was removed", !(await says(fay, "ned sells pills")), await pageText(fay));
  for (const tab of [ann, car, fay]) await turnOnSharing(tab);
  await connectGuest(han, "hana");
  await openChat(han, "lobby-chat");
  // Whoever answers is made to hand on a copy no honest app would: she has no other way
  // of being offered one, everybody's being hidden or gone
  const handedOn = JSON.stringify({ user_id: 77, username: "ned", content: "ned sells pills again", timestamp: beforeBan - 1000, id: "handed-on" });
  const members = [ann, bob, car, fay, ivy];
  for (const tab of members) {
    await tab.evaluate(`(() => { const real = JSON.stringify; window.__stringify = real;
      JSON.stringify = (v, ...rest) => real(Array.isArray(v) && typeof v[0]?.content === "string" ? [...v, ${handedOn}] : v, ...rest); })()`);
  }
  await waitFor(han, `document.querySelector(".resync-btn")`);
  let handed = false;
  for (let i = 0; i < 6 && !handed; i++) {
    await han.evaluate(`document.querySelector(".resync-btn").click()`);
    handed = await seen(han, rowWith("ivy answers ned"), 5_000);
  }
  check("a guest is handed the rest", handed, await pageText(han));
  check("and not what was removed", !(await says(han, "ned sells pills here")), await pageText(han));
  // Under annika's name: hers came last, and takes all that is kept
  check("a copy handed on anyway comes in hidden", await seen(han, byText(".folded-line", "This server says annika removed this with a ban")), await pageText(han));
  check("with nothing of it on her screen", !(await says(han, "ned sells pills again")), await pageText(han));
  for (const tab of members) await tab.evaluate(`JSON.stringify = window.__stringify; 0`);
  check("nobody's page broke at it", [ann, bob, car, fay, han, ivy, ned].every((t) => t.errors.length === 0), [ann, bob, car, fay, han, ivy, ned].flatMap((t) => t.errors).join(" | ").slice(0, 400));

  // ── Summons ──────────────────────────────────────────────────────────────
  //
  // bobby stands in a room whose password fay was never given, and asks her in. Then
  // in one behind a gate that ivy is outside. What the relay refuses and who hears the
  // answer are in session_tests.rs; here are the menu, the popup and each one's screen.
  const voiceRow = (name) => byText(".channel-list.modern .channels.voice .channel", name);
  const standsIn = (name) => `[...document.querySelectorAll(".channels.voice .channel.active")].some((c) => c.textContent.includes(${JSON.stringify(name)}))`;
  const askToJoin = async (tab, name) => {
    await waitFor(tab, voiceRow(name));
    await tab.evaluate(`${voiceRow(name)}.click()`);
    await waitFor(tab, `document.querySelector(".join-voice-btn")`);
    await tab.evaluate(`document.querySelector(".join-voice-btn").click()`);
  };
  const givePassword = async (tab, password) => {
    await waitFor(tab, `document.querySelector(".password-dialog input[type=password]")`);
    await tab.evaluate(setInput(".password-dialog input[type=password]", password));
    await tab.evaluate(`document.querySelector(".password-dialog button[type=submit]").click()`);
  };
  const inviteOffered = async (tab, name) => {
    await openMenuOn(tab, name);
    const there = await tab.evaluate(`!!${menuItem("Invite to Channel")}`);
    await tab.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);
    return there;
  };
  for (const tab of [fay, ivy]) await keepToasts(tab);
  for (const tab of [bob, fay, ivy]) await openChat(tab, "lobby-chat");

  // Who is offered it: not a moderator in no room, nor a member standing in one
  check("a moderator in no room has nowhere to invite to", !(await inviteOffered(bob, "fay")));
  await askToJoin(fay, "crew-room");
  await waitFor(fay, standsIn("crew-room"));
  await openChat(fay, "lobby-chat");
  check("a member in a room she did not make is offered no invite", !(await inviteOffered(fay, "ivy")));

  // The control: the password keeps fay out
  await askToJoin(fay, "locked-room");
  await givePassword(fay, "not-the-password");
  check("without the password fay is turned away", await seen(fay, `window.__toasts.some((t) => t.includes("incorrect channel password"))`), await fay.evaluate(`window.__toasts.join(" | ")`));
  check("and stays where she was", await fay.evaluate(standsIn("crew-room")), await pageText(fay));
  await openChat(fay, "lobby-chat");

  await askToJoin(bob, "locked-room");
  await givePassword(bob, "room-secret");
  await waitFor(bob, standsIn("locked-room"));
  await openChat(bob, "lobby-chat");
  check("standing in it, a moderator is offered it", await inviteOffered(bob, "fay"));
  await choose(bob, "fay", "Invite to Channel");
  check("fay gets the popup", await seen(fay, invited), await pageText(fay));
  check("saying who asks, and to where", await fay.evaluate(`["bobby", "#locked-room"].every((w) => ${invited}.textContent.includes(w))`), await fay.evaluate(`${invited}.textContent`));
  check("and nothing has moved her", await fay.evaluate(standsIn("crew-room")), await pageText(fay));
  await fay.evaluate(`document.querySelector(".invite .accept-btn").click()`);
  check("she accepts and is in, with no password asked", await seen(fay, standsIn("locked-room")), await pageText(fay));
  check("no password prompt came up", await fay.evaluate(`!document.querySelector(".password-dialog")`));
  check("bobby hears of it", await seen(bob, `window.__toasts.some((t) => t.includes("fay accepted your invite"))`), await bob.evaluate(`window.__toasts.join(" | ")`));
  check("and is offered no invite for someone already there", !(await inviteOffered(bob, "fay")));

  // It is written down, on the relay's word
  await panelOpens(bob);
  await openPanel(bob);
  await waitFor(bob, byText(".admin-tabs button", "Moderation log"));
  await bob.evaluate(`${byText(".admin-tabs button", "Moderation log")}.click()`);
  check("the log has the invite", await seen(bob, logRow("summon")), await shownText(bob));
  const summonText = await bob.evaluate(`${logRow("summon")}?.innerText ?? ""`);
  check("who, whom and where", ["bobby", "invited", "fay", "#locked-room"].every((w) => summonText.includes(w)), summonText);
  check("and not as his app's word", await bob.evaluate(`!${logRow("summon")}.querySelector(".pill")`), summonText);
  await bob.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await waitFor(bob, `!document.querySelector(".admin-dialog")`);

  // A gate. The room is open at first, so that all that changes below is the gate
  await askToJoin(bob, "crew-room");
  await waitFor(bob, standsIn("crew-room"));
  await openChat(bob, "lobby-chat");
  await choose(bob, "ivy", "Invite to Channel");
  check("the control: with the room open, ivy gets the popup", await seen(ivy, `${invited}?.textContent.includes("#crew-room")`), await pageText(ivy));
  await ivy.evaluate(`document.querySelector(".invite .decline-btn").click()`);
  check("and bobby hears she declined", await seen(bob, `window.__toasts.some((t) => t.includes("declined"))`), await bob.evaluate(`window.__toasts.join(" | ")`));
  const gateBox = (group) => `[...document.querySelectorAll('.gate-groups[data-gate="groups"] label')].find((l) => l.textContent.trim() === ${JSON.stringify(group)})?.querySelector("input")`;
  await waitFor(ann, voiceRow("crew-room"));
  await ann.evaluate(`${voiceRow("crew-room")}.closest(".channel-row").querySelector('[aria-label="Channel settings"]').click()`);
  await waitFor(ann, gateBox("moderator"));
  await ann.evaluate(`${gateBox("moderator")}.click()`);
  await ann.evaluate(`document.querySelector(".password-dialog button[type=submit]").click()`);
  check("annika gates it, and it goes from ivy's list", await seen(ivy, `!${voiceRow("crew-room")}`), await pageText(ivy));
  check("bobby holds a group it lets in, and stays", await bob.evaluate(standsIn("crew-room")), await pageText(bob));
  await choose(bob, "ivy", "Invite to Channel");
  check("now she is refused, and he is told", await seen(bob, `window.__toasts.some((t) => t.includes("they cannot join this channel"))`), await bob.evaluate(`window.__toasts.join(" | ")`));
  await sleep(1000);
  check("she gets no popup", await ivy.evaluate(`!${invited}`), await pageText(ivy));
  check("and nothing on her screen names the room", await ivy.evaluate(`!document.body.innerText.includes("crew-room") && !window.__toasts.some((t) => t.includes("crew-room"))`), await pageText(ivy));

  // From behind a pseudonym it would say who that is
  await askToJoin(bob, "masked-room");
  await waitFor(bob, standsIn("masked-room"));
  await openChat(bob, "lobby-chat");
  check("behind a pseudonym he is offered no invite", !(await inviteOffered(bob, "ivy")));
  for (const tab of [bob, fay]) await tab.evaluate(`document.querySelector(".voice-panel .leave-btn")?.click(); 0`);
  check("nobody's page broke at a summons", [ann, bob, fay, ivy].every((t) => t.errors.length === 0), [ann, bob, fay, ivy].flatMap((t) => t.errors).join(" | ").slice(0, 400));

  // ── Reports ──────────────────────────────────────────────────────────────
  //
  // carla reports what dan wrote, to whoever takes reports: bobby and annika here, mona
  // away. Who the relay names is in session_tests.rs, the mark and the check against a
  // copy in report-rules.test.ts: here the dialog, the label, and where each copy lands.
  await signIn(dan, "dan");
  await keepToasts(car);
  for (const tab of [ann, bob, car, dan, fay, han, ivy]) await openChat(tab, "lobby-chat");
  const takerRows = `[...document.querySelectorAll(".report-dialog .report-takers .report-taker")]`;
  const takerNames = (tab) => tab.evaluate(`${takerRows}.map((l) => l.querySelector("span").textContent.trim())`);
  const takerRow = (name) => `${takerRows}.find((l) => l.querySelector("span").textContent.trim() === ${JSON.stringify(name)})`;
  const askReport = async (tab, words) => {
    const answered = `document.querySelector(".report-dialog .report-send, .report-dialog .report-none")`;
    await messageMenu(tab, words);
    await tab.evaluate(`${offered("Report")}.click()`);
    // Four asks at once, then one per 30 s: a fast run can reach that, and it is no failure
    if (await waitFor(tab, answered, 10_000).then(() => true, () => false)) return;
    await cancelIt(tab);
    await sleep(31_000);
    await messageMenu(tab, words);
    await tab.evaluate(`${offered("Report")}.click()`);
    await waitFor(tab, answered);
  };
  const untick = (tab, name) => tab.evaluate(`${takerRow(name)}.querySelector("input").click()`);
  const sendIt = (tab) => tab.evaluate(`document.querySelector(".report-dialog .report-send").click()`);
  const cancelIt = async (tab) => {
    await tab.evaluate(`document.querySelector(".report-dialog .link-close-btn").click()`);
    await waitFor(tab, `!document.querySelector(".report-dialog")`);
  };
  const reportOn = (words) => `${rowWith(words)}?.querySelector(".report-label")`;
  const lineOf = (tab, words) => tab.evaluate(`${reportOn(words)}?.querySelector(".report-line")?.textContent.trim() ?? ""`);
  const checkOf = (tab, words) => tab.evaluate(`${reportOn(words)}?.querySelector(".report-check")?.dataset.check ?? ""`);
  const checkText = (tab, words) => tab.evaluate(`${reportOn(words)}?.querySelector(".report-check")?.textContent.trim() ?? ""`);
  const openDm = async (tab, name) => {
    await waitFor(tab, dmRow(name));
    await tab.evaluate(`${dmRow(name)}.click()`);
  };

  // What bobby's system would show: he is not looking, and notifications are allowed
  await bob.evaluate(`(() => { window.__notes = []; document.hasFocus = () => false;
    window.Notification = class { static permission = "granted"; static requestPermission = async () => "granted";
      constructor(title, o) { window.__notes.push(title + " | " + (o?.body ?? "")); } }; })()`);

  await say(dan, "dan says buy my pills");
  for (const tab of [ann, bob, car, fay]) await waitFor(tab, rowWith("dan says buy my pills"), 60_000);
  await say(car, "carla says hello");
  await waitFor(car, rowWith("carla says hello"));
  check("Report is not offered on your own message", !(await offeredOn(car, "carla says hello", "Report")));
  check("the control: it is on someone else's", await offeredOn(car, "dan says buy my pills", "Report"));

  await askReport(car, "dan says buy my pills");
  const named = await takerNames(car);
  check("the dialog names those who take reports", ["annika", "bobby", "mona"].every((n) => named.includes(n)), named.join(", "));
  check("and not the writer, nor the reporter", !named.includes("dan") && !named.includes("carla"), named.join(", "));
  check("someone gone is marked as away", await car.evaluate(`!!${takerRow("mona")}.querySelector(".report-away")`));
  check("someone here is not", await car.evaluate(`!${takerRow("bobby")}.querySelector(".report-away")`));
  const noteText = await car.evaluate(`document.querySelector(".report-dialog .report-note").textContent.replace(/\\s+/g, " ").trim()`);
  check("it says what they see and what the server does", noteText === "They will see your name and this message as you have it. The server sees that you wrote to them, not what.", noteText);
  check("with copies on, a copy for those away is the default", await car.evaluate(`document.querySelector(".report-keep input").checked`));
  check("with no file there is none to untick", await car.evaluate(`!document.querySelector(".report-dialog .report-file")`));

  // Unticked, annika gets nothing. Remembered: the id the mark names, for the forgery below
  await untick(car, "annika");
  await car.evaluate(setInput(".report-dialog .report-why", "selling **pills**"));
  await car.evaluate(`(() => { const real = JSON.stringify; JSON.stringify = (v, ...rest) => {
    if (v && v.report) { window.__markId ??= v.report.id; if (window.__forge) v = { ...v, report: { ...v.report, id: window.__markId } }; }
    return real(v, ...rest); }; })()`);
  await sendIt(car);
  check("it goes, and says to whom", await seen(car, `window.__toasts.some((t) => t.includes("Report sent to") && t.includes("bobby") && t.includes("mona") && !t.includes("annika"))`), await car.evaluate(`JSON.stringify(window.__toasts)`));
  check("filed under the moderator's own row", await seen(car, dmRow("bobby")), await pageText(car));
  check("and the one away under hers", await seen(car, dmRow("mona")), await pageText(car));
  check("never under Unknown", await car.evaluate(`!${dmRow("Unknown")}`), await pageText(car));
  check("and our own copy counts as nothing unread", await car.evaluate(`!${dmRow("bobby")}.querySelector(".unread-badge, .dm-unread")`));
  await openDm(car, "bobby");
  check("carla's copy says it is her word", (await seen(car, reportOn("dan says buy my pills"))) && (await lineOf(car, "dan says buy my pills")).startsWith("You reported this. You say dan wrote this in #lobby-chat at"), await pageText(car));

  check("bobby hears from carla", await seen(bob, dmRow("carla"), 60_000), await pageText(bob));
  await openDm(bob, "carla");
  check("the label names her", await seen(bob, reportOn("dan says buy my pills")), await pageText(bob));
  const line = await lineOf(bob, "dan says buy my pills");
  check("and says it is her word", line.startsWith("Report from carla. They say dan wrote this in #lobby-chat at"), line);
  check("he was in the channel: it matches his copy", (await checkOf(bob, "dan says buy my pills")) === "same" && (await checkText(bob, "dan says buy my pills")) === "matches your copy", await pageText(bob));
  check("the reason is plain text", await bob.evaluate(`${reportOn("dan says buy my pills")}.querySelector(".report-reason").textContent === "selling **pills**" && !${reportOn("dan says buy my pills")}.querySelector("strong")`), await pageText(bob));
  const notes = await bob.evaluate(`window.__notes.join(" || ")`);
  check("his notification leaves out what it quotes", notes.includes("Reported a message") && !notes.includes("pills"), notes);
  await say(car, "a plain word for bobby");
  await sleep(2200);
  await say(car, "a second plain word for bobby");
  check("the control: a plain message does say what it says", await seen(bob, `window.__notes.join(" ").includes("plain word for bobby")`), await bob.evaluate(`window.__notes.join(" || ")`));
  await sleep(1500);
  check("annika, unticked, got nothing", await ann.evaluate(`!${dmRow("carla")}`), await pageText(ann));

  // Reported once
  await openChat(car, "lobby-chat");
  await messageMenu(car, "dan says buy my pills");
  await car.evaluate(`${offered("Report")}.click()`);
  check("once is enough for a message", await seen(car, `window.__toasts.some((t) => t.includes("already"))`), await car.evaluate(`JSON.stringify(window.__toasts)`));
  check("and no dialog comes up", await car.evaluate(`!document.querySelector(".report-dialog")`));

  // Another text under the same id. Nothing stops a reporter saying so: the check does
  await say(dan, "dan says something else");
  await waitFor(car, rowWith("dan says something else"), 60_000);
  await car.evaluate(`window.__forge = true`);
  await askReport(car, "dan says something else");
  await untick(car, "annika");
  await sendIt(car);
  check("a forged report arrives", await seen(bob, reportOn("dan says something else"), 60_000), await pageText(bob));
  check("and his copy says otherwise", (await checkOf(bob, "dan says something else")) === "differs" && (await checkText(bob, "dan says something else")) === "your copy says otherwise", await pageText(bob));
  await car.evaluate(`window.__forge = false`);

  // A moderator on no list: out of every text channel, in a room gated to moderators
  await bob.evaluate(`[...document.querySelectorAll('.channels.text [aria-label^="Leave this channel"]')].forEach((b) => b.click()); 0`);
  await waitFor(bob, `!document.querySelector('.channels.text [aria-label^="Leave this channel"]')`);
  await askToJoin(bob, "crew-room");
  await waitFor(bob, standsIn("crew-room"));
  check("fay sees no such room", await seen(fay, `!${voiceRow("crew-room")}`), await pageText(fay));
  check("and bobby on no list of hers", await seen(fay, `!${memberRow("bobby")}`), await pageText(fay));
  await say(dan, "dan writes a third thing");
  await waitFor(fay, rowWith("dan writes a third thing"), 60_000);
  await askReport(fay, "dan writes a third thing");
  check("the relay names him all the same", (await takerNames(fay)).includes("bobby"), (await takerNames(fay)).join(", "));
  check("as here now", await fay.evaluate(`!${takerRow("bobby")}.querySelector(".report-away")`));
  await sendIt(fay);
  check("it goes", await seen(fay, `window.__toasts.some((t) => t.includes("Report sent to") && t.includes("bobby"))`), await fay.evaluate(`JSON.stringify(window.__toasts)`));
  check("from a hidden room, bobby hears from fay", await seen(bob, dmRow("fay"), 60_000), await pageText(bob));
  await openDm(bob, "fay");
  check("labelled as her word", (await seen(bob, reportOn("dan writes a third thing"))) && (await lineOf(bob, "dan writes a third thing")).startsWith("Report from fay. They say dan wrote this in #lobby-chat at"), await pageText(bob));
  check("he has no copy, and is told so", (await checkOf(bob, "dan writes a third thing")) === "none" && (await checkText(bob, "dan writes a third thing")) === "you have no copy, nothing proves it", await pageText(bob));
  check("fay's copy is under his name", await seen(fay, dmRow("bobby")), await pageText(fay));
  check("not under Unknown", await fay.evaluate(`!${dmRow("Unknown")}`), await pageText(fay));

  // Behind a pseudonym: he is not named, not even as away. What fay reported she cannot
  // report again, so this is about something new, and a cancel leaves it open
  await say(dan, "dan writes a fourth thing");
  await waitFor(fay, rowWith("dan writes a fourth thing"), 60_000);
  await askToJoin(bob, "masked-room");
  await waitFor(bob, standsIn("masked-room"));
  await askReport(fay, "dan writes a fourth thing");
  check("someone behind a pseudonym is not named", !(await takerNames(fay)).includes("bobby"), (await takerNames(fay)).join(", "));
  check("the control: annika is", (await takerNames(fay)).includes("annika"));
  await cancelIt(fay);
  await bob.evaluate(`document.querySelector(".voice-panel .leave-btn")?.click(); 0`);
  await waitFor(bob, `!${standsIn("masked-room")}`);
  // And from behind one: only those online, under that name
  await askToJoin(fay, "masked-room");
  await waitFor(fay, standsIn("masked-room"));
  await openChat(fay, "lobby-chat");
  await askReport(fay, "dan writes a fourth thing");
  check("behind a pseudonym the dialog says so", await fay.evaluate(`!!document.querySelector(".report-dialog .report-pseudonym")`), await pageText(fay));
  check("and that the pseudonym is what they see", await fay.evaluate(`document.querySelector(".report-dialog .report-note").textContent.includes("your pseudonym")`));
  check("and offers nobody away", await fay.evaluate(`!document.querySelector(".report-dialog .report-away") && !document.querySelector(".report-dialog .report-keep")`), (await takerNames(fay)).join(", "));
  await cancelIt(fay);
  await fay.evaluate(`document.querySelector(".voice-panel .leave-btn")?.click(); 0`);

  // A guest can keep nothing for anyone, so they hear of those here
  await waitFor(han, rowWith("dan writes a third thing"), 60_000);
  await askReport(han, "dan writes a third thing");
  check("a guest hears of those here", (await takerNames(han)).includes("annika"), (await takerNames(han)).join(", "));
  check("and of nobody away", await han.evaluate(`!document.querySelector(".report-dialog .report-away") && !document.querySelector(".report-dialog .report-keep")`), (await takerNames(han)).join(", "));
  await cancelIt(han);

  // Timed out: no compose box and no reply, and still a report
  await waitFor(ann, memberRow("ivy"));
  await choose(ann, "ivy", "Time out");
  await waitFor(ann, `document.querySelector(".restrict-duration")`);
  await ann.evaluate(`${byText(".poke-send-btn", "Time out")}.click()`);
  await waitFor(ivy, heldFooter);
  await waitFor(ivy, rowWith("dan writes a third thing"), 60_000);
  await messageMenu(ivy, "dan writes a third thing");
  check("someone timed out cannot answer", await ivy.evaluate(`!${offered("Reply")}`), await pageText(ivy));
  check("and can still report", await ivy.evaluate(`!!${offered("Report")}`), await pageText(ivy));
  await shutMenu(ivy);
  await askReport(ivy, "dan writes a third thing");
  await sendIt(ivy);
  check("and it goes", await seen(ivy, `window.__toasts.some((t) => t.includes("Report sent to"))`), await ivy.evaluate(`JSON.stringify(window.__toasts)`));
  await openMenuOn(ann, "ivy");
  await waitFor(ann, menuItem("Lift mute or timeout"));
  await ann.evaluate(`${menuItem("Lift mute or timeout")}.click()`);
  await waitFor(ivy, `!${heldFooter}`);

  // ivy keeps no copies, and bobby goes away. A report to him is kept all the same,
  // because she says so for this one. It is about a direct message, so a conversation
  // with someone else is open when it is filed
  await openAccountPanel(ivy);
  await ivy.evaluate(`[...document.querySelectorAll('${dialogOf("account")} .row')].find((r) => r.textContent.includes("Messages kept on this server")).querySelector(".secondary").click()`);
  await waitFor(ivy, `document.querySelector('${dialogOf("cloud")}')`);
  await ivy.evaluate(`document.querySelector('${dialogOf("cloud")} .secondary').click()`);
  await waitFor(ivy, `!document.querySelector('${dialogOf("cloud")}')`);
  await choose(fay, "ivy", "Direct message");
  await waitFor(fay, composer);
  await say(fay, "fay whispers something nasty");
  await openDm(ivy, "fay");
  await waitFor(ivy, rowWith("fay whispers something nasty"), 60_000);
  await bob.send("Page.navigate", { url: "about:blank" });
  await sleep(4000);
  await askReport(ivy, "fay whispers something nasty");
  check("bobby is away now", await ivy.evaluate(`!!${takerRow("bobby")}?.querySelector(".report-away")`), (await takerNames(ivy)).join(", "));
  check("with copies off, keeping it is asked and not assumed", await ivy.evaluate(`document.querySelector(".report-keep input").checked === false`));
  await untick(ivy, "annika");
  check("with nobody here and nothing kept, nothing can go", await ivy.evaluate(`document.querySelector(".report-send").disabled`));
  await ivy.evaluate(`document.querySelector(".report-keep input").click()`);
  check("kept, it can", await ivy.evaluate(`!document.querySelector(".report-send").disabled`));
  await sendIt(ivy);
  check("a sealed copy waits for him", await seen(ivy, `window.__toasts.filter((t) => t.includes("Report sent to")).length === 2`), await ivy.evaluate(`JSON.stringify(window.__toasts)`));
  check("filed under his row", await seen(ivy, dmRow("bobby")), await pageText(ivy));
  check("not under Unknown", await ivy.evaluate(`!${dmRow("Unknown")}`), await pageText(ivy));
  check("nor in the conversation open when it went", await ivy.evaluate(`!document.querySelector(".report-label")`), await pageText(ivy));
  await openDm(ivy, "bobby");
  check("it is there, as her word", (await seen(ivy, reportOn("fay whispers something nasty"))) && (await lineOf(ivy, "fay whispers something nasty")).startsWith("You reported this. You say fay wrote this in a direct message at"), await pageText(ivy));
  await openAccountPanel(ivy);
  check("and that was for this one: her copies are still off", await ivy.evaluate(`document.querySelector('${dialogOf("account")}').textContent.includes("Messages kept on this server: no")`));
  await closeAccountPanel(ivy);

  await signIn(bob, "bobby", bobSecret);
  check("bobby signs in and finds it", await seen(bob, dmRow("ivy"), 60_000), await pageText(bob));
  await openDm(bob, "ivy");
  check("labelled as her word", (await seen(bob, reportOn("fay whispers something nasty"), 30_000)) && (await lineOf(bob, "fay whispers something nasty")).startsWith("Report from ivy. They say fay wrote this in a direct message at"), await pageText(bob));
  check("nothing can prove a direct message to him", (await checkOf(bob, "fay whispers something nasty")) === "none", await pageText(bob));

  // A moderator passes it on: it stays a report, and says who passed it on and from whom
  await messageMenu(bob, "fay whispers something nasty");
  await bob.evaluate(`${offered("Forward")}.click()`);
  await waitFor(bob, `[...document.querySelectorAll(".forward-dialog .forward-dest")].find((b) => b.textContent.includes("carla"))`);
  await bob.evaluate(`[...document.querySelectorAll(".forward-dialog .forward-dest")].find((b) => b.textContent.includes("carla")).click()`);
  await openDm(car, "bobby");
  check("a report passed on stays one", await seen(car, reportOn("fay whispers something nasty"), 30_000), await pageText(car));
  const passed = await lineOf(car, "fay whispers something nasty");
  check("and says who passed it on, and who that says it came from", passed.startsWith("Report passed on by bobby, who says it came from ivy. They say fay wrote this in a direct message at"), passed);

  // A file goes along. One that cannot go does not take the words with it
  await openChat(dan, "lobby-chat");
  await dan.evaluate(`(() => { const input = document.querySelector(".chat-main .input-bar .file-picker");
    const dt = new DataTransfer(); dt.items.add(new File(["what dan attached"], "attached.txt", { type: "text/plain" })); input.files = dt.files;
    input.dispatchEvent(new Event("change", { bubbles: true })); })()`);
  await sleep(300);
  await say(dan, "dan attaches this");
  await waitFor(han, `${rowWith("dan attaches this")}?.querySelector(".file-card")`, 60_000);
  await askReport(han, "dan attaches this");
  const fileBox = `document.querySelector(".report-dialog .report-file")`;
  check("the dialog says the file goes too, and what that shows the server", await han.evaluate(`${fileBox}?.textContent.includes("which conversation it came from")`), await pageText(han));
  check("by default", await han.evaluate(`${fileBox}.querySelector("input").checked`));
  await han.evaluate(`${fileBox}.querySelector("input").click()`);
  await cancelIt(han);
  await askReport(han, "dan attaches this");
  check("an untick lasts for that dialog only", await han.evaluate(`${fileBox}.querySelector("input").checked`));
  await sendIt(han);
  check("a report carries the file", (await seen(bob, dmRow("hana"), 60_000)) && (await openDm(bob, "hana"), await seen(bob, `${rowWith("dan attaches this")}?.querySelector(".file-card")`, 30_000)), await pageText(bob));
  check("and its label", await bob.evaluate(`!!${reportOn("dan attaches this")}`), await pageText(bob));
  // Unticked, the words go alone. The file is the only link to where it was written
  await openChat(fay, "lobby-chat");
  await waitFor(fay, `${rowWith("dan attaches this")}?.querySelector(".file-card")`, 60_000);
  await askReport(fay, "dan attaches this");
  await fay.evaluate(`${fileBox}.querySelector("input").click()`);
  await sendIt(fay);
  await openDm(bob, "fay");
  check("unticked, the words go", await seen(bob, reportOn("dan attaches this"), 30_000), await pageText(bob));
  check("with the label and without the file", await bob.evaluate(`!${rowWith("dan attaches this")}.querySelector(".file-card")`), await pageText(bob));
  check("and nothing says a file failed", await fay.evaluate(`!window.__toasts.some((t) => t.includes("Could not forward the file"))`), await fay.evaluate(`JSON.stringify(window.__toasts)`));
  // bobby leaves with the dialog up: the relay has no such conversation for the file
  await openChat(ivy, "lobby-chat");
  await waitFor(ivy, `${rowWith("dan attaches this")}?.querySelector(".file-card")`, 60_000);
  await askReport(ivy, "dan attaches this");
  await untick(ivy, "annika");
  await bob.send("Page.navigate", { url: "about:blank" });
  await sleep(4000);
  await sendIt(ivy);
  check("a file that cannot go is said", await seen(ivy, `window.__toasts.some((t) => t.includes("Could not forward the file"))`), await ivy.evaluate(`JSON.stringify(window.__toasts)`));
  await openDm(ivy, "bobby");
  check("and the words go without it", (await seen(ivy, reportOn("dan attaches this"), 30_000)) && (await ivy.evaluate(`!${rowWith("dan attaches this")}.querySelector(".file-card")`)), await pageText(ivy));

  // The privilege decides, at the next ask. bobby is away now, and named as that
  await openChat(car, "lobby-chat");
  await waitFor(car, rowWith("dan writes a third thing"), 60_000);
  await askReport(car, "dan writes a third thing");
  check("the control: before, bobby is named, as away", await car.evaluate(`!!${takerRow("bobby")}?.querySelector(".report-away")`), (await takerNames(car)).join(", "));
  await cancelIt(car);
  await serverMenu(ann, "Server admin");
  await waitFor(ann, `document.querySelector(".admin-tabs")`);
  await tabTo("Groups");
  await waitFor(ann, groupRow("moderator"));
  await ann.evaluate(`${groupRow("moderator")}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[data-scope="voipc:reports"]')`);
  await ann.evaluate(`document.querySelector('.admin-dialog input[data-scope="voipc:reports"]').click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  await waitFor(ann, groupRow("moderator"));
  await ann.evaluate(`document.querySelector(".admin-dialog .admin-close")?.click(); 0`);
  await waitFor(ann, `!document.querySelector(".admin-dialog")`);
  await sleep(1000);
  await askReport(car, "dan writes a third thing");
  const left = await takerNames(car);
  check("taken from the group, bobby is gone at the next ask", !left.includes("bobby") && !left.includes("mona"), left.join(", "));
  check("the control: annika still is", left.includes("annika"), left.join(", "));
  await cancelIt(car);

  // And nobody left but the writer
  await say(ann, "annika writes this one");
  await waitFor(car, rowWith("annika writes this one"), 60_000);
  await askReport(car, "annika writes this one");
  check("if only the writer takes reports, nobody does", await car.evaluate(`document.querySelector(".report-dialog .report-none")?.textContent.trim() === "Nobody takes reports on this server right now"`), await pageText(car));
  check("and there is nothing to send", await car.evaluate(`!document.querySelector(".report-dialog .report-send")`));
  await cancelIt(car);
  check("nobody's page broke at a report", [ann, bob, car, dan, fay, han, ivy].every((t) => t.errors.length === 0), [ann, bob, car, dan, fay, han, ivy].flatMap((t) => t.errors).join(" | ").slice(0, 400));

  // A report dialog lists the takers of the server on screen and sends on the message's,
  // so moving to another server closes it. A phone's swipe reaches the rail with it open
  const S1 = `127.0.0.1:${PORT}`;
  const S2 = `127.0.0.1:${PORT + 1}`;
  const railItem = (id) => `.server-rail .rail-item[data-server="${id}"]`;
  await han.evaluate(`document.querySelector(".server-rail .rail-item.add").click()`);
  await waitFor(han, `document.querySelector(".connect-btn")`);
  await han.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await han.evaluate(setInput('input[placeholder="9987"]', String(PORT + 1)));
  await han.evaluate(setInput('input[placeholder="Your name"]', "hana"));
  await han.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(han, `!document.querySelector(".connect-btn") && document.querySelector('${railItem(S2)}.active')`);
  await settle(han);
  await han.evaluate(`document.querySelector('${railItem(S1)}').click()`);
  await openChat(han, "lobby-chat");
  await waitFor(han, rowWith("annika writes this one"), 60_000);
  await askReport(han, "annika writes this one");
  await sleep(500);
  check("the control: a dialog stays up while the server on screen does", await han.evaluate(`!!document.querySelector(".report-dialog")`));
  await han.evaluate(`document.querySelector('${railItem(S2)}').click()`);
  check("another server on screen closes it", await seen(han, `document.querySelector('${railItem(S2)}.active') && !document.querySelector(".report-dialog")`, 5_000), await pageText(han));
  await han.evaluate(`document.querySelector('${railItem(S1)}').click()`);
  await waitFor(han, `document.querySelector('${railItem(S1)}.active')`);
  await sleep(500);
  check("and it stays closed on coming back", await han.evaluate(`!document.querySelector(".report-dialog")`), await pageText(han));

  // ── The stream view ──────────────────────────────────────────────────────
  //
  // fay watches carla's share with the chat shut. She has blocked dan, so what he writes
  // there lights nothing; what carla writes does. Headless Chromium has no screen, so a
  // canvas stands in for one, as in test-ui.mjs.
  const liveTag = `document.querySelector(".channel-list.modern button.live-tag.watch")`;
  const chatDot = `document.querySelector(".chat-toggle .unread-dot")`;
  await dan.evaluate(`document.querySelector('button[title="Create channel"]').click()`);
  await waitFor(dan, `document.querySelector(".create-form")`);
  await dan.evaluate(setInput(".create-form input[type=text]", "dan-room"));
  await dan.evaluate(`document.querySelector(".create-form .create-btn").click()`);
  await waitFor(dan, standsIn("dan-room"));
  await dan.evaluate(`${voiceRow("dan-room")}.click()`);
  for (const tab of [fay, car]) {
    await askToJoin(tab, "dan-room");
    await waitFor(tab, `${standsIn("dan-room")} && document.querySelector(".input-bar .chat-input")`);
  }
  await choose(fay, "dan", "Block");
  await waitFor(fay, marked("dan"));
  await car.evaluate(`(() => { const canvas = document.createElement("canvas");
    canvas.width = 640; canvas.height = 360;
    const ctx = canvas.getContext("2d");
    let f = 0;
    setInterval(() => { f++; ctx.fillStyle = "hsl(" + (f * 9) % 360 + ", 70%, 45%)"; ctx.fillRect(0, 0, 640, 360); }, 66);
    const stream = canvas.captureStream(15);
    navigator.mediaDevices.getDisplayMedia = async () => stream; })()`);
  await car.evaluate(`document.querySelector(".voice-panel .share-btn").click()`);
  await waitFor(car, `document.querySelector(".start-btn")`);
  await car.evaluate(`document.querySelector(".start-btn").click()`);
  await waitFor(fay, liveTag);
  await fay.evaluate(`${liveTag}.click()`);
  await waitFor(fay, `document.querySelector(".stream-stage .chat-toggle")`);
  check("the stream view starts with nothing new", await fay.evaluate(`!document.querySelector(".stream-stage .stream-chat") && !${chatDot}`), await pageText(fay));
  await say(dan, "dan writes over the share");
  await waitFor(car, rowWith("dan writes over the share"), 60_000);
  await sleep(2500);
  check("someone blocked lights nothing on the chat toggle", await fay.evaluate(`!${chatDot}`), await pageText(fay));
  await say(car, "carla writes over the share");
  check("the control: anyone else does", await seen(fay, chatDot, 30_000), await pageText(fay));
  await fay.evaluate(`document.querySelector(".stream-stage .chat-toggle").click()`);
  check("and his message was there all along, folded", await seen(fay, `(${folds}) > 0 && document.querySelector(".stream-stage .stream-chat")`), await pageText(fay));
  check("nobody's page broke at the end", [dan, fay, han, car].every((t) => t.errors.length === 0), [dan, fay, han, car].flatMap((t) => t.errors).join(" | ").slice(0, 400));

  for (const [name, tab] of [["annika", ann], ["bobby", bob], ["carla", car], ["erin", eri]]) {
    check(`no page error on ${name}'s side`, tab.errors.length === 0, tab.errors.join(" | ").slice(0, 400));
  }
}

try {
  await lane();
  console.log(failures ? `test-moderation: ${failures} failed` : "test-moderation: all checks passed");
  await stop(failures ? 1 : 0);
} catch (e) {
  console.log(`FAIL the lane stopped: ${e.stack ?? e}`);
  await stop(1);
}
