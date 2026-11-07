#!/usr/bin/env node
// Community basics (1.9), in real browsers against a real relay: what a server
// calls itself, a channel made in the app, a group's colour and section, a display
// name beside the `@name`, a picture that only ever reaches the page sanitized,
// `@everyone` from someone allowed and from someone not, an invite link, by password
// and through a provider (a stand-in on a local port), and a group's section turned off.
// (session_tests.rs has the rules; what only a browser shows is here.)
//
//   VOIPC_SELFTEST=1 npm run web      # a release relay has no stand-in provider
//   node test-community.mjs [port]
//   COMMUNITY_DATABASE=postgres://... node test-community.mjs [port]   # another database
//
// No dependencies. Needs openssl and chromium (CHROME=/path/to/chrome).

import { spawn, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] ?? 49991);
const CHROME = process.env.CHROME ?? "chromium";
const ORIGIN = `https://127.0.0.1:${PORT}`;
const WORK = mkdtempSync(join(tmpdir(), "voipc-community-"));
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
  provider.close();
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

// ── A picture, written here so the lane needs no file of its own ──────────

function png(side, [r, g, b]) {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const x of buf) c = crcTable[(c ^ x) & 255] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const head = Buffer.alloc(4);
    head.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type), data]);
    const tail = Buffer.alloc(4);
    tail.writeUInt32BE(crc(body));
    return Buffer.concat([head, body, tail]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(side, 0);
  ihdr.writeUInt32BE(side, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const row = Buffer.concat([Buffer.from([0]), Buffer.from(Array.from({ length: side }, () => [r, g, b]).flat())]);
  const pixels = Buffer.concat(Array.from({ length: side }, () => row));
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(pixels)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const picture = join(WORK, "me.png");
writeFileSync(picture, png(300, [30, 200, 90]));

// ── The stand-in provider ─────────────────────────────────────────────────

const provider = createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    res.end(
      req.method === "POST"
        ? JSON.stringify({ access_token: "at", token_type: "Bearer" })
        : JSON.stringify({ id: "424242", username: "dee_d", global_name: "Dee D" }),
    );
  });
});
await new Promise((r) => provider.listen(0, "127.0.0.1", r));
const providerBase = `http://127.0.0.1:${provider.address().port}`;

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
public_url = "${ORIGIN}"
${process.env.COMMUNITY_DATABASE ? `database = "${process.env.COMMUNITY_DATABASE}"` : ""}
`,
);
writeFileSync(join(WORK, "channels.json"), JSON.stringify([
  { name: "lobby-chat", text: true, auto_join: true },
  { name: "side-a", text: true, auto_join: true },
  { name: "side-b", text: true, auto_join: true },
  { name: "side-c", text: true, auto_join: true },
]));
const relay = spawn(
  join(ROOT, "target/release/voipc-server"),
  ["-c", "server.toml", "--admin-token", TOKEN, "--channels", "channels.json"],
  {
    cwd: WORK,
    env: {
      ...process.env,
      VOIPC_OAUTH_DISCORD_ID: "client",
      VOIPC_OAUTH_DISCORD_SECRET: "secret",
      VOIPC_OAUTH_TEST_BASE: providerBase,
    },
    stdio: ["ignore", "ignore", "inherit"],
  },
);
children.push(relay);
await sleep(1500);

// ── Browsers, each its own device ─────────────────────────────────────────

async function browser(cdpPort) {
  const c = spawn(
    CHROME,
    ["--headless=new", "--no-sandbox", "--ignore-certificate-errors", `--remote-debugging-port=${cdpPort}`,
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

/** The connect dialog on the relay's own page, at `fragment`, its Account tab open. */
async function openDialog(cdpPort, fragment = "") {
  const tab = await newTab(cdpPort);
  await tab.send("Page.navigate", { url: `${ORIGIN}/${fragment}` });
  await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(`document.querySelector(".skip-link").click()`);
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(`window.open = (url) => { window.__opened = url; return null; }; 0`);
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  if (!fragment) await tab.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(tab, `document.querySelector("#account-name")`);
  return tab;
}

/** A click on Continue, the code, the provider's page in a tab of its own, and the
 *  tap on the code there. */
async function throughProvider(tab, cdpPort) {
  await waitFor(tab, `document.querySelector(".connect-provider")`);
  await tab.evaluate(`${byText(".connect-provider", "Continue with Discord")}.click()`);
  await waitFor(tab, `document.querySelector(".provider-code")`);
  const code = await tab.evaluate(`document.querySelector(".provider-code").textContent.trim()`);
  await tab.evaluate(`${byText(".connect-provider", "Open Discord")}.click()`);
  await waitFor(tab, `window.__opened`);
  const state = new URL(await tab.evaluate(`window.__opened`)).searchParams.get("state");
  const page = await newTab(cdpPort);
  await page.send("Page.navigate", { url: `${ORIGIN}/account/oauth/discord/cb?state=${state}&code=abc` });
  await waitFor(page, `document.querySelector("button[name=pick]")`);
  await page.evaluate(`document.querySelector('button[name=pick][value="${code}"]').click()`);
  // body?: the submit is navigating, and a document starts with none
  await waitFor(page, `document.body?.innerText.includes("go back to the app")`);
  await page.send("Page.close").catch(() => {});
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
  throw new Error("the first-connect questions did not end");
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

async function serverMenu(tab, label) {
  await tab.evaluate(`document.querySelector(".server-header .menu") || document.querySelector(".server-header .header-btn").click(); 0`);
  await waitFor(tab, byText(".server-header .menu > button", label));
  await tab.evaluate(`${byText(".server-header .menu > button", label)}.click()`);
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

async function openAccountPanel(tab) {
  await serverMenu(tab, "Your account");
  await waitFor(tab, `document.querySelector('${dialogOf("account")}')`);
}

async function closeAccountPanel(tab) {
  await tab.evaluate(`document.querySelector('${dialogOf("account")} .submit-btn').click()`);
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
  const [one, two, three, four] = await Promise.all([
    browser(PORT + 100),
    browser(PORT + 101),
    browser(PORT + 102),
    browser(PORT + 103),
  ]);

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

  const bob = await openDialog(two);
  await createAccount(bob, "bobby");

  const tabTo = (name) => ann.evaluate(`${byText(".admin-tabs button", name)}.click()`);
  /** The panel's step-up: a code one step ahead each time, since a code is good once. */
  let codeStep = Math.floor(Date.now() / 30_000);
  const stepUp = async () => {
    const asked = await seen(ann, `document.querySelector('.admin-dialog input[aria-label="Two-factor code"]')`, 3_000);
    if (!asked) return;
    codeStep += 1;
    await ann.evaluate(setInput('.admin-dialog input[aria-label="Two-factor code"]', totpAt(secret, codeStep)));
    await ann.evaluate(`${byText(".admin-dialog button", "Confirm")}.click()`);
  };

  // What the server calls itself: above its address, never instead of it.
  await tabTo("Server");
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Server name"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Server name"]', "Night Owls"));
  await ann.evaluate(setInput('.admin-dialog textarea[aria-label="Server description"]', "Be kind."));
  await ann.evaluate(`document.querySelector(".server-form .btn-primary").click()`);
  await stepUp();
  const named = await seen(bob, `document.querySelector(".server-header .server-name")?.textContent === "Night Owls"`);
  check("everybody sees what the server calls itself", named, await bob.evaluate(`document.querySelector(".server-header")?.innerText ?? ""`));
  check(
    "with its address under it",
    await bob.evaluate(`document.querySelector(".server-header .server-host")?.textContent === "127.0.0.1:${PORT}"`),
    await bob.evaluate(`document.querySelector(".server-header")?.innerText ?? ""`),
  );
  check(
    "and in the rail's title too",
    await bob.evaluate(`[...document.querySelectorAll("[aria-current]")].some((e) => /Night Owls \\(127\\.0\\.0\\.1:${PORT}\\)/.test(e.title))`),
  );

  // A channel made in the app, in a category.
  await tabTo("Channels");
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Category name"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Category name"]', "Games"));
  await ann.evaluate(`document.querySelector(".new-category button[type=submit]").click()`);
  await waitFor(ann, `document.querySelector('.category[data-category="Games"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Channel name"]', "dungeon"));
  check("a new text channel joins by itself unless told not to", await ann.evaluate(`document.querySelector('.admin-dialog input[aria-label="Joins by itself"]').checked`));
  await ann.evaluate(`document.querySelector('.admin-dialog input[aria-label="Joins by itself"]').click()`);
  await ann.evaluate(`document.querySelector('.admin-dialog .inline-form button.btn-primary').click()`);
  await stepUp();
  const made = await seen(bob, `document.querySelector(".channel-list.modern")?.innerText.includes("dungeon")`);
  check("a channel made in the app reaches the others", made, await bob.evaluate(`document.querySelector(".channel-list.modern")?.innerText ?? ""`));

  // In the browser "no category" arrives as undefined, not null
  const dungeonRow = `[...document.querySelectorAll(".admin-dialog button")].find((b) => b.getAttribute("aria-label") === "Move dungeon up")`;
  check("a channel outside any category has its row in the panel", await seen(ann, dungeonRow), await ann.evaluate(`document.querySelector(".admin-dialog")?.innerText.slice(0, 500) ?? ""`));
  await ann.evaluate(`${dungeonRow}?.parentElement.querySelector("button[title^='Opens the first time']")?.click(); 0`);
  await sleep(300);
  check(
    "and can be made the welcome channel",
    await seen(ann, `${dungeonRow}?.parentElement.textContent.includes("Not the welcome")`, 5_000),
    await ann.evaluate(`${dungeonRow}?.parentElement.textContent ?? "no row"`),
  );

  // A category renamed in place: the desktop's webview may have no prompt.
  await ann.evaluate(`[...document.querySelectorAll('.category[data-category="Games"] button')].find((b) => b.textContent.trim() === "Rename").click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="The name of Games"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="The name of Games"]', "Tabletop"));
  await ann.evaluate(`document.querySelector('.category .inline-form button[type=submit]').click()`);
  check("a category is renamed in place", await seen(ann, `document.querySelector('.category[data-category="Tabletop"]')`));

  // A group, its colour, and the section its people stand under.
  await tabTo("Groups");
  await waitFor(ann, byText(".admin-dialog button", "New group"));
  await ann.evaluate(`${byText(".admin-dialog button", "New group")}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Group name"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Group name"]', "crew"));
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Badge"]', "Crew"));
  await waitFor(ann, `document.querySelector('.colour-row input[type="color"]')`);
  await ann.evaluate(setInput('.colour-row input[type="color"]', "#ff8800"));
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  await waitFor(ann, byText(".admin-dialog .list-row .row-name", "crew"));
  await tabTo("Users");
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Search accounts"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Search accounts"]', "bobby"));
  await ann.evaluate(`document.querySelector('.admin-dialog form[role="search"] button[type="submit"]').click()`);
  const row = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent === "bobby")`;
  await waitFor(ann, row);
  await ann.evaluate(`${row}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[data-group="crew"]')`);
  await ann.evaluate(`document.querySelector('.admin-dialog input[data-group="crew"]').click()`);
  await stepUp();
  await sleep(500);
  // Out of the panel for the member list
  await ann.evaluate(`document.querySelector(".admin-dialog .close-btn, .admin-dialog [aria-label='Close']")?.click(); 0`);

  await openChat(ann, "lobby-chat");
  await openChat(bob, "lobby-chat");
  const section = `[...document.querySelectorAll(".user-list.modern .group-label")].some((l) => l.textContent.startsWith("Crew"))`;
  check("a group's people stand under its badge", await seen(ann, section), await ann.evaluate(`document.querySelector(".user-list.modern")?.innerText ?? ""`));
  const pill = `[...document.querySelectorAll(".user-list.modern .badge")].find((b) => b.textContent === "Crew")`;
  const colour = await ann.evaluate(`${pill} ? getComputedStyle(${pill}).backgroundColor : ""`);
  check("in the group's colour", colour === "rgb(255, 136, 0)", colour);

  // A display name beside the name, and never instead of it.
  await openAccountPanel(bob);
  await bob.evaluate(setInput(`${dialogOf("account")} input[aria-label="Display name"]`, "Robert Example"));
  await bob.evaluate(`document.querySelector('${dialogOf("account")} form.row button[type=submit]').click()`);
  await sleep(300);
  const rowName = `[...document.querySelectorAll(".user-list.modern .user .name")].find((n) => n.textContent.includes("@bobby"))`;
  check("a display name reaches the others", await seen(ann, `${rowName}?.textContent.includes("Robert Example")`), await ann.evaluate(`document.querySelector(".user-list.modern")?.innerText ?? ""`));
  await bob.evaluate(setInput(`${dialogOf("account")} input[aria-label="Display name"]`, "annika"));
  await bob.evaluate(`document.querySelector('${dialogOf("account")} form.row button[type=submit]').click()`);
  check(
    "and it cannot be another account's name",
    await seen(bob, `(window.__toasts ?? []).join(" ").includes("another account") || document.body.innerText.includes("another account")`, 5_000),
    await bob.evaluate(`document.body.innerText.slice(0, 200)`),
  );

  // A picture: goes up small, comes down through the sanitizer.
  const { root } = (await bob.send("DOM.getDocument")).result;
  const input = (await bob.send("DOM.querySelector", { nodeId: root.nodeId, selector: `${dialogOf("account")} input[type=file]` })).result;
  await bob.send("DOM.setFileInputFiles", { nodeId: input.nodeId, files: [picture] });
  await closeAccountPanel(bob);
  const face = `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes("@bobby"))?.querySelector(".avatar img")`;
  const shown = await seen(ann, `${face}?.src.startsWith("blob:") && ${face}.naturalWidth > 0`);
  check("a picture reaches the others, as an image the page can draw", shown, await ann.evaluate(`${face}?.src ?? "no img"`));
  check("and at most the size kept for it", (await ann.evaluate(`${face}?.naturalWidth ?? 999`)) <= 128);

  // `@everyone`: from someone allowed, and from someone not.
  await say(ann, "@everyone meet at eight");
  const toBob = lastMessage("meet at eight");
  check("@everyone from an admin stands out for the others", await seen(bob, `${toBob}?.classList.contains("to-me")`), await bob.evaluate(`${toBob}?.className ?? "no such message"`));
  check("as a mention, not as text", await bob.evaluate(`!!${toBob}?.querySelector(".mention")`));
  await say(bob, "@everyone free stuff");
  const toAnn = lastMessage("free stuff");
  await waitFor(ann, toAnn);
  check("@everyone from someone without the privilege does not", !(await ann.evaluate(`${toAnn}.classList.contains("to-me")`)));
  check("and is only text", !(await ann.evaluate(`!!${toAnn}.querySelector(".mention")`)));
  check(
    "their name in the chat goes by the display name too",
    (await ann.evaluate(`${toAnn}.textContent`)).includes("Robert Example"),
    await ann.evaluate(`${toAnn}.textContent`),
  );
  await say(ann, "@&Crew over here");
  const toCrew = lastMessage("over here");
  check("@&badge reaches the group's people", await seen(bob, `${toCrew}?.classList.contains("to-me")`), await bob.evaluate(`${toCrew}?.className ?? "no such message"`));

  // An invite link: shown once, its code in the sign-up form, gone from the address.
  await serverMenu(ann, "Server admin");
  await waitFor(ann, `document.querySelector(".admin-tabs")`);
  await tabTo("Users");
  // It reopens on the account last looked at
  await sleep(300);
  await ann.evaluate(`document.querySelector(".admin-dialog .btn-back")?.click(); 0`);
  await waitFor(ann, `document.querySelector('.admin-dialog select[aria-label="Starting group"]')`);
  await ann.evaluate(setInput('.admin-dialog select[aria-label="Starting group"]', "crew"));
  await sleep(200);
  await ann.evaluate(`${byText(".admin-dialog button", "Make link")}.click()`);
  await waitFor(ann, `[...document.querySelectorAll(".admin-dialog .code")].find((c) => c.textContent.includes("#join="))`);
  const link = await ann.evaluate(`[...document.querySelectorAll(".admin-dialog .code")].find((c) => c.textContent.includes("#join=")).textContent`);
  check("a link is shown once, on this server", link.startsWith(`https://127.0.0.1:${PORT}/#join=`), link);
  const usedRow = `[...document.querySelectorAll(".admin-dialog .row-name")].some((r) => r.textContent.includes("1 of 1000"))`;

  const cat = await openDialog(three, new URL(link).hash);
  check(
    "the link opens the sign-up with its code in place",
    await cat.evaluate(`document.querySelector("#signup-invite")?.value === ${JSON.stringify(new URL(link).hash.slice(6))}`),
    await cat.evaluate(`document.querySelector("#signup-invite")?.value ?? "no field"`),
  );
  check("and the address bar no longer holds it", (await cat.evaluate(`location.hash`)) === "");
  await cat.evaluate(setInput("#account-name", "cathy"));
  await cat.evaluate(setInput("#account-password", PASSWORD));
  await cat.evaluate(setInput("#account-password2", PASSWORD));
  await cat.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(cat, `document.querySelector('${dialogOf("recovery")}')`, 60_000);
  await cat.evaluate(`document.querySelector('${dialogOf("recovery")} .submit-btn').click()`);
  await settle(cat);
  // The list is read when the tab opens
  await tabTo("Groups");
  await sleep(300);
  await tabTo("Users");
  check(
    "someone new lands in the welcome channel, whenever its layout came",
    await seen(cat, `document.querySelector(".chat-title")?.textContent.includes("dungeon")`, 8_000),
    await cat.evaluate(`document.querySelector(".chat-title")?.textContent ?? "no chat open"`),
  );
  check("signing up with it counts a use", await seen(ann, usedRow), await ann.evaluate(`document.querySelector(".admin-dialog")?.innerText.slice(-300) ?? ""`));
  await ann.evaluate(`document.querySelector(".admin-dialog .close-btn, .admin-dialog [aria-label='Close']")?.click(); 0`);
  await openChat(cat, "lobby-chat");
  const inCrew = `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes("cathy"))?.textContent.includes("Crew")`;
  check("and it starts in the link's group", await seen(cat, inCrew), await cat.evaluate(`document.querySelector(".user-list.modern")?.innerText ?? ""`));

  // Someone holding `voipc:channels` and nothing the panel used to open for
  await turnOnCodes(cat);
  await serverMenu(ann, "Server admin");
  await waitFor(ann, `document.querySelector(".admin-tabs")`);
  await tabTo("Users");
  await sleep(300);
  await ann.evaluate(`document.querySelector(".admin-dialog .btn-back")?.click(); 0`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Search accounts"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Search accounts"]', "cathy"));
  await ann.evaluate(`document.querySelector('.admin-dialog form[role="search"] button[type="submit"]').click()`);
  const cathyRow = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent === "cathy")`;
  await waitFor(ann, cathyRow);
  await ann.evaluate(`${cathyRow}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[data-group="moderator"]')`);
  await ann.evaluate(`document.querySelector('.admin-dialog input[data-group="moderator"]').click()`);
  await stepUp();
  const panel = await seen(cat, `(document.querySelector(".server-header .menu") || document.querySelector(".server-header .header-btn").click(), ${byText(".server-header .menu > button", "Server admin")})`, 20_000);
  check("a moderator's menu opens the panel", panel, await cat.evaluate(`document.querySelector(".server-header .menu")?.innerText ?? ""`));
  if (panel) {
    await cat.evaluate(`${byText(".server-header .menu > button", "Server admin")}.click()`);
    check("on the Channels tab", await seen(cat, `document.querySelector('.admin-dialog input[aria-label="Channel name"]')`, 8_000), await cat.evaluate(`document.querySelector(".admin-dialog")?.innerText.slice(0, 300) ?? ""`));
  }

  // The same link through a provider: the buttons are there beside its code
  const dee = await openDialog(four, new URL(link).hash);
  await throughProvider(dee, four);
  await waitFor(dee, `document.querySelector('${dialogOf("provider-name")}')`);
  await dee.evaluate(setInput("#acct-provider-name", "deedee"));
  await dee.evaluate(`document.querySelector('${dialogOf("provider-name")} .submit-btn').click()`);
  await waitFor(dee, `document.querySelector('${dialogOf("provider-choice")}')`, 60_000);
  await dee.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await waitFor(dee, `document.querySelector('${dialogOf("provider-choice")}')?.innerText.includes("used this account before")`);
  await dee.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  // Its yes goes live a moment after it shows
  await waitFor(dee, `document.querySelector('${dialogOf("provider-key")} .submit-btn:enabled')`);
  await dee.evaluate(`document.querySelector('${dialogOf("provider-key")} .submit-btn').click()`);
  await settle(dee);
  await openChat(dee, "lobby-chat");
  const deeRow = `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes("deedee"))`;
  check("through a provider, a link starts in its group too", await seen(dee, `${deeRow}?.textContent.includes("Crew")`), await dee.evaluate(`document.querySelector(".user-list.modern")?.innerText ?? ""`));

  // A group's section turned off: the badge stays, the heading goes
  const crewHeading = `[...document.querySelectorAll(".user-list.modern .group-label")].some((l) => l.textContent.startsWith("Crew"))`;
  check("before, its people stand under it", await seen(dee, crewHeading));
  await tabTo("Groups");
  const crewRow = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent.trim().startsWith("crew"))`;
  await waitFor(ann, crewRow);
  await ann.evaluate(`${crewRow}.click()`);
  const sectionBox = `document.querySelector('.admin-dialog input[aria-label="Own section in the member list"]')`;
  await waitFor(ann, sectionBox);
  await ann.evaluate(`${sectionBox}.click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  check("turned off, the heading goes", await seen(dee, `!(${crewHeading})`), await dee.evaluate(`document.querySelector(".user-list.modern")?.innerText ?? ""`));
  check("and the badge stays", await dee.evaluate(`!!${deeRow}?.textContent.includes("Crew")`));

  // Sharing history: a switch each person turns on, and here also a privilege an admin gives.
  const shareBox = `[...document.querySelectorAll(".toggle-row")].find((r) => r.textContent.includes("Share recent channel chat"))?.querySelector("input")`;
  const shareReach = `document.querySelector(".share-reach")?.textContent ?? ""`;
  const openShare = async (tab) => {
    await tab.evaluate(`document.querySelector(".settings-btn").click()`);
    await waitFor(tab, byText(".tabs .tab", "Privacy"));
    await tab.evaluate(`${byText(".tabs .tab", "Privacy")}.click()`);
    await waitFor(tab, shareBox);
  };
  const closeShare = async (tab) => {
    await tab.evaluate(`document.querySelector(".panel .close-btn").click()`);
    await sleep(200);
  };
  const rowOf = (name) => `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes(${JSON.stringify(name)}))`;
  const marked = (name) => `!!${rowOf(name)}?.querySelector(".sharing-history")`;
  await openChat(cat, "lobby-chat");
  await openChat(dee, "lobby-chat");
  // A text channel, frame by frame: the first time these two meet. The post goes first, the
  // reader opens the session, the key follows.
  const heard = async (tab) => (await tab.evaluate(`window.__voipc_heard.splice(0)`)) ?? [];
  const tagsOf = (frames) => frames.map(([tag]) => tag);
  await Promise.all([heard(cat), heard(dee), heard(ann)]);
  await say(dee, "for whoever comes later");
  await waitFor(cat, lastMessage("for whoever comes later"), 60_000);
  const reader = tagsOf(await heard(cat));
  const writer = tagsOf(await heard(dee));
  check("a post comes ahead of its key", reader.includes("TextPost") && reader.indexOf("TextPost") < reader.indexOf("TextKeyReceived"), reader.join(" "));
  check("and the reader is who opens the session", reader.includes("SessionAsked") && reader.indexOf("SessionAsked") < reader.indexOf("TextKeyReceived"), reader.join(" "));
  check("the writer asks whom it owes, and hears the hello", writer.includes("KeysOwed") && writer.includes("SessionHello"), writer.join(" "));
  check("no frame of the old way reaches anyone", ![...reader, ...writer].some((t) => ["EncryptedChannelChatMessage", "SenderKeyReceived"].includes(t)), [...reader, ...writer].join(" "));

  // On, without the privilege: nothing changes, and the switch says why
  await openShare(cat);
  await sleep(800);
  check(
    "a tab that asks about Discord posts by itself gives no toast for an account with none linked",
    !(await cat.evaluate(`[...document.querySelectorAll(".toast")].some((t) => t.textContent.includes("Link your Discord"))`)),
    await cat.evaluate(`[...document.querySelectorAll(".toast")].map((t) => t.textContent).join(" | ")`),
  );
  check("the switch starts off", !(await cat.evaluate(`${shareBox}.checked`)));
  await cat.evaluate(`${shareBox}.click()`);
  check(
    "beside the switch, why it does nothing here",
    await seen(cat, `(${shareReach}).startsWith("Not on this server: none of your groups")`),
    await cat.evaluate(shareReach),
  );
  await closeShare(cat);
  await openShare(dee);
  await dee.evaluate(`${shareBox}.click()`);
  await closeShare(dee);
  const newcomerTab = await newTab(await browser(PORT + 105));
  await newcomerTab.send("Page.navigate", { url: `${ORIGIN}/` });
  await waitFor(newcomerTab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  await newcomerTab.evaluate(`document.querySelector(".skip-link")?.click(); 0`);
  await waitFor(newcomerTab, `document.querySelector(".connect-btn")`);
  await newcomerTab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await newcomerTab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await newcomerTab.evaluate(setInput('input[placeholder="Your name"]', "nora"));
  await newcomerTab.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(newcomerTab, `document.querySelector(".channel-list")`, 60_000);
  await settle(newcomerTab);
  await openChat(newcomerTab, "lobby-chat");
  check("being there asked nobody for a key", !tagsOf(await heard(newcomerTab)).some((t) => ["PreKeyBundle", "SessionAsked", "TextKeyReceived"].includes(t)));
  const joinsHeard = (await heard(ann)).filter(([tag, channel]) => tag === "UserJoined" && channel !== 0);
  check("and nobody is told she follows a channel", joinsHeard.length === 0, JSON.stringify(joinsHeard));
  await openShare(newcomerTab);
  await newcomerTab.evaluate(`${shareBox}.click()`);
  check("a guest is told too, and not told to sign in", await seen(newcomerTab, `(${shareReach}) === "Not on this server for a guest."`), await newcomerTab.evaluate(shareReach));
  await closeShare(newcomerTab);
  await sleep(1500);
  const noMark = async () => !(await newcomerTab.evaluate(marked("deedee"))) && !(await newcomerTab.evaluate(marked("cathy"))) && !(await newcomerTab.evaluate(marked("nora")));
  check("with the switch on and no privilege, no mark on anyone: a guest's neither", await noMark());
  check("and nobody to ask", !(await newcomerTab.evaluate(`!!document.querySelector(".resync-btn")`)));
  check("and nothing handed over", !(await newcomerTab.evaluate(lastMessage("for whoever comes later"))));
  const emptyLine = `document.querySelector(".empty-state")?.textContent ?? ""`;
  check(
    "the empty channel says people wrote before, and not that nobody has a copy",
    await seen(newcomerTab, `(${emptyLine}).includes("People wrote here before. Nobody online shares it, so you read from now on.")`),
    await newcomerTab.evaluate(emptyLine),
  );

  // Opening a followed channel tells the relay nothing, on a screen with no one to ask
  const said = async (tab) => JSON.stringify((await tab.evaluate(`window.__voipc_said.splice(0)`)) ?? []);
  await sleep(1000);
  await said(newcomerTab);
  for (const name of ["side-a", "side-b", "side-c"]) {
    await openChat(newcomerTab, name);
    await sleep(300);
  }
  await sleep(1200);
  const openingSaid = await said(newcomerTab);
  check("three channels opened: nothing that names one goes out", !/channel_id|channelId|"conv"/.test(openingSaid), openingSaid);
  check("and nobody asked about who is there", !/RequestChannel/.test(openingSaid), openingSaid);
  await openChat(newcomerTab, "lobby-chat");

  // The group that gives it. It applies at once, with no codes
  await tabTo("Groups");
  await waitFor(ann, byText(".admin-dialog button", "New group"));
  await ann.evaluate(`${byText(".admin-dialog button", "New group")}.click()`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Group name"]')`);
  const shareScope = `document.querySelector('.admin-dialog input[data-scope="voipc:share_history"]')`;
  check("the editor offers Share history, unticked", await seen(ann, `${shareScope}?.checked === false`));
  check("and says it applies at once", await ann.evaluate(`document.querySelector(".group-form").innerText.includes("except Share history, which applies at once")`));
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Group name"]', "sharers"));
  await ann.evaluate(`${shareScope}.click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  const sharersRow = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent.trim().startsWith("sharers"))`;
  await waitFor(ann, sharersRow);
  await tabTo("Users");
  await sleep(300);
  await ann.evaluate(`document.querySelector(".admin-dialog .btn-back")?.click(); 0`);
  await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Search accounts"]')`);
  await ann.evaluate(setInput('.admin-dialog input[aria-label="Search accounts"]', "deedee"));
  await ann.evaluate(`document.querySelector('.admin-dialog form[role="search"] button[type="submit"]').click()`);
  const deeUser = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent === "deedee")`;
  await waitFor(ann, deeUser);
  await ann.evaluate(`${deeUser}.click()`);
  const sharersBox = `document.querySelector('.admin-dialog input[data-group="sharers"]')`;
  await waitFor(ann, sharersBox);
  check(
    "a share-only group's row says what it gives, not codes",
    await ann.evaluate(`${sharersBox}.closest(".check-row").textContent.includes("Can share history, if they turn it on")`),
  );
  await ann.evaluate(`${sharersBox}.click()`);
  await stepUp();

  // deedee's switch was on: she shares now, and nobody reconnected
  check("with the privilege the switch counts: the mark comes, and nobody reconnects", await seen(newcomerTab, marked("deedee"), 30_000), await newcomerTab.evaluate(`${rowOf("deedee")}?.outerHTML ?? "no row"`));
  check("the mark has words a phone can read", await newcomerTab.evaluate(`${rowOf("deedee")}.querySelector(".sharing-history").getAttribute("aria-label") === "Shares history with newcomers"`));
  check("the control: someone without it still has none", !(await newcomerTab.evaluate(marked("cathy"))));
  check("and a guest has none", !(await newcomerTab.evaluate(marked("nora"))));
  await openShare(dee);
  check("beside the switch, nothing to explain any more", (await dee.evaluate(shareReach)) === "", await dee.evaluate(shareReach));
  await closeShare(dee);
  check("now there is someone to ask", await seen(newcomerTab, `document.querySelector(".resync-btn")`));
  check("and the empty channel names her and offers it", await seen(newcomerTab, `(${emptyLine}).includes("deedee shares recent messages.") && document.querySelector(".empty-state .join-text-btn")?.textContent === "Ask"`), await newcomerTab.evaluate(emptyLine));
  await heard(dee);
  await said(newcomerTab);
  await newcomerTab.evaluate(`document.querySelector(".empty-state .join-text-btn").click()`);
  check("and asked, she hands it over", await seen(newcomerTab, lastMessage("for whoever comes later"), 30_000));
  check("as a member's copy", await newcomerTab.evaluate(`!!${lastMessage("for whoever comes later")}?.querySelector(".shared-tag")`));
  const asking = await said(newcomerTab);
  check("the ask names no channel on the wire", !/RequestChannelHistory/.test(asking), asking);
  check("to the relay it is a direct message", tagsOf(await heard(dee)).includes("EncryptedDirectChatMessage"));

  // Someone new, opening it for the first time: asked without a click, and a second opening asks nothing
  const nilsTab = await newTab(await browser(PORT + 108));
  await nilsTab.send("Page.navigate", { url: `${ORIGIN}/` });
  await waitFor(nilsTab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  await nilsTab.evaluate(`document.querySelector(".skip-link")?.click(); 0`);
  await waitFor(nilsTab, `document.querySelector(".connect-btn")`);
  await nilsTab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await nilsTab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await nilsTab.evaluate(setInput('input[placeholder="Your name"]', "nils"));
  await nilsTab.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(nilsTab, `document.querySelector(".channel-list")`, 60_000);
  await settle(nilsTab);
  await heard(dee);
  await sleep(1500);
  check("connecting asked nobody for history", !tagsOf(await heard(dee)).includes("EncryptedDirectChatMessage"));
  await openChat(nilsTab, "lobby-chat");
  check("a first opening asks, with no click", await seen(nilsTab, lastMessage("for whoever comes later"), 30_000));
  await openChat(nilsTab, "side-a");
  await openChat(nilsTab, "lobby-chat");
  await sleep(2000);
  await heard(dee);
  await openChat(nilsTab, "side-a");
  await openChat(nilsTab, "lobby-chat");
  await sleep(1500);
  check("a second opening asks nothing", !tagsOf(await heard(dee)).includes("EncryptedDirectChatMessage"));
  check(`no page error on nils's side`, nilsTab.errors.length === 0, nilsTab.errors.join(" | ").slice(0, 400));

  // Taken from the group: gone for everyone, with nobody reconnecting
  await tabTo("Groups");
  await waitFor(ann, sharersRow);
  await ann.evaluate(`${sharersRow}.click()`);
  await waitFor(ann, `${shareScope}?.checked === true`);
  await ann.evaluate(`${shareScope}.click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  check("unticked, the mark goes", await seen(newcomerTab, `!(${marked("deedee")})`, 30_000));
  check("with nobody signed out", (await dee.evaluate(`!!document.querySelector(".channel-list") && !document.querySelector(".connect-btn")`)));
  check("and there is nobody to ask", await seen(newcomerTab, `!document.querySelector(".resync-btn")`));

  // The copies question: no box without the right, unticked with it
  const asksCopies = async (cdp, name) => {
    const tab = await openDialog(cdp);
    await tab.evaluate(`document.querySelector(".mode-switch.small button:nth-child(2)").click()`);
    await waitFor(tab, `document.querySelector("#account-password2")`);
    await tab.evaluate(setInput("#account-name", name));
    await tab.evaluate(setInput("#account-password", PASSWORD));
    await tab.evaluate(setInput("#account-password2", PASSWORD));
    await tab.evaluate(`document.querySelector(".connect-btn").click()`);
    await waitFor(tab, `document.querySelector('${dialogOf("recovery")}')`, 60_000);
    await tab.evaluate(`document.querySelector('${dialogOf("recovery")} .submit-btn').click()`);
    await waitFor(tab, `document.querySelector('${dialogOf("cloud")}')`, 30_000);
    const box = await tab.evaluate(`document.querySelector('${dialogOf("cloud")} input[type="checkbox"]')?.checked ?? "no box"`);
    const says = await tab.evaluate(`document.querySelector('${dialogOf("cloud")}').innerText`);
    await settle(tab);
    return [tab, box, says];
  };
  const [plain, plainBox, plainSays] = await asksCopies(await browser(PORT + 106), "oskar");
  check("no right: no box, and not a word about it", plainBox === "no box" && !/join a channel later/.test(plainSays), `${plainBox}: ${plainSays}`);
  await tabTo("Groups");
  const userRow = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent.trim().startsWith("user"))`;
  await waitFor(ann, userRow);
  await ann.evaluate(`${userRow}.click()`);
  await waitFor(ann, `${shareScope}?.checked === false`);
  await ann.evaluate(`${shareScope}.click()`);
  check("ticked on `user`, the editor says what that means", await seen(ann, `document.querySelector(".group-form").innerText.includes("Every account here may then share")`));
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  await waitFor(ann, userRow);
  const [held, heldBox, heldSays] = await asksCopies(await browser(PORT + 107), "paula");
  check("with the right: the box, unticked", heldBox === false && /join a channel later/.test(heldSays), `${heldBox}: ${heldSays}`);
  check("given to `user`, whoever had the switch on shares", await seen(newcomerTab, marked("cathy"), 30_000));
  check("and whoever had it off does not", !(await newcomerTab.evaluate(marked("oskar"))) && !(await newcomerTab.evaluate(marked("paula"))));
  // Now someone shares: what she keeps opens for whoever takes a seat later. Their wait on her
  // ends with the last frame of her answer, and the reader goes on from there.
  await openChat(cat, "lobby-chat");
  await say(cat, "kept by someone who shares");
  await waitFor(dee, lastMessage("kept by someone who shares"), 60_000);
  await sleep(1500);
  const ivy = await openDialog(await browser(PORT + 110));
  await createAccount(ivy, "ivy");
  await settle(ivy);
  await openChat(ivy, "lobby-chat");
  check("a sharer's answer reaches a newcomer: what she kept opens", await seen(ivy, lastMessage("kept by someone who shares"), 60_000), await ivy.evaluate(`document.querySelector(".messages")?.innerText.slice(-400) ?? ""`));
  check("no page error on ivy's side", ivy.errors.length === 0, ivy.errors.join(" | ").slice(0, 400));
  await ivy.send("Page.close").catch(() => {});
  await ann.evaluate(`${userRow}.click()`);
  await waitFor(ann, `${shareScope}?.checked === true`);
  await ann.evaluate(`${shareScope}.click()`);
  await ann.evaluate(`document.querySelector('.group-form button[type="submit"]').click()`);
  await stepUp();
  await waitFor(ann, userRow);
  check("taken from `user`, the mark goes again", await seen(newcomerTab, `!(${marked("cathy")})`, 30_000));
  for (const [who, tab] of [["nora", newcomerTab], ["oskar", plain], ["paula", held]]) {
    check(`no page error on ${who}'s side`, tab.errors.length === 0, tab.errors.join(" | ").slice(0, 400));
  }

  // A link that drops: an account's sessions wait for its next connection, in memory, so a
  // writer back from it wraps at once, under a new id, and nobody opens anything.
  await say(cat, "before the cut");
  await waitFor(dee, lastMessage("before the cut"), 60_000);
  await sleep(2500);
  await Promise.all([heard(cat), heard(dee)]);
  await cat.evaluate(`window.__voipc_cut("127.0.0.1:${PORT}"); 0`);
  check("the writer comes back by itself", await seen(cat, `window.__voipc_heard.some(([tag]) => tag === "Authenticated")`, 60_000));
  check(
    "on the channel they had open, with its input bar, and no click",
    await seen(cat, `document.querySelector(".chat-title")?.textContent.includes("lobby-chat") && document.querySelector(".input-bar .chat-input")`, 30_000),
    await cat.evaluate(`document.querySelector(".chat-panel, .messages")?.innerText.slice(0, 200) ?? ""`),
  );
  check("the rows there still shown", await seen(cat, lastMessage("before the cut")), await cat.evaluate(`document.querySelector(".messages")?.innerText.slice(-200) ?? ""`));
  check("the drop is said once, and the toast goes at the reconnect", await seen(cat, `![...document.querySelectorAll(".toast")].some((t) => t.textContent.includes("Connection lost"))`), await cat.evaluate(`[...document.querySelectorAll(".toast")].map((t) => t.textContent).join(" | ")`));
  await sleep(1500);
  await heard(dee);
  await say(cat, "after the cut");
  check("and is read", await seen(dee, lastMessage("after the cut"), 60_000), await dee.evaluate(`document.querySelector(".messages")?.innerText.slice(-300) ?? ""`));
  const afterCut = tagsOf(await heard(dee));
  check("on a session kept from before: a key, and no one asked to open", afterCut.includes("TextKeyReceived") && !afterCut.includes("SessionAsked"), afterCut.join(" "));

  // A reader that reloads has no session any more: the wrap fails, one reset, a new one.
  await dee.send("Page.reload");
  await waitFor(dee, `window.__voipc_heard?.some(([tag]) => tag === "TextJoined")`, 60_000);
  await openChat(dee, "lobby-chat");
  // Past the writer's check of two seconds ago, or this post is one the log brings
  await sleep(2500);
  await say(cat, "after the reload");
  check("a reader back from a reload reads on", await seen(dee, lastMessage("after the reload"), 60_000), await dee.evaluate(`document.querySelector(".messages")?.innerText.slice(-300) ?? ""`));
  const afterReload = tagsOf(await heard(dee));
  check("by opening a new session", afterReload.includes("SessionAsked"), afterReload.join(" "));

  // Written while away, and nobody to ask: a ring on the row, and opening it clears it.
  await openChat(newcomerTab, "side-a");
  await sleep(6000);
  await newcomerTab.evaluate(`window.__voipc_cut("127.0.0.1:${PORT}"); 0`);
  await say(cat, "while nora was away");
  const noraRow = byText(".channel-list.modern .channels.text .channel", "lobby-chat");
  check("back from a cut, the row has a ring", await seen(newcomerTab, `!!${noraRow}?.querySelector(".channel-ring")`, 60_000), await newcomerTab.evaluate(`${noraRow}?.outerHTML ?? "no row"`));
  check("and the post itself is not here", !(await newcomerTab.evaluate(lastMessage("while nora was away"))));
  await openChat(newcomerTab, "lobby-chat");
  check("opening it says what is known", await seen(newcomerTab, `document.querySelector(".ring-line")?.textContent.includes("Written while you were away. Nobody online shares it.")`), await newcomerTab.evaluate(`document.querySelector(".messages")?.innerText.slice(-200) ?? ""`));
  check("and with nobody left to ask the row is plain", await seen(newcomerTab, `!${noraRow}?.querySelector(".channel-ring")`));

  // A channel joined by hand goes by a list. A dot, a name once, and whoever leaves is off it at once.
  const joinByHand = async (tab, name) => {
    const row = byText(".channel-list.modern .channels.text .channel", name);
    await waitFor(tab, row);
    await tab.evaluate(`${row}.click()`);
    await waitFor(tab, `document.querySelector(".join-text-btn")`);
    await tab.evaluate(`document.querySelector(".join-text-btn").click()`);
    await waitFor(tab, `document.querySelector(".input-bar .chat-input")`);
  };
  await joinByHand(cat, "dungeon");
  await joinByHand(dee, "dungeon");
  const namesList = `document.querySelector(".user-list.modern .users")?.innerText ?? ""`;
  check("a click on Join brings the list with it", await seen(dee, `(${namesList}).includes("cathy")`), await dee.evaluate(namesList));
  check("with a way to ask again, and how old it may be", await dee.evaluate(`!!document.querySelector(".refresh-list")`));
  await sleep(2500);
  await say(cat, "only the two of us");
  check("the post reaches the other", await seen(dee, lastMessage("only the two of us"), 60_000));
  const namedLine = `[...document.querySelectorAll(".history-marker")].some((m) => m.textContent.includes("deedee can now read what you write here"))`;
  check("the writer's app names who it handed a key", await seen(cat, namedLine), await cat.evaluate(`document.querySelector(".messages")?.innerText.slice(-300) ?? ""`));
  await sleep(2500);
  await say(cat, "and again");
  await waitFor(dee, lastMessage("and again"), 60_000);
  await sleep(500);
  check("once", (await cat.evaluate(`[...document.querySelectorAll(".history-marker")].filter((m) => m.textContent.includes("can now read what you write here")).length`)) === 1);
  await openChat(dee, "lobby-chat");
  await say(cat, "a dot on the row");
  const dungeonRowOf = byText(".channel-list.modern .channels.text .channel", "dungeon");
  check("off screen, an ordinary post is a dot", await seen(dee, `!!${dungeonRowOf}?.querySelector(".channel-dot, .channel-unread")`, 60_000), await dee.evaluate(`${dungeonRowOf}?.outerHTML ?? "no row"`));
  await openChat(dee, "dungeon");
  check("opening clears it", await seen(dee, `!${dungeonRowOf}?.querySelector(".channel-dot, .channel-unread")`));
  await dee.evaluate(`[...${dungeonRowOf}.parentElement.querySelectorAll(".settings-icon")].find((b) => b.title.startsWith("Leave this channel")).click()`);
  check("whoever leaves is off the list at once, with nobody asking", await seen(cat, `!(${namesList}).includes("deedee")`), await cat.evaluate(namesList));
  await openChat(dee, "lobby-chat");
  await openChat(cat, "lobby-chat");

  // Someone who has gone: no live row to open the menu on, and their name stands on old posts.
  const openOnUsers = async (name) => {
    await ann.evaluate(`document.querySelector(".admin-dialog .btn-back")?.click(); 0`);
    await waitFor(ann, `document.querySelector('.admin-dialog input[aria-label="Search accounts"]')`);
    await ann.evaluate(setInput('.admin-dialog input[aria-label="Search accounts"]', name));
    await ann.evaluate(`document.querySelector('.admin-dialog form[role="search"] button[type="submit"]').click()`);
    const person = `[...document.querySelectorAll(".admin-dialog .list-row")].find((r) => r.querySelector(".row-name")?.textContent === ${JSON.stringify(name)})`;
    await waitFor(ann, person);
    await ann.evaluate(`${person}.click()`);
    await waitFor(ann, byText(".admin-dialog .section-title", "Groups"));
  };
  await openChat(bob, "lobby-chat");
  await say(bob, "gone soon");
  const oldPost = lastMessage("gone soon");
  check("an old post shows the chosen name", await seen(dee, `${oldPost}?.textContent.includes("Robert Example")`), await dee.evaluate(`${oldPost}?.textContent ?? "no such post"`));
  await serverMenu(bob, "Disconnect");
  await waitFor(bob, `document.querySelector(".connect-btn")`);
  await tabTo("Users");
  await openOnUsers("bobby");
  const clearIt = `document.querySelector(".admin-dialog .clear-profile")`;
  check("the Users tab offers to clear someone who has gone", await seen(ann, clearIt), await ann.evaluate(`document.querySelector(".admin-dialog")?.innerText.slice(0, 400) ?? ""`));
  check("under the name they chose", await ann.evaluate(`document.querySelector(".admin-dialog .section-title")?.textContent.includes("Robert Example")`));
  await ann.send("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(300);
  check(
    "beside the other actions, all on a phone's screen",
    await ann.evaluate(`[...document.querySelectorAll(".admin-dialog .account-actions button")].every((b) => b.getBoundingClientRect().right <= innerWidth && b.getBoundingClientRect().left >= 0)`),
    await ann.evaluate(`JSON.stringify([...document.querySelectorAll(".admin-dialog .account-actions button")].map((b) => [b.textContent.trim(), Math.round(b.getBoundingClientRect().left), Math.round(b.getBoundingClientRect().right)]))`),
  );
  await ann.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(300);
  await ann.evaluate(`${clearIt}.click()`);
  await waitFor(ann, byText(".confirm button", "Clear them"));
  await ann.evaluate(`${byText(".confirm button", "Clear them")}.click()`);
  check(
    "everyone connected sees it at once, on old posts too",
    await seen(dee, `${oldPost}?.textContent.includes("bobby") && !${oldPost}?.textContent.includes("Robert Example")`),
    await dee.evaluate(`${oldPost}?.textContent ?? "no such post"`),
  );
  check("the button going is what says it worked", await seen(ann, `!${clearIt}`));
  check("and their history says so in words", await seen(ann, `document.querySelector(".admin-dialog .history")?.textContent.includes("Display name or picture cleared")`), await ann.evaluate(`document.querySelector(".admin-dialog .history")?.textContent ?? ""`));
  await openOnUsers("cathy");
  await sleep(500);
  check("someone with nothing chosen has no such button", await ann.evaluate(`!${clearIt}`));
  await ann.evaluate(`document.querySelector(".admin-dialog .close-btn, .admin-dialog [aria-label='Close']")?.click(); 0`);

  // The tab a remembered name comes back on: Guest would only be told the name is taken.
  const onTab = (t) => `document.querySelector('.mode-switch [role="tab"][aria-selected="true"]')?.textContent.trim() === ${JSON.stringify(t)}`;
  await bob.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(bob, `document.querySelector("#account-name")`);
  await bob.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await bob.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await bob.evaluate(setInput("#account-name", "bobby"));
  await bob.evaluate(setInput("#account-password", PASSWORD));
  await bob.evaluate(`(() => { const box = [...document.querySelectorAll(".checkbox-label")].find((l) => l.textContent.includes("Remember connection details")).querySelector("input"); if (!box.checked) box.click(); })()`);
  await bob.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(bob, `document.querySelector(".channel-list")`, 60_000);
  await settle(bob);
  await serverMenu(bob, "Disconnect");
  await waitFor(bob, `document.querySelector(".connect-btn")`);
  const formSays = () => bob.evaluate(`document.querySelector(".mode-switch")?.parentElement?.innerText.slice(0, 300) ?? ""`);
  check("a remembered account comes back on the Account tab", await seen(bob, `${onTab("Account")} && document.querySelector("#account-name")?.value === "bobby"`), await formSays());
  await bob.send("Page.reload");
  await waitFor(bob, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`, 60_000);
  await bob.evaluate(`document.querySelector(".skip-link")?.click(); 0`);
  await waitFor(bob, `document.querySelector(".connect-btn")`);
  check("and after a new start", await seen(bob, `${onTab("Account")} && document.querySelector("#account-name")?.value === "bobby"`), await formSays());
  await bob.evaluate(`document.querySelector(".mode-switch button:nth-child(1)").click()`);
  await waitFor(bob, `document.querySelector('input[placeholder="Your name"]')`);
  await bob.evaluate(setInput('input[placeholder="Your name"]', "walker"));
  await bob.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(bob, `document.querySelector(".channel-list")`, 60_000);
  await settle(bob);
  await serverMenu(bob, "Disconnect");
  await waitFor(bob, `document.querySelector(".connect-btn")`);
  check("a remembered guest comes back on the Guest tab", await seen(bob, `${onTab("Guest")} && document.querySelector('input[placeholder="Your name"]')?.value === "walker"`), await formSays());

  // Kept copies on chains and buckets, across real browsers: a browser keeps no chat of its
  // own, so whatever a reload shows came back from the server's copy and opened here.
  const messagesOf = (tab) => tab.evaluate(`document.querySelector(".messages")?.innerText.slice(-400) ?? ""`);
  const reloaded = async (tab) => {
    await tab.evaluate(`window.__voipc_heard?.splice(0); 0`);
    await tab.send("Page.reload");
    await waitFor(tab, `window.__voipc_heard?.some(([tag]) => tag === "TextJoined")`, 60_000);
    await openChat(tab, "lobby-chat");
  };
  await openChat(cat, "lobby-chat");
  await openChat(held, "lobby-chat");
  await say(cat, "kept for later");
  await waitFor(held, lastMessage("kept for later"), 60_000);
  await sleep(1500);
  await reloaded(held);
  check("kept: a reload reads it back", await seen(held, lastMessage("kept for later"), 60_000), await messagesOf(held));

  await serverMenu(held, "Disconnect");
  await waitFor(held, `document.querySelector(".connect-btn")`);
  // Who she met goes on a page as she leaves, and only the rest of her memory in localStorage
  const heldMemory = `Object.entries(localStorage).filter(([k]) => k.startsWith("voipc.cursors.") && k.endsWith("|paula")).map(([, v]) => JSON.parse(v))[0]`;
  // The form is back before the leaving has done: the page, its answer, then the index
  const pinsSaved = await seen(held, `(() => { const g = (${heldMemory})?.vault_gens ?? {}; return g["pins.0"] > 0 && g["item.pins"] > 0; })()`, 10_000);
  const heldLeft = await held.evaluate(heldMemory);
  check("pins: saved on a page as she left, and the index after it", pinsSaved, JSON.stringify(heldLeft?.vault_gens));
  check("and who was named lives apart from what localStorage keeps", Object.keys(heldLeft?.readers ?? {}).length === 0, JSON.stringify(heldLeft));
  await say(cat, "while they were away");
  await sleep(1500);
  await held.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(held, `document.querySelector("#account-name")`);
  await held.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await held.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await held.evaluate(setInput("#account-name", "paula"));
  await held.evaluate(setInput("#account-password", PASSWORD));
  await held.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(held, `document.querySelector(".channel-list")`, 60_000);
  await settle(held);
  await openChat(held, "lobby-chat");
  check("kept: back from being away, it is there", await seen(held, lastMessage("while they were away"), 60_000), await messagesOf(held));
  check(
    "pins: read back with no word about them",
    !(await held.evaluate(`document.body.textContent.includes("the identities you pinned")`)),
    await held.evaluate(`document.body.textContent.slice(-300)`),
  );

  // Someone holding a key leaves: the writer's next post starts a new chain, and a reload
  // opens that one too.
  const leaveRow = `[...${byText(".channel-list.modern .channels.text .channel", "lobby-chat")}.parentElement.querySelectorAll(".settings-icon")].find((b) => b.title.startsWith("Leave this channel"))`;
  await openChat(plain, "lobby-chat");
  await waitFor(plain, leaveRow);
  await plain.evaluate(`${leaveRow}.click()`);
  await sleep(1500);
  await say(cat, "after someone left");
  await waitFor(held, lastMessage("after someone left"), 60_000);
  await sleep(1500);
  await reloaded(held);
  check("kept: past a leave, a reload still reads it back", await seen(held, lastMessage("after someone left"), 60_000), await messagesOf(held));
  check("and what came before it", await seen(held, lastMessage("kept for later"), 30_000), await messagesOf(held));

  // The writer's own reload: it goes on from what it reads back of its chain
  await reloaded(cat);
  await sleep(1500);
  await say(cat, "the writer came back");
  await waitFor(held, lastMessage("the writer came back"), 60_000);
  await sleep(1500);
  await reloaded(held);
  check("kept: a writer back from a reload goes on, and is read back", await seen(held, lastMessage("the writer came back"), 60_000), await messagesOf(held));
  check("its own posts read back on its own page too", await seen(cat, lastMessage("kept for later"), 60_000), await messagesOf(cat));

  // Quiet mode: nothing tells a reader of a post on a chain they hold, so a channel that slept
  // is read as it comes on screen.
  const quietMode = async (tab, mode) => {
    await tab.evaluate(`document.querySelector(".settings-btn").click()`);
    await waitFor(tab, byText(".tabs .tab", "Privacy"));
    await tab.evaluate(`${byText(".tabs .tab", "Privacy")}.click()`);
    const box = `document.querySelector('select[aria-label="Quiet mode on this server"]')`;
    await waitFor(tab, box);
    await tab.evaluate(`(() => { const b = ${box}; b.value = ${JSON.stringify(mode)}; b.dispatchEvent(new Event("change", { bubbles: true })); })()`);
    await tab.evaluate(`document.querySelector(".panel .close-btn")?.click()`);
    await sleep(500);
  };
  await openChat(cat, "side-c");
  await say(cat, "side-c has a chain now");
  await sleep(1500);
  await quietMode(held, "always");
  await sleep(1500);
  await held.evaluate(`window.__voipc_heard?.splice(0); 0`);
  await say(cat, "while it slept");
  await sleep(4000);
  const asleep = tagsOf(await heard(held));
  check("kept: a channel asleep is sent no post", !asleep.includes("TextPost"), asleep.join(" "));
  await openChat(held, "side-c");
  check("kept: opening it reads what was written there", await seen(held, lastMessage("while it slept"), 30_000), await messagesOf(held));
  await quietMode(held, "off");
  await openChat(held, "lobby-chat");
  await openChat(cat, "lobby-chat");

  // Opening a channel that holds messages tells the relay nothing either: whoever wrote there
  // was asked for at connect, or when their row came. The first list drawn names no channel,
  // being everyone online, so it goes first.
  await openChat(cat, "side-a");
  await say(cat, "something in side-a");
  await openChat(cat, "side-b");
  await sleep(2500);
  await say(cat, "something in side-b");
  await sleep(2500);
  await openChat(cat, "lobby-chat");
  await held.evaluate(`window.__voipc_heard?.splice(0); 0`);
  await held.send("Page.reload");
  await waitFor(held, `window.__voipc_heard?.some(([tag]) => tag === "TextJoined")`, 60_000);
  await sleep(6000);
  await openChat(held, "side-c");
  await sleep(1500);
  await said(held);
  for (const [name, words] of [["side-a", "something in side-a"], ["side-b", "something in side-b"], ["lobby-chat", "kept for later"]]) {
    await openChat(held, name);
    check(`after a reload, ${name} holds what was kept`, await seen(held, lastMessage(words), 30_000), await messagesOf(held));
  }
  await sleep(1200);
  const readingSaid = await said(held);
  check("three channels with messages opened: no name is asked for", !/ProfilesGet/.test(readingSaid), readingSaid);
  check("and nothing that names one goes out", !/channel_id|channelId|"conv"/.test(readingSaid), readingSaid);

  // A gate lost and won back on one connection. One toast, and what she writes is kept again.
  const keepToasts = (tab) => tab.evaluate(`(() => { window.__toasts = [];
    new MutationObserver(() => { for (const e of document.querySelectorAll(".toast-message")) window.__toasts.includes(e.textContent) || window.__toasts.push(e.textContent); })
      .observe(document.body, { childList: true, subtree: true, characterData: true }); })()`);
  await keepToasts(held);
  const inCrew2 = async (on) => {
    await serverMenu(ann, "Server admin");
    await waitFor(ann, `document.querySelector(".admin-tabs")`);
    await tabTo("Users");
    await openOnUsers("paula");
    const box = `document.querySelector('.admin-dialog input[data-group="crew"]')`;
    await waitFor(ann, box);
    if ((await ann.evaluate(`${box}.checked`)) !== on) await ann.evaluate(`${box}.click()`);
    await stepUp();
    await sleep(500);
    await ann.evaluate(`document.querySelector(".admin-dialog .close-btn, .admin-dialog [aria-label='Close']")?.click(); 0`);
  };
  const sideC = byText(".channel-list.modern .channels.text .channel", "side-c");
  await inCrew2(true);
  await waitFor(ann, sideC);
  await ann.evaluate(`${sideC}.parentElement.querySelector('[aria-label="Channel settings"]').click()`);
  const gateCrew = `[...document.querySelectorAll('.gate-groups[data-gate="groups"] label')].find((l) => l.textContent.trim() === "crew")?.querySelector("input")`;
  await waitFor(ann, gateCrew);
  await ann.evaluate(`${gateCrew}.click()`);
  await ann.evaluate(`document.querySelector(".password-dialog button[type=submit]").click()`);
  await stepUp();
  await sleep(1000);
  await openChat(cat, "side-c");
  await openChat(held, "side-c");
  await say(cat, "for the crew");
  check("a gated channel reads, for someone in its group", await seen(held, lastMessage("for the crew"), 60_000), await messagesOf(held));
  await sleep(2500);
  await held.evaluate(`window.__toasts.length = 0; 0`);
  await inCrew2(false);
  check("out of its group, the channel goes from her list", await seen(held, `!${sideC}`), await held.evaluate(`document.querySelector(".channel-list.modern")?.innerText ?? ""`));
  await sleep(1000);
  const lostToasts = (await held.evaluate(`window.__toasts`)).filter((t) => t.includes("side-c"));
  check("and she is told, with exactly one toast", lostToasts.length === 1 && lostToasts[0].includes("You were removed from #side-c"), JSON.stringify(await held.evaluate(`window.__toasts`)));
  await inCrew2(true);
  check("back in it, the channel is back", await seen(held, sideC, 30_000));
  await sleep(1500);
  await openChat(held, "side-c");
  await held.evaluate(`window.__toasts.length = 0; 0`);
  await say(held, "won it back");
  check("what she writes reaches the channel", await seen(cat, lastMessage("won it back"), 60_000), await messagesOf(cat));
  await sleep(2500);
  check("and it is kept: no word that it is not", !(await held.evaluate(`window.__toasts.some((t) => t.includes("not kept") || t.includes("could not be read"))`)), JSON.stringify(await held.evaluate(`window.__toasts`)));
  await held.send("Page.reload");
  await waitFor(held, `window.__voipc_heard?.some(([tag]) => tag === "TextJoined")`, 60_000);
  await openChat(held, "side-c");
  check("and it reads back after a reload", await seen(held, lastMessage("won it back"), 60_000), await messagesOf(held));
  await openChat(held, "lobby-chat");

  // Someone new, with nobody sharing: they read from now on, and are told so without a fuss
  const gina = await openDialog(await browser(PORT + 108));
  await createAccount(gina, "gina");
  await settle(gina);
  await openChat(gina, "lobby-chat");
  const quiet = `document.querySelector(".messages")?.textContent.includes("Some earlier messages here can't be opened")`;
  check("a newcomer is told quietly what cannot be opened", await seen(gina, quiet, 60_000), await messagesOf(gina));
  check("and opens none of it", !(await gina.evaluate(lastMessage("kept for later"))));
  await sleep(1500);
  await openChat(cat, "lobby-chat");
  await say(cat, "for the newcomer too");
  await waitFor(gina, lastMessage("for the newcomer too"), 60_000);
  await sleep(1500);
  await reloaded(gina);
  check("kept: a newcomer's step reads back after a reload", await seen(gina, lastMessage("for the newcomer too"), 60_000), await messagesOf(gina));
  check("and still nothing before it", !(await gina.evaluate(lastMessage("kept for later"))));
  check("no page error on gina's side", gina.errors.length === 0, gina.errors.join(" | ").slice(0, 400));

  // Verify opens no session of its own: the key it was shown names one, and the bundle it came
  // in retires within the hour. A first message after that asks for a bundle of its own, so
  // it starts on keys the other side still holds.
  const memberRow = (name) => `[...document.querySelectorAll(".user-list.modern .user")].find((u) => u.textContent.includes(${JSON.stringify(name)}))`;
  const openMenuOn = async (tab, name) => {
    await tab.evaluate(`document.querySelector(".ctx-overlay")?.click(); 0`);
    await waitFor(tab, memberRow(name));
    await tab.evaluate(`${memberRow(name)}.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 }))`);
    await waitFor(tab, `document.querySelector(".ctx-menu")`);
  };
  const choose = async (tab, name, label) => {
    await openMenuOn(tab, name);
    await waitFor(tab, byText(".ctx-item", label));
    await tab.evaluate(`${byText(".ctx-item", label)}.click()`);
  };
  await said(gina);
  await choose(gina, "oskar", "Verify identity");
  await sleep(1500);
  await choose(gina, "oskar", "Verify identity");
  check("Verify shows the number with someone never met", await seen(gina, `document.querySelector('${dialogOf("safety")}')`), await gina.evaluate(`document.body.innerText.slice(-200)`));
  await gina.evaluate(`document.querySelector('${dialogOf("safety")} .submit-btn')?.click(); 0`);
  const verifying = await said(gina);
  check("asking for their key once", (verifying.match(/RequestPreKeyBundle/g) ?? []).length === 1, verifying);
  await choose(gina, "oskar", "Direct message");
  await waitFor(gina, `document.querySelector(".input-bar .chat-input")`);
  await say(gina, "a first word after verifying");
  check("a first message opens its own session", await seen(gina, `window.__voipc_said.some((m) => m?.RequestPreKeyBundle)`), await said(gina));
  const oskarDm = `[...document.querySelectorAll(".dm-entry")].find((d) => d.textContent.includes("gina"))`;
  check("and it arrives", await seen(plain, oskarDm, 30_000), await plain.evaluate(`document.querySelector(".dm-section")?.innerText ?? ""`));
  await plain.evaluate(`${oskarDm}.click()`);
  check("readable", await seen(plain, lastMessage("a first word after verifying")), await messagesOf(plain));

  // A poke from a member's menu with no conversation open: our own copy says to whom
  await openChat(gina, "lobby-chat");
  await choose(gina, "cathy", "Poke");
  await waitFor(gina, `document.querySelector(".poke-input")`);
  await gina.evaluate(setInput(".poke-input", "over here"));
  await gina.evaluate(`document.querySelector(".poke-send-btn").click()`);
  check("a poke's own row names who it was for", await seen(gina, `[...document.querySelectorAll(".dm-entry")].some((d) => d.textContent.includes("cathy"))`), await gina.evaluate(`document.querySelector(".dm-section")?.innerText ?? ""`));
  check("never \"Unknown\"", !(await gina.evaluate(`document.querySelector(".dm-section")?.innerText.includes("Unknown") ?? false`)));

  // A channel list past one frame: the reconnect goes by all of it, to a channel near its end.
  const longPort = PORT + 150;
  writeFileSync(join(WORK, "long.toml"), `host = "127.0.0.1"\ntcp_port = ${longPort}\nudp_port = ${longPort}\ncert_path = "server.crt"\nkey_path = "server.key"\n`);
  writeFileSync(join(WORK, "long.json"), JSON.stringify(Array.from({ length: 450 }, (_, i) => ({ name: `room-${i}`, description: "d".repeat(200), text: true }))));
  const longRelay = spawn(join(ROOT, "target/release/voipc-server"), ["-c", "long.toml", "--channels", "long.json"], { cwd: WORK, stdio: ["ignore", "ignore", "inherit"] });
  children.push(longRelay);
  await sleep(1500);
  const lena = await newTab(await browser(PORT + 109));
  await lena.send("Page.navigate", { url: `https://127.0.0.1:${longPort}/` });
  await waitFor(lena, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  await lena.evaluate(`document.querySelector(".skip-link")?.click(); 0`);
  await waitFor(lena, `document.querySelector(".connect-btn")`);
  await lena.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await lena.evaluate(setInput('input[placeholder="9987"]', String(longPort)));
  await lena.evaluate(setInput('input[placeholder="Your name"]', "lena"));
  await lena.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(lena, `document.querySelector(".channel-list")`, 60_000);
  await settle(lena);
  const farRow = byText(".channel-list.modern .channels.text .channel", "room-449");
  check("a long channel list is all here", await seen(lena, farRow, 30_000), await lena.evaluate(`document.querySelector(".channel-list.modern")?.innerText.slice(-200) ?? ""`));
  const listFrames = tagsOf(await lena.evaluate(`window.__voipc_heard.slice()`));
  check("having come in more than one frame, none of them a whole list", listFrames.filter((t) => t === "ChannelListMore").length >= 2 && !listFrames.includes("ChannelList"), listFrames.slice(0, 12).join(" "));
  await lena.evaluate(`${farRow}.click()`);
  await waitFor(lena, `document.querySelector(".join-text-btn")`);
  await lena.evaluate(`document.querySelector(".join-text-btn").click()`);
  await waitFor(lena, `document.querySelector(".input-bar .chat-input")`);
  await lena.evaluate(`window.__voipc_heard.splice(0); window.__voipc_cut("127.0.0.1:${longPort}"); 0`);
  check("it comes back by itself", await seen(lena, `window.__voipc_heard.some(([tag]) => tag === "Authenticated")`, 60_000));
  check(
    "into a channel joined by hand past the first frame, on screen",
    await seen(lena, `document.querySelector(".chat-title")?.textContent.includes("room-449") && document.querySelector(".input-bar .chat-input")`, 30_000),
    await lena.evaluate(`document.body.innerText.slice(0, 200)`),
  );
  check("no page error on lena's side", lena.errors.length === 0, lena.errors.join(" | ").slice(0, 400));

  // The first-run select: the chevron stands once, at its end, in either theme.
  const fresh = await newTab(await browser(PORT + 104));
  await fresh.send("Page.navigate", { url: `${ORIGIN}/` });
  await waitFor(fresh, `document.querySelector(".connect-btn")`);
  await fresh.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await fresh.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await fresh.evaluate(setInput('input[placeholder="Your name"]', "newcomer"));
  await fresh.evaluate(`document.querySelector(".connect-btn").click()`);
  await waitFor(fresh, `document.querySelector(".audio-setup .text-link")`, 60_000);
  await fresh.evaluate(`document.querySelector(".audio-setup .text-link").click()`);
  await waitFor(fresh, `document.querySelector(".audio-setup select.device")`);
  for (const theme of ["dark", "light"]) {
    await fresh.evaluate(`document.documentElement.dataset.theme = ${JSON.stringify(theme)}; 0`);
    const look = await fresh.evaluate(`(() => { const s = getComputedStyle(document.querySelector(".audio-setup select.device")); return [s.backgroundImage.includes("svg"), s.backgroundRepeat, s.backgroundPositionX]; })()`);
    check(`the device list's chevron stands once in the ${theme} theme`, look[0] === true && look[1] === "no-repeat" && look[2] !== "0%", JSON.stringify(look));
  }

  for (const [who, tab] of [["annika", ann], ["bobby", bob], ["cathy", cat], ["deedee", dee], ["a new device", fresh]]) {
    check(`no page error on ${who}'s side`, tab.errors.length === 0, tab.errors.join(" | ").slice(0, 400));
  }
}

try {
  await lane();
  console.log(failures ? `test-community: ${failures} failed` : "test-community: all checks passed");
  await stop(failures ? 1 : 0);
} catch (e) {
  console.log(`FAIL the lane stopped: ${e.stack ?? e}`);
  await stop(1);
}
