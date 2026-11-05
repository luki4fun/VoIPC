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
writeFileSync(join(WORK, "channels.json"), JSON.stringify([{ name: "lobby-chat", text: true, auto_join: true }]));
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
  await waitFor(dee, `document.querySelector('${dialogOf("recovery")}')`);
  await dee.evaluate(`document.querySelector('${dialogOf("recovery")} .submit-btn').click()`);
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

  for (const [who, tab] of [["annika", ann], ["bobby", bob], ["cathy", cat], ["deedee", dee]]) {
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
