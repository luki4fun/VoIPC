#!/usr/bin/env node
// Sign-in with a provider, in real browsers against a real relay: the buttons,
// the code, the provider's page back on the relay, claiming an account, the
// recovery key on a new device, and pairing two devices. Only the provider is a
// stand-in, on a local port. (session_tests.rs `providers` has the security rules;
// what only a browser shows, such as a wasm object the page cannot read, is here.)
//
//   VOIPC_SELFTEST=1 npm run web      # a release relay has no stand-in provider
//   node test-provider.mjs [port]
//
// No dependencies. Needs openssl and chromium (CHROME=/path/to/chrome).

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] ?? 49990);
const CHROME = process.env.CHROME ?? "chromium";
const ORIGIN = `https://127.0.0.1:${PORT}`;
const WORK = mkdtempSync(join(tmpdir(), "voipc-provider-"));
const children = [];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
function check(what, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${what}${!ok && detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

async function stop(code) {
  for (const c of children) c.kill("SIGKILL");
  // Chromium's helpers outlive it by a moment, and write as they go
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

// ── The stand-in provider ─────────────────────────────────────────────────

const subject = "424242";
const provider = createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    res.end(
      req.method === "POST"
        ? JSON.stringify({ access_token: "at", token_type: "Bearer" })
        : JSON.stringify({ id: subject, username: "dee_d", global_name: "Dee D" }),
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
`,
);
const relay = spawn(join(ROOT, "target/release/voipc-server"), ["-c", "server.toml"], {
  cwd: WORK,
  env: {
    ...process.env,
    VOIPC_OAUTH_DISCORD_ID: "client",
    VOIPC_OAUTH_DISCORD_SECRET: "secret",
    VOIPC_OAUTH_TEST_BASE: providerBase,
  },
  stdio: ["ignore", "ignore", "inherit"],
});
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
  await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  return { send, evaluate, errors };
}

async function waitFor(tab, expression, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return;
    await sleep(150);
  }
  const text = await tab.evaluate(`document.body?.innerText?.slice(0, 500) ?? ""`).catch(() => "");
  throw new Error(`timed out waiting for ${expression}\n--- page: ${text.replace(/\s+/g, " ")}`);
}

const setInput = (selector, value) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false;
    el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true })); return true; })()`;

/** The first element matching `selector` whose text has `text`, clicked. */
const clickText = (selector, text) =>
  `(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].find((e) => e.textContent.includes(${JSON.stringify(text)}));
    if (!el) return false; el.click(); return true; })()`;

const dialogOf = (kind) => `.account-dialog[data-kind="${kind}"]`;

/** The connect dialog on the relay's own page, with the Account tab open and
 *  `window.open` noted instead of opening anything. */
async function openDialog(cdpPort) {
  const tab = await newTab(cdpPort);
  await tab.send("Page.navigate", { url: `${ORIGIN}/` });
  await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(`document.querySelector(".skip-link").click()`);
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(`window.open = (url) => { window.__opened = url; return null; }; 0`);
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await tab.evaluate(`document.querySelector(".mode-switch button:nth-child(2)").click()`);
  await waitFor(tab, `document.querySelector("#account-name")`);
  return tab;
}

/** Up to the first thing the sign-in asks: a click on Continue, the code, the
 *  provider's page in a tab of its own, and the tap on the code there. */
async function throughProvider(tab, cdpPort) {
  await waitFor(tab, `document.querySelector(".connect-provider")`);
  await tab.evaluate(clickText(".connect-provider", "Continue with Discord"));
  await waitFor(tab, `document.querySelector(".provider-code")`);
  const code = await tab.evaluate(`document.querySelector(".provider-code").textContent.trim()`);
  await tab.evaluate(clickText(".connect-provider", "Open Discord"));
  await waitFor(tab, `window.__opened`);
  const opened = await tab.evaluate(`window.__opened`);
  const state = new URL(opened).searchParams.get("state");

  const page = await newTab(cdpPort);
  await page.send("Page.navigate", { url: `${ORIGIN}/account/oauth/discord/cb?state=${state}&code=abc` });
  await waitFor(page, `document.querySelector("button[name=pick]")`);
  const choices = await page.evaluate(`[...document.querySelectorAll("button[name=pick]")].map((b) => b.value)`);
  // A real submit: this is what the page's own policy has to allow
  await page.evaluate(`document.querySelector('button[name=pick][value="${code}"]').click()`);
  // body?: the submit is navigating, and a document starts with none
  await waitFor(page, `document.body?.innerText.includes("go back to the app")`);
  await page.send("Page.close").catch(() => {});
  return { code, opened, choices };
}

/** What a first connect asks after the sign-in: answered. */
async function settle(tab) {
  const end = Date.now() + 40_000;
  while (Date.now() < end) {
    await tab.evaluate(`document.querySelector('${dialogOf("cloud")} .submit-btn')?.click(); 0`);
    await tab.evaluate(`document.querySelector(".audio-setup .skip-link")?.click(); 0`);
    await tab.evaluate(`document.querySelector('.layout-setup .layout-choice[data-layout="modern"]')?.click();
      document.querySelector(".layout-setup .submit-btn")?.click(); 0`);
    const quiet = await tab.evaluate(`!document.querySelector(".connect-btn") && !document.querySelector(".account-dialog")
      && !document.querySelector(".audio-setup") && !document.querySelector(".layout-setup")`);
    if (quiet) {
      await sleep(800);
      if (await tab.evaluate(`!document.querySelector(".account-dialog") && !document.querySelector(".audio-setup") && !document.querySelector(".layout-setup")`)) return;
    }
    await sleep(200);
  }
  throw new Error("the first-connect questions did not end");
}

const devices = (tab) =>
  tab.evaluate(`new Promise((done) => { const r = indexedDB.open("voipc-accounts", 1);
    r.onsuccess = () => { const q = r.result.transaction("devices").objectStore("devices").count();
      q.onsuccess = () => done(q.result); q.onerror = () => done(-1); };
    r.onerror = () => done(-1); })`);

// ── The lane ──────────────────────────────────────────────────────────────

async function lane() {
  const [one, two] = await Promise.all([browser(PORT + 100), browser(PORT + 101)]);

  // First sign-in: the provider's person takes a name, and claims.
  const a = await openDialog(one);
  const { code, opened, choices } = await throughProvider(a, one);
  check("the page opened is the provider's own", opened.startsWith("https://discord.com/oauth2/authorize?"), opened);
  check("the provider's page offers the code among others", choices.length === 3 && choices.includes(code), choices.join());

  await waitFor(a, `document.querySelector('${dialogOf("provider-name")}')`);
  const suggestion = await a.evaluate(`document.querySelector("#acct-provider-name").value`);
  // l4f prefers the display name ("Dee D"), in the username alphabet
  check("a first sign-in suggests the provider's name", suggestion === "deed", suggestion);
  await a.evaluate(setInput("#acct-provider-name", "deedee"));
  await a.evaluate(`document.querySelector('${dialogOf("provider-name")} .submit-btn').click()`);

  await waitFor(a, `document.querySelector('${dialogOf("provider-choice")}')`, 60_000);
  await a.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await waitFor(a, `document.querySelector('${dialogOf("provider-choice")}')?.innerText.includes("used this account before")`);
  check("claiming warns before it goes on", true);
  await a.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);

  await waitFor(a, `document.querySelector('${dialogOf("recovery")}')`);
  const key = await a.evaluate(`document.querySelector('${dialogOf("recovery")} .secret').textContent`);
  check("a claim shows a recovery key once", /^[A-Z2-7]{4}(-[A-Z2-7]{1,4}){12}$/.test(key), key);
  await a.evaluate(`document.querySelector('${dialogOf("recovery")} .submit-btn').click()`);
  await settle(a);
  check("and the account is in, by the name chosen", (await a.evaluate(`document.body.innerText`)).includes("deedee"));
  for (let i = 0; i < 40 && (await devices(a)) < 1; i++) await sleep(150);
  check("this browser is remembered, with no password", (await devices(a)) === 1);

  // The account panel lists the provider, and has no password to change.
  await a.evaluate(`document.querySelector(".server-header .header-btn").click()`);
  await waitFor(a, `document.querySelector(".server-header .menu")`);
  await a.evaluate(clickText(".server-header .menu > button", "Your account"));
  await waitFor(a, `document.querySelector('${dialogOf("account")}')?.innerText.includes("linked as")`);
  const panel = await a.evaluate(`document.querySelector('${dialogOf("account")}').innerText`);
  check("the account panel shows the link", panel.includes("Discord") && panel.includes("linked as"), panel);
  check("and no password to change", !panel.includes("Password"), panel);
  await a.evaluate(`document.querySelector('${dialogOf("account")} .submit-btn').click()`);

  // A second device: the wrong key asks again; pairing hands the vault over.
  const b = await openDialog(two);
  await throughProvider(b, two);
  await waitFor(b, `document.querySelector('${dialogOf("provider-choice")}')`);
  check(
    "a new device is asked what unlocks the account, not to claim it",
    await b.evaluate(`document.querySelector('${dialogOf("provider-choice")}').innerText.includes("Unlock")`),
  );
  check(
    "and without a password, it is not offered one",
    !(await b.evaluate(`document.querySelector('${dialogOf("provider-choice")}').innerText.includes("Use my password")`)),
  );
  await b.evaluate(setInput("#acct-provider-recovery", "AAAA-BBBB-CCCC"));
  await b.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await waitFor(b, `document.querySelector('${dialogOf("provider-choice")} .error')`);
  check("a mistyped recovery key asks again", true);

  await b.evaluate(clickText(`${dialogOf("provider-choice")} button`, "Ask my other device"));
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")}')`);
  await waitFor(b, `document.querySelector('${dialogOf("pair-wait")} .secret')`);
  const [oldCode, newCode] = await Promise.all([
    a.evaluate(`document.querySelector('${dialogOf("pair-ask")} .secret').textContent`),
    b.evaluate(`document.querySelector('${dialogOf("pair-wait")} .secret').textContent`),
  ]);
  check("both devices show the same six digits", /^\d{6}$/.test(oldCode) && oldCode === newCode, `${oldCode} / ${newCode}`);

  await a.evaluate(`document.querySelector('${dialogOf("pair-ask")} .submit-btn').click()`);
  await settle(b);
  check("the new device is in", (await b.evaluate(`document.body.innerText`)).includes("deedee"));
  for (let i = 0; i < 40 && (await devices(b)) < 1; i++) await sleep(150);
  check("and remembered too", (await devices(b)) === 1);

  // A third way in: the recovery key, on the first browser with its memory wiped.
  const back = await newTab(one);
  await back.send("Page.navigate", { url: `${ORIGIN}/favicon.png` });
  await sleep(300);
  await a.send("Page.close").catch(() => {});
  await sleep(300);
  await back.evaluate(`new Promise((done) => { const r = indexedDB.deleteDatabase("voipc-accounts");
    r.onsuccess = r.onerror = r.onblocked = () => done(true); })`);
  await back.send("Page.close").catch(() => {});
  const c = await openDialog(one);
  await throughProvider(c, one);
  await waitFor(c, `document.querySelector('${dialogOf("provider-choice")}')`);
  await c.evaluate(setInput("#acct-provider-recovery", key));
  await c.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await settle(c);
  check("the recovery key opens the same account on a new device", (await c.evaluate(`document.body.innerText`)).includes("deedee"));
  check(
    "and shows no new recovery key",
    !(await c.evaluate(`!!document.querySelector('${dialogOf("recovery")}')`)),
  );

  for (const [who, tab] of [["first device", c], ["second device", b]]) {
    const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
    check(`nothing threw on the ${who}'s page`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
  }
}

try {
  await lane();
} catch (e) {
  check("the lane ran to its end", false, String(e));
}
console.log(failures === 0 ? "test-provider: all checks passed" : `test-provider: ${failures} check(s) failed`);
await stop(failures === 0 ? 0 : 1);
