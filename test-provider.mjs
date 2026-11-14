#!/usr/bin/env node
// Sign-in with a provider, in real browsers against a real relay: the buttons,
// the code, the provider's page back on the relay, claiming an account, the
// recovery key on a new device, and pairing two devices. Only the provider is a
// stand-in, on a local port. (session_tests.rs `providers` has the security rules;
// what only a browser shows, such as a wasm object the page cannot read, is here.)
//
//   VOIPC_SELFTEST=1 npm run web      # a release relay has no stand-in provider, a release page no door for forged frames
//   node test-provider.mjs [port]
//
// No dependencies. Needs openssl and chromium (CHROME=/path/to/chrome).

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HANG_MS, loadPage, openTab, seen, sleep, startChromium, waitFor } from "./test-cdp.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] ?? 49990);
const CHROME = process.env.CHROME ?? "chromium";
const ORIGIN = `https://127.0.0.1:${PORT}`;
const WORK = mkdtempSync(join(tmpdir(), "voipc-provider-"));
const children = [];

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
  // RELAY_LOG=<file>: the relay's log there, for a run that needs to see why (test-web.sh sets it)
  stdio: ["ignore", process.env.RELAY_LOG ? openSync(process.env.RELAY_LOG, "a") : "ignore", "inherit"],
});
children.push(relay);
await sleep(1500);

// ── Browsers, each its own device ─────────────────────────────────────────

const browser = async (cdpPort) => {
  await startChromium({ chrome: CHROME, work: WORK, cdpPort, children });
  return cdpPort;
};
const newTab = (cdpPort) => openTab(cdpPort);

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
  await loadPage(tab, `${ORIGIN}/`, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
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
 *  provider's page in a tab of its own, and the tap on the code there. `outsider`
 *  first tries the tap as whoever holds the link and the code but not that page. */
async function throughProvider(tab, cdpPort, { outsider = false } = {}) {
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
  if (outsider) {
    const answer = await tab.evaluate(`fetch("/account/oauth/confirm", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "state=${state}&pick=${code}",
    }).then((r) => r.status)`);
    check("a tap from outside the browser that came back does nothing", answer === 410, String(answer));
    const key = () => page.evaluate(`document.querySelector("input[name=key]").value`);
    const before = await key();
    await page.evaluate(`window.__beforeReload = true`);
    await page.send("Page.reload");
    await waitFor(page, `!window.__beforeReload && document.querySelector("button[name=pick]")`);
    check("a reload keeps the page's key", /^[\w-]{43}$/.test(before) && (await key()) === before, before);
    check(
      "and the page offers None of these",
      await page.evaluate(`document.querySelector("button[name=none]")?.innerText === "None of these"`),
    );
  }
  // A real submit: this is what the page's own policy has to allow
  await page.evaluate(`document.querySelector('button[name=pick][value="${code}"]').click()`);
  // body?: the submit is navigating, and a document starts with none
  await waitFor(page, `document.body?.innerText.includes("go back to the app")`);
  await page.send("Page.close").catch(() => {});
  return { code, opened, choices };
}

/** What a first connect asks after the sign-in: answered. */
async function settle(tab) {
  // Rule 1: a limit says hung, not slow
  const end = Date.now() + HANG_MS;
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
/** An expression for waitFor: this browser has a device remembered. It is saved in the background
 *  after the sign-in; each look starts a count, and says what the one before it found. */
const deviceKept = `(() => { const r = indexedDB.open("voipc-accounts", 1);
    r.onsuccess = () => { try { const q = r.result.transaction("devices").objectStore("devices").count();
      q.onsuccess = () => { window.__devicesKept = q.result; r.result.close(); }; } catch { r.result.close(); } };
    return (window.__devicesKept ?? 0) >= 1; })()`;

// ── Frames no honest relay sends ──────────────────────────────────────────

const varint = (n) => {
  const out = [];
  for (; n > 127; n >>>= 7) out.push((n & 127) | 128);
  return [...out, n];
};
const str = (s) => {
  const bytes = [...new TextEncoder().encode(s)];
  return [...varint(bytes.length), ...bytes];
};
// As the wire numbers them, and it only ever adds: each goes in through the test build's
// door into a session (session.ts `__voipc_frame`), and `forge` checks what the page read.
const ACCOUNT = varint(46);
const DISCORD = 0;
const forged = {
  ChannelError: (reason) => [...varint(15), ...str(reason)],
  Disconnected: (reason) => [...varint(40), ...str(reason)],
  AuthError: (reason) => [...varint(1), ...str(reason)],
  ProviderBrowser: (url, code) => [...ACCOUNT, ...varint(27), ...str(url), ...str(code)],
  ProviderDone: () => [...ACCOUNT, ...varint(28), DISCORD, 0],
  ProviderUnlinked: () => [...ACCOUNT, ...varint(29), DISCORD],
  Error: (request, reason) => [...ACCOUNT, ...varint(7), ...str(request), ...str(reason)],
};
async function forge(tab, kind, ...args) {
  const read = await tab.evaluate(
    `JSON.stringify(window.__voipc_frame(${JSON.stringify(`127.0.0.1:${PORT}`)}, ${JSON.stringify(forged[kind](...args))}))`,
  );
  if (!read.includes(`"${kind}"`)) throw new Error(`the page read that ${kind} as ${read}`);
}
/** Long enough for what a frame raises to show. */
const settled = () => sleep(300);
const bodyText = (tab) => tab.evaluate(`document.body.innerText`);
const hasFocus = (tab, kind) => tab.evaluate(`document.querySelector('${dialogOf(kind)}').contains(document.activeElement)`);
async function pressEscape(tab) {
  const key = { key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 };
  await tab.send("Input.dispatchKeyEvent", { type: "keyDown", ...key });
  await tab.send("Input.dispatchKeyEvent", { type: "keyUp", ...key });
}

// ── The lane ──────────────────────────────────────────────────────────────

async function lane() {
  const [one, two] = await Promise.all([browser(PORT + 100), browser(PORT + 101)]);

  // First sign-in: the provider's person takes a name, and claims.
  const a = await openDialog(one);
  const { code, opened, choices } = await throughProvider(a, one, { outsider: true });
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

  // The key comes first, with nothing sent: going back leaves a dead key and no lockout.
  await waitFor(a, `document.querySelector('${dialogOf("provider-key")}')`);
  const dropped = await a.evaluate(`document.querySelector('${dialogOf("provider-key")} .secret').textContent`);
  check("a claim shows its recovery key while the page has no account yet", /^[A-Z2-7]{4}(-[A-Z2-7]{1,4}){12}$/.test(dropped), dropped);
  check(
    "and its yes is not live at once: a double click must not land on it",
    await a.evaluate(`document.querySelector('${dialogOf("provider-key")} .submit-btn').disabled`),
  );
  await a.evaluate(clickText(`${dialogOf("provider-key")} button`, "Cancel"));
  await waitFor(a, `!document.querySelector(".account-dialog") && document.querySelector(".dialog .error")`);
  await throughProvider(a, one);
  await waitFor(a, `document.querySelector('${dialogOf("provider-choice")}')`, 60_000);
  check(
    "cancelled at the key, the account is still to be opened",
    await a.evaluate(`document.querySelector('${dialogOf("provider-choice")}').innerText.includes("Open deedee")`),
  );
  await a.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await waitFor(a, `document.querySelector('${dialogOf("provider-choice")}')?.innerText.includes("used this account before")`);
  await a.evaluate(`document.querySelector('${dialogOf("provider-choice")} .submit-btn').click()`);
  await waitFor(a, `document.querySelector('${dialogOf("provider-key")}')`);
  const key = await a.evaluate(`document.querySelector('${dialogOf("provider-key")} .secret').textContent`);
  check("and the next try has a key of its own", /^[A-Z2-7]{4}(-[A-Z2-7]{1,4}){12}$/.test(key) && key !== dropped, key);
  await waitFor(a, `document.querySelector('${dialogOf("provider-key")} .submit-btn:enabled')`);
  await a.evaluate(`document.querySelector('${dialogOf("provider-key")} .submit-btn').click()`);
  await settle(a);
  check("and it shows no key a second time", !(await a.evaluate(`!!document.querySelector('${dialogOf("recovery")}')`)));
  check("and the account is in, by the name chosen", (await a.evaluate(`document.body.innerText`)).includes("deedee"));
  await seen(a, deviceKept);
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

  // The first ask, up to the code. The new device gives up there, at the window's first size.
  await b.send("Emulation.setDeviceMetricsOverride", { width: 800, height: 600, deviceScaleFactor: 1, mobile: false });
  await b.evaluate(clickText(`${dialogOf("provider-choice")} button`, "Ask my other device"));
  await waitFor(a, `document.querySelector('${dialogOf("pair-look")}')`);
  await waitFor(b, `document.querySelector('${dialogOf("pair-wait")}')`);
  check("no code on the new device before the person agrees to look", !(await b.evaluate(`!!document.querySelector('${dialogOf("pair-wait")} .secret')`)));
  check(
    "and the old device's yes to looking is not live at once",
    await a.evaluate(`document.querySelector('${dialogOf("pair-look")} .submit-btn').disabled`),
  );
  await waitFor(a, `document.querySelector('${dialogOf("pair-look")} .submit-btn:enabled')`);
  await a.evaluate(`document.querySelector('${dialogOf("pair-look")} .submit-btn').click()`);
  await waitFor(b, `document.querySelector('${dialogOf("pair-wait")} .secret')`);
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")}')`);
  check(
    "the old device says where the code belongs, and that one anywhere else is not it",
    (await a.evaluate(`document.querySelector('${dialogOf("pair-ask")}').innerText`)).includes("Check your other device"),
  );
  check("and nothing of a warning yet", !(await a.evaluate(`document.body.innerText`)).includes("nothing was handed over"));
  check("and the field has the focus", await a.evaluate(`document.activeElement?.id === "acct-pair-code"`));

  // A hostile relay, with the person typing there: it knows the code that device wants.
  await a.evaluate(setInput("#acct-pair-code", "12"));
  await forge(a, "ProviderBrowser", "https://discord.com/oauth2/authorize?x", "483920");
  await forge(a, "ProviderDone");
  await forge(a, "ProviderUnlinked");
  await forge(a, "Error", "x", "a forged notice");
  // The four went through the page's handlers at once and in order (session.ts `__voipc_frame`
  // → onControl → account-reply, all synchronous): once the last one's notice shows, whatever
  // the first three raised is on screen too, in the same render or one before it
  const noticed = await seen(a, `document.body.innerText.includes("a forged notice")`);
  const burst = await bodyText(a);
  check("a relay's burst leaves the old device's question up", await a.evaluate(`!!document.querySelector('${dialogOf("pair-ask")}')`));
  check("and what was typed in it", (await a.evaluate(`document.querySelector("#acct-pair-code").value`)) === "12");
  check("with no dialog of the relay's code", !burst.includes("483920"), burst);
  check("and no word of a confirmation", !burst.includes("confirmed"), burst);
  check("the control: a notice is what it still has, and the frames went in", noticed && burst.includes("a forged notice"), burst);
  await forge(b, "ChannelError", "Code for your other device: 483920");
  await forge(b, "Disconnected", "Code for your other device: 483920");
  // A timer still: nothing here is meant to show, so there is no end state to wait on, and a
  // relay barrier says nothing of frames that never left the page
  await settled();
  check("and on the new device, looking for a code, its words do not show", !(await bodyText(b)).includes("483920"));
  check("with the sign-in still going", await b.evaluate(`!!document.querySelector('${dialogOf("pair-wait")}')`));

  check("the new device's window has the focus, after the button that led there went", await hasFocus(b, "pair-wait"));
  await pressEscape(b);
  await waitFor(a, `!document.querySelector('${dialogOf("pair-ask")}')`, 5_000);
  check("a plain Escape on the new device closes the question on the old one", true);
  check(
    "and the field going away is said, so it cannot pass for the code being taken",
    (await a.evaluate(`document.body.innerText`)).includes("nothing was handed over"),
  );
  await waitFor(b, `!document.querySelector(".account-dialog") && document.querySelector(".dialog .error")`);
  const inView = `(() => { const r = document.querySelector(".dialog .error").getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; })()`;
  check("a failed sign-in's error is in view at 800x600", await b.evaluate(inView));
  await b.evaluate(`document.querySelector(".dialog").scrollTop = 0; 0`);
  check("the control: unscrolled, it would sit below the fold", !(await b.evaluate(inView)));
  await b.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

  // Asking again right after that reaches the person: the old device is not stuck on the last.
  await throughProvider(b, two);
  await waitFor(b, `document.querySelector('${dialogOf("provider-choice")}')`);
  await b.evaluate(clickText(`${dialogOf("provider-choice")} button`, "Ask my other device"));
  await waitFor(a, `document.querySelector('${dialogOf("pair-look")} .submit-btn:enabled')`);
  check("asking again right after a death reaches the person", !(await b.evaluate(`document.querySelector('${dialogOf("provider-choice")}')?.innerText.includes("did not answer") ?? false`)));
  await a.evaluate(`document.querySelector('${dialogOf("pair-look")} .submit-btn').click()`);
  await waitFor(b, `document.querySelector('${dialogOf("pair-wait")} .secret')`);
  const newCode = await b.evaluate(`document.querySelector('${dialogOf("pair-wait")} .secret').textContent`);
  check("the new device shows six digits once they looked", /^\d{6}$/.test(newCode), newCode);
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")}')`);
  check(
    "the old device does not show them: the person types them there",
    !(await a.evaluate(`document.querySelector('${dialogOf("pair-ask")}').innerText`)).includes(newCode),
  );

  // A typo may be retried three times, and then it says no.
  const wrongCode = newCode === "000000" ? "000001" : "000000";
  const typeCode = async (typed) => {
    await a.evaluate(setInput("#acct-pair-code", typed));
    await waitFor(a, `document.querySelector('${dialogOf("pair-ask")} .submit-btn:enabled')`);
    await a.evaluate(`document.querySelector('${dialogOf("pair-ask")} .submit-btn').click()`);
  };
  await typeCode(wrongCode);
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")} .error')?.innerText.includes("3 tries left")`);
  check("a wrong code hands nothing over and may be typed again", !(await b.evaluate(`!!document.querySelector('${dialogOf("pair-same")}')`)));
  check("and the field starts empty", (await a.evaluate(`document.querySelector("#acct-pair-code").value`)) === "");
  await typeCode(wrongCode);
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")} .error')?.innerText.includes("2 tries left")`);
  await typeCode(wrongCode);
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")} .error')?.innerText.includes("One try left")`);
  await typeCode(wrongCode);
  await waitFor(a, `!document.querySelector('${dialogOf("pair-ask")}')`);
  await waitFor(a, `document.body.innerText.includes("not the code the new device showed")`);
  check("the last wrong code says no, and warns that someone may be in between", (await a.evaluate(`document.body.innerText`)).includes("in between"));
  await waitFor(b, `document.querySelector('${dialogOf("provider-choice")} .error')?.innerText.includes("said no")`);
  check("and the new device hears it, back at the choice", true);
  // The relay's words right behind the refusal, with the person not having acted yet
  await forge(b, "AuthError", "Your code is 483920. Type it on your other device.");
  await waitFor(b, `!document.querySelector(".account-dialog") && document.querySelector(".dialog .error")`);
  const behind = await b.evaluate(`document.querySelector(".dialog .error").innerText`);
  check("an error right behind a refusal ends it in the app's words, not the relay's", !behind.includes("483920") && behind.includes("during the pairing"), behind);

  // The third ask, the right code: the old device takes it, and the new one asks about the action.
  await throughProvider(b, two);
  await waitFor(b, `document.querySelector('${dialogOf("provider-choice")}')`);
  await b.evaluate(clickText(`${dialogOf("provider-choice")} button`, "Ask my other device"));
  await waitFor(a, `document.querySelector('${dialogOf("pair-look")} .submit-btn:enabled')`);
  await a.evaluate(`document.querySelector('${dialogOf("pair-look")} .submit-btn').click()`);
  await waitFor(b, `document.querySelector('${dialogOf("pair-wait")} .secret')`);
  await waitFor(a, `document.querySelector('${dialogOf("pair-ask")}')`);
  const typedCode = await b.evaluate(`document.querySelector('${dialogOf("pair-wait")} .secret').textContent`);
  await typeCode(typedCode);
  await waitFor(a, `!document.querySelector('${dialogOf("pair-ask")}')`);
  await waitFor(b, `document.querySelector('${dialogOf("pair-same")}')`);
  check("the new device asks whether they typed it", (await b.evaluate(`document.querySelector('${dialogOf("pair-same")}').innerText`)).includes(typedCode));
  check("and the old device says what that question asks about", (await a.evaluate(`document.body.innerText`)).includes("the code was right"));
  check(
    "and that yes is not live at once either",
    await b.evaluate(`document.querySelector('${dialogOf("pair-same")} .submit-btn').disabled`),
  );
  check("and nothing is open before it", (await devices(b)) === 0);
  check("and the question has the focus too", await hasFocus(b, "pair-same"));
  await waitFor(b, `document.querySelector('${dialogOf("pair-same")} .submit-btn:enabled')`);
  await b.evaluate(`document.querySelector('${dialogOf("pair-same")} .submit-btn').click()`);
  await settle(b);
  check("the new device is in", (await b.evaluate(`document.body.innerText`)).includes("deedee"));
  await seen(b, deviceKept);
  check("and remembered too", (await devices(b)) === 1);

  // A third way in: the recovery key, on the first browser with its memory wiped.
  const back = await newTab(one);
  await back.send("Page.navigate", { url: `${ORIGIN}/favicon.png` });
  // The database is the origin's: the tab has to be on it first
  await waitFor(back, `location.href === ${JSON.stringify(`${ORIGIN}/favicon.png`)} && document.readyState === "complete"`);
  await a.send("Page.close").catch(() => {});
  // Done only once it is gone: a tab still holding it open (the old one, closing) blocks it
  // until its connection closes, and the delete then goes through
  // (send, not evaluate: evaluate's CDP deadline is 30 s, a bet on speed; this one says hung)
  const wipe = await back.send("Runtime.evaluate", {
    expression: `new Promise((done) => { const r = indexedDB.deleteDatabase("voipc-accounts");
    r.onsuccess = () => done(true); r.onerror = () => done(false); setTimeout(() => done(false), ${HANG_MS}); })`,
    awaitPromise: true,
    returnByValue: true,
  }, HANG_MS + 10_000);
  if (wipe.result?.result?.value !== true) throw new Error(`the first browser's memory could not be wiped: ${JSON.stringify(wipe).slice(0, 300)}`);
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

  // The honest way to a provider's dialogs: a proof the person started gets its page and its word.
  await c.evaluate(`document.querySelector(".server-header .header-btn").click()`);
  await waitFor(c, `document.querySelector(".server-header .menu")`);
  await c.evaluate(clickText(".server-header .menu > button", "Your account"));
  await waitFor(c, `document.querySelector('${dialogOf("account")}')?.innerText.includes("linked as")`);
  await c.evaluate(clickText(`${dialogOf("account")} button`, "Confirm it's you"));
  await waitFor(c, `document.querySelector('${dialogOf("provider-page")}')`);
  const proof = await c.evaluate(`document.querySelector('${dialogOf("provider-page")} h2').innerText.replace("Your code: ", "")`);
  await c.evaluate(`window.__opened = null; 0`);
  await c.evaluate(clickText(`${dialogOf("provider-page")} button`, "Open the page"));
  await waitFor(c, `window.__opened`);
  const proofPage = await newTab(one);
  await proofPage.send("Page.navigate", { url: `${ORIGIN}/account/oauth/discord/cb?state=${new URL(await c.evaluate(`window.__opened`)).searchParams.get("state")}&code=abc` });
  await waitFor(proofPage, `document.querySelector('button[name=pick][value="${proof}"]')`);
  await proofPage.evaluate(`document.querySelector('button[name=pick][value="${proof}"]').click()`);
  await waitFor(proofPage, `document.body?.innerText.includes("go back to the app")`);
  await proofPage.send("Page.close").catch(() => {});
  await waitFor(c, `!document.querySelector('${dialogOf("provider-page")}') && document.body.innerText.includes("confirmed")`);
  check("a proof the person started gets its page and its confirmation", true);
  await forge(c, "ProviderBrowser", "https://discord.com/oauth2/authorize?x", "483920");
  await forge(c, "ChannelError", "a forged channel error");
  // Both went through the page's handlers at once and in order (session.ts `__voipc_frame`
  // → onControl, all synchronous): once the second one's toast shows, whatever the first
  // raised is on screen too
  const shown = await seen(c, `document.body.innerText.includes("a forged channel error")`);
  const after = await bodyText(c);
  check("and that flow over, a page from nobody's click stays away", !after.includes("483920"), after);
  check("the control: signed in, what kept away from a sign-in shows", shown && after.includes("a forged channel error"));

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
