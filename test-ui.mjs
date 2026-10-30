// Regression test for the web client's real Svelte UI, driven through the
// Chrome DevTools Protocol (Node 22's built-in WebSocket, no dependencies).
//
// test-web.sh checks the protocol and the media path through the in-page
// self-test, which never renders a component. This one clicks the actual UI —
// where a duplicate key in a keyed {#each} throws inside Svelte's flush, the
// store keeps the duplicate and every later update throws again, so the whole
// window is dead. That bug shipped once; this is what would have caught it.
//
// House rule, learned from a bug that shipped: never click with el.click() on
// anything whose behaviour depends on pointer events, and NEVER stub a browser
// mechanism (setPointerCapture and friends) to make a test pass. A close button
// that pointer capture was swallowing passed a test that did both. Use
// realClick / realDrag below — Input.dispatchMouseEvent produces trusted events
// that hit-test at real coordinates and honour capture.
//
//   node test-ui.mjs <serverPort> <cdpPort>
//
// It expects a VoIPC server serving the web client on <serverPort> and a
// headless Chromium started with --remote-debugging-port=<cdpPort>. Firefox
// has no CDP, so test-web.sh only runs this in its Chromium lanes.

import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PORT = process.argv[2] ?? "19987";
const CDP = process.argv[3] ?? "9222";
/** A second, empty server for the multi-server lane; that lane is skipped without one. */
const PORT2 = process.argv[4] ?? "";
/** A server with accounts (open sign-up), for the accounts lane; skipped without one. */
const PORT3 = process.argv[5] ?? "";
const URL = `https://127.0.0.1:${PORT}/`;
const CHANNEL = `ui-${process.pid % 10000}`;
/** The text channel test-web.sh's channels.json asks every client into. */
const AUTO_JOIN_CHANNEL = "lobby-chat";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;

function check(description, ok, detail = "") {
  if (ok) {
    console.log(`PASS ${description}`);
  } else {
    console.log(`FAIL ${description}${detail ? ` — ${detail}` : ""}`);
    failures++;
  }
}

async function newTab() {
  const res = await fetch(`http://127.0.0.1:${CDP}/json/new?about:blank`, { method: "PUT" });
  const info = await res.json();
  const ws = new WebSocket(info.webSocketDebuggerUrl);
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
      return;
    }
    // Only the page's own code counts. Chrome's built-in component scripts run
    // in the page too (content-utils.js, "Attempting to use a disconnected port
    // object" while a screen is shared) and report into the same console.
    const foreign = (url) => !!url && !/^https?:/.test(url);
    const where = (at) => (at ? ` @${at.url}:${at.lineNumber + 1}` : "");
    const preview = (o) =>
      o?.preview ? JSON.stringify(Object.fromEntries(o.preview.properties.map((x) => [x.name, x.value]))) : "";
    if (msg.method === "Runtime.exceptionThrown") {
      // A rejection with a plain object describes itself as "Object": its
      // preview and where it was thrown are what make the report readable
      const d = msg.params.exceptionDetails;
      const at = d.stackTrace?.callFrames?.[0] ?? (d.url ? { url: d.url, lineNumber: d.lineNumber ?? 0 } : null);
      if (foreign(at?.url)) return;
      errors.push(`${d.text ?? ""} ${d.exception?.description ?? ""} ${preview(d.exception)}`.trim() + where(at));
    }
    if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      const at = msg.params.stackTrace?.callFrames?.[0];
      if (foreign(at?.url)) return;
      errors.push(msg.params.args.map((a) => a.value ?? (preview(a) || a.description) ?? "").join(" ") + where(at));
    }
  };
  // Every call gets a deadline. Input.dispatchTouchEvent waits on the renderer
  // and simply never answers if the page cannot process the event, which turned
  // one refused touch into a fifteen-minute suite that ended in a bare 124.
  const send = (method, params = {}, timeoutMs = 30_000) =>
    new Promise((resolve, reject) => {
      const i = ++id;
      const timer = setTimeout(() => {
        pending.delete(i);
        reject(new Error(`CDP timed out after ${timeoutMs}ms: ${method}`));
      }, timeoutMs);
      pending.set(i, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) {
      throw new Error(`evaluate failed: ${JSON.stringify(r.result.exceptionDetails).slice(0, 300)}`);
    }
    return r.result?.result?.value;
  };
  await send("Runtime.enable");
  await send("Page.enable");
  // Headless Chromium defaults to 800x600; the mixer's layout is designed for
  // the width the app actually runs at, and elements below the fold get
  // coordinates the input events cannot reach.
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1280, height: 800, deviceScaleFactor: 1, mobile: false,
  });
  return { send, evaluate, errors };
}

async function waitFor(tab, expression, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return true;
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${expression}`);
}

const setInput = (selector, value) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false;
    el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true })); return true; })()`;
const setSelect = (selector, value) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false;
    el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`;
const click = (selector) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; el.click(); return true; })()`;

/** Centre of an element in viewport coordinates, after scrolling it into view. */
const centre = (selector) =>
  `(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return null;
    el.scrollIntoView({ block: "center", inline: "center" });
    const r = el.getBoundingClientRect();
    return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2),
             w: Math.round(r.width), h: Math.round(r.height) }; })()`;

/** A real mouse click: hit-tested, trusted, and subject to pointer capture. */
async function realClick(tab, selector) {
  const at = await tab.evaluate(centre(selector));
  if (!at) return false;
  const base = { x: at.x, y: at.y, button: "left", clickCount: 1 };
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0 });
  await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1 });
  await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1 });
  await sleep(120);
  return true;
}

/** A real double click: two trusted clicks at the same point, clickCount 2 on
 *  the second, which is what the DOM turns into a dblclick event. */
async function realDoubleClick(tab, selector) {
  const at = await tab.evaluate(centre(selector));
  if (!at) return false;
  const base = { x: at.x, y: at.y, button: "left" };
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0, clickCount: 0 });
  await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1, clickCount: 1 });
  await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1, clickCount: 1 });
  await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1, clickCount: 2 });
  await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1, clickCount: 2 });
  await sleep(150);
  return true;
}

/** Put the pointer over an element, for anything a row only reveals on hover. */
async function hover(tab, selector) {
  const at = await tab.evaluate(centre(selector));
  if (!at) return false;
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: at.x, y: at.y, buttons: 0 });
  await sleep(150);
  return true;
}

/** A real drag along an element, `dy` pixels vertically. */
async function realDrag(tab, selector, dy) {
  const at = await tab.evaluate(centre(selector));
  if (!at) return false;
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: at.x, y: at.y, buttons: 0 });
  await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", x: at.x, y: at.y, button: "left", buttons: 1, clickCount: 1 });
  for (let i = 1; i <= 5; i++) {
    // buttons: 1 on every move, or Chromium reads the whole thing as a hover
    await tab.send("Input.dispatchMouseEvent", {
      type: "mouseMoved", x: at.x, y: Math.round(at.y + (dy * i) / 5), button: "left", buttons: 1,
    });
  }
  await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: at.x, y: at.y + dy, button: "left", buttons: 1, clickCount: 1 });
  await sleep(200);
  return true;
}

/** A real drag along an element, `dx` pixels horizontally. */
async function realDragX(tab, selector, dx) {
  const at = await tab.evaluate(centre(selector));
  if (!at) return false;
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: at.x, y: at.y, buttons: 0 });
  await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", x: at.x, y: at.y, button: "left", buttons: 1, clickCount: 1 });
  for (let i = 1; i <= 5; i++) {
    await tab.send("Input.dispatchMouseEvent", {
      type: "mouseMoved", x: Math.round(at.x + (dx * i) / 5), y: at.y, button: "left", buttons: 1,
    });
  }
  await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: at.x + dx, y: at.y, button: "left", buttons: 1, clickCount: 1 });
  await sleep(200);
  return true;
}

/** Channel names as the sidebar renders them, in order. */
const channelNames = `[...document.querySelectorAll(".channel .channel-name")].map((e) => e.textContent)`;
/** Users as the member list renders them (UserList.svelte `.users > .user > .name`). */
const userNames = `[...document.querySelectorAll(".users .user .name")].map((e) => e.textContent.trim())`;
/** Whether a member list row carries the muted marker. `name` of null means our own row. */
const rowMuted = (name) => `(() => { const rows = [...document.querySelectorAll(".users .user")];
  const row = ${name === null ? `rows.find((e) => e.querySelector(".you"))`
    : `rows.find((e) => e.textContent.includes(${JSON.stringify(name)}))`};
  return row ? !!row.querySelector(".status-icon.muted") : null; })()`;
/** The proximity tag of our own channel — other channels on the server have their own. */
const ownProximityTag = `(() => { const row = [...document.querySelectorAll(".channel")]
  .find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(CHANNEL)});
  return row?.querySelector(".proximity-tag")?.textContent?.trim() ?? ""; })()`;

async function connect(name, tag = "") {
  const tab = await newTab();
  await tab.send("Page.navigate", { url: URL });
  await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  // First run offers the encrypted chat vault; the test keeps chat in memory
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(click(".skip-link"));
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', PORT));
  await tab.evaluate(setInput('input[placeholder="Your name"]', name));
  if (tag) await tab.evaluate(setInput("#tag", tag));
  // Every toast from here on, kept: one lasts 5 s, and on a slow runner the
  // first-run dialogs below take most of that before a check gets to read it
  await tab.evaluate(`(() => { window.__toasts = [];
    new MutationObserver(() => { for (const e of document.querySelectorAll(".toast-message"))
      if (!window.__toasts.includes(e.textContent)) window.__toasts.push(e.textContent); })
      .observe(document.body, { childList: true, subtree: true, characterData: true }); })()`);
  await tab.evaluate(click(".connect-btn"));
  await waitFor(tab, `document.querySelector(".channel-list")`);
  await answerFirstRun(tab, name);
  console.log(`${name}: connected`);
  return tab;
}

/**
 * Answers the first-run dialogs a connection brings up, however late they come:
 * the audio setup is skipped (section 8 drives it properly), the layout picker
 * is answered.
 *
 * App.svelte shows the audio setup once the connection is up, the picker only
 * after the audio setup is gone, and neither again once answered. The shell,
 * .channel-list included, is on screen before any of that, and over the TCP
 * fallback or a lossy link the dialogs come seconds after it — fixed sleeps
 * missed them there. So this waits for the connect dialog to close (it does
 * once connected), answers whatever shows, and returns once the picker is
 * answered and nothing has shown for a second.
 *
 * Conditional, because test-web.sh runs one Chromium with one profile: every
 * tab shares localStorage, so the first browser is asked and the second is not.
 * It ANSWERS the picker rather than skipping it: the default is the modern
 * layout, and every selector below this point is the classic one's. Section 11
 * is where switching between them is exercised on purpose, through Settings,
 * which this never undoes.
 * Leaving either up would be worse than a timeout — it is a real overlay, so
 * every realClick after it would land on its backdrop and read as "element not
 * found". A timeout is a FAIL here, and the checks after it say what is wrong.
 */
async function answerFirstRun(tab, who, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  let quietSince = 0;
  let seen;
  while (Date.now() < deadline) {
    seen = await tab.evaluate(`({
      connected: !document.querySelector(".connect-btn"),
      audio: !!document.querySelector(".audio-setup .skip-link"),
      layout: !!document.querySelector(".layout-setup"),
      answered: JSON.parse(localStorage.getItem("voipc.settings") ?? "{}").ui_prefs?.layout_asked_version === 2,
    })`);
    if (seen.audio) {
      await realClick(tab, ".audio-setup .skip-link");
      await waitFor(tab, `!document.querySelector(".audio-setup")`);
      quietSince = 0;
    } else if (seen.layout) {
      await realClick(tab, '.layout-setup .layout-choice[data-layout="classic"]');
      await sleep(200);
      await realClick(tab, ".layout-setup .submit-btn");
      await waitFor(tab, `!document.querySelector(".layout-setup")`);
      quietSince = 0;
    } else if (seen.connected && seen.answered) {
      quietSince ||= Date.now();
      if (Date.now() - quietSince >= 1_000) return;
    } else {
      quietSince = 0;
    }
    await sleep(150);
  }
  check(`${who}: the first-run dialogs are answered`, false, JSON.stringify(seen));
}

/**
 * Connect without dismissing the audio setup, for the lane that drives it.
 *
 * `asNewUser` is what makes "a new user" true: every tab here shares one
 * Chromium profile, so the questions another tab has already ANSWERED would
 * not be asked again. It puts back the one answer that is not a skip — the
 * layout, which the shared lane has to answer to land in the classic shell —
 * and reloads so the app reads it from scratch. Nothing else is touched.
 */
async function connectRaw(name, asNewUser = false) {
  const tab = await newTab();
  if (asNewUser) {
    // On a same-origin page that is NOT the app, so the write lands before the
    // app has read it. Reloading the app instead loses the race the other way:
    // the config hydrates asynchronously and would overwrite anything typed
    // into the connect dialog before it landed.
    await tab.send("Page.navigate", { url: `${URL}favicon.png` });
    await waitFor(tab, `document.readyState === "complete"`);
    await tab.evaluate(`(() => {
      const saved = JSON.parse(localStorage.getItem("voipc.settings") ?? "{}");
      // null, not a patched object: "nothing has been chosen" is the state a
      // new install is in, and it is what makes the default testable.
      saved.ui_prefs = null;
      localStorage.setItem("voipc.settings", JSON.stringify(saved));
      return true;
    })()`);
  }
  await tab.send("Page.navigate", { url: URL });
  await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(click(".skip-link"));
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await tab.evaluate(setInput('input[placeholder="9987"]', PORT));
  await tab.evaluate(setInput('input[placeholder="Your name"]', name));
  await tab.evaluate(click(".connect-btn"));
  // Connected, not just the shell: .channel-list is on screen before that, and
  // the audio setup comes only with the connection (see answerFirstRun).
  await waitFor(tab, `!document.querySelector(".connect-btn")`);
  return tab;
}

const alice = await connect("ui-alice");
const bob = await connect("ui-bob");
check(
  "answering the layout question is remembered",
  (await alice.evaluate(
    `JSON.parse(localStorage.getItem("voipc.settings") ?? "{}").ui_prefs?.layout_asked_version`,
  )) === 2,
);
check(
  "and it put us in the layout that was picked",
  await alice.evaluate(`!!document.querySelector(".app-layout") && !document.querySelector(".modern-shell")`),
);
await sleep(800);

// 0. Arriving on a server is not walking into a voice channel. The server still
//    parks every session in its lobby, channel 0, but that is "not in voice"
//    and the UI must say so: no General row to be standing in, a voice bar with
//    nothing to leave, and the other people on the server listed as online.
check(
  "connecting puts you in no voice channel",
  await alice.evaluate(`!!document.querySelector(".voice-controls .voice-disabled") && !document.querySelector(".leave-voice-btn")`),
);
check("the lobby is not drawn as a channel", !(await alice.evaluate(channelNames)).includes("General"));
check(
  "the others on the server are listed as online",
  (await alice.evaluate(userNames)).some((u) => u.includes("ui-bob")),
  (await alice.evaluate(userNames)).join(","),
);

// 1. Create a proximity channel through the form. The creator is auto-joined,
//    so ChannelCreated and the UserList snapshot race — the bug's trigger.
await alice.evaluate(click('button[title="Create channel"]'));
await waitFor(alice, `document.querySelector(".create-form")`);
await alice.evaluate(setInput(".create-form input[type=text]", CHANNEL));
await alice.evaluate(setSelect(".create-form select", "2d"));
await alice.evaluate(click(".create-form .create-btn"));
await sleep(2500);

const aliceChannels = await alice.evaluate(channelNames);
const bobChannels = await bob.evaluate(channelNames);
check("the creator's sidebar lists the new channel", aliceChannels.includes(CHANNEL), aliceChannels.join(","));
check("the creator's sidebar lists it once", aliceChannels.filter((c) => c === CHANNEL).length === 1, aliceChannels.join(","));
check("the observer's sidebar lists it once", bobChannels.filter((c) => c === CHANNEL).length === 1, bobChannels.join(","));
check("the channel is tagged 2D", (await alice.evaluate(ownProximityTag)) === "2D");

// 2. The virtual room: open it, place someone, share the position, use a preset
check("the room button appears in a proximity channel", await alice.evaluate(`!!document.querySelector('button[title="Show the virtual room"]')`));
await alice.evaluate(click('button[title="Show the virtual room"]'));
await waitFor(alice, `document.querySelector(".room")`);
await alice.evaluate(click(".tray .chip"));
await sleep(300);
await alice.evaluate(click(".sync input"));
await sleep(600);
await alice.evaluate(setSelect(".room select.control", "round"));
await sleep(300);
check("an avatar is drawn in the room", await alice.evaluate(`document.querySelectorAll(".avatar").length >= 1`));

// 3. The second client joins the same channel (double click, as a user would)
await bob.evaluate(
  `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.textContent.includes(${JSON.stringify(CHANNEL)}));
     if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
);
await sleep(2500);
const aliceUsers = await alice.evaluate(userNames);
check("both members are listed once", new Set(aliceUsers).size === aliceUsers.length, aliceUsers.join(","));
check("the joiner is in the member list", aliceUsers.some((u) => u.includes("ui-bob")), aliceUsers.join(","));

// The number on the row is arithmetic over join and leave broadcasts, so it
// drifts away from the roster the moment one of them goes missing. Both sides
// are on screen here, which is the only place the two can be compared.
const ownCount = `(() => { const row = [...document.querySelectorAll(".channel")]
  .find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(CHANNEL)});
  const text = row?.querySelector(".user-count")?.textContent ?? "";
  const first = text.match(/[0-9]+/);
  return first ? Number(first[0]) : -1; })()`;
check(
  "the member count matches the list",
  (await alice.evaluate(ownCount)) === aliceUsers.length,
  `count ${await alice.evaluate(ownCount)}, listed ${aliceUsers.length}`,
);

// 3a2. The mixer: it takes the centre column, carries a strip per member with a
//      real fader and a meter, and every control answers a REAL mouse click.
//      The floating panel this replaced had a close button that pointer capture
//      swallowed — and a test that called el.click() never saw it.
check(
  "the mixer button is in the toolbar",
  await alice.evaluate(`!!document.querySelector('button[title^="Mixer"]')`),
);
check("a real click reaches the mixer button", await realClick(alice, 'button[title^="Mixer"]'));
await waitFor(alice, `document.querySelector(".mixer")`);
check(
  "the mixer owns the centre column",
  await alice.evaluate(`!!document.querySelector(".main-content .mixer")`),
);
check(
  "there is a master strip and one per member",
  (await alice.evaluate(`document.querySelectorAll(".mixer .strip").length`)) ===
    (await alice.evaluate(`document.querySelectorAll(".users .user").length`)),
);
check(
  "every strip has a fader and a meter",
  await alice.evaluate(
    `[...document.querySelectorAll(".mixer .strip")].every((s) => s.querySelector(".fader") && s.querySelector(".meter"))`,
  ),
);
check(
  "a member strip has a mute and a preset picker",
  await alice.evaluate(
    `!!document.querySelector(".mixer .strip[data-user] .mute") &&
     !!document.querySelector(".mixer .strip[data-user] select")`,
  ),
);
check(
  "the picker offers at least twelve effects",
  (await alice.evaluate(
    `document.querySelectorAll(".mixer .strip[data-user] select option").length`,
  )) >= 12,
);
const faderBox = await alice.evaluate(centre(".mixer .strip[data-user] .fader"));
check(
  "the fader is big enough to use",
  faderBox && faderBox.w >= 44 && faderBox.h >= 120,
  faderBox ? `${faderBox.w}x${faderBox.h}` : "missing",
);
check(
  "the mixer places nobody",
  await alice.evaluate(`!document.querySelector('.mixer input[type=number]')`),
);

// A real drag on the fader must move the number the member menu shows: those
// two used to be independent component-local records that disagreed.
const bobId = await alice.evaluate(
  `(() => { const s = document.querySelector(".mixer .strip[data-user]"); return s ? Number(s.dataset.user) : 0; })()`,
);
await realDrag(alice, `.mixer .strip[data-user="${bobId}"] .fader`, 40);
const stripValue = await alice.evaluate(
  `Number(document.querySelector('.mixer .strip[data-user="${bobId}"] .fader').value)`,
);
check("dragging the fader moves it", stripValue !== 1, `value is ${stripValue}`);
await alice.evaluate(
  `(() => { const el = [...document.querySelectorAll(".users .user")].find((e) => e.textContent.includes("ui-bob"));
     if (!el) return false; el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 })); return true; })()`,
);
await sleep(300);
const menuValue = await alice.evaluate(
  `(() => { const el = document.querySelector(".ctx-vol-slider"); return el ? Number(el.value) : null; })()`,
);
check(
  "the member menu shows the same volume as the strip",
  menuValue !== null && Math.abs(menuValue - stripValue) < 0.001,
  `strip ${stripValue}, menu ${menuValue}`,
);
await alice.evaluate(click(".ctx-overlay"));
await sleep(200);

// 3a3. The mixer at a narrow width. This lane exists because the first version
//      of the mixer was only ever tested at 1280 px: at 700 the centre column
//      is barely 300 px, and the layout ran strips off the side and painted
//      them over each other. The geometry is measured, not eyeballed.
const MIXER_AUDIT = `(() => {
  const mixer = document.querySelector(".mixer");
  if (!mixer) return null;
  const rack = mixer.querySelector(".rack");
  const strips = [...mixer.querySelectorAll(".strip")];
  const mb = mixer.getBoundingClientRect();
  let overlaps = 0;
  for (let i = 0; i < strips.length; i++) {
    for (let j = i + 1; j < strips.length; j++) {
      const a = strips[i].getBoundingClientRect();
      const b = strips[j].getBoundingClientRect();
      if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) overlaps++;
    }
  }
  const outside = strips.filter((s) => {
    const r = s.getBoundingClientRect();
    return r.right > mb.right + 1 || r.left < mb.left - 1;
  }).length;
  return {
    width: Math.round(mb.width),
    strips: strips.length,
    outside,
    overlaps,
    scrollsY: rack.scrollHeight > rack.clientHeight + 1,
    overflowY: getComputedStyle(rack).overflowY,
    faderWidth: Math.round((mixer.querySelector(".strip[data-user] .fader")?.getBoundingClientRect().width) ?? 0),
    faderHeight: Math.round((mixer.querySelector(".strip[data-user] .fader")?.getBoundingClientRect().height) ?? 0),
  };
})()`;

for (const width of [1280, 900, 700, 600]) {
  await alice.send("Emulation.setDeviceMetricsOverride", { width, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(600);
  const a = await alice.evaluate(MIXER_AUDIT);
  check(`no strip escapes the mixer at ${width}px`, a && a.outside === 0, a ? `${a.outside} of ${a.strips}, mixer ${a.width}px` : "no mixer");
  check(`no two strips overlap at ${width}px`, a && a.overlaps === 0, a ? `${a.overlaps} pairs` : "no mixer");
  // Below ~520px of mixer the strips stack, and a stacked list has to scroll
  if (a && a.width > 0 && a.width <= 520) {
    check(`the stack scrolls at ${width}px`, a.overflowY === "auto", `overflow-y is ${a.overflowY}`);
  }
  check(
    `the fader stays usable at ${width}px`,
    a && a.faderWidth >= 40 && a.faderHeight >= 40,
    a ? `${a.faderWidth}x${a.faderHeight}` : "no fader",
  );
}
await alice.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
await sleep(500);

// Room and mixer are radio buttons, not checkboxes: opening one hands the
// column over, so neither button can end up looking dead.
check(
  "the room button hands the column back",
  await realClick(alice, 'button[title="Show the virtual room"]'),
);
await sleep(400);
check(
  "the mixer is gone while the room owns the column",
  await alice.evaluate(`!document.querySelector(".mixer")`),
);
await realClick(alice, 'button[title^="Back to chat"]');
await sleep(400);

// 3b. Muting yourself has to show on your own row straight away. The server
//     never sends UserMuted back to the session that caused it, so only the
//     local update can put the marker there — it used to appear on the next
//     UserList, i.e. not before the next channel switch.
await alice.evaluate(click('button[title^="Mute"]'));
await sleep(800);
check("muting yourself marks your own row", (await alice.evaluate(rowMuted(null))) === true);
check("the other client sees the mute too", (await bob.evaluate(rowMuted("ui-alice"))) === true);
await alice.evaluate(click('button[title^="Unmute"]'));
await sleep(800);
check("unmuting clears your own row again", (await alice.evaluate(rowMuted(null))) === false);

// 4. Channel settings: change the proximity mode (and leave the password alone)
await alice.evaluate(`(() => { const el = document.querySelector(".channel-row:has(> .channel.active) .settings-icon"); if (!el) return false; el.click(); return true; })()`);
await sleep(400);
if (await alice.evaluate(`!!document.querySelector(".password-dialog select")`)) {
  await alice.evaluate(setSelect(".password-dialog select", "3d"));
  await alice.evaluate(click(".password-dialog .create-btn"));
  await sleep(1200);
  const tag = await alice.evaluate(ownProximityTag);
  check("the mode change reaches the sidebar", tag === "3D", `tag is "${tag}"`);
} else {
  check("the channel settings dialog opens", false);
}

// 5. Switching the channel off closes the room again
await alice.evaluate(`(() => { const el = document.querySelector(".channel-row:has(> .channel.active) .settings-icon"); if (!el) return false; el.click(); return true; })()`);
await sleep(400);
await alice.evaluate(setSelect(".password-dialog select", "off"));
await alice.evaluate(click(".password-dialog .create-btn"));
await sleep(1200);
check("the room closes when proximity is switched off", await alice.evaluate(`!document.querySelector(".room")`));

// 6. The channel options: an anonymous, hidden, share-less room where the
//    members are not listed. Everything is checked from the other client's
//    page, which is where a leak would show.
const SECRET = `secret-${process.pid % 10000}`;
await alice.evaluate(click('button[title="Create channel"]'));
await waitFor(alice, `document.querySelector(".create-form")`);
await alice.evaluate(setInput(".create-form input[type=text]", SECRET));
await alice.evaluate(click(".create-form .dialog-check input"));
await alice.evaluate(click(".create-form .create-btn"));
await sleep(2500);

const secretUsers = await alice.evaluate(userNames);
check(
  "an anonymous channel renames its members",
  secretUsers.length > 0 && secretUsers.every((u) => /^Guest-\d{4}/.test(u)),
  secretUsers.join(","),
);
check(
  "the creator does not see their own real name either",
  !secretUsers.some((u) => u.includes("ui-alice")),
  secretUsers.join(","),
);

// The observer joins and must never learn the real name
await bob.evaluate(
  `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.textContent.includes(${JSON.stringify(SECRET)}));
     if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
);
await sleep(2500);
const bobSees = await bob.evaluate(userNames);
check("the observer sees pseudonyms", bobSees.every((u) => /^Guest-\d{4}/.test(u)), bobSees.join(","));
check("the observer never receives a real name", !bobSees.some((u) => u.includes("ui-")), bobSees.join(","));
// The store holds what the wire delivered, so this catches a leak the DOM hides
const wireNames = await bob.evaluate(
  `JSON.stringify([...document.querySelectorAll(".users .user .name")].map((e) => e.textContent))`,
);
check("no real name reached the observer's client", !wireNames.includes("ui-alice"), wireNames);

// Hidden + no sharing + hidden members, set through the settings dialog
await alice.evaluate(`(() => { const el = document.querySelector(".channel-row:has(> .channel.active) .settings-icon"); if (!el) return false; el.click(); return true; })()`);
await sleep(400);
// By data-opt, not by position: these used to be b[0], b[2] and b[3] of the
// checkbox list, so inserting an option — or moving this dialog into its own
// component, which is how it nearly happened — silently set the wrong ones and
// failed further down as if the server were at fault.
await alice.evaluate(`(() => {
  const pick = (opt) => document.querySelector('.password-dialog input[data-opt="' + opt + '"]');
  for (const opt of ["hidden", "hide-members", "screen-share"]) {
    const el = pick(opt);
    if (!el) throw new Error("no channel option checkbox: " + opt);
    el.click();
  }
  return true; })()`);
await alice.evaluate(click(".password-dialog .create-btn"));
await sleep(1500);

check(
  "the share button is gone where sharing is off",
  !(await alice.evaluate(`!!document.querySelector('button[title="Share your screen"]')`)),
);
const hiddenList = await alice.evaluate(userNames);
check("hidden members leave only yourself listed", hiddenList.length === 1, hiddenList.join(","));
check(
  "the reason is spelled out",
  await alice.evaluate(`!!document.querySelector(".hidden-note")`),
);
const bobChannelsAfter = await bob.evaluate(channelNames);
check(
  "a hidden channel stays listed for the member standing in it",
  bobChannelsAfter.includes(SECRET),
  bobChannelsAfter.join(","),
);

// 8. The first-run audio setup. It is the first thing a new user sees, it
//    drives the microphone and the speakers, and until now nothing checked
//    that it appears at all — which is how it came to be missing entirely.
{
  const fresh = await connectRaw(`ui-setup-${process.pid % 1000}`, true);
  await sleep(1200);
  check(
    "a new user is offered the audio setup",
    await fresh.evaluate(`!!document.querySelector(".audio-setup")`),
  );

  // Web starts at the permission step; Chromium is run with a fake device and
  // --use-fake-ui-for-media-stream, so the grant is automatic.
  if (await fresh.evaluate(`!!document.querySelector(".audio-setup button.submit-btn")`)) {
    const heading = await fresh.evaluate(`document.querySelector(".audio-setup h2").textContent`);
    if (/hear you/i.test(heading)) {
      await realClick(fresh, ".audio-setup .submit-btn");
      await sleep(1500);
    }
  }

  check(
    "it asks which microphone",
    /microphone/i.test(await fresh.evaluate(`document.querySelector(".audio-setup h2").textContent`)),
  );
  check(
    "the fake capture device is listed",
    (await fresh.evaluate(`document.querySelectorAll(".audio-setup select option").length`)) > 0,
  );
  // The meter is the whole point of the step: it is fed by mic-test-level,
  // which only arrives if the wizard actually started a capture. The fake
  // microphone takes its time on a busy runner (8 s was not always enough).
  let meterMoved = true;
  try {
    await waitFor(
      fresh,
      `document.querySelector(".audio-setup .level-fill").style.width !== "0%"`,
      20_000,
    );
  } catch {
    meterMoved = false;
  }
  check(
    "the microphone meter moves",
    meterMoved,
    await fresh.evaluate(`document.querySelector(".audio-setup .level-fill")?.style.width`),
  );

  await realClick(fresh, ".audio-setup .submit-btn");
  await sleep(600);
  check(
    "it asks about the speakers next",
    /ear/i.test(await fresh.evaluate(`document.querySelector(".audio-setup h2").textContent`)),
  );
  await realClick(fresh, ".audio-setup .play");
  await sleep(400);
  const firstSide = await fresh.evaluate(`document.querySelector(".audio-setup .verdict").textContent`);
  check("the output test names the side it is playing", /left|right/i.test(firstSide), firstSide);
  // It alternates every 1.2 s, so this is the swap, not a still frame
  await sleep(1600);
  const secondSide = await fresh.evaluate(`document.querySelector(".audio-setup .verdict").textContent`);
  check("and swaps to the other ear", firstSide.trim() !== secondSide.trim(), `${firstSide} -> ${secondSide}`);

  await realClick(fresh, ".audio-setup .submit-btn");
  await sleep(600);
  check(
    "it asks how the microphone should open",
    (await fresh.evaluate(`document.querySelectorAll(".audio-setup .choice").length`)) === 3,
  );
  await realClick(fresh, ".audio-setup .choice:nth-of-type(2)");
  await sleep(400);
  check(
    "voice activation offers a threshold",
    await fresh.evaluate(`!!document.querySelector(".audio-setup input.threshold")`),
  );

  await realClick(fresh, ".audio-setup .submit-btn");
  await sleep(300);
  await realClick(fresh, ".audio-setup .submit-btn");
  await sleep(600);
  check("finishing closes it", !(await fresh.evaluate(`!!document.querySelector(".audio-setup")`)));
  check(
    "and it is remembered",
    (await fresh.evaluate(`JSON.parse(localStorage.getItem("voipc.settings")).audio_setup_version`)) >= 1,
  );

  // The layout picker comes next on this fresh profile — it is the one lane
  // that reaches it with nothing already answered.
  await sleep(500);
  check(
    "a new user is asked which layout to use",
    await fresh.evaluate(`!!document.querySelector(".layout-setup")`),
  );
  check(
    "it offers all three layouts",
    (await fresh.evaluate(`[...document.querySelectorAll(".layout-setup .layout-choice")].map((b) => b.dataset.layout).join(",")`)) === "modern,classic,stage",
  );
  // The default, asserted where it is decided rather than in a unit test: this
  // client has no stored appearance at all, and it is in the modern shell.
  check(
    "a new user starts in the modern layout",
    await fresh.evaluate(`!!document.querySelector(".modern-shell") && !document.querySelector(".app-layout")`),
  );
  await realClick(fresh, ".layout-setup .skip-link");
  await waitFor(fresh, `!document.querySelector(".layout-setup")`);
  // The same rule the audio setup keeps: skip is not an answer, so the offer
  // stands next time. Two states are honest here — this user has never written
  // an appearance blob at all, and if something does write one it must still
  // say "never asked". Anything else means a skip was recorded as an answer.
  const skipState = await fresh.evaluate(`(() => {
    const p = JSON.parse(localStorage.getItem("voipc.settings")).ui_prefs;
    return p === null ? "nothing written" : String(p.layout_asked_version);
  })()`);
  check(
    "skipping the layout question leaves it unanswered",
    skipState === "nothing written" || skipState === "0",
    skipState,
  );
  check(
    "and skipping changes nothing",
    await fresh.evaluate(`!!document.querySelector(".modern-shell")`),
  );

  const fatal = fresh.errors.filter((e) => !/Failed to load resource/.test(e));
  check("no uncaught error during the audio setup", fatal.length === 0, fatal.slice(0, 3).join(" | "));
}

// 9. Settings: the panel nothing has ever opened. The device picker showing
//    the saved device rather than the system default is the bug this catches.
{
  await realClick(alice, ".settings-btn");
  await waitFor(alice, `document.querySelector(".settings-panel, .panel")`);
  await sleep(400);
  const selected = await alice.evaluate(
    `(() => { const s = document.querySelectorAll(".section select"); return s.length ? s[0].value : null; })()`,
  );
  check("the settings panel shows a chosen input device", !!selected, String(selected));

  const micBtn = `[...document.querySelectorAll("button")].find((b) => /test microphone/i.test(b.textContent))`;
  if (await alice.evaluate(`!!(${micBtn})`)) {
    await alice.evaluate(`(${micBtn}).click()`);
    await sleep(1500);
    check(
      "the settings mic test shows a meter",
      await alice.evaluate(`!!document.querySelector(".level-track")`),
    );
    const stopBtn = `[...document.querySelectorAll("button")].find((b) => /stop test/i.test(b.textContent))`;
    await alice.evaluate(`(${stopBtn})?.click()`);
    await sleep(300);
  }
  const close = `document.querySelector(".close-btn")?.click()`;
  await alice.evaluate(close);
  await sleep(400);
}

// 9b. Keyboard (H5-04). Every overlay shares one modal behaviour
//     (actions/dialog.ts): it is announced as a modal dialog named after its
//     title, focus moves into it, Tab cannot walk out into the page behind,
//     Escape closes it, and focus goes back to what opened it. A channel row's
//     own controls are buttons beside the row, so Tab reaches them.
{
  const press = async (k, code, vk, modifiers = 0) => {
    await alice.send("Input.dispatchKeyEvent", { type: "rawKeyDown", key: k, code, windowsVirtualKeyCode: vk, modifiers });
    await alice.send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk, modifiers });
    await sleep(150);
  };
  const SHIFT = 8;
  const modal = `document.querySelector('[role="dialog"][aria-modal="true"]')`;
  const inside = `(() => { const d = ${modal}; return !!d && d.contains(document.activeElement); })()`;

  await realClick(alice, ".settings-btn");
  await waitFor(alice, modal);
  await sleep(300);
  const title = await alice.evaluate(
    `(() => { const d = ${modal}; return document.getElementById(d?.getAttribute("aria-labelledby"))?.textContent.trim() ?? null; })()`,
  );
  check("Settings is a modal dialog named after its title", title === "Settings", String(title));
  check("opening it puts focus inside", await alice.evaluate(inside));
  let stayed = true;
  for (let i = 0; i < 3; i++) {
    await press("Tab", "Tab", 9, SHIFT);
    stayed &&= await alice.evaluate(inside);
  }
  check("Shift+Tab does not leave it", stayed);
  await press("Escape", "Escape", 27);
  check("Escape closes it", !(await alice.evaluate(`!!${modal}`)));
  check(
    "and focus goes back to the button that opened it",
    await alice.evaluate(`!!document.activeElement?.classList.contains("settings-btn")`),
  );

  // Settings' tabs move with the arrow keys (R5-11), and About carries the
  // third-party notices this build serves beside the page (R4-09)
  const tab = (name) => `[...document.querySelectorAll('[role="tab"]')].find((e) => e.textContent.trim() === ${JSON.stringify(name)})`;
  await realClick(alice, ".settings-btn");
  await waitFor(alice, tab("About"));
  await alice.evaluate(`${tab("About")}.click()`);
  await waitFor(alice, `document.querySelector("details.notices summary")`, 5_000).catch(() => {});
  await realClick(alice, "details.notices summary");
  const notices = await waitFor(alice, `document.querySelector(".notices-text")?.textContent.length > 1000`, 10_000).then(() => true, () => false);
  check("About shows the third-party notices", notices,
    await alice.evaluate(`document.querySelector("details.notices")?.innerText.slice(0, 200) ?? "no notices section"`));
  await alice.evaluate(`${tab("About")}.focus()`);
  await press("ArrowLeft", "ArrowLeft", 37);
  const moved = await alice.evaluate(`document.querySelector('[role="tab"][aria-selected="true"]')?.textContent.trim()`);
  check("ArrowLeft moves to the tab before it", moved !== "About" && moved === (await alice.evaluate(`document.activeElement?.textContent.trim()`)), moved);
  await press("Escape", "Escape", 27);

  const row = `document.querySelector(".channel-row:has(.settings-icon) > .channel")`;
  if (await alice.evaluate(`!!${row}`)) {
    await alice.evaluate(`${row}.focus()`);
    await press("Tab", "Tab", 9);
    check(
      "Tab goes from a channel row to its own controls",
      await alice.evaluate(
        `document.activeElement?.tagName === "BUTTON" && document.activeElement.classList.contains("settings-icon") && !document.activeElement.closest(".channel")`,
      ),
    );
    await alice.evaluate(`document.activeElement?.blur()`);
  }
}

// 10. Appearance: the palette actually reaches the document, and what it
//     reaches it with is readable. Measured rather than eyeballed — the whole
//     point of driving colours from tokens is that a machine can check them,
//     and "the light theme has one invisible thing on it" is not a bug anybody
//     files, they just switch back.
{
  await realClick(alice, ".settings-btn");
  await waitFor(alice, `document.querySelector(".tab")`);
  const appearanceTab = `[...document.querySelectorAll(".tab")].find((b) => /appearance/i.test(b.textContent))`;
  check("Settings has an Appearance tab", await alice.evaluate(`!!(${appearanceTab})`));
  await alice.evaluate(`(${appearanceTab}).click()`);
  await sleep(300);

  // By id, not by label: a label is copy and gets edited ("VoIPC dark" became
  // "Navy" when VoIPC night became the default)
  const pickPalette = (id) => `document.querySelector('.swatch[data-palette="${id}"]')`;
  check("the palettes are offered", await alice.evaluate(`!!(${pickPalette("slate-light")})`));

  // Start from a dark palette on purpose. Which palette a fresh client opens in
  // follows the machine's light/dark setting now, so "switch to the light one
  // and watch it change" only means something from a known dark starting point
  // — and this headless browser reports a light preference.
  await alice.evaluate(`(${pickPalette("voipc-dark")}).click()`);
  await sleep(400);
  const before = await alice.evaluate(`getComputedStyle(document.body).backgroundColor`);
  await alice.evaluate(`(${pickPalette("slate-light")}).click()`);
  await sleep(400);

  const after = await alice.evaluate(`getComputedStyle(document.body).backgroundColor`);
  check("switching palette repaints the app", before !== after, `${before} -> ${after}`);
  check(
    "a light palette says so on the document",
    (await alice.evaluate(`document.documentElement.dataset.theme`)) === "light",
  );

  // The contrast probe. theme.test.ts holds every *shipped palette* to this,
  // but only the live DOM can say whether the token actually reached the rule
  // that paints the sidebar.
  const contrast = `(() => {
    const lum = (c) => {
      const [r, g, b] = c.match(/\\d+/g).slice(0, 3).map(Number).map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const row = document.querySelector(".channel");
    const list = document.querySelector(".channel-list");
    if (!row || !list) return null;
    const a = lum(getComputedStyle(row).color);
    const b = lum(getComputedStyle(list).backgroundColor);
    const [hi, lo] = a > b ? [a, b] : [b, a];
    return Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
  })()`;
  const ratio = await alice.evaluate(contrast);
  check("a channel name is readable on the light sidebar", ratio !== null && ratio >= 4.5, `${ratio}:1`);

  // Zoom is left at 1 deliberately: it shifts getBoundingClientRect, and the
  // mixer geometry audit above measures real pixels.
  await alice.evaluate(`(${pickPalette("voipc-dark")}).click()`);
  await sleep(400);
  check(
    "switching back restores the dark document",
    (await alice.evaluate(`document.documentElement.dataset.theme`)) === "dark",
  );
  // Waited for, not slept on: saving is debounced by as long as the sleep
  // above (SAVE_DELAY_MS, 400 ms), and a tab Chrome has put in the background
  // runs that timer late — a race that CI's Chrome started losing half the time.
  const saved = `JSON.parse(localStorage.getItem("voipc.settings") ?? "{}").ui_prefs?.palette`;
  check(
    "the choice is remembered",
    await waitFor(alice, `${saved} === "voipc-dark"`, 5000).catch(() => false),
    await alice.evaluate(saved),
  );

  await alice.evaluate(`document.querySelector(".close-btn")?.click()`);
  await sleep(400);
}

// 11. The modern layout. Switched through Settings rather than a query
//     parameter on purpose: switching is the thing that has to work, and a
//     test-only way in would be a code path nothing else uses.
//
//     The assertion that matters most here is the error census at the end of
//     the block. Swapping shells destroys and rebuilds every child, which is
//     exactly where a duplicate-keyed {#each} or a listener registered twice
//     shows up — the bug class this whole file was written for.
{
  const openAppearance = async () => {
    await realClick(alice, ".settings-btn");
    await waitFor(alice, `document.querySelector(".tab")`, 8_000);
    await alice.evaluate(
      `[...document.querySelectorAll(".tab")].find((b) => /appearance/i.test(b.textContent)).click()`,
    );
    await sleep(300);
  };
  const pickLayout = (id) => `document.querySelector('.layout-choice[data-layout="${id}"]')`;

  await openAppearance();
  check(
    "Appearance offers both layouts",
    (await alice.evaluate(`!!(${pickLayout("modern")})`)) &&
      (await alice.evaluate(`!!(${pickLayout("classic")})`)),
  );
  await alice.evaluate(`(${pickLayout("modern")}).click()`);
  await sleep(500);
  await alice.evaluate(`document.querySelector(".close-btn")?.click()`);
  await sleep(500);

  check("the modern shell replaces the classic one", await alice.evaluate(
    `!!document.querySelector(".modern-shell") && !document.querySelector(".app-layout")`,
  ));
  check("it has a server rail", await alice.evaluate(`!!document.querySelector(".server-rail")`));
  check("it has a user panel", await alice.evaluate(`!!document.querySelector(".user-panel")`));
  check("the voice bar is gone", !(await alice.evaluate(`!!document.querySelector(".voice-controls")`)));
  check("the member list is still grouped by state", await alice.evaluate(
    `!!document.querySelector(".user-list.modern .group-label")`,
  ));

  // A click looks, a double click enters — the same rule as the classic
  // sidebar, and the pair of checks that would catch either half regressing.
  // realClick / realDoubleClick, not el.click(): the house rule at the top of
  // this file, and a channel row is exactly the kind of thing that grows
  // pointer behaviour.
  //
  // Voice rows only. A text channel is a subscription with its own rules — a
  // click there reads it rather than entering it, which the block below asserts
  // on its own.
  const activeChannel = () =>
    alice.evaluate(`document.querySelector(".channel-list.modern .channels.voice .channel.active .channel-name")?.textContent`);
  const nextChannel = () =>
    alice.evaluate(`document.querySelector(".channel-list.modern .channels.voice .channel:not(.active) .channel-name")?.textContent`);
  const previewing = () =>
    alice.evaluate(`document.querySelector(".channel-list.modern .channels.voice .channel.previewing .channel-name")?.textContent`);

  // Two joins below each need a voice row alice is not in, and the lobby no
  // longer counts as one — it is not drawn. bob opens a spare room (and, as its
  // creator, stands in it), which also leaves somebody in a channel alice is
  // not in for the nested-members check further down.
  const SPARE = `spare-${process.pid % 10000}`;
  await bob.evaluate(click('button[title="Create channel"]'));
  await waitFor(bob, `document.querySelector(".create-form")`);
  await bob.evaluate(setInput(".create-form input[type=text]", SPARE));
  await bob.evaluate(click(".create-form .create-btn"));
  await sleep(2000);

  // Assert against the row that was acted on, not merely "something is active":
  // "a channel is active" is true whether or not the click did anything.
  const startedIn = await activeChannel();
  const firstTarget = await nextChannel();
  await realClick(alice, ".channel-list.modern .channels.voice .channel:not(.active)");
  await sleep(1000);
  check(
    "one click only previews the channel",
    (await activeChannel()) === startedIn && (await previewing()) === firstTarget,
    `active ${await activeChannel()} (was ${startedIn}), previewing ${await previewing()}, wanted preview of ${firstTarget}`,
  );

  await realDoubleClick(alice, ".channel-list.modern .channels.voice .channel:not(.active)");
  await sleep(1400);
  check(
    "a double click joins it",
    (await activeChannel()) === firstTarget,
    `wanted ${firstTarget}, in ${await activeChannel()}`,
  );

  // Again with the other way in — the one a phone is left with, since a touch
  // screen has no double click: the click opens the pane, and the pane offers
  // the join. Deliberately not asserting we land back where we started: this
  // server has several channels, so "the first non-active row" is not a toggle
  // between two.
  const secondTarget = await nextChannel();
  await realClick(alice, ".channel-list.modern .channels.voice .channel:not(.active)");
  await sleep(900);
  check(
    "the pane offers the way into a previewed voice channel",
    await alice.evaluate(`!!document.querySelector(".join-voice-btn")`),
  );
  await realClick(alice, ".join-voice-btn");
  await sleep(1400);
  check(
    "the pane's button joins it",
    (await activeChannel()) === secondTarget,
    `wanted ${secondTarget} (started in ${startedIn}), in ${await activeChannel()}`,
  );

  // A channel the server asks everyone into is in before anybody clicks. This
  // is the one lane with a channels.json, and the bug it catches is real: the
  // join used to fire on the channel list, which arrives while `connect` is
  // still finishing, and was refused with "Not connected".
  const rowByName = (name) =>
    `[...document.querySelectorAll(".channel-list.modern .channels.text .channel")]` +
    `.find((r) => r.querySelector(".channel-name")?.textContent === ${JSON.stringify(name)})`;
  check(
    "a server's auto-join text channel is joined without asking",
    await alice.evaluate(`!!(${rowByName(AUTO_JOIN_CHANNEL)}) && !(${rowByName(AUTO_JOIN_CHANNEL)}).classList.contains("unjoined")`),
    await alice.evaluate(`(${rowByName(AUTO_JOIN_CHANNEL)})?.className ?? "no such row"`),
  );

  // A text channel is not a room you fall into. One click reads it; entering
  // it is a button of its own, and walking out says so in the sidebar. The
  // self-test's alice left #e2e-text behind for exactly this.
  const TEXT_CHANNEL = "e2e-text";
  const textRow = `.channel-list.modern .channels.text .channel`;
  const textRowState = () =>
    alice.evaluate(`(() => {
      const el = ${rowByName(TEXT_CHANNEL)};
      return el ? { unjoined: el.classList.contains("unjoined"), left: el.classList.contains("left") } : null;
    })()`);
  const clickTextRow = () =>
    alice.evaluate(`(() => { const el = ${rowByName(TEXT_CHANNEL)}; if (!el) return null;
      const r = el.getBoundingClientRect(); return { x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2) }; })()`)
      .then(async (at) => {
        if (!at) return false;
        const base = { x: at.x, y: at.y, button: "left", clickCount: 1 };
        await alice.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0 });
        await alice.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1 });
        await alice.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1 });
        await sleep(120);
        return true;
      });
  if ((await textRowState())?.unjoined) {
    await clickTextRow();
    await sleep(900);
    check(
      "a click on a text channel reads it instead of joining",
      (await textRowState())?.unjoined === true,
    );
    check("the chat pane offers the way in", await alice.evaluate(
      `!!document.querySelector(".join-text-btn")`,
    ));
    await realClick(alice, ".join-text-btn");
    await sleep(1500);
    check("the button joins it", (await textRowState())?.unjoined === false);

    // Looking at another channel must not wedge the pane there. A preview
    // outranks the open text channel in what the pane shows, so until
    // `openTextChannel` dropped it, one click on a voice channel made every
    // later click on a text channel we are *in* do nothing visible.
    await realClick(alice, ".channel-list.modern .channels.voice .channel:not(.active)");
    await sleep(800);
    await clickTextRow();
    await sleep(800);
    const paneTitle = await alice.evaluate(`document.querySelector(".chat-title")?.textContent.trim()`);
    check(
      "a previewed voice channel does not block opening a text channel",
      paneTitle === TEXT_CHANNEL && !(await alice.evaluate(`!!document.querySelector(".preview-label")`)),
      `the pane shows ${paneTitle}`,
    );
    // The leave glyph only exists while the row is hovered
    await alice.evaluate(`(${rowByName(TEXT_CHANNEL)})?.scrollIntoView({block: "center"})`);
    const leaveAt = await alice.evaluate(`(() => {
      const row = ${rowByName(TEXT_CHANNEL)}; if (!row) return null;
      const r = row.getBoundingClientRect();
      return { x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2) };
    })()`);
    await alice.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: leaveAt.x, y: leaveAt.y, buttons: 0 });
    await sleep(200);
    const glyphAt = await alice.evaluate(`(() => {
      const row = ${rowByName(TEXT_CHANNEL)}; if (!row) return null;
      const g = row.parentElement.querySelector('.settings-icon[title="Leave this channel"]'); if (!g) return null;
      const r = g.getBoundingClientRect();
      return { x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2) };
    })()`);
    if (glyphAt) {
      const base = { x: glyphAt.x, y: glyphAt.y, button: "left", clickCount: 1 };
      await alice.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0 });
      await alice.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1 });
      await alice.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1 });
    }
    await sleep(1500);
    const afterLeave = await textRowState();
    check("leaving puts it back out of reach", afterLeave?.unjoined === true);
    check("and the row says it was left", afterLeave?.left === true);
    // Back to our own channel: reading another one holds the pane and the
    // member list, and the checks below are about ourselves.
    await realClick(alice, ".channel-list.modern .channels.voice .channel.active");
    await sleep(600);
  } else {
    check("a text channel row to test with", false, "no unjoined text channel listed");
  }

  // The mute checks at the end of this block need a channel with voice in it,
  // and a mute button that is absent because we are in no voice channel still
  // reads as a broken mute button. The voice panel only renders in voice, so
  // its presence is the check — no need to know which channel we are in.
  check(
    "we are somewhere with voice",
    await alice.evaluate(`!!document.querySelector(".voice-panel")`),
    await activeChannel(),
  );

  // The point of the nested rows: a channel you are NOT in shows who is in it.
  // bob stands in a room alice is not in — the spare, unless the joins above
  // put her there, in which case he moves to hers from before — and that row
  // should name him without hovering it, previewing it or joining it. The names
  // for another channel are never pushed to us, so this is really a check that
  // stores/rosters.ts asked.
  const bobRoom = (await activeChannel()) === SPARE ? CHANNEL : SPARE;
  if (bobRoom !== SPARE) {
    await bob.evaluate(
      `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(bobRoom)});
         if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
    );
  }
  await sleep(1500);
  const nestedUnder = await alice.evaluate(`(() => {
    const row = [...document.querySelectorAll(".channel-list.modern .channel")]
      .find((r) => r.querySelector(".channel-name")?.textContent === ${JSON.stringify(bobRoom)});
    const nested = row?.parentElement?.nextElementSibling;
    return nested && nested.classList.contains("nested")
      ? [...nested.querySelectorAll(".nested-name")].map((e) => e.textContent.trim())
      : []; })()`);
  check(
    "a channel we are not in lists its members",
    nestedUnder.some((n) => n.includes("ui-bob")),
    `${bobRoom}: ${JSON.stringify(nestedUnder)}`,
  );

  // Room and mixer are full-screen activities here, not a centre column.
  const mixerBtn = `[...document.querySelectorAll(".header-btn")].find((b) => /mixing desk|mixer/i.test(b.title))`;
  if (await alice.evaluate(`!!(${mixerBtn})`)) {
    await alice.evaluate(`(${mixerBtn}).click()`);
    await sleep(600);
    check("the mixer opens as an activity", await alice.evaluate(
      `!!document.querySelector(".activity .mixer")`,
    ));
    await alice.send("Input.dispatchKeyEvent", {
      type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27,
    });
    await alice.send("Input.dispatchKeyEvent", {
      type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27,
    });
    await sleep(500);
    check("Escape closes the activity", !(await alice.evaluate(`!!document.querySelector(".activity")`)));
  }

  // Dragging a sidebar edge, with real pointer events and real pointer capture.
  const sidebarWidth = `document.querySelector(".modern-shell .sidebar").getBoundingClientRect().width`;
  const widthBefore = await alice.evaluate(sidebarWidth);
  await realDragX(alice, ".modern-shell .resize-handle", 60);
  await sleep(400);
  const widthAfter = await alice.evaluate(sidebarWidth);
  check("the sidebar can be dragged wider", widthAfter > widthBefore + 20, `${widthBefore} -> ${widthAfter}`);
  // The save is debounced, so this waits for it rather than racing it. Against
  // the width actually on screen, not against a bar the default already clears.
  const readStoredWidth = () =>
    alice.evaluate(
      `JSON.parse(localStorage.getItem("voipc.settings")).ui_prefs?.panels?.modern?.sidebar`,
    );
  let storedWidth = await readStoredWidth();
  for (let i = 0; i < 20 && Math.abs(storedWidth - widthAfter) >= 4; i++) {
    await sleep(200);
    storedWidth = await readStoredWidth();
  }
  check(
    "the new width is remembered",
    Math.abs(storedWidth - widthAfter) < 4,
    `stored ${storedWidth}, on screen ${widthAfter}`,
  );

  // The Stage layout (2026-10-26): the call in the middle. Switched the same
  // way, from inside a call, so the grid has somebody to draw.
  await openAppearance();
  check("Appearance offers the stage layout", await alice.evaluate(`!!(${pickLayout("stage")})`));
  await alice.evaluate(`(${pickLayout("stage")}).click()`);
  await sleep(500);
  await alice.evaluate(`document.querySelector(".close-btn")?.click()`);
  await sleep(500);
  check("the stage shell replaces the modern one", await alice.evaluate(
    `!!document.querySelector(".stage-shell") && !document.querySelector(".modern-shell") && !document.querySelector(".app-layout")`,
  ));
  check("the call fills the stage: there is a tile for each person in it", await alice.evaluate(
    `document.querySelectorAll("[data-stage-grid] [data-stage-tile]").length >= 1`,
  ));
  check("the voice bar is the dock under it", await alice.evaluate(`!!document.querySelector(".dock .voice-controls")`));
  check("the chat starts closed", await alice.evaluate(`!document.querySelector("[data-stage-chat]")`));
  await realClick(alice, "[data-stage-chat-toggle]");
  await sleep(400);
  check("the chat button opens the chat beside the stage", await alice.evaluate(
    `!!document.querySelector("[data-stage-chat] .chat-panel")`,
  ));
  await realClick(alice, "[data-stage-chat-toggle]");
  await sleep(400);
  check("and closes it again", await alice.evaluate(`!document.querySelector("[data-stage-chat]")`));
  check("the stage layout is what is stored", await waitFor(
    alice,
    `JSON.parse(localStorage.getItem("voipc.settings") ?? "{}").ui_prefs?.layout === "stage"`,
    5000,
  ).catch(() => false));

  // Back to classic, in the same tab and with no reload.
  await openAppearance();
  await alice.evaluate(`(${pickLayout("classic")}).click()`);
  await sleep(500);
  await alice.evaluate(`document.querySelector(".close-btn")?.click()`);
  await sleep(500);
  check("switching back restores the classic shell", await alice.evaluate(
    `!!document.querySelector(".app-layout") && !document.querySelector(".modern-shell") && !document.querySelector(".stage-shell")`,
  ));
  check("the connection survived both switches", await alice.evaluate(
    `!!document.querySelector(".status-bar") && /Connected/.test(document.querySelector(".status-bar").textContent)`,
  ));

  // Push-to-talk lives outside the shells precisely so a switch cannot drop it.
  await alice.evaluate(click('button[title^="Mute"]'));
  await sleep(600);
  check("mute still works after switching layouts", await alice.evaluate(rowMuted(null)) === true);
  await alice.evaluate(click('button[title^="Unmute"]'));
  await sleep(600);
  check("and unmute too", await alice.evaluate(rowMuted(null)) === false);

  // Out of the voice channel without leaving the server. A real click: this
  // button sits in the voice bar, the bar that grew pointer behaviour before.
  check("a real click reaches Leave voice", await realClick(alice, ".voice-controls .leave-voice-btn"));
  await sleep(1200);
  check("Leave voice takes you out of the channel", await alice.evaluate(
    `!!document.querySelector(".voice-controls .voice-disabled") && !document.querySelector(".leave-voice-btn")`,
  ));
  check("and keeps you on the server", await alice.evaluate(
    `/Connected/.test(document.querySelector(".status-bar")?.textContent ?? "")`,
  ));
}

// 12. The phone shape. Driven at 390px with real touch events, because none of
//     this reproduces with a mouse: the swipe deliberately ignores a mouse
//     pointer (there are buttons for that), and a drag's velocity — which is
//     half the settle rule — is something only a finger has.
{
  const setLayout = async (title) => {
    // At phone width the settings gear lives in the user panel, which is inside
    // the channel drawer — so it has to be opened first, exactly as a person
    // would. The apps this layout borrows from put it in the same place.
    if (await alice.evaluate(`getComputedStyle(document.querySelector(".drawer-btn") ?? document.body).display !== "none"`)) {
      if (!(await alice.evaluate(`document.querySelector(".pane-left")?.getBoundingClientRect().right > 8`))) {
        await realClick(alice, ".drawer-btn");
        await sleep(500);
      }
    }
    await realClick(alice, ".settings-btn");
    await waitFor(alice, `document.querySelector(".tab")`, 8_000);
    await alice.evaluate(
      `[...document.querySelectorAll(".tab")].find((b) => /appearance/i.test(b.textContent)).click()`,
    );
    await sleep(300);
    await alice.evaluate(`document.querySelector('.layout-choice[data-layout="${title}"]').click()`);
    await sleep(400);
    await alice.evaluate(`document.querySelector(".close-btn")?.click()`);
    await sleep(500);
  };

  await alice.send("Emulation.setDeviceMetricsOverride", {
    width: 390, height: 844, deviceScaleFactor: 1, mobile: true,
  });
  await alice.send("Emulation.setTouchEmulationEnabled", { enabled: true, maxTouchPoints: 1 });
  await sleep(400);
  await setLayout("modern");

  // The panes stack on the container's width, not the device's — which is why
  // this also appears in a narrow desktop window.
  check("the panes stack at phone width", await alice.evaluate(
    `getComputedStyle(document.querySelector(".pane-main")).width === "390px"`,
  ));
  check("a drawer button appears", await alice.evaluate(
    `getComputedStyle(document.querySelector(".drawer-btn")).display !== "none"`,
  ));

  const paneLeftVisible = `document.querySelector(".pane-left").getBoundingClientRect().right > 8`;
  check("the channel drawer starts closed", !(await alice.evaluate(paneLeftVisible)));

  await realClick(alice, ".drawer-btn");
  await sleep(500);
  check("the button opens the channel drawer", await alice.evaluate(paneLeftVisible));

  // …and the button closes it again.
  await realClick(alice, ".drawer-btn");
  await sleep(500);
  check("the button closes it again", !(await alice.evaluate(paneLeftVisible)));

  // Picking a channel from the drawer has to show the chat: the drawer covers
  // it, so a tap that only changes what is behind it reads as a tap that did
  // nothing. This is the phone's main path now that this layout is the default.
  await realClick(alice, ".drawer-btn");
  await sleep(500);
  await realClick(alice, ".pane-left .channels.text .channel");
  await sleep(700);
  check("picking a channel closes the drawer", !(await alice.evaluate(paneLeftVisible)));

  // Settings is reachable on a phone — through the drawer, which is where the
  // user panel lives. Worth its own check: a layout that hides its own settings
  // behind a gesture is one you cannot get out of.
  await realClick(alice, ".drawer-btn");
  await sleep(500);
  check("settings is reachable from the drawer", await alice.evaluate(
    `(() => { const el = document.querySelector(".user-panel .settings-btn");
      if (!el) return false;
      const r = el.getBoundingClientRect();
      return r.left >= 0 && r.right <= window.innerWidth && r.width > 0; })()`,
  ));
  await realClick(alice, ".drawer-btn");
  await sleep(400);

  // NOT TESTED HERE: closing it with a finger.
  //
  // `Input.dispatchTouchEvent` never answers in this headless browser — it
  // waits on the renderer to acknowledge the event and the acknowledgement does
  // not come, with or without --touch-events=enabled, so the call times out
  // rather than failing. It used to hang the whole suite until the outer
  // `timeout` killed it, which is why every CDP call now carries a deadline.
  //
  // What that leaves: the gesture's arithmetic — where a drag settles, and how
  // its velocity is measured — is unit-tested in actions/swipe.test.ts, and the
  // drawer itself is driven above through the buttons, which is the path that
  // has to work anyway for anyone who would rather not swipe. The swipe wiring
  // between the two is what needs a real device, and has not had one.

  await setLayout("classic");
  await alice.send("Emulation.clearDeviceMetricsOverride");
  await alice.send("Emulation.setTouchEmulationEnabled", { enabled: false });
  await sleep(400);
  check("the classic layout comes back at desktop width", await alice.evaluate(
    `!!document.querySelector(".app-layout .main-content")`,
  ));
}

// 13. Message destruction timers. The rules themselves — what a claimed timer
//     is worth, what a channel's own timer does to a message somebody re-shares
//     — are unit-tested in chat-rules.test.ts. What only a browser can show is
//     the wiring: the dialog writes it, the server announces it, and both the
//     writer and somebody merely reading the channel are told.
{
  const TIMED = `timed-${process.pid % 10000}`;
  await alice.evaluate(click('button[title="Create channel"]'));
  await waitFor(alice, `document.querySelector(".create-form")`);
  await alice.evaluate(setInput(".create-form input[type=text]", TIMED));
  await alice.evaluate(click('.create-form input[data-kind="text"]'));
  await sleep(300);
  await alice.evaluate(click(".create-form .create-btn"));
  await sleep(2000);

  const opened = await alice.evaluate(
    `(() => { const row = [...document.querySelectorAll(".channel")].find((e) => e.textContent.includes(${JSON.stringify(TIMED)}));
       const gear = row?.parentElement?.querySelector('[title="Channel settings"]');
       if (!gear) return false; gear.dispatchEvent(new MouseEvent("click", { bubbles: true })); return true; })()`,
  );
  await sleep(500);
  // Svelte binds a select through each option's own value, so the choice is
  // made by selecting the option — assigning `el.value` matches nothing.
  const picked = await alice.evaluate(`(() => {
    const el = document.querySelector('select[data-opt="message-ttl"]');
    if (!el) return false;
    const i = [...el.options].findIndex((o) => o.textContent.includes("5 minutes"));
    if (i < 0) return false;
    el.selectedIndex = i;
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true; })()`);
  check("a channel's destruction timer is in its settings dialog", opened && picked);
  await alice.evaluate(`(() => { const form = document.querySelector('select[data-opt="message-ttl"]')?.closest("form");
    form?.querySelector(".create-btn")?.dispatchEvent(new MouseEvent("click", { bubbles: true })); return true; })()`);
  await sleep(1500);

  const showsTimer = async (tab) => {
    await tab.evaluate(
      `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.textContent.includes(${JSON.stringify(TIMED)}));
         el?.dispatchEvent(new MouseEvent("click", { bubbles: true })); return true; })()`,
    );
    for (let i = 0; i < 20; i++) {
      if (await tab.evaluate(`document.querySelector(".ttl-label")?.textContent?.includes("5 minutes") ?? false`)) return true;
      await sleep(300);
    }
    return false;
  };
  check("the writer is told what the channel's timer is", await showsTimer(alice));
  check("and so is somebody only reading it", await showsTimer(bob));
}

// 15. Name tags, and a direct message to somebody who has left. A name is
//     unique with its four-digit tag, and a tag somebody already holds is
//     swapped for a random one rather than refusing the connect. The tag is
//     shown only where somebody asks who exactly this is. And a message to
//     somebody who has left used to vanish without a word.
{
  const twin = `ui-twin-${process.pid % 10000}`;
  const first = await connect(twin, "0420");
  const second = await connect(twin, "0420");
  const toast = await second.evaluate(`window.__toasts.find((t) => t.includes("is taken there")) ?? ""`);
  const tag = /you are .*#(\d{4})/.exec(toast)?.[1] ?? "";
  check("a taken name and tag still connect, under another tag", tag !== "" && tag !== "0420", toast);

  const other = `${twin}#${tag}`;
  const row = `[...document.querySelectorAll(".user .name")].find((e) => e.title === ${JSON.stringify(other)})`;
  await waitFor(first, row).catch(() => {});
  check(
    "the list shows the name without its tag",
    (await first.evaluate(`${row}?.textContent.trim() ?? ""`)) === twin,
    await first.evaluate(`[...document.querySelectorAll(".user .name")].map((e) => e.title).join(", ")`),
  );
  await first.evaluate(
    `(() => { const el = ${row}?.closest(".user"); if (!el) return false;
       el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 })); return true; })()`,
  );
  await sleep(300);
  check(
    "the member menu spells the tag out",
    (await first.evaluate(`document.querySelector(".ctx-title")?.textContent ?? ""`)) === other &&
      (await first.evaluate(`document.querySelector(".ctx-tag")?.textContent ?? ""`)) === `#${tag}`,
  );
  await first.evaluate(
    `(() => { const b = [...document.querySelectorAll(".ctx-item")].find((e) => /direct message/i.test(e.textContent));
       if (!b) return false; b.click(); return true; })()`,
  );
  await waitFor(first, `document.querySelector(".input-bar .chat-input")`).catch(() => {});
  const say = (text) =>
    first.evaluate(`(() => { const input = document.querySelector(".input-bar .chat-input"); if (!input) return false;
      input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event("input", { bubbles: true }));
      input.closest("form").requestSubmit(); return true; })()`);
  const notDelivered = `[...document.querySelectorAll(".history-marker")].some((e) => e.textContent.includes("Not delivered"))`;

  // Delivered first — which also means the two have a session by now, so the
  // second message really goes to the server instead of waiting in a queue
  await say("hello twin");
  let delivered = false;
  try {
    await waitFor(second, `[...document.querySelectorAll(".dm-name")].some((e) => e.title === "${twin}#0420")`);
    delivered = true;
  } catch {
    // reported below
  }
  check("a direct message to a twin arrives", delivered);
  check("with no complaint", !(await first.evaluate(notDelivered)));

  await realClick(second, ".status-bar .disconnect-btn");
  await waitFor(first, `!${row}`).catch(() => {});
  await say("are you still there?");
  let told = false;
  try {
    await waitFor(first, notDelivered, 5000);
    told = true;
  } catch {
    // reported below
  }
  check("a direct message to somebody who left says it was not delivered", told);
  const fatal = [...first.errors, ...second.errors].filter((e) => !/Failed to load resource/.test(e));
  check("and the twins threw nothing", fatal.length === 0, fatal.slice(0, 2).join(" | "));
}

// 16. A share, from both ends, and the rows people are clicked on. The sharer
//     sees what they send before anybody watches; a viewer gets there in one
//     click and can keep the chat beside the stream or under it, sized and
//     remembered. A member row opens its menu on a left click and from the
//     keyboard too, and says so with the pointer. Two fresh users, so nothing
//     above decides which channel or layout this starts in.
{
  const n = process.pid % 10000;
  const SHOW = `show-${n}`;
  const host = await connect(`ui-host-${n}`);
  const guest = await connect(`ui-guest-${n}`);

  const useLayout = async (tab, id) => {
    await realClick(tab, ".settings-btn");
    await waitFor(tab, `document.querySelector(".tab")`, 8_000);
    await tab.evaluate(
      `[...document.querySelectorAll(".tab")].find((b) => /appearance/i.test(b.textContent)).click()`,
    );
    await sleep(300);
    await tab.evaluate(`document.querySelector('.layout-choice[data-layout="${id}"]').click()`);
    await sleep(500);
    await tab.evaluate(`document.querySelector(".close-btn")?.click()`);
    await sleep(500);
  };
  /** A real click on whatever `expr` evaluates to, near its left edge — on a
   *  member row that is the avatar, clear of the buttons at its end. */
  const clickEl = async (tab, expr) => {
    const at = await tab.evaluate(`(() => { const el = ${expr}; if (!el) return null;
      el.scrollIntoView({ block: "center" }); const r = el.getBoundingClientRect();
      return { x: Math.round(r.left + Math.min(20, r.width / 2)), y: Math.round(r.top + r.height / 2) }; })()`);
    if (!at) return false;
    const base = { x: at.x, y: at.y, button: "left", clickCount: 1 };
    await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0 });
    await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1 });
    await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1 });
    await sleep(200);
    return true;
  };
  const key = async (tab, k, code, vk) => {
    await tab.send("Input.dispatchKeyEvent", { type: "keyDown", key: k, code, windowsVirtualKeyCode: vk });
    await tab.send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk });
    await sleep(250);
  };
  const escape = (tab) => key(tab, "Escape", "Escape", 27);
  const stored = (tab, path) =>
    tab.evaluate(`JSON.parse(localStorage.getItem("voipc.settings")).ui_prefs?.${path}`);
  /** The debounced save, waited for rather than raced. */
  const storedSoon = async (tab, path, want) => {
    let v = await stored(tab, path);
    for (let i = 0; i < 20 && Math.abs(v - want) >= 4; i++) {
      await sleep(200);
      v = await stored(tab, path);
    }
    return v;
  };

  await useLayout(host, "modern");
  await useLayout(guest, "modern");
  await host.evaluate(click('button[title="Create channel"]'));
  await waitFor(host, `document.querySelector(".create-form")`);
  await host.evaluate(setInput(".create-form input[type=text]", SHOW));
  await host.evaluate(click(".create-form .create-btn"));
  await sleep(2000);
  await guest.evaluate(
    `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(SHOW)});
       if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
  );
  await waitFor(guest, `document.querySelector(".voice-panel")`).catch(() => {});
  await sleep(1500);

  // ── Member rows ──
  const rowOf = (who) =>
    `[...document.querySelectorAll(".user-list.modern .users .user")].find((e) => e.querySelector(".name")?.title.startsWith(${JSON.stringify(who)}))`;
  const ownRow = `[...document.querySelectorAll(".user-list.modern .users .user")].find((e) => e.querySelector(".you"))`;
  await waitFor(host, rowOf(`ui-guest-${n}`)).catch(() => {});
  check(
    "a member row with a menu shows the pointer",
    (await host.evaluate(`getComputedStyle(${rowOf(`ui-guest-${n}`)}).cursor`)) === "pointer",
  );
  check(
    "our own row, which has none, does not",
    (await host.evaluate(`getComputedStyle(${ownRow}).cursor`)) !== "pointer",
  );
  await clickEl(host, rowOf(`ui-guest-${n}`));
  check(
    "a left click on a member opens their menu",
    (await host.evaluate(`document.querySelector(".ctx-title")?.textContent ?? ""`)).startsWith(`ui-guest-${n}`),
  );
  await escape(host);
  check("Escape closes it again", !(await host.evaluate(`!!document.querySelector(".ctx-menu")`)));
  await host.evaluate(`${rowOf(`ui-guest-${n}`)}.focus()`);
  await key(host, "Enter", "Enter", 13);
  check(
    "so does Enter on a focused row",
    (await host.evaluate(`document.querySelector(".ctx-title")?.textContent ?? ""`)).startsWith(`ui-guest-${n}`),
  );
  await escape(host);
  await clickEl(host, ownRow);
  check("a click on our own row opens nothing", !(await host.evaluate(`!!document.querySelector(".ctx-menu")`)));

  // ── The sharer's preview, before anybody watches ──
  // Headless Chromium has no screen and no picker: an animated canvas stands
  // in for the display, as in the self-test (web/selftest.ts).
  await host.evaluate(`(() => {
    const canvas = document.createElement("canvas");
    canvas.width = 640; canvas.height = 360;
    const ctx = canvas.getContext("2d");
    let f = 0;
    setInterval(() => { f++; ctx.fillStyle = "hsl(" + (f * 9) % 360 + ", 70%, 45%)";
      ctx.fillRect(0, 0, 640, 360); ctx.fillStyle = "#fff"; ctx.fillRect((f * 11) % 640, 100, 120, 120); }, 66);
    const stream = canvas.captureStream(15);
    navigator.mediaDevices.getDisplayMedia = async () => stream;
    return true; })()`);
  await realClick(host, ".voice-panel .share-btn");
  await waitFor(host, `document.querySelector(".start-btn")`, 8_000).catch(() => {});
  await realClick(host, ".start-btn");
  let previewPlays = false;
  try {
    await waitFor(host, `document.querySelector(".share-preview video")?.videoWidth > 0`, 10_000);
    previewPlays = true;
  } catch {
    // reported below
  }
  check("the sharer sees their own stream", previewPlays);
  check(
    "with nobody watching yet",
    /nobody/i.test(await host.evaluate(`document.querySelector(".share-preview .audience")?.textContent ?? ""`)),
  );

  // ── One click to watch, and the chat beside it ──
  await waitFor(guest, `document.querySelector(".channel-list.modern button.live-tag.watch")`).catch(() => {});
  await realClick(guest, ".channel-list.modern button.live-tag.watch");
  let watching = false;
  try {
    await waitFor(guest, `document.querySelector(".activity .stream-stage .viewer")`, 8_000);
    watching = true;
  } catch {
    // reported below
  }
  check("one click on LIVE watches the share", watching);
  try {
    await waitFor(host, `/1 watching/.test(document.querySelector(".share-preview .audience")?.textContent ?? "")`, 8_000);
  } catch {
    // reported below
  }
  check(
    "and the sharer's preview counts the viewer",
    /1 watching/.test(await host.evaluate(`document.querySelector(".share-preview .audience")?.textContent ?? ""`)),
  );
  check(
    "the stream view starts without the chat here",
    !(await guest.evaluate(`!!document.querySelector(".stream-stage .stream-chat")`)),
  );
  await realClick(guest, ".stream-stage .chat-toggle");
  check(
    "the chat toggle docks the chat beside the stream",
    await guest.evaluate(`!!document.querySelector(".stream-stage.side .stream-chat .chat-panel")`),
  );
  const chatSize = (dim) =>
    guest.evaluate(`document.querySelector(".stream-stage .stream-chat")?.getBoundingClientRect().${dim} ?? 0`);
  const wideBefore = await chatSize("width");
  await realDragX(guest, ".stream-stage .split-handle", -80);
  const wideAfter = await chatSize("width");
  check("the chat can be dragged wider", wideAfter > wideBefore + 40, `${wideBefore} -> ${wideAfter}`);
  check(
    "and the width is remembered",
    Math.abs((await storedSoon(guest, "stream_chat?.modern?.width", wideAfter)) - wideAfter) < 4,
  );
  await realClick(guest, ".stream-stage .split-toggle");
  check(
    "the other button puts it under the stream",
    await guest.evaluate(`!!document.querySelector(".stream-stage.below .stream-chat .chat-panel")`),
  );
  const tallBefore = await chatSize("height");
  await realDrag(guest, ".stream-stage .split-handle", -60);
  const tallAfter = await chatSize("height");
  check("and drags taller there", tallAfter > tallBefore + 30, `${tallBefore} -> ${tallAfter}`);
  check(
    "remembering the height as well",
    Math.abs((await storedSoon(guest, "stream_chat?.modern?.height", tallAfter)) - tallAfter) < 4,
  );

  // ── News while the chat is hidden ──
  await realClick(guest, ".stream-stage .chat-toggle");
  check("the toggle hides it again", !(await guest.evaluate(`!!document.querySelector(".stream-stage .stream-chat")`)));
  check("with nothing new to point at", !(await guest.evaluate(`!!document.querySelector(".chat-toggle .unread-dot")`)));
  await host.evaluate(`(() => { const input = document.querySelector(".input-bar .chat-input"); if (!input) return false;
    input.value = "look at this"; input.dispatchEvent(new Event("input", { bubbles: true }));
    input.closest("form").requestSubmit(); return true; })()`);
  let dot = false;
  try {
    await waitFor(guest, `document.querySelector(".chat-toggle .unread-dot")`, 10_000);
    dot = true;
  } catch {
    // reported below
  }
  check(
    "a message meanwhile marks the chat toggle",
    dot,
    `host shows ${await host.evaluate(`document.querySelector(".chat-title")?.textContent.trim()`)}`,
  );
  await realClick(guest, ".stream-stage .chat-toggle");
  check("opening the chat clears it", !(await guest.evaluate(`!!document.querySelector(".chat-toggle .unread-dot")`)));

  // ── The classic layout gets the same view, chat below by default ──
  // The modern stream view covers the whole window, Settings included, so
  // out of it first — and back in from the classic list's own one click.
  await realClick(guest, ".stream-stage .stop-btn");
  await waitFor(guest, `!document.querySelector(".activity")`, 5_000).catch(() => {});
  await useLayout(guest, "classic");
  // Hover first: the row shows its ⋮ on hover, which moves the icon over by
  // one button — a hand is on the row before it aims, a synthetic click is not.
  await hover(guest, ".users .user button.status-icon.watch");
  await realClick(guest, ".users .user button.status-icon.watch");
  await waitFor(guest, `document.querySelector(".app-layout .stream-stage")`, 8_000).catch(() => {});
  check(
    "classic shows the share with its chat below",
    await guest.evaluate(`!!document.querySelector(".app-layout .stream-stage.below .stream-chat .chat-panel")`),
    await guest.evaluate(`JSON.stringify({
      classic: !!document.querySelector(".app-layout"),
      watchButton: !!document.querySelector(".users .user button.status-icon.watch"),
      stage: document.querySelector(".stream-stage")?.className ?? null })`),
  );

  // ── The sharer's preview, big ──
  await realClick(host, '.share-preview .bar-btn[title^="Enlarge"]');
  check(
    "the preview enlarges into the stream view",
    await host.evaluate(`!!document.querySelector(".activity .share-preview.stage") && !document.querySelector(".share-preview:not(.stage)")`),
  );
  await escape(host);
  check(
    "Escape puts it back in its corner",
    await host.evaluate(`!document.querySelector(".activity") && !!document.querySelector(".share-preview:not(.stage)")`),
  );

  await realClick(host, ".voice-panel .share-btn.active");
  await sleep(1200);
  check("stopping the share takes the preview away", !(await host.evaluate(`!!document.querySelector(".share-preview")`)));
  check("and the viewer's stream view closes", !(await guest.evaluate(`!!document.querySelector(".stream-stage")`)));

  // ── A share this browser cannot decode, watched while sharing (B1-N1) ──
  // It is said with the same event that a share of our own refused comes
  // with, and it used to end ours too. The decoder probe saying no to every
  // codec stands in for a browser without one (Firefox and H.265).
  await guest.evaluate(`(() => {
    const canvas = document.createElement("canvas");
    canvas.width = 320; canvas.height = 180;
    const ctx = canvas.getContext("2d");
    let f = 0;
    setInterval(() => { f++; ctx.fillStyle = "hsl(" + (f * 13) % 360 + ", 60%, 40%)"; ctx.fillRect(0, 0, 320, 180); }, 66);
    navigator.mediaDevices.getDisplayMedia = async () => canvas.captureStream(15);
    return true; })()`);
  // A fresh stream for the host's second share: the first one's track ended with it
  await host.evaluate(`(() => { const canvas = document.createElement("canvas"); canvas.width = 320; canvas.height = 180;
    const ctx = canvas.getContext("2d"); let f = 0;
    setInterval(() => { f++; ctx.fillStyle = "hsl(" + (f * 7) % 360 + ", 60%, 40%)"; ctx.fillRect(0, 0, 320, 180); }, 66);
    navigator.mediaDevices.getDisplayMedia = async () => canvas.captureStream(15); return true; })()`);
  await realClick(guest, '.share-btn[title="Share your screen"]');
  await waitFor(guest, `document.querySelector(".start-btn")`, 8_000).catch(() => {});
  await realClick(guest, ".start-btn");
  const ownShare = await waitFor(guest, `document.querySelector(".share-btn.active")`, 10_000).then(() => true, () => false);
  await realClick(host, ".voice-panel .share-btn");
  await waitFor(host, `document.querySelector(".start-btn")`, 8_000).catch(() => {});
  await realClick(host, ".start-btn");
  const hostWatch = `.users .user:has(.name[title^="ui-host-${n}"]) button.status-icon.watch`;
  await waitFor(guest, `document.querySelector(${JSON.stringify(hostWatch)})`, 10_000).catch(() => {});
  await guest.evaluate(`(() => { window.__probe = VideoDecoder.isConfigSupported;
    VideoDecoder.isConfigSupported = async (config) => ({ supported: false, config }); return true; })()`);
  await hover(guest, hostWatch);
  await realClick(guest, hostWatch);
  const told = await waitFor(guest, `(window.__toasts ?? []).some((t) => /cannot decode/.test(t))`, 10_000).then(() => true, () => false);
  await sleep(1000);
  check(
    "a share this browser cannot decode is said so, and our own share goes on",
    ownShare && told && (await guest.evaluate(`!!document.querySelector(".share-btn.active")`)),
    await guest.evaluate(`JSON.stringify({ ownShare: ${ownShare}, sharing: !!document.querySelector(".share-btn.active"), toasts: window.__toasts?.slice(-3) })`),
  );
  await guest.evaluate(`(() => { if (window.__probe) VideoDecoder.isConfigSupported = window.__probe; return true; })()`);
  await realClick(guest, ".share-btn.active");
  await realClick(host, ".voice-panel .share-btn.active");
  await sleep(1200);

  for (const [who, tab] of [["sharer", host], ["viewer", guest]]) {
    const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
    check(`the ${who} threw nothing`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
  }
  // The profile is shared by every tab: leave it in the layout the rest of
  // this file expects of a fresh connect.
  await useLayout(host, "classic");

  // ── An invite link: a voice channel shows, then asks; a text one opens (S-048) ──
  // The link is somebody else's idea, and a voice channel is a seat with a
  // microphone: following it is no reason to be put in the call.
  const NOTES = `notes-${n}`;
  await host.evaluate(click('button[title="Create channel"]'));
  await waitFor(host, `document.querySelector(".create-form")`);
  await host.evaluate(setInput(".create-form input[type=text]", NOTES));
  await host.evaluate(click('.create-form input[data-kind="text"]'));
  await sleep(300);
  await host.evaluate(click(".create-form .create-btn"));
  await sleep(2000);
  // Connected through the dialog of a page opened on the link. The first-run
  // dialogs are answered after the question, which a new user gets on top
  const byInvite = async (name, channel) => {
    const tab = await newTab();
    await tab.send("Page.navigate", { url: `${URL}#channel=${encodeURIComponent(channel)}` });
    await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
    if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
      await tab.evaluate(click(".skip-link"));
      await waitFor(tab, `document.querySelector(".connect-btn")`);
    }
    await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
    await tab.evaluate(setInput('input[placeholder="9987"]', PORT));
    await tab.evaluate(setInput('input[placeholder="Your name"]', name));
    await tab.evaluate(click(".connect-btn"));
    await waitFor(tab, `!document.querySelector(".connect-btn")`);
    return tab;
  };
  const confirmTitle = `document.querySelector(".confirm .dialog-title")?.textContent ?? ""`;
  const inVoice = `!!document.querySelector(".leave-voice-btn")`;
  const no = await byInvite(`ui-inv-${n}`, SHOW);
  const asked = await waitFor(no, `${confirmTitle} === ${JSON.stringify(`Join voice in ${SHOW}?`)}`, 10_000).then(() => true, () => false);
  check("an invite link to a voice channel asks before it seats you", asked && !(await no.evaluate(inVoice)), await no.evaluate(confirmTitle));
  check("and shows the channel meanwhile", await no.evaluate(`document.querySelector(".join-voice-btn")?.textContent.includes(${JSON.stringify(SHOW)}) ?? false`),
    await no.evaluate(`document.querySelector(".chat-header")?.textContent.trim().slice(0, 120) ?? "no chat header"`));
  await no.evaluate(`[...document.querySelectorAll(".confirm button")].find((b) => b.textContent.trim() === "Cancel")?.click()`);
  await answerFirstRun(no, "invited");
  await sleep(500);
  check("Cancel leaves you out of voice", asked && !(await no.evaluate(`!!document.querySelector(".confirm")`)) && !(await no.evaluate(inVoice)));
  const yes = await byInvite(`ui-inv2-${n}`, SHOW);
  await waitFor(yes, `${confirmTitle}.startsWith("Join voice")`, 10_000).catch(() => {});
  await yes.evaluate(`[...document.querySelectorAll(".confirm button")].find((b) => b.textContent.trim() === "Join voice")?.click()`);
  await answerFirstRun(yes, "seated");
  check("Join voice seats you in it", await waitFor(yes, `${inVoice} && [...document.querySelectorAll(".channel.active .channel-name")].some((e) => e.textContent === ${JSON.stringify(SHOW)})`, 10_000)
    .then(() => true, () => false));
  const text = await byInvite(`ui-inv3-${n}`, NOTES);
  await answerFirstRun(text, "text-invited");
  const opened = await waitFor(text, `document.querySelector(".chat-title")?.textContent.includes(${JSON.stringify(NOTES)}) && !!document.querySelector(".chat-main .input-bar .chat-input")`, 10_000)
    .then(() => true, () => false);
  check("an invite link to a text channel opens it, with nothing to ask", opened && !(await text.evaluate(`!!document.querySelector(".confirm")`)) && !(await text.evaluate(inVoice)),
    await text.evaluate(`(document.querySelector(".chat-title")?.textContent ?? "no title") + " | " + ${confirmTitle}`));
  for (const [who, tab] of [["invited", no], ["seated", yes], ["text-invited", text]]) {
    const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
    check(`the ${who} tab threw nothing`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
    await tab.send("Page.close").catch(() => {});
  }
}

// 19. Chat: markdown, replies and threads (1.2). The rules — what markdown may
//     draw, what an answer finds, which answers fold into a thread — are unit-
//     tested (markdown.test.ts, thread-rules.test.ts). What only a browser can
//     show is that a peer's message arrives drawn, that the tools are reached
//     with a real pointer, and that a quote leads somewhere. It runs here, before
//     the lanes that leave other servers and accounts in the shared profile, where
//     a fresh tab no longer opens on the connect dialog.
{
  const n = (process.pid + 7) % 10000;
  const ROOM = `talk-${n}`;
  const ann = await connect(`ui-ann-${n}`);
  const ben = await connect(`ui-ben-${n}`);
  await ann.evaluate(click('button[title="Create channel"]'));
  await waitFor(ann, `document.querySelector(".create-form")`);
  await ann.evaluate(setInput(".create-form input[type=text]", ROOM));
  await ann.evaluate(click(".create-form .create-btn"));
  await sleep(2000);
  await ben.evaluate(
    `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(ROOM)});
       if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
  );
  await waitFor(ben, `document.querySelector(".input-bar .chat-input")`).catch(() => {});
  await sleep(1500);

  const say = (tab, text, where = ".chat-main") =>
    tab.evaluate(`(() => { const input = document.querySelector(${JSON.stringify(`${where} .input-bar .chat-input`)}); if (!input) return false;
      input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event("input", { bubbles: true }));
      input.closest("form").requestSubmit(); return true; })()`);
  /** The main flow's row holding `text`. */
  const rowWith = (text, where = ".chat-main") =>
    `[...document.querySelectorAll(${JSON.stringify(`${where} .msg`)})].find((e) => e.querySelector(".msg-content")?.textContent.includes(${JSON.stringify(text)}))`;
  const arrived = (tab, text, where) => waitFor(tab, rowWith(text, where), 10_000).then(() => true, () => false);
  /** A real pointer: onto the row (its tools show on hover), then onto `button` inside it. */
  const useTool = async (tab, text, label, where) => {
    const at = (sel) => tab.evaluate(`(() => { const row = ${rowWith(text, where)}; const el = ${sel}; if (!el) return null;
      el.scrollIntoView({ block: "center" }); const r = el.getBoundingClientRect(); if (r.width === 0) return null;
      return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }; })()`);
    const move = (p) => tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: p.x, y: p.y, buttons: 0 });
    const rowAt = await at("row");
    if (!rowAt) return false;
    await move(rowAt);
    await sleep(150);
    const btn = await at(`row?.querySelector('.msg-tools button[aria-label=${JSON.stringify(label)}]')`);
    if (!btn) return false;
    await move(btn);
    for (const type of ["mousePressed", "mouseReleased"]) {
      await tab.send("Input.dispatchMouseEvent", { type, x: btn.x, y: btn.y, button: "left", clickCount: 1, buttons: 1 });
    }
    await sleep(300);
    return true;
  };

  // ── Markdown arrives drawn, and HTML arrives as text ──
  await say(ann, "**bold** move and <b>raw</b>");
  await say(ann, "```rust\nfn main() { let x = 1; }\n```");
  check("a peer's markdown arrives drawn", (await arrived(ben, "bold move")) &&
    (await ben.evaluate(`${rowWith("bold move")}?.querySelector(".msg-content strong")?.textContent === "bold"`)));
  check("their HTML arrives as the text it is", await ben.evaluate(
    `${rowWith("bold move")}?.querySelector(".msg-content").textContent.includes("<b>raw</b>") && !${rowWith("bold move")}?.querySelector(".msg-content b")`));
  let coloured = false;
  try {
    await waitFor(ben, `${rowWith("fn main")}?.querySelector(".code-block pre code .tok-keyword")`, 10_000);
    coloured = true;
  } catch {
    // reported below
  }
  check("a fenced rust block is coloured", coloured, await ben.evaluate(`${rowWith("fn main")}?.innerHTML.slice(0, 300) ?? "no row"`));

  // ── A quote nested 300 deep: it arrives, and the conversation goes on (R2-01) ──
  // 605 characters, within what the box takes: it once overflowed every
  // reader's renderer and took the whole conversation off the screen
  await say(ann, "> ".repeat(300) + "deepx");
  await say(ann, "after the deep one");
  check("a quote nested 300 deep arrives, and so does the next message",
    (await arrived(ben, "deepx")) && (await arrived(ben, "after the deep one")),
    await ben.evaluate(`[...document.querySelectorAll(".chat-main .msg .msg-content")].map((e) => e.textContent.slice(-30)).slice(-3).join(" | ")`));

  // ── Shift+Enter is a new line, not a send ──
  await ben.evaluate(`document.querySelector(".chat-main .input-bar .chat-input").focus()`);
  await ben.send("Input.insertText", { text: "line one" });
  // A key event carries its text, or the browser types nothing: "\r" is what Enter types
  await ben.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, modifiers: 8, text: "\r" });
  await ben.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, modifiers: 8 });
  await ben.send("Input.insertText", { text: "line two" });
  check("Shift+Enter keeps a new line in the box", await ben.evaluate(
    `document.querySelector(".chat-main .input-bar .chat-input").value === "line one\\nline two"`));
  await ben.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await ben.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  check("and Enter sends both lines as one message", await arrived(ann, "line two") &&
    (await ann.evaluate(`${rowWith("line two")}?.querySelector(".msg-content br") !== null`)));

  // ── A reply, from the row's own tool ──
  check("a message's Reply tool is reached with a real pointer", await useTool(ben, "bold move", "Reply"));
  check("the box says what is being answered", await ben.evaluate(`/ui-ann/.test(document.querySelector(".chat-main .reply-bar")?.textContent ?? "")`));
  await say(ben, "agreed on that");
  check("the reply bar goes once it is sent", !(await ben.evaluate(`!!document.querySelector(".chat-main .reply-bar")`)));
  check("the reply arrives quoting what it answers", (await arrived(ann, "agreed on that")) &&
    (await ann.evaluate(`/bold move/.test(${rowWith("agreed on that")}?.querySelector(".quote-text")?.textContent ?? "")`)));
  await ann.evaluate(`${rowWith("agreed on that")}?.querySelector("button.quote")?.click()`);
  check("its quote leads to the message answered", await ann.evaluate(`${rowWith("bold move")}?.classList.contains("flash") ?? false`));

  // ── Busy answers gather into a thread ──
  await useTool(ann, "bold move", "Reply");
  await say(ann, "second answer here");
  await arrived(ben, "second answer here");
  await useTool(ben, "second answer here", "Reply");
  await say(ben, "third answer here");
  let gathered = false;
  try {
    await waitFor(ann, `${rowWith("bold move")}?.querySelector(".thread-summary")?.textContent.includes("3 replies")`, 10_000);
    gathered = true;
  } catch {
    // reported below
  }
  check("three answers from two people become a thread", gathered,
    await ann.evaluate(`[...document.querySelectorAll(".chat-main .msg .msg-content")].map((e) => e.textContent).join(" | ").slice(0, 300)`));
  check("and leave the main flow", !(await ann.evaluate(`!!${rowWith("third answer here")}`)));
  await ann.evaluate(`${rowWith("bold move")}?.querySelector(".thread-summary")?.click()`);
  check("the summary opens the thread", await ann.evaluate(
    `[...document.querySelectorAll(".thread-pane .msg .msg-content")].some((e) => e.textContent.includes("third answer here"))`));
  await ann.evaluate(`document.querySelector(".thread-pane .thread-close")?.click()`);
  await sleep(300);

  // ── An answer sent into a thread ──
  await say(ann, "start a thread on me");
  await arrived(ben, "start a thread on me");
  await useTool(ben, "start a thread on me", "Reply in thread");
  check("Reply in thread opens the thread", await ben.evaluate(`!!document.querySelector(".thread-pane")`));
  await say(ben, "inside the thread", ".thread-pane");
  let threaded = false;
  try {
    await waitFor(ann, `${rowWith("start a thread on me")}?.querySelector(".thread-summary")?.textContent.includes("1 reply")`, 10_000);
    threaded = true;
  } catch {
    // reported below
  }
  check("an answer sent into a thread arrives in it", threaded);
  check("and never in the main flow", !(await ann.evaluate(`!!${rowWith("inside the thread")}`)));

  // ── The row's menu: a right click (a long press, on a touch screen) ──
  const lineAt = await ann.evaluate(`(() => { const r = ${rowWith("line two")}?.getBoundingClientRect();
    return r ? { x: Math.round(r.left + 40), y: Math.round(r.top + 10) } : null; })()`);
  if (lineAt) {
    for (const type of ["mousePressed", "mouseReleased"]) {
      await ann.send("Input.dispatchMouseEvent", { type, x: lineAt.x, y: lineAt.y, button: "right", clickCount: 1, buttons: 2 });
    }
  }
  await sleep(300);
  check("a right click on a message opens its menu", await ann.evaluate(
    `[...document.querySelectorAll(".msg-menu [role=menuitem]")].map((b) => b.textContent.trim()).join(",") === "React,Reply,Reply in thread,Forward,Pin,Copy text"`),
    await ann.evaluate(`document.querySelector(".msg-menu")?.textContent ?? "no menu"`));
  // At the pointer, or ending there where there is no room below it
  check("where the pointer is", !!lineAt && (await ann.evaluate(`(() => { const r = document.querySelector(".msg-menu")?.getBoundingClientRect();
    return !!r && Math.abs(r.left - ${lineAt?.x ?? 0}) < 4 && (Math.abs(r.top - ${lineAt?.y ?? 0}) < 4 || Math.abs(r.bottom - ${lineAt?.y ?? 0}) < 4); })()`)),
    await ann.evaluate(`JSON.stringify(document.querySelector(".msg-menu")?.getBoundingClientRect())`) + ` vs ${JSON.stringify(lineAt)}`);
  await ann.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await ann.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await sleep(200);
  check("and Escape closes it", !(await ann.evaluate(`!!document.querySelector(".msg-menu")`)));

  // ── The list is one Tab stop: its links, spoilers and Copy buttons too (R2-06) ──
  await say(ann, "see [the site](https://\u0430pple.com/login) and ||hidden words||");
  await arrived(ben, "see the site");
  const stops = await ben.evaluate(`(() => {
    const all = [...document.querySelectorAll(".chat-main .messages :is(button, a[href], [tabindex], video, audio)")]
      .filter((e) => e.tabIndex >= 0 && !e.closest("[inert]") && e.checkVisibility());
    return { stops: all.length, rows: new Set(all.map((e) => e.closest(".msg")).filter(Boolean)).size };
  })()`);
  check("the message list is one Tab stop: only the keyboard's row offers its links, spoilers and Copy", stops.rows === 1, JSON.stringify(stops));

  // ── The link popup names where a look-alike host really goes (R2-12) ──
  await ben.evaluate(`${rowWith("see the site")}?.querySelector(".msg-link")?.click()`);
  await sleep(200);
  check("the link popup shows a look-alike host as the punycode it is", await ben.evaluate(
    `document.querySelector(".link-input")?.value === "https://xn--pple-43d.com/login" && /Goes to xn--pple-43d\\.com/.test(document.querySelector(".link-host")?.textContent ?? "")`),
    await ben.evaluate(`(document.querySelector(".link-input")?.value ?? "no popup") + " / " + (document.querySelector(".link-host")?.textContent ?? "")`));
  await ben.evaluate(`document.querySelector(".link-close-btn")?.click()`);
  await sleep(200);

  // ── A long press on a touch screen is the message menu, whatever it selected (D1-01) ──
  // The phone's web view selects the word under the finger first, then asks
  // for the menu: the native selection bar used to win
  const pressed = await ben.evaluate(`(() => {
    const row = ${rowWith("see the site")}; const p = row?.querySelector(".md-p"); if (!p) return false;
    row.scrollIntoView({ block: "center" });
    const word = document.createTreeWalker(p, NodeFilter.SHOW_TEXT).nextNode(); if (!word) return false;
    const range = document.createRange(); range.setStart(word, 0); range.setEnd(word, 3);
    getSelection().removeAllRanges(); getSelection().addRange(range);
    const r = p.getBoundingClientRect();
    const at = { bubbles: true, cancelable: true, pointerType: "touch", clientX: r.left + 5, clientY: r.top + 5 };
    p.dispatchEvent(new PointerEvent("pointerdown", at));
    p.dispatchEvent(new PointerEvent("contextmenu", at));
    return true; })()`);
  await sleep(200);
  check("a long press opens the message menu, even over the word it selected", pressed &&
    (await ben.evaluate(`!!document.querySelector(".msg-menu") && getSelection().toString() === ""`)),
    await ben.evaluate(`(document.querySelector(".msg-menu") ? "menu" : "no menu") + ", selection: " + JSON.stringify(getSelection().toString())`));
  for (const type of ["keyDown", "keyUp"]) {
    await ben.send("Input.dispatchKeyEvent", { type, key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  }
  await sleep(200);

  // ── A tap leaves no tool bar over the text: a finger's hover sticks (D2-09) ──
  const tapAt = await ben.evaluate(`(() => { const r = ${rowWith("after the deep one")}?.getBoundingClientRect();
    return r ? { x: Math.round(r.left + 60), y: Math.round(r.top + r.height / 2) } : null; })()`);
  if (tapAt) {
    await ben.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [tapAt] });
    await ben.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  }
  await sleep(400);
  // A phone keeps :hover on what the finger touched; this browser does not,
  // so the row is held hovered the way the phone holds it
  await ben.evaluate(`${rowWith("after the deep one")}?.setAttribute("data-tapped", "")`);
  const root = (await ben.send("DOM.getDocument", { depth: 0 })).result?.root;
  const nodeId = root && (await ben.send("DOM.querySelector", { nodeId: root.nodeId, selector: ".chat-main .msg[data-tapped]" })).result?.nodeId;
  await ben.send("CSS.enable", {});
  if (nodeId) await ben.send("CSS.forcePseudoState", { nodeId, forcedPseudoClasses: ["hover"] });
  check("a tap on a message leaves no tool bar standing over it", !!tapAt && !!nodeId && (await ben.evaluate(
    `(() => { const t = document.querySelector(".chat-main .msg[data-tapped] .msg-tools"); return !!t && getComputedStyle(t).display === "none"; })()`)),
    await ben.evaluate(`document.querySelector(".chat-main .msg[data-tapped]")?.matches(":hover") ? "hovered" : "not hovered"`));
  if (nodeId) await ben.send("CSS.forcePseudoState", { nodeId, forcedPseudoClasses: [] });
  await ben.evaluate(`document.querySelector(".chat-main .msg[data-tapped]")?.removeAttribute("data-tapped")`);

  // ── A reader at the end stays there as tall messages come (R2-05) ──
  // Rows off screen are only estimated now (content-visibility): the end is
  // followed by the reader's own scrolling, not by measuring
  await ben.evaluate(`(() => { const el = document.querySelector(".chat-main .messages"); el.scrollTop = el.scrollHeight; })()`);
  await sleep(300);
  for (let i = 0; i < 20; i++) await say(ann, `tall ${i}\n- one\n- two\n- three\n\n\`\`\`\ncode ${i}\nmore code\n\`\`\``);
  await arrived(ben, "code 19");
  await sleep(800);
  const below = await ben.evaluate(`(() => { const el = document.querySelector(".chat-main .messages"); return Math.round(el.scrollHeight - el.scrollTop - el.clientHeight); })()`);
  check("a reader at the end stays at the end as tall messages arrive", below < 40, `${below} px above the end`);

  // ── @ completes a name, and the person named sees it ──
  await ben.evaluate(`document.querySelector(".chat-main .input-bar .chat-input").focus()`);
  await ben.send("Input.insertText", { text: "@ui-a" });
  await sleep(200);
  check("@ offers the names that start so", await ben.evaluate(
    `[...document.querySelectorAll(".chat-main .mention-option")].some((e) => e.textContent.includes("ui-ann-${n}"))`));
  await ben.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await ben.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  check("Enter takes the name instead of sending", await ben.evaluate(
    `document.querySelector(".chat-main .input-bar .chat-input").value === "@ui-ann-${n} "`));
  await ben.send("Input.insertText", { text: "look here" });
  await ben.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await ben.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  check("the person named sees their name marked", (await arrived(ann, "look here")) &&
    (await ann.evaluate(`!!${rowWith("look here")}?.querySelector(".mention.me") && ${rowWith("look here")}.classList.contains("to-me")`)));

  // ── "New" marks where the unread part begins ──
  const openChannel = (tab, name) => tab.evaluate(
    `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(name)});
       if (!el) return false; el.dispatchEvent(new MouseEvent("click", { bubbles: true })); return true; })()`);
  await openChannel(ann, "lobby-chat");
  await sleep(600);
  await say(ben, "while you were reading elsewhere");
  await say(ben, "and one more");
  await sleep(1200);
  await openChannel(ann, ROOM);
  await sleep(800);
  check("the first unread message gets a New divider", await ann.evaluate(
    `(() => { const d = document.querySelector(".chat-main .new-divider"); const next = d?.nextElementSibling;
       return !!next && next.querySelector(".msg-content")?.textContent.includes("while you were reading elsewhere"); })()`));

  // ── Search, here and everywhere ──
  await ann.evaluate(`document.querySelector(".search-btn")?.click()`);
  await waitFor(ann, `document.querySelector(".search-pane .search-input")`, 5_000).catch(() => {});
  await ann.evaluate(setInput(".search-pane .search-input", "BOLD"));
  await sleep(300);
  check("search finds a message, whatever its case", await ann.evaluate(
    `[...document.querySelectorAll(".search-pane .result")].some((e) => e.textContent.includes("bold move"))`));
  await ann.evaluate(`[...document.querySelectorAll(".search-pane .result")].find((e) => e.textContent.includes("bold move"))?.click()`);
  await sleep(500);
  check("picking a result goes to the message", await ann.evaluate(
    `!document.querySelector(".search-pane") && (${rowWith("bold move")}?.classList.contains("flash") ?? false)`));
  await ann.evaluate(`document.querySelector(".search-btn")?.click()`);
  await waitFor(ann, `document.querySelector(".search-pane .search-input")`, 5_000).catch(() => {});
  await ann.evaluate(`[...document.querySelectorAll(".search-pane .scope")].find((b) => /everywhere/i.test(b.textContent))?.click()`);
  await ann.evaluate(setInput(".search-pane .search-input", "inside the thread"));
  await sleep(300);
  check("everywhere names the conversation a result is in", await ann.evaluate(
    `[...document.querySelectorAll(".search-pane .result")].some((e) => e.querySelector(".result-conv")?.textContent.includes(${JSON.stringify(ROOM)}))`));
  await ann.evaluate(`document.querySelector(".search-pane .search-close")?.click()`);

  // ── A message far past what the box takes is cut where it arrives (D-7) ──
  // Only a modified client sends one; the reader keeps 16 KiB of it. Last
  // here: a row that long changes where the others sit
  await openChannel(ann, ROOM);
  await sleep(500);
  await say(ann, `long${"z".repeat(20_000)}`);
  check("a message past 16 KiB arrives cut to 16 KiB", (await arrived(ben, "longzzz")) &&
    (await ben.evaluate(`${rowWith("longzzz")}?.querySelector(".msg-content")?.textContent.trim().length === 16 * 1024`)),
    String(await ben.evaluate(`${rowWith("longzzz")}?.querySelector(".msg-content")?.textContent.trim().length`)));

  // The channel's own settings, from its row's gear: `set` runs in the dialog
  const settings = async (set) => {
    await ann.evaluate(`(() => { const row = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(ROOM)});
      row?.parentElement?.querySelector('[title="Channel settings"]')?.dispatchEvent(new MouseEvent("click", { bubbles: true })); return true; })()`);
    await waitFor(ann, `document.querySelector('select[data-opt="message-ttl"]')`, 5_000).catch(() => {});
    await ann.evaluate(set);
    await ann.evaluate(`document.querySelector('select[data-opt="message-ttl"]')?.closest("form")?.querySelector(".create-btn")?.dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
    await sleep(1200);
  };
  const timer = (words) => `(() => { const el = document.querySelector('select[data-opt="message-ttl"]');
    el.selectedIndex = [...el.options].findIndex((o) => o.textContent.includes(${JSON.stringify(words)}));
    el.dispatchEvent(new Event("change", { bubbles: true })); })()`;
  const timerShown = (words) => waitFor(ann, `document.querySelector(".chat-main .ttl-label")?.textContent.includes(${JSON.stringify(words)})`, 10_000).catch(() => {});

  // ── An edit lives no longer than what is left of its message (R3-06) ──
  // It carries the new text, and in a kept log it must not outlast the
  // message it changes, however long the channel's timer is by then. Read in
  // what the reader's page is handed for each event: the event bus copies
  // every payload for its listeners (web/backend/events.ts `emit`), and the
  // copy taken here changes nothing.
  await settings(timer("5 minutes"));
  await timerShown("5 minutes");
  await say(ann, "short-lived words");
  await arrived(ben, "short-lived words");
  await settings(timer("1 hour"));
  await timerShown("1 hour");
  await ben.evaluate(`(() => { const copy = window.__clone = structuredClone; window.__events = [];
    window.structuredClone = (v, o) => { const d = v?.data; if (d?.event != null) window.__events.push({ ttl: d.ttl_secs ?? null, event: d.event }); return copy(v, o); };
    return true; })()`);
  await useTool(ann, "short-lived words", "Edit");
  await ann.evaluate(`(() => { const t = document.querySelector(".chat-main .edit-input"); if (!t) return false;
    t.value = "short-lived words, edited"; t.dispatchEvent(new Event("input", { bubbles: true })); t.focus(); return true; })()`);
  await ann.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
  await ann.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await waitFor(ben, `${rowWith("short-lived words, edited")}?.querySelector(".edited")`, 10_000).catch(() => {});
  const edits = await ben.evaluate(`window.__events.filter((e) => e.event?.kind === "edit")`);
  check("an edit's timer is what is left of its message's, not the channel's longer one",
    edits.length === 1 && edits[0].ttl > 0 && edits[0].ttl <= 300, JSON.stringify(edits));
  await ben.evaluate(`(() => { window.structuredClone = window.__clone; return true; })()`);

  // ── Behind an 18+ gate, search finds nothing (R2-15) ──
  // What the pane hides is not searched either: here, nor everywhere
  const search = async (scope, words) => {
    await ben.evaluate(`document.querySelector(".search-pane") || document.querySelector(".chat-main .search-btn, .search-btn")?.click()`);
    await waitFor(ben, `document.querySelector(".search-pane .search-input")`, 5_000).catch(() => {});
    await ben.evaluate(`[...document.querySelectorAll(".search-pane .scope")].find((b) => b.textContent.trim() === ${JSON.stringify(scope)})?.click()`);
    await ben.evaluate(setInput(".search-pane .search-input", words));
    await sleep(600);
    const found = await ben.evaluate(`[...document.querySelectorAll(".search-pane .result")].map((e) => e.textContent.slice(0, 80))`);
    await ben.evaluate(`document.querySelector(".search-pane .search-close")?.click()`);
    await sleep(200);
    return found;
  };
  const before18 = await search("Everywhere", "bold move");
  await settings(`document.querySelector('.password-dialog input[data-opt="nsfw"]')?.click()`);
  const gate = await waitFor(ben, `document.querySelector(".chat-main .nsfw-gate")`, 10_000).then(() => true, () => false);
  const here = await search("This conversation", "bold move");
  const everywhere = await search("Everywhere", "bold move");
  check("an 18+ channel nobody here said yes to: This conversation finds nothing behind its gate",
    gate && before18.length > 0 && here.length === 0, JSON.stringify({ gate, before18, here }));
  check("and Everywhere leaves it out", gate && before18.length > 0 && everywhere.length === 0, JSON.stringify({ everywhere }));

  for (const [who, tab] of [["writer", ann], ["reader", ben]]) {
    const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
    check(`the chat's ${who} threw nothing`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
  }
}

// 20. Files (1.3). The rules — the envelope's bounds, sniffing, the preview,
//     save names, the cache — are unit-tested (envelope.rs, chat-rules,
//     file-sniff, file-rules) and the transfer has its own lanes (files.rs live
//     tests, the self-test's FILE_KIB). What only a browser shows is the card:
//     a preview drawn with nothing fetched, Load drawing what the bytes are,
//     the original sent as it is, a file that is only ever saved, and the relay
//     letting go (test-web.sh runs it with cache_mins = 1) followed by a member
//     sending it again, or by nobody. Before 14, 17 and 18, as 19 is.
{
  const n = (process.pid + 11) % 10000;
  const ROOM = `files-${n}`;
  const ann = await connect(`ui-fa-${n}`);
  const ben = await connect(`ui-fb-${n}`);
  await ann.evaluate(click('button[title="Create channel"]'));
  await waitFor(ann, `document.querySelector(".create-form")`);
  await ann.evaluate(setInput(".create-form input[type=text]", ROOM));
  await ann.evaluate(click(".create-form .create-btn"));
  await sleep(2000);
  const enter = (tab) =>
    tab.evaluate(
      `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(ROOM)});
         if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
    );
  await enter(ben);
  await waitFor(ben, `document.querySelector(".chat-main .input-bar .chat-input")`).catch(() => {});
  await sleep(1500);

  const say = (tab, text) =>
    tab.evaluate(`(() => { const input = document.querySelector(".chat-main .input-bar .chat-input"); if (!input) return false;
      input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event("input", { bubbles: true }));
      input.closest("form").requestSubmit(); return true; })()`);
  const rowWith = (text) =>
    `[...document.querySelectorAll(".chat-main .msg")].find((e) => e.querySelector(".msg-content")?.textContent.includes(${JSON.stringify(text)}))`;
  /** Stage `make` (code that puts a File in window.__f) through the hidden picker. */
  const attach = (tab, make) =>
    tab.evaluate(`(async () => { ${make}; const input = document.querySelector(".chat-main .input-bar .file-picker"); if (!input) return false;
      const dt = new DataTransfer(); dt.items.add(window.__f); input.files = dt.files;
      input.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
  const picture = (mime, name) => `const c = document.createElement("canvas"); c.width = 320; c.height = 200; const g = c.getContext("2d");
    for (let x = 0; x < 320; x += 20) { g.fillStyle = "hsl(" + x + ",70%,50%)"; g.fillRect(x, 0, 20, 200); }
    const blob = await new Promise((r) => c.toBlob(r, ${JSON.stringify(mime)}, 0.92));
    window.__f = new File([blob], ${JSON.stringify(name)}, { type: blob.type });`;
  const text = (name, body, type = "text/plain") =>
    `window.__f = new File([${JSON.stringify(body)}], ${JSON.stringify(name)}, { type: ${JSON.stringify(type)} });`;
  /** Press a card's button by its words. */
  const press = (tab, rowText, words) =>
    tab.evaluate(`(() => { const b = [...(${rowWith(rowText)})?.querySelectorAll(".file-card button") ?? []].find((e) => e.textContent.trim().startsWith(${JSON.stringify(words)}));
      if (!b) return false; b.click(); return true; })()`);
  const fetched = (tab) => tab.evaluate(`performance.getEntriesByType("resource").filter((e) => e.name.includes("/f/v1/")).length`);
  /** A cheap hash of what an image shows, decoded where it is. */
  const pixels = (source) => `(async () => { const src = ${source}; if (!src) return null;
    const bmp = await createImageBitmap(src); const c = document.createElement("canvas"); c.width = bmp.width; c.height = bmp.height;
    const g = c.getContext("2d"); g.drawImage(bmp, 0, 0); const d = g.getImageData(0, 0, c.width, c.height).data;
    let h = 2166136261; for (let i = 0; i < d.length; i++) { h ^= d[i]; h = Math.imul(h, 16777619) >>> 0; } return c.width + "x" + c.height + ":" + h; })()`;

  check("the composer offers attaching where the relay keeps files",
    await ann.evaluate(`!!document.querySelector(".chat-main .input-bar .file-picker")`));

  // ── A photo, compressed by default ──
  await attach(ann, picture("image/jpeg", "photo.jpg"));
  await waitFor(ann, `document.querySelector(".file-chip .chip-mode")`, 5_000).catch(() => {});
  check("a photo is staged as a chip, compressed, with the original one press away", await ann.evaluate(
    `(() => { const m = document.querySelector(".file-chip .chip-mode"); return !!m && m.textContent.trim() === "Original (1:1)" && m.getAttribute("aria-pressed") === "false"; })()`));
  await say(ann, "look at this");
  const arrived = await waitFor(ben, `${rowWith("look at this")}?.querySelector(".file-card")`, 20_000).then(() => true, () => false);
  check("the file's message arrives with its card", arrived);
  check("the card shows the preview's pixels, with nothing fetched", await ben.evaluate(
    `!!${rowWith("look at this")}?.querySelector(".file-card canvas") && !${rowWith("look at this")}?.querySelector(".file-card img")`) &&
    (await fetched(ben)) === 0);
  check("a compressed photo goes as WebP", await ben.evaluate(`${rowWith("look at this")}?.querySelector(".file-name")?.textContent.endsWith(".webp")`));
  await press(ben, "look at this", "Load");
  const drawn = await waitFor(ben, `${rowWith("look at this")}?.querySelector(".file-card img")?.naturalWidth > 0`, 20_000).then(() => true, () => false);
  check("Load fetches it and draws what its bytes are", drawn && (await fetched(ben)) > 0);
  await ben.evaluate(`${rowWith("look at this")}?.querySelector(".file-card .file-media")?.click()`);
  check("a loaded picture opens big", await waitFor(ben, `document.querySelector(".lightbox img")`, 5_000).then(() => true, () => false));
  await ben.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await ben.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await sleep(300);
  check("and Escape closes it", !(await ben.evaluate(`!!document.querySelector(".lightbox")`)));

  // ── The original, exactly ──
  await attach(ann, picture("image/jpeg", "orig.jpg"));
  await waitFor(ann, `document.querySelector(".file-chip .chip-mode")`, 5_000).catch(() => {});
  await ann.evaluate(`document.querySelector(".file-chip .chip-mode")?.click()`);
  const sent = await ann.evaluate(pixels("window.__f"));
  await say(ann, "the original");
  await waitFor(ben, `${rowWith("the original")}?.querySelector(".file-card")`, 20_000).catch(() => {});
  await press(ben, "the original", "Load");
  await waitFor(ben, `${rowWith("the original")}?.querySelector(".file-card img")?.naturalWidth > 0`, 20_000).catch(() => {});
  // Shown, it is the sanitizer's PNG of it (a decoder of its own, so not the
  // sender's very pixels); saved, it is the file itself, byte for byte
  const shownSize = await ben.evaluate(`(() => { const i = ${rowWith("the original")}?.querySelector(".file-card img"); return i ? i.naturalWidth + "x" + i.naturalHeight : null; })()`);
  const origDir = mkdtempSync(join(tmpdir(), "voipc-ui-orig-"));
  await ben.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: origDir });
  const sentBytes = await ann.evaluate(`(async () => { const b = new Uint8Array(await window.__f.arrayBuffer()); let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s); })()`);
  await press(ben, "the original", "Download");
  let savedOrig = null;
  for (let i = 0; i < 60 && savedOrig === null; i++) {
    await sleep(250);
    if (readdirSync(origDir).includes("orig.jpg")) savedOrig = readFileSync(join(origDir, "orig.jpg")).toString("base64");
  }
  check("the original goes as it is: its name, its size, its very bytes", sent !== null && shownSize === sent.split(":")[0] && savedOrig === sentBytes &&
    (await ben.evaluate(`${rowWith("the original")}?.querySelector(".file-name")?.textContent === "orig.jpg"`)), `${sent} shown ${shownSize}, saved ${savedOrig?.length ?? "nothing"} vs ${sentBytes?.length}`);

  // ── A text file: deflated, saved byte for byte ──
  const dir = mkdtempSync(join(tmpdir(), "voipc-ui-files-"));
  await ann.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: dir });
  const notes = "a line of somebody's notes, again and again\n".repeat(500);
  await attach(ben, text("notes.txt", notes));
  await say(ben, "my notes");
  await waitFor(ann, `${rowWith("my notes")}?.querySelector(".file-card")`, 20_000).catch(() => {});
  check("a file that is not a picture gets a plain card, with no Load", await ann.evaluate(
    `(() => { const c = ${rowWith("my notes")}?.querySelector(".file-card"); return !!c && !c.classList.contains("media") &&
       ![...c.querySelectorAll("button")].some((b) => b.textContent.includes("Load")); })()`));
  await press(ann, "my notes", "Download");
  let saved = null;
  for (let i = 0; i < 60 && saved === null; i++) {
    await sleep(250);
    const done = readdirSync(dir).find((f) => f === "notes.txt");
    if (done) saved = readFileSync(join(dir, done), "utf8");
  }
  check("a text file arrives byte for byte, under its own name", saved === notes, saved === null ? `nothing in ${dir}: ${readdirSync(dir)}` : `${saved.length} chars`);

  // ── What its bytes are decides, never what it claims ──
  // An SVG with a script, claimed as a PNG picture: it gets a picture's card
  // and Load, and loaded, its bytes say it is no picture
  await attach(ben, text("pic.png", "<svg xmlns='http://www.w3.org/2000/svg' onload='window.__ran=1'><script>window.__ran=1</script></svg>", "image/png"));
  await say(ben, "a picture, it says");
  await waitFor(ann, `${rowWith("a picture, it says")}?.querySelector(".file-card")`, 20_000).catch(() => {});
  await press(ann, "a picture, it says", "Load");
  const refused = await waitFor(ann, `${rowWith("a picture, it says")}?.querySelector(".file-note")`, 20_000).then(() => true, () => false);
  check("a page claimed as a picture is loaded, then never shown, only offered to save", refused && (await ann.evaluate(
    `(() => { const c = ${rowWith("a picture, it says")}?.querySelector(".file-card"); return !!c && !c.querySelector("img, iframe, object, embed, video, svg:not(.icon)") && !window.__ran; })()`)));

  // ── Settings → Files: what the chat names, and what this tab keeps ──
  const fmRow = (name) => `[...document.querySelectorAll(".fm-row")].find((r) => r.querySelector(".fm-name")?.textContent === ${JSON.stringify(name)})`;
  const fmNames = (tab) => tab.evaluate(`[...document.querySelectorAll(".fm-row .fm-name")].map((e) => e.textContent).sort().join(",")`);
  const CHIP = { all: "All", local: "On this", other: "Other", image: "Pictures" };
  const fmShow = (tab, value) => tab.evaluate(`[...document.querySelectorAll(".fm-chip")].find((b) => b.textContent.trim().startsWith(${JSON.stringify(CHIP[value])}))?.click() ?? false`);
  // "Show" is the row's name; the rest are named by their title
  const fmPress = (tab, name, words) => tab.evaluate(`(() => { const b = [...(${fmRow(name)})?.querySelectorAll("button") ?? []]
    .find((e) => e.title === ${JSON.stringify(words)} || (${JSON.stringify(words)} === "Show" && e.classList.contains("fm-main")));
    if (!b) return false; b.click(); return true; })()`);
  const usedNow = (tab) => tab.evaluate(`document.querySelector(".fm-usage .num")?.textContent ?? ""`);
  // From another conversation, so going to a message has to open its own
  await ann.evaluate(`[...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === "lobby-chat")
    ?.dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
  await sleep(600);
  const away = !(await ann.evaluate(`!!${rowWith("the original")}`));
  await realClick(ann, ".settings-btn");
  await waitFor(ann, `document.querySelector(".tab")`, 8_000);
  await ann.evaluate(`[...document.querySelectorAll(".tab")].find((b) => b.textContent.trim() === "Files")?.click()`);
  const listed = await waitFor(ann, `${fmRow("notes.txt")}`, 8_000).then(() => true, () => false);
  const everything = await fmNames(ann);
  check("Settings → Files lists every file the chat here names", listed && ["orig.jpg", "notes.txt", "pic.png"].every((f) => everything.includes(f)) &&
    /\.webp/.test(everything), everything);
  await sleep(1500);
  const before = await usedNow(ann);
  await fmShow(ann, "local");
  await sleep(200);
  check("with what this tab keeps of them: the files it sent and loaded", (await fmNames(ann)) === everything && !before.startsWith("0 B"), `${await fmNames(ann)} · ${before}`);
  await fmShow(ann, "other");
  await sleep(200);
  check("filtered by type, from what the message says", (await fmNames(ann)) === "notes.txt", await fmNames(ann));
  await fmShow(ann, "all");
  await ann.evaluate(setInput(".fm-query", "ORIG"));
  await sleep(200);
  check("a search narrows the list to what it names, case aside", (await fmNames(ann)) === "orig.jpg", await fmNames(ann));
  await ann.evaluate(setInput(".fm-query", ""));
  await sleep(200);
  await fmPress(ann, "notes.txt", "Remove copy");
  const removed = await waitFor(ann, `!${fmRow("notes.txt")}?.querySelector(".fm-local")`, 5_000).then(() => true, () => false);
  check("Remove copy takes a file off this tab, and the space it took", removed && (await usedNow(ann)) !== before, `${before} → ${await usedNow(ann)}`);
  const fetchedBefore = await fetched(ann);
  await fmPress(ann, "orig.jpg", "Show");
  await waitFor(ann, `${fmRow("orig.jpg")}?.querySelector(".file-card")`, 5_000).catch(() => {});
  await ann.evaluate(`[...(${fmRow("orig.jpg")})?.querySelectorAll(".file-card button") ?? []].find((b) => b.textContent.trim() === "Load")?.click()`);
  const local = await waitFor(ann, `${fmRow("orig.jpg")}?.querySelector(".file-card img")?.naturalWidth > 0`, 10_000).then(() => true, () => false);
  check("a row opens the chat's card, and Load draws it from this tab's copy", local && (await fetched(ann)) === fetchedBefore);
  await fmPress(ann, "orig.jpg", "Go to message");
  const closed = await waitFor(ann, `!document.querySelector(".fm-row")`, 5_000).then(() => true, () => false);
  await sleep(800);
  check("Go to message closes Settings, opens its conversation and brings the message into view", away && closed && (await ann.evaluate(
    `(() => { const r = ${rowWith("the original")}; const a = document.activeElement; return !!r && !!a && (r === a || r.contains(a) || a.contains(r)); })()`)),
    await ann.evaluate(`document.activeElement?.className ?? "nothing"`));

  // ── Files in a direct message, with the other in another room ──
  // Its conversation used to be looked for among `users`, the room one stands
  // in: someone talking elsewhere got no attach button, and what came could
  // not be loaded, opened from Settings, forwarded in or sent again (1.3.1)
  const dee = await connect(`ui-fd-${n}`);
  await enter(dee);
  const deeRow = `[...document.querySelectorAll(".user .name")].find((e) => e.title.startsWith(${JSON.stringify(`ui-fd-${n}#`)}))`;
  await waitFor(ann, deeRow).catch(() => {});
  await ann.evaluate(`(() => { const el = ${deeRow}?.closest(".user"); if (!el) return false;
    el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 })); return true; })()`);
  await sleep(300);
  await ann.evaluate(`[...document.querySelectorAll(".ctx-item")].find((e) => /direct message/i.test(e.textContent))?.click()`);
  await waitFor(ann, `document.querySelector(".chat-main .input-bar .chat-input")?.placeholder.includes("ui-fd-")`, 5_000).catch(() => {});
  await say(ann, "hi dee");
  const annEntry = `[...document.querySelectorAll(".dm-entry")].find((e) => e.textContent.includes("ui-fa-${n}"))`;
  await waitFor(dee, annEntry, 15_000).catch(() => {});
  // dee goes to a room of its own, then reads the conversation there
  await dee.evaluate(click('button[title="Create channel"]'));
  await waitFor(dee, `document.querySelector(".create-form")`).catch(() => {});
  await dee.evaluate(setInput(".create-form input[type=text]", `elsewhere-${n}`));
  await dee.evaluate(click(".create-form .create-btn"));
  const parted = await waitFor(ann, `!${deeRow}`, 10_000).then(() => true, () => false);
  await sleep(1000);
  await dee.evaluate(`${annEntry}?.click()`);
  check("a direct message to someone in another room offers attaching", parted &&
    (await ann.evaluate(`!!document.querySelector(".chat-main .input-bar .file-picker")`)));
  for (const [file, words] of [["dm.png", "for dee, elsewhere"], ["dm-row.png", "open me from Settings"], ["dm-later.png", "load me once the relay let go"]]) {
    await attach(ann, picture("image/png", file));
    await say(ann, words);
    await waitFor(dee, `${rowWith(words)}?.querySelector(".file-card")`, 20_000).catch(() => {});
  }
  await press(dee, "for dee, elsewhere", "Load");
  check("and what comes loads on the other side", await waitFor(dee,
    `${rowWith("for dee, elsewhere")}?.querySelector(".file-card img")?.naturalWidth > 0`, 20_000).then(() => true, () => false),
    await dee.evaluate(`${rowWith("for dee, elsewhere")}?.querySelector(".file-card")?.textContent ?? "no card"`));
  await realClick(dee, ".settings-btn");
  await waitFor(dee, `document.querySelector(".tab")`, 8_000).catch(() => {});
  await dee.evaluate(`[...document.querySelectorAll(".tab")].find((b) => b.textContent.trim() === "Files")?.click()`);
  await waitFor(dee, fmRow("dm-row.png"), 8_000).catch(() => {});
  await fmPress(dee, "dm-row.png", "Show");
  await waitFor(dee, `${fmRow("dm-row.png")}?.querySelector(".file-card")`, 5_000).catch(() => {});
  await dee.evaluate(`[...(${fmRow("dm-row.png")})?.querySelectorAll(".file-card button") ?? []].find((b) => b.textContent.trim() === "Load")?.click()`);
  check("its row in Settings → Files loads it too", await waitFor(dee,
    `${fmRow("dm-row.png")}?.querySelector(".file-card img")?.naturalWidth > 0`, 20_000).then(() => true, () => false));
  await dee.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await dee.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await waitFor(dee, `!document.querySelector(".fm-row")`, 5_000).catch(() => {});
  // A file from ann's room, forwarded into the conversation
  await ann.evaluate(`[...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(ROOM)})
    ?.dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
  await waitFor(ann, rowWith("the original"), 5_000).catch(() => {});
  const origAt = await ann.evaluate(`(() => { const r = ${rowWith("the original")}; if (!r) return null; r.scrollIntoView({ block: "center" });
    const b = r.getBoundingClientRect(); return { x: Math.round(b.left + 40), y: Math.round(b.top + 10) }; })()`);
  if (origAt) {
    for (const type of ["mousePressed", "mouseReleased"]) {
      await ann.send("Input.dispatchMouseEvent", { type, x: origAt.x, y: origAt.y, button: "right", clickCount: 1, buttons: 2 });
    }
  }
  await sleep(300);
  await ann.evaluate(`[...document.querySelectorAll(".msg-menu [role=menuitem]")].find((e) => e.textContent.trim() === "Forward")?.click()`);
  await waitFor(ann, `document.querySelector(".forward-dialog .forward-dest")`, 3_000).catch(() => {});
  await ann.evaluate(`[...document.querySelectorAll(".forward-dialog .forward-dest")].find((b) => b.textContent.includes("@ui-fd-${n}"))?.click()`);
  await waitFor(dee, `${rowWith("the original")}?.querySelector(".file-card")`, 20_000).catch(() => {});
  await press(dee, "the original", "Load");
  check("a file forwarded into it arrives and loads", await waitFor(dee,
    `${rowWith("the original")}?.querySelector(".file-card img")?.naturalWidth > 0`, 20_000).then(() => true, () => false),
    await ann.evaluate(`window.__toasts?.slice(-2).join(" | ") ?? ""`));

  // ── The relay lets go; a member sends it again, or nobody can ──
  await attach(ben, picture("image/png", "gone.png"));
  await say(ben, "nobody else has this one");
  await waitFor(ann, `${rowWith("nobody else has this one")}?.querySelector(".file-card")`, 20_000).catch(() => {});
  // ben leaves, the only one holding gone.png; ann still holds her photo
  await ben.send("Page.navigate", { url: "about:blank" });
  console.log("waiting 70 s for the relay to let go of the files (cache_mins = 1)…");
  await sleep(70_000);
  const cat = await connect(`ui-fc-${n}`);
  await enter(cat);
  // The two messages come to cat as ann's copy of the channel's history
  const history = await waitFor(cat, `${rowWith("look at this")}?.querySelector(".file-card") && ${rowWith("nobody else has this one")}?.querySelector(".file-card")`, 30_000).then(() => true, () => false);
  check("files come with the channel's history to someone who joins later", history);
  await press(cat, "look at this", "Load");
  await press(cat, "nobody else has this one", "Load");
  const reseeded = await waitFor(cat, `${rowWith("look at this")}?.querySelector(".file-card img")?.naturalWidth > 0`, 45_000).then(() => true, () => false);
  check("once the relay let go of it, a member who holds it sends it again", reseeded,
    await cat.evaluate(`${rowWith("look at this")}?.querySelector(".file-card")?.textContent ?? "no card"`));
  check("while nobody has answered, the card says it is asking", await cat.evaluate(
    `${rowWith("nobody else has this one")}?.querySelector(".file-card")?.textContent.includes("Asking members")`));
  // Inside the picture's box, where "Asking members…" was: under the card it
  // sat out of view on a phone (D2-11)
  const unavailable = await waitFor(cat, `${rowWith("nobody else has this one")}?.querySelector(".file-preview [role=alert]")?.textContent.includes("Nobody online has this file")`, 90_000).then(() => true, () => false);
  check("and with its only holder gone, it says nobody online has it, where it was asking", unavailable,
    await cat.evaluate(`${rowWith("nobody else has this one")}?.querySelector(".file-card")?.textContent ?? "no card"`));
  // Its only holder, ann, is asked through the direct conversation, from another room
  await press(dee, "load me once the relay let go", "Load");
  check("in a direct message too, its sender sends it again once the relay let go", await waitFor(dee,
    `${rowWith("load me once the relay let go")}?.querySelector(".file-card img")?.naturalWidth > 0`, 45_000).then(() => true, () => false),
    await dee.evaluate(`${rowWith("load me once the relay let go")}?.querySelector(".file-card")?.textContent ?? "no card"`));

  for (const [who, tab] of [["sender", ann], ["receiver", ben], ["late joiner", cat], ["direct partner", dee]]) {
    const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
    check(`the files lane's ${who} threw nothing`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
  }
}

// 21. Edit, delete, reactions, pins and forward (1.3). The rules — who may
//     edit, delete or pin, latest-wins reactions, the tombstone a hand-off
//     cannot undo — are unit-tested (chat-rules, channel-post-rules,
//     envelope.rs, sync.rs). What only a browser shows is each one going round
//     the relay and back, drawn where the other person reads, and a forwarded
//     file loading in a conversation it was never sent to. Before 14, 17 and
//     18, as 19 and 20 are.
{
  const n = (process.pid + 13) % 10000;
  const ROOM = `events-${n}`;
  // ann creates the channel, so she manages it; ben is a member
  const ann = await connect(`ui-ea-${n}`);
  const ben = await connect(`ui-eb-${n}`);
  await ann.evaluate(click('button[title="Create channel"]'));
  await waitFor(ann, `document.querySelector(".create-form")`);
  await ann.evaluate(setInput(".create-form input[type=text]", ROOM));
  await ann.evaluate(click(".create-form .create-btn"));
  await sleep(2000);
  const openChannel = (tab, name, how = "click") => tab.evaluate(
    `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(name)});
       if (!el) return false; el.dispatchEvent(new MouseEvent(${JSON.stringify(how)}, { bubbles: true })); return true; })()`);
  await openChannel(ben, ROOM, "dblclick");
  await waitFor(ben, `document.querySelector(".chat-main .input-bar .chat-input")`).catch(() => {});
  await sleep(1500);

  const say = (tab, text) =>
    tab.evaluate(`(() => { const input = document.querySelector(".chat-main .input-bar .chat-input"); if (!input) return false;
      input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event("input", { bubbles: true }));
      input.closest("form").requestSubmit(); return true; })()`);
  const rowWith = (text) =>
    `[...document.querySelectorAll(".chat-main .msg")].find((e) => e.querySelector(".msg-content")?.textContent.includes(${JSON.stringify(text)}))`;
  const arrived = (tab, text) => waitFor(tab, rowWith(text), 10_000).then(() => true, () => false);
  const gone = (tab, text) => waitFor(tab, `!${rowWith(text)}`, 10_000).then(() => true, () => false);
  /** A real pointer onto the row, then onto its tool `label`. */
  const useTool = async (tab, text, label) => {
    const at = (sel) => tab.evaluate(`(() => { const row = ${rowWith(text)}; const el = ${sel}; if (!el) return null;
      el.scrollIntoView({ block: "center" }); const r = el.getBoundingClientRect(); if (r.width === 0) return null;
      return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }; })()`);
    const move = (p) => tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: p.x, y: p.y, buttons: 0 });
    const rowAt = await at("row");
    if (!rowAt) return false;
    await move(rowAt);
    await sleep(150);
    const btn = await at(`row?.querySelector('.msg-tools button[aria-label=${JSON.stringify(label)}]')`);
    if (!btn) return false;
    await move(btn);
    for (const type of ["mousePressed", "mouseReleased"]) {
      await tab.send("Input.dispatchMouseEvent", { type, x: btn.x, y: btn.y, button: "left", clickCount: 1, buttons: 1 });
    }
    await sleep(300);
    return true;
  };
  const menuItems = (tab) => tab.evaluate(`[...document.querySelectorAll(".msg-menu [role=menuitem]")].map((b) => b.textContent.trim()).join(",")`);
  const pressItem = (tab, words) => tab.evaluate(`(() => { const b = [...document.querySelectorAll(".msg-menu [role=menuitem]")].find((e) => e.textContent.trim() === ${JSON.stringify(words)});
    if (!b) return false; b.click(); return true; })()`);
  const enter = async (tab) => {
    await tab.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" });
    await tab.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  };

  // ── A reaction, and taking it back ──
  await say(ann, "react to this one");
  await arrived(ben, "react to this one");
  const picked = (await useTool(ben, "react to this one", "React")) &&
    (await waitFor(ben, `document.querySelector(".react-picker")`, 3_000).then(() => true, () => false));
  check("React opens the emoji picker, reached with a real pointer", picked);
  await ben.evaluate(`document.querySelector('.react-picker button[aria-label="React with 👍"]')?.click()`);
  const chip = (tab) => `${rowWith("react to this one")}?.querySelector(".reaction")`;
  check("a reaction arrives as a chip under the message, with its count",
    await waitFor(ann, `${chip(ann)}?.textContent === "👍1"`, 10_000).then(() => true, () => false),
    await ann.evaluate(`${chip(ann)}?.outerHTML ?? "no chip"`));
  check("and the reactor's own chip is pressed", await ben.evaluate(`${chip(ben)}?.getAttribute("aria-pressed") === "true"`));
  check("which names who reacted", await ann.evaluate(`${chip(ann)}?.title === "ui-eb-${n}"`), await ann.evaluate(`${chip(ann)}?.title ?? ""`));
  await ben.evaluate(`${chip(ben)}?.click()`);
  check("pressing your own chip takes the reaction back, for everyone",
    await waitFor(ann, `!${chip(ann)}`, 10_000).then(() => true, () => false));
  // The menu's React too (a long press on a phone): it once read the message
  // after the menu had let go of it, threw, and opened nothing
  const before = ben.errors.length;
  await useTool(ben, "react to this one", "More");
  await pressItem(ben, "React");
  check("React from the message menu opens the picker too",
    (await waitFor(ben, `document.querySelector(".react-picker")`, 3_000).then(() => true, () => false)) && ben.errors.length === before,
    ben.errors.slice(before, before + 2).join(" | "));
  for (const type of ["keyDown", "keyUp"]) {
    await ben.send("Input.dispatchKeyEvent", { type, key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  }
  await sleep(300);

  // Send with a real pointer leaves the focus in the box: on a phone a focus
  // move dropped the keyboard, the shell reflowed, and the tap missed Send
  await ben.evaluate(`(() => { const input = document.querySelector(".chat-main .input-bar .chat-input"); input.focus();
    input.value = "sent by a tap"; input.dispatchEvent(new Event("input", { bubbles: true })); })()`);
  await sleep(200);
  const tapped = await realClick(ben, ".chat-main .input-bar .send-btn");
  check("a tap on Send sends, and the text field keeps the focus",
    tapped && (await arrived(ann, "sent by a tap")) &&
      (await ben.evaluate(`document.activeElement?.classList.contains("chat-input") ?? false`)),
    await ben.evaluate(`document.activeElement?.className ?? "none"`));

  // ── An edit: only your own, marked as edited ──
  await say(ann, "a typo hree");
  await arrived(ben, "a typo hree");
  check("someone else's message has no Edit", !(await useTool(ben, "a typo hree", "Edit")));
  check("your own does, and it opens a box with the text", (await useTool(ann, "a typo hree", "Edit")) &&
    (await ann.evaluate(`document.querySelector(".chat-main .edit-input")?.value === "a typo hree"`)));
  await ann.evaluate(`(() => { const t = document.querySelector(".chat-main .edit-input"); t.value = "a typo here"; t.dispatchEvent(new Event("input", { bubbles: true })); t.focus(); })()`);
  await enter(ann);
  check("Enter saves the edit, and the box goes", await waitFor(ann, `!document.querySelector(".chat-main .edit-input") && !!${rowWith("a typo here")}`, 5_000).then(() => true, () => false));
  check("the edit reaches the reader, marked (edited), in place of the old text",
    (await waitFor(ben, `${rowWith("a typo here")}?.querySelector(".edited")`, 10_000).then(() => true, () => false)) && !(await ben.evaluate(`!!${rowWith("hree")}`)));

  // A press on Save leaves the focus in the box until it saves: on a phone the
  // keyboard stays up, so Save does not move from under the finger (D3-01)
  await say(ann, "press save here");
  await arrived(ann, "press save here");
  await useTool(ann, "press save here", "Edit");
  await ann.evaluate(`(() => { const t = document.querySelector(".chat-main .edit-input"); t.value = "pressed save here"; t.dispatchEvent(new Event("input", { bubbles: true })); t.focus(); })()`);
  const save = await ann.evaluate(`(() => { const b = [...document.querySelectorAll(".chat-main .edit-box button")].find((e) => e.textContent.trim() === "Save");
    if (!b) return null; const r = b.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`);
  let keptFocus = false;
  if (save) {
    await ann.send("Input.dispatchMouseEvent", { type: "mousePressed", x: save.x, y: save.y, button: "left", clickCount: 1, buttons: 1 });
    keptFocus = await ann.evaluate(`document.activeElement?.classList.contains("edit-input") ?? false`);
    await ann.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: save.x, y: save.y, button: "left", clickCount: 1 });
  }
  check("pressing Save keeps the focus in the box, and the edit is saved",
    keptFocus && (await waitFor(ann, `!document.querySelector(".chat-main .edit-input") && !!${rowWith("pressed save here")}`, 5_000).then(() => true, () => false)),
    save ? `focus was on ${keptFocus ? "the box" : "something else"}` : "no Save button");

  // ── A delete: confirmed first, then gone for everyone ──
  await say(ann, "delete me soon");
  await arrived(ben, "delete me soon");
  await useTool(ben, "delete me soon", "More");
  check("someone else's message offers no Delete, and a member no Pin", !/Delete|Pin/.test(await menuItems(ben)), await menuItems(ben));
  await ben.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await ben.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await sleep(200);
  await useTool(ann, "delete me soon", "More");
  check("your own message's menu has Edit and Delete, and a manager's has Pin",
    (await menuItems(ann)) === "React,Reply,Reply in thread,Forward,Edit,Pin,Copy text,Delete", await menuItems(ann));
  await pressItem(ann, "Delete");
  const asked = await waitFor(ann, `document.querySelector(".confirm .btn-danger")`, 3_000).then(() => true, () => false);
  check("Delete asks first", asked);
  await ann.evaluate(`document.querySelector(".confirm .btn-danger")?.click()`);
  check("then the message goes, here and for the reader", (await gone(ann, "delete me soon")) && (await gone(ben, "delete me soon")));

  // ── A pin, by the channel's manager, listed in the header ──
  await useTool(ann, "react to this one", "More");
  await pressItem(ann, "Pin");
  check("a manager's pin reaches the reader: marked, and counted in the header",
    await waitFor(ben, `!!${rowWith("react to this one")}?.querySelector(".pinned-tag") && document.querySelector(".chat-header .pins-btn")?.textContent.trim() === "1"`, 10_000)
      .then(() => true, () => false));
  await ben.evaluate(`document.querySelector(".chat-header .pins-btn")?.click()`);
  await sleep(200);
  check("the header lists what is pinned", await ben.evaluate(
    `[...document.querySelectorAll(".pins-menu .pin-row")].some((b) => b.textContent.includes("react to this one"))`));
  await ben.evaluate(`[...document.querySelectorAll(".pins-menu .pin-row")].find((b) => b.textContent.includes("react to this one"))?.click()`);
  await sleep(500);
  check("and a pin leads to its message", await ben.evaluate(`${rowWith("react to this one")}?.classList.contains("flash") ?? false`));

  // ── Someone who joins later: the edit comes with the history, the delete never ──
  const cy = await connect(`ui-ec-${n}`);
  await openChannel(cy, ROOM, "dblclick");
  const handed = await waitFor(cy, `${rowWith("a typo here")}`, 30_000).then(() => true, () => false);
  check("history hands on the edited text, marked edited", handed && (await cy.evaluate(`!!${rowWith("a typo here")}?.querySelector(".edited")`)));
  check("and never a deleted message", handed && !(await cy.evaluate(`!!${rowWith("delete me soon")}`)));
  // A member's copy is their word for who wrote it: forwarded, that would
  // become a "Forwarded from" label with no mark of hearsay (D-15)
  await useTool(cy, "a typo here", "More");
  check("a message handed over in the history offers no Forward", handed && /Copy text/.test(await menuItems(cy)) && !/Forward/.test(await menuItems(cy)),
    await menuItems(cy));
  for (const type of ["keyDown", "keyUp"]) {
    await cy.send("Input.dispatchKeyEvent", { type, key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  }
  await sleep(200);

  // ── Forward: a file, as it is, to a conversation it was never in ──
  const dir = mkdtempSync(join(tmpdir(), "voipc-ui-fwd-"));
  await cy.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: dir });
  const body = "forwarded words, kept as they are\n".repeat(40);
  await ann.evaluate(`(async () => { window.__f = new File([${JSON.stringify(body)}], "fwd.txt", { type: "text/plain" });
    const input = document.querySelector(".chat-main .input-bar .file-picker"); if (!input) return false;
    const dt = new DataTransfer(); dt.items.add(window.__f); input.files = dt.files;
    input.dispatchEvent(new Event("change", { bubbles: true })); return true; })()`);
  await say(ann, "pass this on");
  await waitFor(ben, `${rowWith("pass this on")}?.querySelector(".file-card")`, 20_000).catch(() => {});
  await useTool(ben, "pass this on", "More");
  await pressItem(ben, "Forward");
  const offered = await waitFor(ben, `[...document.querySelectorAll(".forward-dialog .forward-dest")].some((b) => b.textContent.includes("#lobby-chat"))`, 3_000)
    .then(() => true, () => false);
  check("Forward offers the conversations one may write in", offered);
  await ben.evaluate(`[...document.querySelectorAll(".forward-dialog .forward-dest")].find((b) => b.textContent.includes("#lobby-chat"))?.click()`);
  await openChannel(cy, "lobby-chat");
  const there = await waitFor(cy, `${rowWith("pass this on")}?.querySelector(".file-card")`, 30_000).then(() => true, () => false);
  check("the forward arrives as the forwarder's message, labelled with who wrote it first", there && (await cy.evaluate(
    `${rowWith("pass this on")}?.querySelector(".fwd-label")?.textContent.includes("ui-ea-${n}") && ${rowWith("pass this on")}?.querySelector(".msg-username")?.textContent.startsWith("ui-eb-")`)),
    await cy.evaluate(`${rowWith("pass this on")}?.textContent.slice(0, 200) ?? "no row"`));
  // Nobody who holds it is left to send it again: the relay's own copy,
  // posted for lobby-chat by the forward, is the only way it loads there
  const fatalOf = (tab) => tab.errors.filter((e) => !/Failed to load resource/.test(e));
  const [annFatal, benFatal] = [fatalOf(ann), fatalOf(ben)];
  await ann.send("Page.navigate", { url: "about:blank" });
  await ben.send("Page.navigate", { url: "about:blank" });
  await sleep(1500);
  await cy.evaluate(`[...(${rowWith("pass this on")})?.querySelectorAll(".file-card button") ?? []].find((b) => b.textContent.trim().startsWith("Download"))?.click()`);
  let saved = null;
  for (let i = 0; i < 80 && saved === null; i++) {
    await sleep(250);
    if (readdirSync(dir).includes("fwd.txt")) saved = readFileSync(join(dir, "fwd.txt"), "utf8");
  }
  check("its file loads there, byte for byte, with its senders gone: posted for that conversation too", saved === body,
    saved === null ? await cy.evaluate(`${rowWith("pass this on")}?.querySelector(".file-card")?.textContent ?? "no card"`) : `${saved.length} chars`);

  for (const [who, fatal] of [["writer", annFatal], ["reader", benFatal], ["late joiner", fatalOf(cy)]]) {
    check(`the events lane's ${who} threw nothing`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
  }
}

// 22. Emotes (1.4, protocol 14). The rules — the token, names, the sanitizer,
//     the relay's checks — are unit-tested (emote-rules, voipc-media,
//     emotes.rs). What only a browser shows: an admin adds one through the
//     importer, which shows only the sanitizer's PNG and turns away what is no
//     picture; `:name:` goes out as its token; and the other member's page
//     draws it from the PNG its own worker wrote. Before 14, 17 and 18.
{
  const n = (process.pid + 17) % 10000;
  const ROOM = `emotes-${n}`;
  const ann = await connect(`ui-ma-${n}`);
  const ben = await connect(`ui-mb-${n}`);
  await ann.evaluate(click('button[title="Create channel"]'));
  await waitFor(ann, `document.querySelector(".create-form")`);
  await ann.evaluate(setInput(".create-form input[type=text]", ROOM));
  await ann.evaluate(click(".create-form .create-btn"));
  await sleep(2000);
  await ben.evaluate(`[...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(ROOM)})
    ?.dispatchEvent(new MouseEvent("dblclick", { bubbles: true }))`);
  await waitFor(ben, `document.querySelector(".chat-main .input-bar .chat-input")`).catch(() => {});
  const rowWith = (text) =>
    `[...document.querySelectorAll(".chat-main .msg")].find((e) => e.querySelector(".msg-content")?.textContent.includes(${JSON.stringify(text)}))`;

  await ann.evaluate(click('button.admin-btn[title^="Admin login"]'));
  await waitFor(ann, `document.querySelector(".admin-dialog .admin-input")`);
  await ann.evaluate(setInput('.admin-dialog input[type="password"]', "e2e-admin-token-0001"));
  await ann.evaluate(click(".admin-dialog .admin-ok"));
  const admin = await waitFor(ann, `document.querySelector(".admin-btn.active")`, 15_000).then(() => true, () => false);
  check("the admin token makes this tab the server's admin", admin);
  await ann.evaluate(click("button.admin-btn.active"));
  await waitFor(ann, `[...document.querySelectorAll(".admin-tabs button")].some((b) => b.textContent === "Emotes")`, 5_000).catch(() => {});
  await ann.evaluate(`[...document.querySelectorAll(".admin-tabs button")].find((b) => b.textContent === "Emotes")?.click()`);
  await waitFor(ann, `document.querySelector(".em-pick input[type=file][multiple]")`, 5_000).catch(() => {});
  const name = `party_parrot_${n}`;
  await ann.evaluate(`(async () => {
    const c = document.createElement("canvas"); c.width = 64; c.height = 64;
    const g = c.getContext("2d"); g.fillStyle = "#e33"; g.fillRect(0, 0, 64, 64);
    const png = await new Promise((r) => c.toBlob(r, "image/png"));
    const svg = new Blob(["<svg xmlns='http://www.w3.org/2000/svg' onload='window.__ran=1'/>"], { type: "image/png" });
    const dt = new DataTransfer();
    dt.items.add(new File([png], "Party Parrot ${n}.png", { type: "image/png" }));
    dt.items.add(new File([svg], "evil.png", { type: "image/png" }));
    const input = document.querySelector(".em-pick input[type=file][multiple]");
    input.files = dt.files; input.dispatchEvent(new Event("change", { bubbles: true })); })()`);
  const readied = await waitFor(ann, `[...document.querySelectorAll(".em-add .em-row input.em-name")].some((i) => i.value === ${JSON.stringify(name)})
    && [...document.querySelectorAll(".em-add .em-row img")].every((i) => i.src.startsWith("blob:") && i.naturalWidth > 0)`, 20_000).then(() => true, () => false);
  check("an imported picture is named from its file and previewed as the sanitizer's PNG", readied);
  check("a page claiming to be a picture is turned away, saying why, and never runs", await ann.evaluate(
    `(() => { const r = [...document.querySelectorAll(".em-add .em-row")].find((e) => e.textContent.includes("evil.png")); return !!r && r.textContent.includes("SVG") && !window.__ran; })()`),
    await ann.evaluate(`[...document.querySelectorAll(".em-add .em-row")].map((e) => e.textContent.trim()).join(" | ")`));
  await ann.evaluate(`[...document.querySelectorAll(".em-actions .btn-primary")].find((b) => b.textContent.trim().startsWith("Add"))?.click()`);
  const listed = await waitFor(ann, `[...document.querySelectorAll(".em > .em-list .em-name")].some((e) => e.textContent === ${JSON.stringify(`:${name}:`)})`, 20_000)
    .then(() => true, () => false);
  check("added, it is in the server's list", listed, await ann.evaluate(`(window.__toasts ?? []).slice(-3).join(" | ")`));
  await ann.evaluate(`document.querySelector(".admin-dialog .admin-cancel")?.click()`);
  await sleep(300);
  await ann.evaluate(`(() => { const input = document.querySelector(".chat-main .input-bar .chat-input"); if (!input) return false;
    input.value = ${JSON.stringify(`look :${name}:`)}; input.dispatchEvent(new Event("input", { bubbles: true }));
    input.closest("form").requestSubmit(); return true; })()`);
  const drawn = await waitFor(ben, `(() => { const i = ${rowWith("look")}?.querySelector("img.emote"); return !!i && i.src.startsWith("blob:") && i.naturalWidth > 0; })()`, 30_000)
    .then(() => true, () => false);
  check("the other member's page draws it, from the PNG its own worker wrote", drawn,
    await ben.evaluate(`${rowWith("look")}?.querySelector(".msg-content")?.innerHTML.slice(0, 200) ?? "no row"`));
  check("and the message reads as written, with no token in sight", await ben.evaluate(
    `(() => { const t = ${rowWith("look")}?.querySelector(".msg-content")?.textContent ?? ""; return !t.includes("<:") && t.trim().startsWith("look"); })()`));

  for (const [who, tab] of [["admin", ann], ["member", ben]]) {
    const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
    check(`the emotes lane's ${who} threw nothing`, fatal.length === 0, fatal.slice(0, 2).join(" | "));
  }
}

// 14. Several servers at once. The rail's "+" used to disconnect you to bring
//     up the connect dialog; now it adds a connection beside the others, a
//     click on the rail only changes what is on screen, and voice follows the
//     last channel joined — leaving the call on the other server, never the
//     server itself.
if (PORT2) {
  await alice.send("Emulation.setDeviceMetricsOverride", {
    width: 1280, height: 800, deviceScaleFactor: 1, mobile: false,
  });
  await sleep(400);
  const S1 = `127.0.0.1:${PORT}`;
  const S2 = `127.0.0.1:${PORT2}`;
  const railItem = (id) => `.server-rail .rail-item[data-server="${id}"]`;
  const openIds = () =>
    alice.evaluate(`[...document.querySelectorAll(".server-rail .rail-item.open")].map((e) => e.dataset.server)`);
  const railTitle = (id) => alice.evaluate(`document.querySelector('${railItem(id)}')?.title ?? ""`);
  const onScreen = () => alice.evaluate(`document.querySelector(".server-rail .rail-item.active")?.dataset.server`);
  const voiceRowActive = (name) => alice.evaluate(`(() => {
    const row = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(name)});
    return row ? row.classList.contains("active") : null; })()`);

  // In a call on server 1 first, so there is something for server 2 to keep.
  // A room of its own: CHANNEL has stood empty since section 8, and the relay
  // deletes an empty channel after 300 s, which the sections before this one
  // now take longer than. The creator is seated in it at once.
  const HOME = `home-${process.pid % 10000}`;
  await alice.evaluate(click('button[title="Create channel"]'));
  await waitFor(alice, `document.querySelector(".create-form")`);
  await alice.evaluate(setInput(".create-form input[type=text]", HOME));
  await alice.evaluate(click(".create-form .create-btn"));
  await sleep(2500);
  // bob joins her there, so he can witness her leaving it
  await bob.evaluate(
    `(() => { const el = [...document.querySelectorAll(".channel")].find((e) => e.querySelector(".channel-name")?.textContent === ${JSON.stringify(HOME)});
       if (!el) return false; el.dispatchEvent(new MouseEvent("dblclick", { bubbles: true })); return true; })()`,
  );
  await sleep(1500);
  check("the other client sees alice in the channel", (await bob.evaluate(userNames)).some((u) => u.includes("ui-alice")));
  check("the rail lists the server we are on", JSON.stringify(await openIds()) === JSON.stringify([S1]), JSON.stringify(await openIds()));
  check("and says we are in voice there", /in voice/.test(await railTitle(S1)), await railTitle(S1));

  check("a real click reaches the rail's +", await realClick(alice, ".server-rail .rail-item.add"));
  await waitFor(alice, `document.querySelector(".connect-btn")`, 8_000);
  check(
    "adding a server does not disconnect the first",
    JSON.stringify(await openIds()) === JSON.stringify([S1]) && /in voice/.test(await railTitle(S1)),
    await railTitle(S1),
  );
  check("the dialog can be closed again", await alice.evaluate(`!!document.querySelector(".connect-close")`));
  await alice.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await alice.evaluate(setInput('input[placeholder="9987"]', PORT2));
  await alice.evaluate(setInput('input[placeholder="Your name"]', "ui-alice"));
  await alice.evaluate(click(".connect-btn"));
  await waitFor(alice, `!document.querySelector(".connect-btn") && document.querySelectorAll(".server-rail .rail-item.open").length === 2`);
  await sleep(800);
  check("the second server opens beside the first", JSON.stringify(await openIds()) === JSON.stringify([S1, S2]), JSON.stringify(await openIds()));
  check("and it is the one on screen", (await onScreen()) === S2, await onScreen());
  check("its channel list is its own", !(await alice.evaluate(channelNames)).includes(HOME));
  check("the call on server 1 carried on", /in voice/.test(await railTitle(S1)), await railTitle(S1));
  check("and the voice bar still offers to leave it", await alice.evaluate(`!!document.querySelector(".leave-voice-btn")`));

  await realClick(alice, railItem(S1));
  await sleep(800);
  check("the rail brings server 1 back", (await onScreen()) === S1 && (await alice.evaluate(channelNames)).includes(HOME));
  check("still standing in the same channel", (await voiceRowActive(HOME)) === true);

  // Voice follows the last join: a room on server 2 ends the call on server 1
  await realClick(alice, railItem(S2));
  await sleep(600);
  const MS = `multi-${process.pid % 10000}`;
  await alice.evaluate(click('button[title="Create channel"]'));
  await waitFor(alice, `document.querySelector(".create-form")`);
  await alice.evaluate(setInput(".create-form input[type=text]", MS));
  await alice.evaluate(click(".create-form .create-btn"));
  await sleep(2500);
  check("joining voice on server 2 moves the call there", /in voice/.test(await railTitle(S2)), await railTitle(S2));
  check("and out of server 1", !/in voice/.test(await railTitle(S1)), await railTitle(S1));
  check("server 1 stays connected", JSON.stringify(await openIds()) === JSON.stringify([S1, S2]), JSON.stringify(await openIds()));
  check(
    "the other client sees alice leave her channel on server 1",
    !(await bob.evaluate(userNames)).some((u) => u.includes("ui-alice")),
    (await bob.evaluate(userNames)).join(","),
  );

  // Mute is global and reaches the call wherever it is
  await alice.evaluate(click('button[title^="Mute"]'));
  await sleep(600);
  check("mute works in a call on the second server", (await alice.evaluate(rowMuted(null))) === true);
  await alice.evaluate(click('button[title^="Unmute"]'));
  await sleep(600);

  // Disconnect is per server
  check("a real click reaches server 2's disconnect", await realClick(alice, ".status-bar .disconnect-btn"));
  await sleep(1200);
  check("disconnecting server 2 closes only that one", JSON.stringify(await openIds()) === JSON.stringify([S1]), JSON.stringify(await openIds()));
  check("server 1 is on screen and connected", (await onScreen()) === S1 && await alice.evaluate(
    `/Connected/.test(document.querySelector(".status-bar")?.textContent ?? "")`,
  ));
  check("and no connect dialog came up", !(await alice.evaluate(`!!document.querySelector(".connect-btn")`)));

  // Starting up with both servers remembered and auto-connect on: every one of
  // them comes back at once, with nobody clicking anything. This path froze
  // the whole window once — a store written from inside a $derived while two
  // connects landed together — and none of the clicking above goes near it.
  const boot = await newTab();
  await boot.send("Page.navigate", { url: `${URL}favicon.png` });
  await waitFor(boot, `document.readyState === "complete"`);
  const bootName = `ui-boot-${process.pid % 10000}`;
  const remembered = (port) =>
    ({ name: "127.0.0.1", host: "127.0.0.1", port: Number(port), username: bootName, accept_self_signed: true });
  await boot.evaluate(`(() => {
    const saved = JSON.parse(localStorage.getItem("voipc.settings") ?? "{}");
    Object.assign(saved, {
      auto_connect: true, remember_connection: true, chat_history_disabled: true,
      open_servers: ${JSON.stringify([remembered(PORT), remembered(PORT2)])},
    });
    localStorage.setItem("voipc.settings", JSON.stringify(saved));
    return true; })()`);
  await boot.send("Page.navigate", { url: URL });
  const bootOpen = () =>
    boot.evaluate(`[...document.querySelectorAll(".server-rail .rail-item.open")].map((e) => [e.dataset.server, e.title])`);
  try {
    await waitFor(boot, `[...document.querySelectorAll(".server-rail .rail-item.open")].filter((e) => /connected/.test(e.title)).length === 2`);
  } catch {
    // reported by the checks below
  }
  const opened = await bootOpen();
  check(
    "at startup every remembered server connects",
    opened.length === 2 && opened.every(([, t]) => /connected/.test(t)),
    JSON.stringify(opened),
  );
  check("and the one on screen shows its channels", (await boot.evaluate(channelNames)).includes(HOME));
  const bootFatal = boot.errors.filter((e) => !/Failed to load resource/.test(e));
  check("with nothing thrown on the way", bootFatal.length === 0, bootFatal.slice(0, 2).join(" | "));
} else {
  console.log("SKIP the multi-server lane (no second server port given)");
}

// 17. Accounts. Signing up through the connect dialog, the recovery key shown
//     once, and the browser remembered afterwards: a second sign-in needs no
//     password at all. The server is its own origin, so this is a fresh
//     profile as far as the page can tell (first-run dialogs included).
if (PORT3) {
  const URL3 = `https://127.0.0.1:${PORT3}/`;
  const acct = `ui${process.pid % 100000}`;
  const pw = "correct horse battery staple";
  const openDialog = async () => {
    const tab = await newTab();
    await tab.send("Page.navigate", { url: URL3 });
    await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
    if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
      await tab.evaluate(click(".skip-link"));
      await waitFor(tab, `document.querySelector(".connect-btn")`);
    }
    // Every toast, kept (as `connect` does): what went wrong is said in one.
    await tab.evaluate(`(() => { window.__toasts = [];
      new MutationObserver(() => { for (const e of document.querySelectorAll(".toast-message"))
        if (!window.__toasts.includes(e.textContent)) window.__toasts.push(e.textContent); })
        .observe(document.body, { childList: true, subtree: true, characterData: true }); })()`);
    await tab.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
    await tab.evaluate(setInput('input[placeholder="9987"]', PORT3));
    await realClick(tab, ".mode-switch button:nth-child(2)");
    await waitFor(tab, `document.querySelector("#account-name")`);
    return tab;
  };
  // The first-connect question about copies on the server: answered (kept,
  // unless told otherwise) where it comes up, which is once per account.
  const settle = async (tab, keep = true) => {
    await waitFor(tab, `document.querySelector(".channel-list")`, 30_000);
    const cloud = '.account-dialog[data-kind="cloud"]';
    if (await waitFor(tab, `document.querySelector('${cloud}')`, 3_000).then(() => true, () => false)) {
      await realClick(tab, `${cloud} ${keep ? ".submit-btn" : ".secondary"}`);
      await waitFor(tab, `!document.querySelector('${cloud}')`);
    }
    await answerFirstRun(tab, "accounts", 30_000);
  };

  const up = await openDialog();
  await realClick(up, ".mode-switch.small button:nth-child(2)");
  await waitFor(up, `document.querySelector("#account-password2")`);
  await up.evaluate(setInput("#account-name", acct));
  await up.evaluate(setInput("#account-password", pw));
  await up.evaluate(setInput("#account-password2", pw));
  const t0 = Date.now();
  await realClick(up, ".connect-btn");
  await waitFor(up, `document.querySelector('.account-dialog[data-kind="recovery"]')`, 60_000);
  const signupMs = Date.now() - t0;
  console.log(`accounts: sign-up took ${signupMs} ms (proof of work and key stretching in the page)`);
  const key = await up.evaluate(`document.querySelector('.account-dialog .secret')?.textContent ?? ""`);
  check("a new account shows its recovery key once", /^[A-Z2-7]{4}(-[A-Z2-7]{1,4}){12}$/.test(key), key);
  await realClick(up, '.account-dialog[data-kind="recovery"] .submit-btn');
  // (The question about copies on the server follows it; `settle` answers.)
  await waitFor(up, `!document.querySelector('.account-dialog[data-kind="recovery"]')`);
  await settle(up);
  check("and it is in, under its own bare name", (await up.evaluate(`document.body.innerText`)).includes(acct));
  // The device key: enrolled right after the sign-in, kept in IndexedDB.
  const remembered = async (tab) =>
    tab.evaluate(`new Promise((done) => { const r = indexedDB.open("voipc-accounts", 1);
      r.onsuccess = () => { const q = r.result.transaction("devices").objectStore("devices").count();
        q.onsuccess = () => done(q.result); q.onerror = () => done(-1); };
      r.onerror = () => done(-1); })`);
  for (let i = 0; i < 40 && (await remembered(up)) < 1; i++) await sleep(150);
  check("this browser is remembered for the account", (await remembered(up)) === 1);
  await up.send("Page.close").catch(() => {});

  // Back again: no password typed, the remembered key signs in.
  const back = await openDialog();
  await back.evaluate(setInput("#account-name", acct));
  await waitFor(back, `document.querySelector("#account-password")?.placeholder?.includes("remembered")`);
  await realClick(back, ".connect-btn");
  await settle(back);
  const backText = await back.evaluate(`document.body.innerText`);
  check(
    "a remembered browser signs in without its password",
    backText.includes(acct),
    (await back.evaluate(`document.querySelector(".error")?.textContent ?? ""`)) + " | " + backText.slice(0, 400).replace(/\s+/g, " "),
  );
  check(
    "and without a recovery key or a code to type",
    !(await back.evaluate(`!!document.querySelector(".account-dialog")`)),
  );

  // A second account meets the first: each pins the other's identity, and
  // both see the same safety number for the pair.
  const acctB = `${acct}b`;
  const two = await openDialog();
  await realClick(two, ".mode-switch.small button:nth-child(2)");
  await waitFor(two, `document.querySelector("#account-password2")`);
  await two.evaluate(setInput("#account-name", acctB));
  await two.evaluate(setInput("#account-password", pw));
  await two.evaluate(setInput("#account-password2", pw));
  await realClick(two, ".connect-btn");
  await waitFor(two, `document.querySelector('.account-dialog[data-kind="recovery"]')`, 60_000);
  const keyB = await two.evaluate(`document.querySelector('.account-dialog .secret')?.textContent ?? ""`);
  await realClick(two, '.account-dialog[data-kind="recovery"] .submit-btn');
  await settle(two);
  const safety = async (tab, other) => {
    const row = `[...document.querySelectorAll(".user .name")].find((e) => e.title === ${JSON.stringify(other)})`;
    await waitFor(tab, row, 15_000);
    await sleep(1500); // the pre-key bundles, which carry the identities, follow the roster
    await tab.evaluate(`(() => { const el = ${row}?.closest(".user"); if (!el) return false;
      el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 })); return true; })()`);
    await sleep(300);
    await tab.evaluate(`(() => { const b = [...document.querySelectorAll(".ctx-item")].find((e) => e.textContent.includes("Verify identity"));
      if (!b) return false; b.click(); return true; })()`);
    await waitFor(tab, `document.querySelector('.account-dialog[data-kind="safety"] .secret')`, 10_000).catch(() => {});
    const n = await tab.evaluate(`document.querySelector('.account-dialog[data-kind="safety"] .secret')?.textContent?.trim() ?? ""`);
    await tab.evaluate(click('.account-dialog[data-kind="safety"] .submit-btn'));
    return n;
  };
  const fromA = await safety(back, acctB);
  const fromB = await safety(two, acct);
  check("two accounts see one safety number for the pair", /^(\d{5} ){11}\d{5}$/.test(fromA) && fromA === fromB, `${fromA} / ${fromB}`);
  check(
    "and meeting raised no identity warning",
    !(await back.evaluate(`(window.__toasts ?? []).some((t) => /identity changed/.test(t))`)),
  );
  // Offline catch-up: the second account leaves; the first writes to it
  // directly and in the kept channel, then leaves too. Nobody is left to hand
  // anything over live, so what the second account finds when it comes back
  // on its remembered browser came from the server's copies. Both said yes
  // to copies above.
  const sayIn = (tab, text) =>
    tab.evaluate(`(() => { const input = document.querySelector(".input-bar .chat-input"); if (!input) return false;
      input.value = ${JSON.stringify(text)}; input.dispatchEvent(new Event("input", { bubbles: true }));
      input.closest("form").requestSubmit(); return true; })()`);
  const markers = (tab) => tab.evaluate(`[...document.querySelectorAll(".history-marker")].map((e) => e.textContent).join(" | ")`);
  const texts = (tab) => tab.evaluate(`[...document.querySelectorAll(".msg-content")].map((e) => e.textContent).join(" | ").slice(0, 300)`);
  const row = `[...document.querySelectorAll(".user .name")].find((e) => e.title === ${JSON.stringify(acctB)})`;
  await back.evaluate(`(() => { const el = ${row}?.closest(".user"); if (!el) return false;
    el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 })); return true; })()`);
  await sleep(300);
  await back.evaluate(`(() => { const b = [...document.querySelectorAll(".ctx-item")].find((e) => /direct message/i.test(e.textContent));
    if (!b) return false; b.click(); return true; })()`);
  await waitFor(back, `document.querySelector(".input-bar .chat-input")`, 10_000);
  await two.send("Page.close").catch(() => {});
  await sleep(1000);
  const dmNote = `a word for later ${process.pid}`;
  await sayIn(back, dmNote);
  const dmKept = await waitFor(
    back,
    `[...document.querySelectorAll(".history-marker")].some((e) => e.textContent.includes("kept there for when they are back"))`,
    15_000,
  ).then(() => true, () => false);
  check("a message to somebody who left is kept for them, and says so", dmKept, await markers(back));
  const openKept = async (tab) => {
    await waitFor(tab, `[...document.querySelectorAll(".channel-list .channel .channel-name")].some((e) => e.textContent === "kept")`, 10_000);
    await tab.evaluate(`[...document.querySelectorAll(".channel-list .channel")].find((e) => e.querySelector(".channel-name")?.textContent === "kept").click()`);
    await waitFor(tab, `document.querySelector(".input-bar .chat-input")`, 10_000);
  };
  await openKept(back);
  const note = `while you were away ${process.pid}`;
  await sayIn(back, note);
  const told = await waitFor(
    back,
    `[...document.querySelectorAll(".history-marker")].some((e) => e.textContent.includes("can be read by") && e.textContent.includes(${JSON.stringify(acctB)}))`,
    15_000,
  ).then(() => true, () => false);
  check("the writer is told who can read what it keeps", told, await markers(back));
  await sleep(1000);
  await back.send("Page.close").catch(() => {});

  const bobAgain = await openDialog();
  await bobAgain.evaluate(setInput("#account-name", acctB));
  await waitFor(bobAgain, `document.querySelector("#account-password")?.placeholder?.includes("remembered")`);
  await realClick(bobAgain, ".connect-btn");
  await settle(bobAgain);
  await openKept(bobAgain);
  const caught = await waitFor(
    bobAgain,
    `[...document.querySelectorAll(".msg-content")].some((e) => e.textContent.includes(${JSON.stringify(note)}))`,
    20_000,
  ).then(() => true, () => false);
  check("a channel message written while they were away is there when they come back", caught, await texts(bobAgain));
  const dmRow = `[...document.querySelectorAll(".dm-name")].find((e) => e.title === ${JSON.stringify(acct)})`;
  const dmListed = await waitFor(bobAgain, `!!(${dmRow})`, 15_000).then(() => true, () => false);
  if (dmListed) await bobAgain.evaluate(`${dmRow}.closest(".dm-entry").click()`);
  const dmCaught = dmListed && (await waitFor(
    bobAgain,
    `[...document.querySelectorAll(".msg-content")].some((e) => e.textContent.includes(${JSON.stringify(dmNote)}))`,
    10_000,
  ).then(() => true, () => false));
  check("and so is the direct message", dmCaught, dmListed ? await texts(bobAgain) : "no conversation listed");
  // A reply while the writer is still away goes the same way, and is there
  // when they are back.
  const reply = `got it ${process.pid}`;
  await sayIn(bobAgain, reply);
  await sleep(1500);
  check(
    "a reply to somebody away is sent without an error",
    !(await bobAgain.evaluate(`(window.__toasts ?? []).some((t) => /away|not kept|Failed/.test(t))`)) &&
      (await bobAgain.evaluate(`[...document.querySelectorAll(".msg-content")].some((e) => e.textContent.includes(${JSON.stringify(reply)}))`)),
    await bobAgain.evaluate(`(window.__toasts ?? []).join(" | ")`),
  );
  await bobAgain.send("Page.close").catch(() => {});
  const aliceAgain = await openDialog();
  await aliceAgain.evaluate(setInput("#account-name", acct));
  await waitFor(aliceAgain, `document.querySelector("#account-password")?.placeholder?.includes("remembered")`);
  await realClick(aliceAgain, ".connect-btn");
  await settle(aliceAgain);
  const replyRow = `[...document.querySelectorAll(".dm-name")].find((e) => e.title === ${JSON.stringify(acctB)})`;
  const replyListed = await waitFor(aliceAgain, `!!(${replyRow})`, 15_000).then(() => true, () => false);
  if (replyListed) await aliceAgain.evaluate(`${replyRow}.closest(".dm-entry").click()`);
  const replyCaught = replyListed && (await waitFor(
    aliceAgain,
    `[...document.querySelectorAll(".msg-content")].some((e) => e.textContent.includes(${JSON.stringify(reply)}))`,
    10_000,
  ).then(() => true, () => false));
  check("and the reply is there when they come back", replyCaught, replyListed ? await texts(aliceAgain) : "no conversation listed");
  // 1.0 (A6): the writer deletes what she kept in the channel, the server's
  // copy included (a tombstone follows for the readers' devices).
  await openKept(aliceAgain);
  await waitFor(aliceAgain, `[...document.querySelectorAll(".msg-content")].some((e) => e.textContent.includes(${JSON.stringify(note)}))`, 15_000).catch(() => {});
  await aliceAgain.evaluate(click('button.clear-chat-btn[title="Clear chat history"]'));
  const menu = await waitFor(aliceAgain, `document.querySelector(".clear-menu")`, 5_000).then(() => true, () => false);
  if (menu) await aliceAgain.evaluate(`[...document.querySelectorAll(".clear-menu .ttl-choice")].find((b) => b.textContent.includes("server's copy"))?.click()`);
  const purgedToast = await waitFor(aliceAgain, `(window.__toasts ?? []).some((t) => /[1-9]\d* kept messages? deleted/.test(t))`, 15_000).then(() => true, () => false);
  check("a writer deletes what she kept in a channel from the server", menu && purgedToast, await aliceAgain.evaluate(`(window.__toasts ?? []).join(" | ")`));
  await sleep(1500); // the tombstone goes out
  await aliceAgain.send("Page.close").catch(() => {});

  // Two-factor codes, set up from the account panel, then a sign-in on a
  // browser that types the password: the code prompt comes mid-sign-in, before
  // the session is listed, and its answer must still reach the sign-in.
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
  const acctC = `${acct}c`;
  const three = await openDialog();
  await realClick(three, ".mode-switch.small button:nth-child(2)");
  await waitFor(three, `document.querySelector("#account-password2")`);
  await three.evaluate(setInput("#account-name", acctC));
  await three.evaluate(setInput("#account-password", pw));
  await three.evaluate(setInput("#account-password2", pw));
  await realClick(three, ".connect-btn");
  await waitFor(three, `document.querySelector('.account-dialog[data-kind="recovery"]')`, 60_000);
  await realClick(three, '.account-dialog[data-kind="recovery"] .submit-btn');
  await settle(three, false);
  // The account panel: the status bar's button in the classic layout this lane
  // picks (the modern one has it in the server menu).
  const panel = 'button[title="Your account on this server"]';
  await waitFor(three, `document.querySelector('${panel}')`, 10_000);
  await realClick(three, panel);
  await waitFor(three, `document.querySelector('.account-dialog[data-kind="account"]')`);
  await three.evaluate(`[...document.querySelectorAll('.account-dialog[data-kind="account"] .secondary')].find((e) => e.textContent.includes("Set up")).click()`);
  await waitFor(three, `document.querySelector('.account-dialog[data-kind="totp-setup"] .secret')`, 10_000);
  const secret = (await three.evaluate(`document.querySelector('.account-dialog[data-kind="totp-setup"] .secret').textContent`)).trim();
  let step = Math.floor(Date.now() / 30_000);
  await three.evaluate(setInput("#acct-setup-code", totpAt(secret, step)));
  await realClick(three, '.account-dialog[data-kind="totp-setup"] .submit-btn');
  const codesShown = await waitFor(three, `document.querySelector('.account-dialog[data-kind="recovery-codes"]')`, 10_000).then(() => true, () => false);
  check("two-factor codes go on from the account panel", codesShown, await three.evaluate(`document.querySelector(".account-dialog .error")?.textContent ?? ""`));
  if (codesShown) await realClick(three, '.account-dialog[data-kind="recovery-codes"] .submit-btn');
  await sleep(1000);
  await three.send("Page.close").catch(() => {});
  // A code is good once: the sign-in waits for the next one.
  while (Math.floor(Date.now() / 30_000) === step) await sleep(500);
  step = Math.floor(Date.now() / 30_000);
  const four = await openDialog();
  await four.evaluate(setInput("#account-name", acctC));
  await four.evaluate(setInput("#account-password", pw));
  await realClick(four, ".connect-btn");
  const asked = await waitFor(four, `document.querySelector('.account-dialog[data-kind="totp"]')`, 60_000).then(() => true, () => false);
  check("a password sign-in asks for the code", asked);
  if (asked) {
    await four.evaluate(setInput("#acct-code", totpAt(secret, Math.floor(Date.now() / 30_000))));
    await realClick(four, '.account-dialog[data-kind="totp"] .submit-btn');
  }
  // In: the code prompt is gone and the account is this connection's (the
  // channel list alone proves nothing: the shell renders one behind the dialog).
  const signedIn = `!document.querySelector('.account-dialog[data-kind="totp"]') && !!document.querySelector('button[title="Your account on this server"]')`;
  const inWithCode = asked && (await waitFor(four, signedIn, 20_000).then(() => true, () => false));
  check(
    "and the code signs it in",
    inWithCode,
    (await four.evaluate(`document.querySelector(".account-dialog .error")?.textContent ?? document.querySelector(".error")?.textContent ?? ""`)) +
      " | " + (await four.evaluate(`(window.__toasts ?? []).join(" | ")`)),
  );
  // 1.0 (A5): bans that outlast a restart. The admin token makes this account
  // (codes on) the first admin; it bans the second account by name from
  // Active bans, which then cannot sign in, and lifting it lets it back.
  if (inWithCode) {
    // DOM clicks: a toast from the sign-in may cover the status bar. (The
    // account's own button there is an .admin-btn too.)
    await four.evaluate(click('button.admin-btn[title^="Admin login"]'));
    await waitFor(four, `document.querySelector(".admin-dialog .admin-input")`);
    await four.evaluate(setInput('.admin-dialog input[type="password"]', "e2e-admin-token-0001"));
    await four.evaluate(click(".admin-dialog .admin-ok"));
    const madeAdmin = await waitFor(four, `document.querySelector(".admin-btn.active")`, 15_000).then(() => true, () => false);
    check("the admin token makes an account with codes the first admin", madeAdmin, await four.evaluate(`(window.__toasts ?? []).join(" | ")`));
    if (madeAdmin) {
      await four.evaluate(click("button.admin-btn.active"));
      await waitFor(four, `document.querySelector(".ban-add")`);
      await four.evaluate(setInput('.ban-add input[aria-label="Account to ban"]', acctB));
      await four.evaluate(setInput('.ban-add input[aria-label="Reason"]', "e2e ban"));
      await four.evaluate(click(".ban-add .admin-ok"));
      const banRow = `[...document.querySelectorAll(".ban-list li")].find((li) => li.querySelector(".ban-label")?.textContent === ${JSON.stringify(acctB)})`;
      const listed = await waitFor(four, `!!(${banRow})`, 10_000).then(() => true, () => false);
      check("an account banned by name is listed under Active bans", listed, await four.evaluate(`document.querySelector(".admin-dialog")?.innerText ?? ""`));
      const banned = await openDialog();
      await banned.evaluate(setInput("#account-name", acctB));
      await banned.evaluate(setInput("#account-password", pw));
      await realClick(banned, ".connect-btn");
      const refusedBan = await waitFor(banned, `/This account is banned/.test(document.querySelector(".error")?.textContent ?? "")`, 30_000).then(() => true, () => false);
      check("and cannot sign in", refusedBan, await banned.evaluate(`document.querySelector(".error")?.textContent ?? ""`));
      await banned.send("Page.close").catch(() => {});
      await four.evaluate(`${banRow}?.querySelector("button")?.click()`);
      const lifted = await waitFor(four, `!(${banRow})`, 10_000).then(() => true, () => false);
      check("Unban lifts it", listed && lifted);
    }
  }
  await four.send("Page.close").catch(() => {});

  // A new password from the account panel, on a browser the relay remembers
  // (a device-key session, never "fresh": the form asks for the current
  // password). Every device key goes with the old password, this browser's
  // too, so it is remembered again at once.
  const pw2 = "a brand new passphrase";
  const five = await openDialog();
  await five.evaluate(setInput("#account-name", acct));
  await waitFor(five, `document.querySelector("#account-password")?.placeholder?.includes("remembered")`);
  await realClick(five, ".connect-btn");
  await settle(five);
  await waitFor(five, `document.querySelector('${panel}')`, 10_000);
  await realClick(five, panel);
  await waitFor(five, `document.querySelector('.account-dialog[data-kind="account"]')`);
  await five.evaluate(`[...document.querySelectorAll('.account-dialog[data-kind="account"] .row')].find((r) => r.querySelector("span")?.textContent === "Password").querySelector("button").click()`);
  await waitFor(five, `document.querySelector("#acct-old-password")`);
  await five.evaluate(setInput("#acct-old-password", pw));
  await five.evaluate(setInput("#acct-new-password", pw2));
  await five.evaluate(setInput("#acct-new-password2", pw2));
  await realClick(five, '.account-dialog[data-kind="password"] .submit-btn');
  const changed = await waitFor(five, `(window.__toasts ?? []).some((t) => /password changed/.test(t))`, 30_000).then(() => true, () => false);
  check(
    "a new password from the account panel",
    changed,
    (await five.evaluate(`document.querySelector(".account-dialog .error")?.textContent ?? ""`)) + " | " + (await five.evaluate(`(window.__toasts ?? []).join(" | ")`)),
  );
  const reRemembered = await waitFor(five, `(window.__toasts ?? []).some((t) => /this device is remembered/.test(t))`, 15_000).then(() => true, () => false);
  check("and this browser is remembered again at once", reRemembered, await five.evaluate(`(window.__toasts ?? []).join(" | ")`));
  await five.send("Page.close").catch(() => {});

  // 1.0 audit H5-01: a server naming the relay id this browser knows from
  // another address is refused before anything of the password goes out.
  // Planted here, as a second account relay would have left it.
  const clash = await openDialog();
  const ids = JSON.parse(await clash.evaluate(`localStorage.getItem("voipc.relay_ids") ?? "{}"`));
  const realId = Object.values(ids)[0];
  check("the browser remembers the relay's id", typeof realId === "string" && realId.length === 32, JSON.stringify(ids));
  await clash.evaluate(`localStorage.setItem("voipc.relay_ids", ${JSON.stringify(JSON.stringify({ "elsewhere.example:9987": realId }))})`);
  await clash.evaluate(setInput("#account-name", acct));
  await clash.evaluate(setInput("#account-password", pw2));
  await realClick(clash, ".connect-btn");
  const clashed = await waitFor(clash, `/another server you use/.test(document.querySelector(".error")?.textContent ?? "")`, 30_000).then(() => true, () => false);
  check("a server claiming another's relay id is refused", clashed, await clash.evaluate(`document.querySelector(".error")?.textContent ?? ""`));
  // The way out the dialog offers: forget that id; then the new password signs in.
  await clash.evaluate(`[...document.querySelectorAll(".save-server-btn")].find((b) => b.textContent.includes("Forget the account id"))?.click()`);
  await clash.evaluate(setInput("#account-password", pw2));
  await realClick(clash, ".connect-btn");
  const newIn = await waitFor(clash, `!!document.querySelector('${panel}')`, 60_000).then(() => true, () => false);
  check(
    "and once it is forgotten, the new password signs in",
    newIn,
    (await clash.evaluate(`document.querySelector(".error")?.textContent ?? ""`)) + " | " + (await clash.evaluate(`(window.__toasts ?? []).join(" | ")`)),
  );
  await clash.send("Page.close").catch(() => {});

  // A new recovery key, from the account panel (S-006): the password is asked
  // for, the key is shown only once the relay took it, and the old one stops
  // working.
  const keyNew = await openDialog();
  await keyNew.evaluate(setInput("#account-name", acctB));
  await waitFor(keyNew, `document.querySelector("#account-password")?.placeholder?.includes("remembered")`);
  await realClick(keyNew, ".connect-btn");
  await settle(keyNew);
  await waitFor(keyNew, `document.querySelector('${panel}')`, 10_000);
  await realClick(keyNew, panel);
  await waitFor(keyNew, `document.querySelector('.account-dialog[data-kind="account"]')`);
  await keyNew.evaluate(`[...document.querySelectorAll('.account-dialog[data-kind="account"] .row')].find((r) => r.textContent.includes("Recovery key"))?.querySelector("button")?.click()`);
  await waitFor(keyNew, `document.querySelector('.account-dialog[data-kind="recovery-new"] #acct-recovery-password')`, 10_000).catch(() => {});
  await keyNew.evaluate(setInput("#acct-recovery-password", "not the password at all"));
  await realClick(keyNew, '.account-dialog[data-kind="recovery-new"] .submit-btn');
  const wrongNew = await waitFor(keyNew, `document.querySelector('.account-dialog[data-kind="recovery-new"] .error')`, 30_000).then(() => true, () => false);
  check(
    "a new recovery key asks for the password: a wrong one is refused there, and no key is shown",
    wrongNew && !(await keyNew.evaluate(`!!document.querySelector('.account-dialog[data-kind="recovery"]')`)),
    await keyNew.evaluate(`document.querySelector(".account-dialog")?.innerText.slice(0, 300) ?? "no dialog"`),
  );
  await keyNew.evaluate(setInput("#acct-recovery-password", pw));
  await realClick(keyNew, '.account-dialog[data-kind="recovery-new"] .submit-btn');
  await waitFor(keyNew, `document.querySelector('.account-dialog[data-kind="recovery"] .secret')`, 30_000).catch(() => {});
  const keyB2 = await keyNew.evaluate(`document.querySelector('.account-dialog[data-kind="recovery"] .secret')?.textContent ?? ""`);
  const keyHead = await keyNew.evaluate(`document.querySelector('.account-dialog[data-kind="recovery"] h2')?.textContent ?? ""`);
  check(
    "the right one shows the new key, and says it is the new one",
    /^[A-Z2-7]{4}(-[A-Z2-7]{1,4}){12}$/.test(keyB2) && keyB2 !== keyB && /new recovery key/.test(keyHead),
    `${keyHead} | ${keyB2}`,
  );
  await realClick(keyNew, '.account-dialog[data-kind="recovery"] .submit-btn');
  await keyNew.send("Page.close").catch(() => {});
  const stale = await openDialog();
  await stale.evaluate(setInput("#account-name", acctB));
  await realClick(stale, ".link-btn");
  await waitFor(stale, `document.querySelector("#account-recovery")`);
  await stale.evaluate(setInput("#account-recovery", keyB));
  await stale.evaluate(setInput("#account-password", "reset with the old key"));
  await stale.evaluate(setInput("#account-password2", "reset with the old key"));
  await realClick(stale, ".connect-btn");
  const staleOut = await waitFor(stale, `/does not open this account/.test(document.querySelector(".error")?.textContent ?? "") || !!document.querySelector('${panel}')`, 60_000)
    .then(() => true, () => false);
  check(
    "and the old recovery key no longer resets the password",
    staleOut && !(await stale.evaluate(`!!document.querySelector('${panel}')`)),
    await stale.evaluate(`document.querySelector(".error")?.textContent ?? ""`),
  );
  await stale.send("Page.close").catch(() => {});

  // Forgot the password: the recovery key (the new one) sets a new password,
  // and the dialog signs in with it at once.
  const pw3 = "reset with the recovery key";
  const six = await openDialog();
  await six.evaluate(setInput("#account-name", acctB));
  await realClick(six, ".link-btn");
  await waitFor(six, `document.querySelector("#account-recovery")`);
  await six.evaluate(setInput("#account-recovery", keyB2 || keyB));
  await six.evaluate(setInput("#account-password", pw3));
  await six.evaluate(setInput("#account-password2", pw3));
  await realClick(six, ".connect-btn");
  const resetIn = await waitFor(six, `!!document.querySelector('${panel}')`, 60_000).then(() => true, () => false);
  check(
    "the recovery key sets a new password and signs in with it",
    resetIn,
    (await six.evaluate(`document.querySelector(".error")?.textContent ?? ""`)) + " | " + (await six.evaluate(`(window.__toasts ?? []).join(" | ")`)),
  );
  if (resetIn) {
    // What the writer deleted above does not come back to this reader
    await openKept(six);
    await sleep(5000);
    check(
      "and a message its writer deleted is not there for the reader",
      !(await six.evaluate(`[...document.querySelectorAll(".msg-content")].some((e) => e.textContent.includes(${JSON.stringify(note)}))`)),
      await texts(six),
    );
  }
  await six.send("Page.close").catch(() => {});

  // The name is the account's now: a guest cannot take it.
  const guest = await newTab();
  await guest.send("Page.navigate", { url: URL3 });
  await waitFor(guest, `document.querySelector(".connect-btn")`);
  await guest.evaluate(setInput('input[placeholder="localhost"]', "127.0.0.1"));
  await guest.evaluate(setInput('input[placeholder="9987"]', PORT3));
  await guest.evaluate(setInput('input[placeholder="Your name"]', acct));
  await realClick(guest, ".connect-btn");
  await waitFor(guest, `document.querySelector(".error")`, 15_000);
  check(
    "a guest cannot take an account's name",
    /belongs to an account/.test(await guest.evaluate(`document.querySelector(".error").textContent`)),
  );
  // A wrong password: the relay says so, and nothing is remembered for it.
  await realClick(guest, ".mode-switch button:nth-child(2)");
  await waitFor(guest, `document.querySelector("#account-name")`);
  await guest.evaluate(setInput("#account-name", acct));
  await guest.evaluate(setInput("#account-password", "not the password at all"));
  await realClick(guest, ".connect-btn");
  await waitFor(guest, `/Wrong username or password/.test(document.querySelector(".error")?.textContent ?? "")`, 30_000);
  check("a wrong password is refused", true);
  const fatal = [...up.errors, ...back.errors, ...two.errors, ...bobAgain.errors, ...aliceAgain.errors, ...three.errors, ...four.errors, ...five.errors, ...clash.errors, ...keyNew.errors, ...stale.errors, ...six.errors, ...guest.errors].filter(
    (e) => !/Failed to load resource/.test(e),
  );
  check("the accounts lane threw nothing", fatal.length === 0, fatal.slice(0, 2).join(" | "));
} else {
  console.log("SKIP the accounts lane (no accounts server port given)");
}

// 18. A browser that ran 0.12.0 (1.0 upgrade fixtures). Its voipc.settings,
//     written by 0.12.0's own config.ts (client/src/lib/__fixtures__/0.12.0),
//     must load as it is: nothing set aside as unreadable, the saved server
//     still offered. On the second server's origin, because localStorage is
//     per origin and every other lane shares the first one's.
if (PORT2) {
  const { readFileSync } = await import("node:fs");
  const settings = readFileSync(new globalThis.URL("client/src/lib/__fixtures__/0.12.0/voipc.settings.json", import.meta.url), "utf8");
  const old = await newTab();
  await old.send("Page.navigate", { url: `https://127.0.0.1:${PORT2}/favicon.png` });
  await waitFor(old, `document.readyState === "complete"`);
  await old.evaluate(`(() => { localStorage.clear();
    localStorage.setItem("voipc.settings", ${JSON.stringify(settings)}); return true; })()`);
  await old.send("Page.navigate", { url: `https://127.0.0.1:${PORT2}/` });
  await waitFor(old, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  if (await old.evaluate(`!!document.querySelector(".skip-link")`)) {
    await old.evaluate(click(".skip-link"));
    await waitFor(old, `document.querySelector(".connect-btn")`);
  }
  check(
    "a 0.12 browser's settings are not set aside as unreadable",
    await old.evaluate(`localStorage.getItem("voipc.settings.unreadable") === null`),
  );
  check(
    "a 0.12 browser's saved server is still offered",
    await old.evaluate(`[...document.querySelectorAll(".saved-server")].some((e) =>
      e.querySelector(".saved-name")?.textContent === "Home" && /voice\.example\.org:9987/.test(e.textContent))`),
  );
  const fatal = old.errors.filter((e) => !/Failed to load resource/.test(e));
  check("the 0.12 settings threw nothing", fatal.length === 0, fatal.slice(0, 2).join(" | "));
}

// 7. Nothing threw anywhere. One uncaught exception in a keyed {#each} wedges
//    the UI for the rest of the session, so this is the real assertion.
for (const [name, tab] of [["creator", alice], ["observer", bob]]) {
  const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
  check(`no uncaught error on the ${name}'s page`, fatal.length === 0, fatal.slice(0, 3).join(" | "));
}
check("the creator's UI still responds", await alice.evaluate(`!!document.querySelector(".channel-list")`));

console.log(failures === 0 ? "test-ui: all checks passed" : `test-ui: ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
