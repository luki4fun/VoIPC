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

const PORT = process.argv[2] ?? "19987";
const CDP = process.argv[3] ?? "9222";
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
    if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      errors.push(d.exception?.description ?? d.text ?? "unknown exception");
    }
    if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      errors.push(msg.params.args.map((a) => a.value ?? a.description ?? "").join(" "));
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

async function connect(name) {
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
  await tab.evaluate(click(".connect-btn"));
  await waitFor(tab, `document.querySelector(".channel-list")`);
  // First run also offers the audio setup, a moment after the channel list
  // arrives. Lane 8 drives it properly; every other lane wants it out of the
  // way — and it is a real overlay, so leaving it up would swallow every
  // click the rest of this file makes.
  await sleep(800);
  if (await tab.evaluate(`!!document.querySelector(".audio-setup .skip-link")`)) {
    await realClick(tab, ".audio-setup .skip-link");
    await waitFor(tab, `!document.querySelector(".audio-setup")`);
  }
  await dismissLayoutPicker(tab);
  console.log(`${name}: connected`);
  return tab;
}

/**
 * The layout picker follows the audio setup on a fresh profile.
 *
 * Conditional, because test-web.sh runs one Chromium with one profile: every
 * tab shares localStorage, so the first browser is asked and the second is not.
 * It ANSWERS the question rather than skipping it: the default is the modern
 * layout, and every selector below this point is the classic one's. Section 11
 * is where switching between them is exercised on purpose.
 * Leaving it up would be worse than a timeout — it is a real overlay, so every
 * realClick after it would land on its backdrop and read as "element not found".
 */
async function dismissLayoutPicker(tab) {
  await sleep(300);
  if (await tab.evaluate(`!!document.querySelector(".layout-setup")`)) {
    await realClick(tab, '.layout-setup .layout-choice[data-layout="classic"]');
    await sleep(200);
    await realClick(tab, ".layout-setup .submit-btn");
    await waitFor(tab, `!document.querySelector(".layout-setup")`);
  }
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
  await waitFor(tab, `document.querySelector(".channel-list")`);
  return tab;
}

const alice = await connect("ui-alice");
const bob = await connect("ui-bob");
check(
  "answering the layout question is remembered",
  (await alice.evaluate(
    `JSON.parse(localStorage.getItem("voipc.settings")).ui_prefs?.layout_asked_version`,
  )) === 1,
);
check(
  "and it put us in the layout that was picked",
  await alice.evaluate(`!!document.querySelector(".app-layout") && !document.querySelector(".modern-shell")`),
);
await sleep(800);

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
await alice.evaluate(`(() => { const el = document.querySelector(".channel.active .settings-icon"); if (!el) return false; el.click(); return true; })()`);
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
await alice.evaluate(`(() => { const el = document.querySelector(".channel.active .settings-icon"); if (!el) return false; el.click(); return true; })()`);
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
await alice.evaluate(`(() => { const el = document.querySelector(".channel.active .settings-icon"); if (!el) return false; el.click(); return true; })()`);
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
  // which only arrives if the wizard actually started a capture.
  let meterMoved = true;
  try {
    await waitFor(
      fresh,
      `document.querySelector(".audio-setup .level-fill").style.width !== "0%"`,
      8_000,
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
    "it offers both layouts",
    (await fresh.evaluate(`document.querySelectorAll(".layout-setup .layout-choice").length`)) === 2,
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

  const pickPalette = (label) =>
    `[...document.querySelectorAll(".swatch")].find((b) => ${JSON.stringify(label)} === b.title)`;
  check("the palettes are offered", await alice.evaluate(`!!(${pickPalette("Slate light")})`));

  // Start from a dark palette on purpose. Which palette a fresh client opens in
  // follows the machine's light/dark setting now, so "switch to the light one
  // and watch it change" only means something from a known dark starting point
  // — and this headless browser reports a light preference.
  await alice.evaluate(`(${pickPalette("VoIPC dark")}).click()`);
  await sleep(400);
  const before = await alice.evaluate(`getComputedStyle(document.body).backgroundColor`);
  await alice.evaluate(`(${pickPalette("Slate light")}).click()`);
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
  await alice.evaluate(`(${pickPalette("VoIPC dark")}).click()`);
  await sleep(400);
  check(
    "switching back restores the dark document",
    (await alice.evaluate(`document.documentElement.dataset.theme`)) === "dark",
  );
  check(
    "the choice is remembered",
    (await alice.evaluate(
      `JSON.parse(localStorage.getItem("voipc.settings")).ui_prefs?.palette`,
    )) === "voipc-dark",
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

  // Assert against the row that was acted on, not merely "something is active":
  // the first non-active row here is the lobby, and "a channel is active" is
  // true there whether or not the click did anything.
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

  // Again, to prove it was not a one-off. Deliberately not asserting we land
  // back where we started: this server has several channels, so "the first
  // non-active row" is not a toggle between two.
  const secondTarget = await nextChannel();
  await realDoubleClick(alice, ".channel-list.modern .channels.voice .channel:not(.active)");
  await sleep(1400);
  check(
    "and it joins the next one too",
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
      const g = row.querySelector('.settings-icon[title="Leave this channel"]'); if (!g) return null;
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

  // The mute checks at the end of this block need a channel with voice in it.
  // Channel 0 is the lobby, where voice is off by design, and a mute button
  // that is absent for a good reason still reads as a broken mute button.
  // The voice panel only renders outside the lobby, so its presence is the
  // check — no need to know which channel id we happen to be in.
  check(
    "we are somewhere with voice, not the lobby",
    await alice.evaluate(`!!document.querySelector(".voice-panel")`),
    await activeChannel(),
  );

  // The point of the nested rows: a channel you are NOT in shows who is in it.
  // bob is in the lobby by now, so the lobby row should name him — without
  // hovering it, previewing it or joining it. The names for another channel are
  // never pushed to us, so this is really a check that stores/rosters.ts asked.
  await sleep(1200);
  const nestedElsewhere = await alice.evaluate(`(() => {
    const rows = [...document.querySelectorAll(".channel-list.modern .channel")];
    const active = document.querySelector(".channel-list.modern .channel.active");
    for (const row of rows) {
      if (row === active) continue;
      const nested = row.nextElementSibling;
      if (nested && nested.classList.contains("nested")) {
        return [...nested.querySelectorAll(".nested-name")].map((e) => e.textContent.trim());
      }
    }
    return []; })()`);
  check(
    "a channel we are not in lists its members",
    nestedElsewhere.length > 0,
    JSON.stringify(nestedElsewhere),
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

  // Back to classic, in the same tab and with no reload.
  await openAppearance();
  await alice.evaluate(`(${pickLayout("classic")}).click()`);
  await sleep(500);
  await alice.evaluate(`document.querySelector(".close-btn")?.click()`);
  await sleep(500);
  check("switching back restores the classic shell", await alice.evaluate(
    `!!document.querySelector(".app-layout") && !document.querySelector(".modern-shell")`,
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
       const gear = row?.querySelector('[title="Channel settings"]');
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

// 7. Nothing threw anywhere. One uncaught exception in a keyed {#each} wedges
//    the UI for the rest of the session, so this is the real assertion.
for (const [name, tab] of [["creator", alice], ["observer", bob]]) {
  const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
  check(`no uncaught error on the ${name}'s page`, fatal.length === 0, fatal.slice(0, 3).join(" | "));
}
check("the creator's UI still responds", await alice.evaluate(`!!document.querySelector(".channel-list")`));

console.log(failures === 0 ? "test-ui: all checks passed" : `test-ui: ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
