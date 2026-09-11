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
  const send = (method, params = {}) =>
    new Promise((resolve) => {
      const i = ++id;
      pending.set(i, resolve);
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
  console.log(`${name}: connected`);
  return tab;
}

/** Connect without dismissing the audio setup, for the lane that drives it. */
async function connectRaw(name) {
  const tab = await newTab();
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
// Order in the dialog: hidden, anonymous, hide members, allow screen sharing
await alice.evaluate(`(() => { const b = [...document.querySelectorAll(".password-dialog .dialog-check input")];
  b[0].click(); b[2].click(); b[3].click(); return b.length; })()`);
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
  const fresh = await connectRaw(`ui-setup-${process.pid % 1000}`);
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

// 7. Nothing threw anywhere. One uncaught exception in a keyed {#each} wedges
//    the UI for the rest of the session, so this is the real assertion.
for (const [name, tab] of [["creator", alice], ["observer", bob]]) {
  const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
  check(`no uncaught error on the ${name}'s page`, fatal.length === 0, fatal.slice(0, 3).join(" | "));
}
check("the creator's UI still responds", await alice.evaluate(`!!document.querySelector(".channel-list")`));

console.log(failures === 0 ? "test-ui: all checks passed" : `test-ui: ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
