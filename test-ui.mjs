// Regression test for the web client's real Svelte UI, driven through the
// Chrome DevTools Protocol (Node 22's built-in WebSocket, no dependencies).
//
// test-web.sh checks the protocol and the media path through the in-page
// self-test, which never renders a component. This one clicks the actual UI —
// where a duplicate key in a keyed {#each} throws inside Svelte's flush, the
// store keeps the duplicate and every later update throws again, so the whole
// window is dead. That bug shipped once; this is what would have caught it.
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
  console.log(`${name}: connected`);
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

// 7. Nothing threw anywhere. One uncaught exception in a keyed {#each} wedges
//    the UI for the rest of the session, so this is the real assertion.
for (const [name, tab] of [["creator", alice], ["observer", bob]]) {
  const fatal = tab.errors.filter((e) => !/Failed to load resource/.test(e));
  check(`no uncaught error on the ${name}'s page`, fatal.length === 0, fatal.slice(0, 3).join(" | "));
}
check("the creator's UI still responds", await alice.evaluate(`!!document.querySelector(".channel-list")`));

console.log(failures === 0 ? "test-ui: all checks passed" : `test-ui: ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
