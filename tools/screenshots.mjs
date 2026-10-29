// Screenshots of the real web client, unattended: every layout in every
// palette, at a desktop, a tablet and a phone width, against a scratch server
// with a curated channels.json and four people in it.
//
//   node tools/screenshots.mjs [--out DIR] [--layouts modern,classic,stage]
//                              [--palettes id,id] [--website] [--port N]
//
// What it needs is what test-web.sh needs: a release server with the web
// client embedded (`npm run web`), openssl, and chromium (CHROME=... to pick
// one). Nothing is installed and nothing outside --out and a temp directory is
// written, except with --website, which also rewrites website/screenshots/.
//
// Why a script and not a demo seed in the app: the website showed a 0.4.0
// window for weeks because regenerating it was a manual afternoon. This makes
// it one command, and it drives the same UI a person does — Settings →
// Appearance for the layout and palette, the channel rows to join, the composer
// to talk — so a broken path shows up as a failed run, not a pretty lie.
//
// Same rules as test-ui.mjs: trusted CDP input for anything pointer-driven,
// el.click() only for plain buttons, and every CDP call has a deadline.

import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : fallback;
};
const flag = (name) => args.includes(`--${name}`);

const PORT = Number(opt("port", "29987"));
const CDP = PORT + 1000;
const OUT = resolve(opt("out", join(tmpdir(), `voipc-shots-${process.pid}`)));
const LAYOUTS = opt("layouts", "modern,classic,stage").split(",");
// empty = every one the app offers; the website shows the default, and day
// once (README: the app opens in it on a light system)
const PALETTES = opt("palettes", flag("website") ? "voipc-night,voipc-day" : "").split(",").filter(Boolean);
const WEBSITE = flag("website");
const SERVER = resolve(ROOT, process.env.SERVER ?? "target/release/voipc-server");
const CHROME = process.env.CHROME
  ?? ["chromium", "chromium-browser", "google-chrome"].map((c) => {
    try { return execFileSync("sh", ["-c", `command -v ${c}`]).toString().trim(); } catch { return ""; }
  }).find(Boolean);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const die = (msg) => { console.error(`screenshots: ${msg}`); process.exit(1); };

if (!existsSync(SERVER)) die(`${SERVER} missing — run \`npm run web\` first`);
if (!CHROME) die("no chromium found (set CHROME=...)");
mkdirSync(OUT, { recursive: true });

// ── Scratch server ──────────────────────────────────────────────────────────

const WORK = mkdtempSync(join(tmpdir(), "voipc-shots-work-"));
const children = [];
const cleanup = () => {
  for (const c of children) { try { c.kill("SIGTERM"); } catch { /* gone */ } }
  try { rmSync(WORK, { recursive: true, force: true }); } catch { /* best effort */ }
};
process.on("exit", cleanup);
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(130));

execFileSync("openssl", [
  "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
  "-keyout", join(WORK, "server.key"), "-out", join(WORK, "server.crt"), "-days", "2", "-nodes",
  "-subj", "/CN=voipc-shots", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
], { stdio: "ignore" });

// The server people see in every shot: a lobby, two text channels, three voice
// channels, one of them with proximity on so its tag shows.
writeFileSync(join(WORK, "channels.json"), JSON.stringify([
  { name: "chat", description: "Text channel everyone lands in", text: true, auto_join: true },
  { name: "offtopic", description: "Text channel you join yourself", text: true },
  { name: "Lounge", description: "Hang out" },
  { name: "Gaming", description: "Proximity chat: you hear people where they stand", proximity: "2d" },
  { name: "AFK", description: "Away from keyboard" },
], null, 2));

// `--host ::` so the connect dialog can say "localhost" (Chromium resolves it
// to ::1 first) — reads better in a picture than an address.
children.push(spawn(SERVER, [
  "--host", "::", "--tcp-port", String(PORT), "--udp-port", String(PORT),
  "--cert", "server.crt", "--key", "server.key", "--channels", "channels.json",
], { cwd: WORK, stdio: "ignore" }));

for (let i = 0; i < 50; i++) {
  try {
    execFileSync("curl", ["-sk", "--http2-prior-knowledge", `https://127.0.0.1:${PORT}/wt.json`], { stdio: "pipe" });
    break;
  } catch { await sleep(200); }
  if (i === 49) die(`server did not come up on ${PORT} (port taken?)`);
}

children.push(spawn(CHROME, [
  "--headless=new", `--remote-debugging-port=${CDP}`, `--user-data-dir=${join(WORK, "chrome")}`,
  "--ignore-certificate-errors", "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream",
  "--autoplay-policy=no-user-gesture-required", "--no-first-run", "--hide-scrollbars",
  // Four people in four tabs, and only the one being photographed is in
  // front: without these the others' timers and frames are throttled, and a
  // share from a tab behind reads 4 fps in its own stats
  "--disable-background-timer-throttling", "--disable-renderer-backgrounding",
  "--disable-backgrounding-occluded-windows",
  // The link card (tools/og-card.html) loads the site's fonts from disk
  "--allow-file-access-from-files", "about:blank",
], { stdio: "ignore" }));
for (let i = 0; i < 50; i++) {
  try { await fetch(`http://127.0.0.1:${CDP}/json/version`); break; } catch { await sleep(200); }
}

// ── CDP ─────────────────────────────────────────────────────────────────────

const URL = `https://localhost:${PORT}/`;
const PHONE_UA =
  "Mozilla/5.0 (Linux; Android 13; SM-A127F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36";

async function newTab({ width = 1280, height = 800, scale = 2, phone = false } = {}) {
  const info = await (await fetch(`http://127.0.0.1:${CDP}/json/new?about:blank`, { method: "PUT" })).json();
  const ws = new WebSocket(info.webSocketDebuggerUrl);
  await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = bad; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  };
  const send = (method, params = {}, timeoutMs = 30_000) => new Promise((ok, bad) => {
    const i = ++id;
    const t = setTimeout(() => { pending.delete(i); bad(new Error(`CDP timeout: ${method}`)); }, timeoutMs);
    pending.set(i, (msg) => { clearTimeout(t); ok(msg); });
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(`evaluate: ${JSON.stringify(r.result.exceptionDetails).slice(0, 300)}`);
    return r.result?.result?.value;
  };
  await send("Page.enable");
  await send("Runtime.enable");
  const tab = { send, evaluate, phone };
  tab.resize = (w, h, s = scale) =>
    send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: s, mobile: phone });
  await tab.resize(width, height);
  if (phone) {
    // Before the page loads: platform.ts decides "phone" once, at start
    await send("Emulation.setUserAgentOverride", { userAgent: PHONE_UA, platform: "Linux armv8l" });
    await send("Emulation.setTouchEmulationEnabled", { enabled: true, maxTouchPoints: 5 });
  }
  return tab;
}

async function waitFor(tab, expression, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return true;
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${expression}`);
}

const q = JSON.stringify;
const click = (sel) => `(() => { const el = document.querySelector(${q(sel)}); if (!el) return false; el.click(); return true; })()`;
const setInput = (sel, v) => `(() => { const el = document.querySelector(${q(sel)}); if (!el) return false;
  el.value = ${q(v)}; el.dispatchEvent(new Event("input", { bubbles: true })); return true; })()`;
/** Tags the first element matching `sel` whose text is `text`, so a trusted click can aim at it. */
const mark = (sel, text, inner = null) => `(() => {
  document.querySelectorAll("[data-shot]").forEach((e) => e.removeAttribute("data-shot"));
  const el = [...document.querySelectorAll(${q(sel)})].find((e) =>
    (${inner ? `e.querySelector(${q(inner)})` : "e"})?.textContent.trim() === ${q(text)});
  if (!el) return false; el.setAttribute("data-shot", ""); return true; })()`;

async function realDoubleClick(tab, sel) {
  const at = await tab.evaluate(`(() => { const el = document.querySelector(${q(sel)}); if (!el) return null;
    el.scrollIntoView({ block: "center" }); const r = el.getBoundingClientRect();
    return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }; })()`);
  if (!at) return false;
  const base = { x: at.x, y: at.y, button: "left" };
  await tab.send("Input.dispatchMouseEvent", { type: "mouseMoved", ...base, buttons: 0, clickCount: 0 });
  for (const n of [1, 2]) {
    await tab.send("Input.dispatchMouseEvent", { type: "mousePressed", ...base, buttons: 1, clickCount: n });
    await tab.send("Input.dispatchMouseEvent", { type: "mouseReleased", ...base, buttons: 1, clickCount: n });
  }
  await sleep(200);
  return true;
}

// ── People ──────────────────────────────────────────────────────────────────

/** Settings written before a tab loads the app, from a same-origin page that is
 *  not the app (the app hydrates asynchronously and would overwrite them). */
async function seedSettings(tab, patch) {
  await tab.send("Page.navigate", { url: `${URL}favicon.png` });
  await waitFor(tab, `document.readyState === "complete"`);
  await tab.evaluate(`(() => { const s = JSON.parse(localStorage.getItem("voipc.settings") ?? "{}");
    localStorage.setItem("voipc.settings", JSON.stringify(Object.assign(s, ${q(patch)}))); return true; })()`);
}

async function connect(name, tabOpts = {}, { talking = false } = {}) {
  const tab = await newTab(tabOpts);
  // Everyone shares one profile, so whatever the last tab saved is what this
  // one would read: the voice mode is set per person on the way in.
  await seedSettings(tab, { voice_mode: talking ? "always_on" : "ptt" });
  await tab.send("Page.navigate", { url: URL });
  await waitFor(tab, `document.querySelector(".skip-link") || document.querySelector(".connect-btn")`);
  if (await tab.evaluate(`!!document.querySelector(".skip-link")`)) {
    await tab.evaluate(click(".skip-link"));
    await waitFor(tab, `document.querySelector(".connect-btn")`);
  }
  await tab.evaluate(setInput('input[placeholder="localhost"]', "localhost"));
  await tab.evaluate(setInput('input[placeholder="9987"]', String(PORT)));
  await tab.evaluate(setInput('input[placeholder="Your name"]', name));
  await tab.evaluate(click(".connect-btn"));
  await waitFor(tab, `!document.querySelector(".connect-btn")`, 30_000);
  // The first-run questions: skip the audio setup, answer the layout picker
  const deadline = Date.now() + 15_000;
  let quiet = 0;
  while (Date.now() < deadline) {
    const s = await tab.evaluate(`({ audio: !!document.querySelector(".audio-setup .skip-link"),
      layout: !!document.querySelector(".layout-setup") })`);
    if (s.audio) { await tab.evaluate(click(".audio-setup .skip-link")); quiet = 0; }
    else if (s.layout) {
      await tab.evaluate(click(`.layout-setup .layout-choice[data-layout="${LAYOUTS[0]}"]`));
      await sleep(150);
      await tab.evaluate(click(".layout-setup .submit-btn"));
      quiet = 0;
    } else if ((quiet ||= Date.now()) && Date.now() - quiet > 1000) break;
    await sleep(150);
  }
  console.log(`${name}: connected`);
  return tab;
}

async function joinVoice(tab, channel) {
  if (!(await tab.evaluate(mark(".channel", channel, ".channel-name")))) throw new Error(`no channel ${channel}`);
  if (tab.phone) {
    // A phone has no double click: the row previews, the pane offers the join
    await tab.evaluate(click("[data-shot]"));
    await waitFor(tab, `document.querySelector(".join-voice-btn")`);
    await tab.evaluate(click(".join-voice-btn"));
  } else {
    await realDoubleClick(tab, "[data-shot]");
  }
  await sleep(1200);
}

async function say(tab, text) {
  await waitFor(tab, `document.querySelector(".input-bar .chat-input")`);
  await tab.evaluate(`(() => { const i = document.querySelector(".input-bar .chat-input");
    i.value = ${q(text)}; i.dispatchEvent(new Event("input", { bubbles: true }));
    i.closest("form").requestSubmit(); return true; })()`);
  await sleep(700);
}

/** Layout and palette, the way a person changes them: Settings → Appearance. */
async function appearance(tab, layout, palette) {
  await tab.send("Page.bringToFront");
  // Stage on a phone keeps Settings in its channel drawer, shut until opened
  if (!(await tab.evaluate(`!!document.querySelector(".settings-btn")`))) {
    await tab.evaluate(click('.top-btn[aria-label="Channels"]'));
    await sleep(300);
  }
  await tab.evaluate(click(".settings-btn"));
  await waitFor(tab, `document.querySelector(".panel .tabs")`);
  await tab.evaluate(`[...document.querySelectorAll(".panel .tab")].find((t) => t.textContent.trim() === "Appearance")?.click() ?? false`);
  await waitFor(tab, `document.querySelector(".layout-choice")`);
  await tab.evaluate(click(`.layout-choice[data-layout="${layout}"]`));
  await sleep(300);
  // The settings panel survives a layout switch (App.svelte owns it)
  await tab.evaluate(`(() => { const b = [...document.querySelectorAll(".swatch")]
    .find((s) => s.dataset.palette === ${q(palette.id)} || s.querySelector(".swatch-label")?.textContent.trim() === ${q(palette.label)});
    if (!b) return false; b.click(); return true; })()`);
  await sleep(200);
}

const closeSettings = (tab) => tab.evaluate(click(".panel .close-btn")).then(() => sleep(300));

async function shoot(tab, file) {
  // A tab in the background renders no frames, and a capture then waits for
  // one forever: the one being photographed comes to the front first
  await tab.send("Page.bringToFront");
  await sleep(250);
  const r = await tab.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(OUT, file), Buffer.from(r.result.data, "base64"));
  console.log(`  ${file}`);
}

// ── The run ─────────────────────────────────────────────────────────────────

const tom = await connect("Tom", { width: 1024, height: 700, scale: 1 }, { talking: true });
const ada = await connect("Ada", { width: 1024, height: 700, scale: 1 });
const mira = await connect("Mira");
const lena = await connect("Lena", { width: 390, height: 844, scale: 2, phone: true });

await joinVoice(tom, "Lounge");
await joinVoice(mira, "Lounge");
await joinVoice(ada, "Gaming");
await joinVoice(lena, "Lounge");
await say(tom, "anyone up for a round after this?");
await say(mira, "give me ten minutes, finishing a build");
await say(tom, "classic");
await say(mira, "the server keeps none of this, by the way");

// What the app offers, read from the app — a palette added later is covered
const offered = await mira.evaluate(`(async () => {
  document.querySelector(".settings-btn")?.click();
  await new Promise((r) => setTimeout(r, 300));
  [...document.querySelectorAll(".panel .tab")].find((t) => t.textContent.trim() === "Appearance")?.click();
  await new Promise((r) => setTimeout(r, 300));
  const list = [...document.querySelectorAll(".swatch")].map((s) => ({
    id: s.dataset.palette ?? s.querySelector(".swatch-label")?.textContent.trim().toLowerCase().replace(/\\s+/g, "-"),
    label: s.querySelector(".swatch-label")?.textContent.trim() }));
  document.querySelector(".panel .close-btn")?.click();
  return list; })()`);
const palettes = PALETTES.length ? offered.filter((p) => PALETTES.includes(p.id)) : offered;
console.log(`palettes: ${palettes.map((p) => p.id).join(", ")}`);
await sleep(400);

for (const layout of LAYOUTS) {
  for (const palette of palettes) {
    const tag = `${layout}-${palette.id}`;
    await appearance(mira, layout, palette);
    if (palette === palettes[0]) await shoot(mira, `${tag}-settings.png`);
    await closeSettings(mira);
    await mira.resize(1280, 800);
    await shoot(mira, `${tag}-desktop.png`);
    await mira.resize(768, 1024);
    await shoot(mira, `${tag}-tablet.png`);
    await mira.resize(1280, 800);

    await appearance(lena, layout, palette);
    await closeSettings(lena);
    // ...and the drawer it opened for that is shut again (Stage)
    await lena.evaluate(click(".stage-shell .scrim"));
    await sleep(200);
    await shoot(lena, `${tag}-phone.png`);
  }
}

if (WEBSITE) {
  const dir = join(ROOT, "website", "screenshots");
  mkdirSync(dir, { recursive: true });
  const p = (palettes.find((x) => x.id === "voipc-night") ?? palettes[0])?.id;

  // The mixing desk, mid-call: Mira on the stage opens it, Tom still talking.
  // Back in the site's palette first: the loop above ends on the last one.
  await mira.send("Page.bringToFront");
  await mira.resize(1280, 800);
  await appearance(mira, "stage", palettes.find((x) => x.id === p));
  await closeSettings(mira);
  await mira.evaluate(click('.top-btn[aria-label="Mixing desk"]'));
  await sleep(1500);
  await shoot(mira, `stage-${p}-mixer.png`);
  await mira.evaluate(click('.top-btn[aria-label="Mixing desk"]'));
  await sleep(400);

  // A share, both ends of it. Tom's tab shares a canvas — a code editor drawn
  // from this repository's own source, so the picture is real text — through
  // the browser's capture API, overridden the way device-run tests do it.
  const code = readFileSync(join(ROOT, "crates/voipc-server/src/main.rs"), "utf8").split("\n").slice(0, 46);
  await tom.send("Page.bringToFront");
  await tom.evaluate(`(() => {
    const lines = ${q(code)};
    const c = document.createElement("canvas");
    c.width = 1600; c.height = 900;
    const g = c.getContext("2d");
    const draw = () => {
      g.fillStyle = "#16181d"; g.fillRect(0, 0, 1600, 900);
      g.fillStyle = "#0f1114"; g.fillRect(0, 0, 260, 900);
      g.font = "15px monospace";
      ["src/", "  main.rs", "  tcp.rs", "  relay.rs", "  web.rs", "Cargo.toml"].forEach((f, i) => {
        g.fillStyle = i === 1 ? "#e3e6ea" : "#8b939e"; g.fillText(f, 24, 48 + i * 26);
      });
      lines.forEach((l, i) => {
        g.fillStyle = "#5f6873"; g.fillText(String(i + 1).padStart(3), 290, 48 + i * 18);
        g.fillStyle = /^\s*\/\//.test(l) ? "#8b939e" : /\b(fn|let|use|pub|mod|async|struct)\b/.test(l) ? "#9fd8ff" : "#e3e6ea";
        g.fillText(l.slice(0, 120), 330, 48 + i * 18);
      });
    };
    draw();
    setInterval(draw, 250);
    const stream = c.captureStream(15);
    navigator.mediaDevices.getDisplayMedia = async () => stream;
    return true; })()`);
  await tom.evaluate(click(".share-btn"));
  await waitFor(tom, `document.querySelector(".start-btn")`);
  await tom.evaluate(click(".start-btn"));
  await sleep(2500);

  // Mira, on the stage, watches it
  await mira.send("Page.bringToFront");
  await mira.resize(1280, 800);
  await waitFor(mira, `document.querySelector("[data-stage-tile] .live")`, 20_000);
  await mira.evaluate(`(() => { const b = [...document.querySelectorAll("[data-stage-tile] .live")][0]; b?.click(); return !!b; })()`);
  await waitFor(mira, `document.querySelector(".stream-stage")`, 20_000);
  await sleep(4000);
  await shoot(mira, `stage-${p}-share.png`);

  // The link card
  const card = await newTab({ width: 1200, height: 630, scale: 1 });
  await card.send("Page.navigate", { url: "file://" + join(ROOT, "tools", "og-card.html") });
  await sleep(1200);
  await shoot(card, "og.png");

  const pairs = [
    [`stage-${p}-desktop.png`, "stage.png"],
    [`stage-${p}-share.png`, "share.png"],
    [`stage-${p}-mixer.png`, "mixer.png"],
    [`modern-${p}-desktop.png`, "modern.png"],
    [`classic-${p}-desktop.png`, "classic.png"],
    [`modern-${p}-phone.png`, "phone.png"],
    [`stage-${p}-phone.png`, "phone-stage.png"],
    [`modern-${p}-settings.png`, "appearance.png"],
    ["modern-voipc-day-desktop.png", "day.png"],
    ["og.png", "og.png"],
  ];
  for (const [from, to] of pairs) {
    if (!existsSync(join(OUT, from))) { console.log(`website: ${from} missing`); continue; }
    copyFileSync(join(OUT, from), join(dir, to));
    // A WebP beside every PNG the page shows, at the widths its srcset asks
    // for: the PNGs are 2560 px and up to a quarter of a megabyte each.
    // README takes the PNGs. Classic is only ever a 320 px thumbnail.
    const base = to.replace(/\.png$/, "");
    const widths = {
      stage: [960, 1920], share: [960, 1920], mixer: [960, 1920], modern: [960, 1920],
      classic: [960], "phone-stage": [390, 780],
    }[base] ?? [];
    for (const w of widths) {
      execFileSync("magick", [join(dir, to), "-resize", `${w}x`, "-quality", "82", join(dir, `${base}-${w}.webp`)]);
    }
    console.log(`website: ${to}`);
  }
}

console.log(`done: ${OUT}`);
process.exit(0);
