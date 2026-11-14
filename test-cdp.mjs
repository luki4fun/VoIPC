// What every browser lane shares: a Chromium per device, a tab driven over the DevTools
// protocol, waits that say why they ran out, and a first page load.
//
// One copy, imported by test-ui, test-provider, test-community, test-moderation and
// test-move. Each lane had its own until 1.11.0-rc.2, and they drifted: the blank-first-load
// diagnosis reached two of the five, and CI run 42534244761 then failed in a third with a
// blank page and nothing in its log to say why.
//
// What a lane counts as a page error stays the lane's own choice (openTab's options): its
// checks are "no page error on X's side", and what that means must not change under it.

import { spawn } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const clock = () => new Date().toISOString().slice(11, 23);

/**
 * ServerMessage variants by their postcard index (crates/voipc-protocol/src/messages.rs,
 * declaration order): the ones the live path and its diagnosis are about. Any other shows as
 * its number. A variant added before these moves them: recount when the protocol changes.
 */
const FRAME_NAMES = {
  0: "Authenticated", 3: "UserJoined", 4: "UserLeft", 33: "EncryptedChannelChatMessage", 34: "SenderKeyReceived",
  46: "Account", 47: "PreKeysLow", 73: "TextJoined", 74: "KeysOwed", 75: "SessionAsked", 76: "SessionHello",
  77: "TextKeyReceived", 78: "KeyWanted", 79: "ChannelPage", 80: "ChannelMarks", 81: "Evicted", 82: "ChannelExits",
  83: "TextPost", 85: "MemberGone",
};

/**
 * Records every frame the page reads off its control stream: [time, variant index]. A stream
 * is taken for a control stream when its first chunk starts with one (a u32 length, then an
 * index below 128); any other is left alone. Over QUIC (WebTransport) only: a tunnel's
 * WebSocket is read another way.
 */
const FRAME_RECORDER = `(() => {
  window.__frames = [];
  const streams = new WeakMap();
  const read = ReadableStreamDefaultReader.prototype.read;
  ReadableStreamDefaultReader.prototype.read = function () {
    return read.call(this).then((r) => {
      try {
        const v = r.value;
        if (v instanceof Uint8Array && v.length > 0) {
          let st = streams.get(this);
          if (st === undefined) {
            const ok = v.length >= 5 && new DataView(v.buffer, v.byteOffset).getUint32(0) <= (1 << 22) && v[4] < 128;
            st = ok ? { buf: new Uint8Array(0) } : null;
            streams.set(this, st);
          }
          if (st) {
            const b = new Uint8Array(st.buf.length + v.length);
            b.set(st.buf);
            b.set(v, st.buf.length);
            let o = 0;
            while (b.length - o >= 5) {
              const len = new DataView(b.buffer, b.byteOffset + o).getUint32(0);
              if (len > (1 << 22)) { st = null; break; }
              if (b.length - o - 4 < len) break;
              window.__frames.push([Date.now(), b[o + 4]]);
              o += 4 + len;
            }
            if (st) st.buf = b.slice(o);
            streams.set(this, st);
            if (window.__frames.length > 6000) window.__frames.splice(0, 2000);
          }
        }
      } catch {}
      return r;
    });
  };
})()`;

/**
 * The frames a tab with `frames: true` read since its page loaded (or in the last `ms`):
 * counts by type, then the live path's own frames in order with how long ago, then what the
 * page last said on its console. Since the load, not a window: a wait of 90 s that runs out
 * starts after the post it waits for, and a 30 s window showed only keepalives (run
 * 42696335107). Empty when the tab records none.
 */
export async function frameSummary(tab, ms = null) {
  const since = ms === null ? 0 : `Date.now() - ${ms}`;
  // null, not none: a tab without the recorder must not read as one that heard nothing
  const got = await tab.evaluate(`window.__frames ? JSON.stringify(window.__frames.filter(([t]) => t >= ${since}).map(([t, i]) => [Date.now() - t, i])) : "null"`).then(JSON.parse, () => null);
  if (!got) return "";
  const name = (i) => FRAME_NAMES[i] ?? `#${i}`;
  const counts = {};
  for (const [, i] of got) counts[name(i)] = (counts[name(i)] ?? 0) + 1;
  const live = got.filter(([, i]) => i >= 73 && i <= 85).slice(-40).map(([ago, i]) => `${name(i)} -${(ago / 1000).toFixed(1)}s`);
  // A test build also logs, by name, what the session took in and what it sent since the
  // load (session.ts __voipc_heard, __voipc_said): whether it joined, answered an ask, wanted a key
  const tags = await tab
    .evaluate(`window.__voipc_heard ? JSON.stringify({ heard: window.__voipc_heard.map(([t]) => t), sent: window.__voipc_said.map((m) => typeof m === "string" ? m : Object.keys(m ?? {})[0]) }) : "null"`)
    .then(JSON.parse, () => null);
  const tally = (list) => {
    const n = {};
    for (const t of list) if (t !== "Ping" && t !== "Pong") n[t] = (n[t] ?? 0) + 1;
    return Object.entries(n).map(([k, c]) => `${k}×${c}`).join(", ") || "none";
  };
  const said = tab.net?.said ?? [];
  return `--- frames read ${ms === null ? "since the page loaded" : `in the last ${ms / 1000}s`} (${got.length}): ${Object.entries(counts).map(([k, n]) => `${k}×${n}`).join(", ") || "none"}`
    + (live.length ? `\n--- live path, oldest first: ${live.join(", ")}` : "")
    + (tags ? `\n--- the session took in: ${tally(tags.heard)}\n--- and sent: ${tally(tags.sent)}` : "")
    + (said.length ? `\n--- the page last said: ${said.join(" | ").slice(-2000)}` : "");
}

/**
 * Chromium on `cdpPort` with a profile of its own under `work`, up once its DevTools answer.
 * `args` go between the common flags and the profile. The process joins `children`, for the
 * lane's stop() to end.
 */
export async function startChromium({ chrome, work, cdpPort, children, args = [] }) {
  // Chromium's own output goes to a file (in KEEP_LOGS when set, which CI uploads), and a start
  // that fails says whether it exited and what it last said. Soak run 42831799186 had only
  // "did not come up": the output was thrown away, so nothing told a crash from a slow start.
  const logDir = process.env.KEEP_LOGS || work;
  mkdirSync(logDir, { recursive: true });
  const logPath = join(logDir, `chromium-${cdpPort}.log`);
  const fd = openSync(logPath, "w");
  const started = Date.now();
  const c = spawn(
    chrome,
    ["--headless=new", "--no-sandbox", "--ignore-certificate-errors", `--remote-debugging-port=${cdpPort}`,
     ...args, `--user-data-dir=${join(work, `profile-${cdpPort}`)}`, "about:blank"],
    { stdio: ["ignore", fd, fd] },
  );
  closeSync(fd);
  children.push(c);
  let exited = null;
  c.on("exit", (code, signal) => { exited = `it exited (code ${code}, signal ${signal})`; });
  c.on("error", (e) => { exited = `it did not start (${e.message})`; });
  for (let i = 0; i < 60 && !exited; i++) {
    if (await fetch(`http://127.0.0.1:${cdpPort}/json/version`).then((r) => r.ok, () => false)) {
      const took = Date.now() - started;
      if (took > 5000) console.log(`note: chromium on ${cdpPort} took ${(took / 1000).toFixed(1)} s to come up`);
      return c;
    }
    await sleep(250);
  }
  const state = exited ?? `it was still running after ${((Date.now() - started) / 1000).toFixed(1)} s`;
  const tail = readFileSync(logPath, "utf8").trim().split("\n").slice(-15).join("\n");
  throw new Error(`chromium on ${cdpPort} did not come up: ${state}. Its last lines (${logPath}):\n${tail || "(nothing)"}`);
}

/**
 * A new tab on the browser at `cdpPort`.
 *
 * Options, each what one lane already counted before the harness was shared:
 * - `console`: a console.error is a page error too (test-move, test-ui)
 * - `ownCodeOnly`: errors from scripts that are not http(s) do not count. Chrome's built-in
 *   component scripts run in the page and report into its console ("Attempting to use a
 *   disconnected port object" while a screen is shared) (test-ui)
 * - `detailed`: an error says where it was thrown, and a plain object rejected shows its
 *   fields rather than "Object" (test-ui)
 * - `dom`: DOM.enable
 * - `onNewDocument`: a script that runs in every document before the page's own
 * - `viewport`: { width, height }, 1280×900 by default
 *
 * Whatever the options, the tab follows its requests: which are open, which failed and why
 * (net::ERR_…), and what its last navigation answered. waitFor prints all of it when it runs
 * out, so a timeout names its own cause.
 */
export async function openTab(cdpPort, opts = {}) {
  const { console: consoleErrors = false, ownCodeOnly = false, detailed = false, dom = false, frames = false, onNewDocument, viewport } = opts;
  const res = await fetch(`http://127.0.0.1:${cdpPort}/json/new?about:blank`, { method: "PUT" });
  const target = await res.json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let id = 0;
  const pending = new Map();
  const errors = [];
  // In a plain object, so a lane's wrapper ({ ...tab }) still sees the live state
  // `said`: the page's last console warnings and errors, counted or not, for a report
  const net = { open: new Map(), failed: [], navigation: null, said: [] };
  // Chrome changes its certificate verifier once, soon after it starts, and a load still being
  // verified then fails with net::ERR_CERT_VERIFIER_CHANGED: no script or style, a blank page.
  // CI runs 43121449320, 43247162522 and 43582560287 failed so, each on a browser's first load,
  // 0.4 s after its start. Soak run 43620651318 lost a first load's chunks as net::ERR_FAILED,
  // 4 s in, with nothing at the relay. Neither is the app (the relay's failures are statuses,
  // resets and closes; Chrome's own cancels are ERR_ABORTED): the tab loads again, once, and
  // says so (test-web.sh counts it); what the broken load threw is not the page's error.
  // A file that failed for a reason of its own (a reset, a close, a timeout) is the relay's or the
  // link's: once one has, no ERR_FAILED alongside it loads the tab again either.
  const verifierFailed = new Set();
  let reloaded = false;
  let ownCause = false;
  const ownAsset = (url) => {
    try {
      return new URL(url).pathname.startsWith("/assets/");
    } catch {
      return false;
    }
  };
  const lostFile = (p, url) => {
    if (p.errorText === "net::ERR_CERT_VERIFIER_CHANGED") return !!url;
    if (p.canceled || p.blockedReason || p.corsErrorStatus || !ownAsset(url)) return false;
    if (p.errorText !== "net::ERR_FAILED") {
      ownCause = true;
      return false;
    }
    return !ownCause;
  };
  const byVerifier = (text) =>
    [...verifierFailed].some((url) => {
      try {
        return text.includes(new URL(url).pathname);
      } catch {
        return false;
      }
    });
  const foreign = (url) => ownCodeOnly && !!url && !/^https?:/.test(url);
  const where = (at) => (detailed && at ? ` @${at.url}:${at.lineNumber + 1}` : "");
  const preview = (o) =>
    detailed && o?.preview ? JSON.stringify(Object.fromEntries(o.preview.properties.map((x) => [x.name, x.value]))) : "";
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
      return;
    }
    const p = msg.params;
    if (msg.method === "Network.requestWillBeSent") {
      net.open.set(p.requestId, { url: p.request.url, at: Date.now() });
      // A page that never settles must not grow this without end: the oldest go
      if (net.open.size > 400) net.open.delete(net.open.keys().next().value);
    } else if (msg.method === "Network.loadingFinished") {
      net.open.delete(p.requestId);
    } else if (msg.method === "Network.loadingFailed") {
      const url = net.open.get(p.requestId)?.url ?? "";
      net.failed.push(`${clock()} ${p.errorText}${p.canceled ? " (canceled)" : ""}${p.blockedReason ? ` (blocked: ${p.blockedReason})` : ""} ${url}`);
      net.failed.splice(0, net.failed.length - 12);
      net.open.delete(p.requestId);
      if (lostFile(p, url)) {
        verifierFailed.add(url);
        if (!reloaded) {
          reloaded = true;
          console.log(`NOTE chrome lost a file of the page (${p.errorText} ${url}): the tab loads again`);
          send("Page.reload", { ignoreCache: true }).catch(() => {});
        }
      }
    } else if (msg.method === "Runtime.exceptionThrown") {
      // A rejection with a plain object describes itself as "Object": its
      // preview and where it was thrown are what make the report readable (detailed)
      const d = p.exceptionDetails;
      const at = d.stackTrace?.callFrames?.[0] ?? (d.url ? { url: d.url, lineNumber: d.lineNumber ?? 0 } : null);
      if (foreign(at?.url)) return;
      if (byVerifier(`${d.text ?? ""} ${d.exception?.description ?? ""}`)) return;
      // A file that did not load says why it did not, from the network's side
      const why = /dynamically imported module|preload CSS/.test(`${d.exception?.description}`)
        ? ` [failed loads: ${net.failed.join("; ")}]`
        : "";
      errors.push(`${`${d.text ?? ""} ${d.exception?.description ?? ""} ${preview(d.exception)}`.trim()}${where(at)}${why}`);
    }
    if (msg.method === "Runtime.consoleAPICalled" && (p.type === "error" || p.type === "warning")) {
      net.said.push(`${clock()} ${p.type}: ${p.args.map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 300)}`);
      net.said.splice(0, net.said.length - 16);
    }
    if (msg.method === "Runtime.consoleAPICalled" && p.type === "error" && consoleErrors) {
      const at = p.stackTrace?.callFrames?.[0];
      if (foreign(at?.url)) return;
      if (byVerifier(p.args.map((a) => a.value ?? a.description ?? "").join(" "))) return;
      // test-ui's lines never had the prefix, test-move's always did
      errors.push(`${detailed ? "" : "console: "}${p.args.map((a) => a.value ?? (preview(a) || a.description) ?? "").join(" ")}${where(at)}`);
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
        if (method === "Page.navigate") {
          net.navigation = { at: clock(), url: params.url, error: msg.result?.errorText ?? msg.error?.message ?? "" };
        }
        resolve(msg);
      });
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(`evaluate failed: ${JSON.stringify(r.result.exceptionDetails).slice(0, 300)}`);
    return r.result?.result?.value;
  };
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Page.enable");
  if (dom) await send("DOM.enable");
  if (frames) await send("Page.addScriptToEvaluateOnNewDocument", { source: FRAME_RECORDER });
  if (onNewDocument) await send("Page.addScriptToEvaluateOnNewDocument", { source: onNewDocument });
  await send("Emulation.setDeviceMetricsOverride", {
    width: viewport?.width ?? 1280, height: viewport?.height ?? 900, deviceScaleFactor: 1, mobile: false,
  });
  return {
    send, evaluate, errors, net, cdpPort, targetId: target.id,
    activate: () => fetch(`http://127.0.0.1:${cdpPort}/json/activate/${target.id}`),
  };
}

/**
 * What a tab is doing, for a wait that ran out: its text, its document, its last navigation,
 * its page errors since `since`, and its requests still open or failed.
 */
export async function diagnose(tab, since = 0) {
  const doc = await tab
    .evaluate(`JSON.stringify({ state: document.readyState, href: location.href, text: (document.body?.innerText ?? "").slice(0, 900) })`)
    .then((s) => JSON.parse(s), (e) => ({ text: "", state: `no answer (${e.message.slice(0, 120)})`, href: "?" }));
  const lines = [`--- page: ${doc.text.replace(/\s+/g, " ")}`, `--- document ${doc.state} at ${doc.href} (${clock()})`];
  const nav = tab.net?.navigation;
  if (nav) lines.push(`--- last navigation ${nav.at} to ${nav.url}${nav.error ? `: ${nav.error}` : ", answered"}`);
  const errs = tab.errors.slice(since);
  if (errs.length) lines.push(`--- page errors (${errs.length}): ${errs.slice(-4).join(" | ").slice(0, 1200)}`);
  if (tab.net) {
    const now = Date.now();
    // Over a second: what a page is waiting on, not what it just asked for
    const open = [...tab.net.open.values()].filter((r) => now - r.at > 1000);
    if (open.length) {
      lines.push(`--- requests open (${open.length}): ${open.slice(0, 8).map((r) => `${r.url} for ${((now - r.at) / 1000).toFixed(1)}s`).join("; ")}`);
    }
    if (tab.net.failed.length) lines.push(`--- requests failed: ${tab.net.failed.join("; ")}`);
  }
  const frames = await frameSummary(tab);
  if (frames) lines.push(frames);
  return lines.join("\n");
}

/**
 * A wait's time limit says "hung", never "slow". Every wait for something that has to happen
 * gets at least this, whatever a lane asks for, and ends the moment it is there: a green run
 * is no slower for it. A limit that was also a bet on the machine's speed (15 s, 25 s, the
 * relay tests' 5 s) failed a different check on most CI runs of a busy 4-vCPU runner.
 */
export const HANG_MS = 90_000;
/** A wait longer than this is said (SLOW), not failed: a real slowdown stays visible. */
const SLOW_MS = 10_000;

async function until(tab, expression, timeoutMs) {
  const t0 = Date.now();
  const started = clock();
  const deadline = t0 + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return Date.now() - t0;
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${expression} (from ${started}, ${timeoutMs / 1000}s)\n${await diagnose(tab)}`);
}

/** Waits for `expression` to be truthy in `tab`; past HANG_MS throws with diagnose(). */
export async function waitFor(tab, expression, timeoutMs = HANG_MS) {
  // A wait that runs out in a run that passes was caught somewhere: a probe in disguise,
  // costing HANG_MS each time. Said, so test-web.sh can count them (lane_verdict).
  const took = await until(tab, expression, Math.max(timeoutMs, HANG_MS)).catch((e) => {
    console.log(`TIMEOUT ${expression.replace(/\s+/g, " ").slice(0, 160)}`);
    throw e;
  });
  if (took > SLOW_MS) console.log(`SLOW ${(took / 1000).toFixed(1)}s waiting for ${expression.replace(/\s+/g, " ").slice(0, 160)}`);
  return true;
}

/** waitFor as a yes or no, for a check: what it saw is the check's to print. */
export const seen = (tab, expression, timeoutMs = HANG_MS) =>
  waitFor(tab, expression, timeoutMs).then(() => true, () => false);

/**
 * A short look for something that may well not come: an optional prompt, one go of a retry.
 * Its limit is kept as given, and its no is an answer, not a failure. Never for a check.
 */
export const probe = (tab, expression, timeoutMs) =>
  until(tab, expression, timeoutMs).then(() => true, () => false);

/**
 * `url` in `tab`, until `shown`. With `retry`, a first load that stays blank is logged as a
 * NOTE line, with its diagnosis, and tried once more; the lanes that have always done that
 * (move, moderation) keep it, the others fail with the diagnosis instead.
 */
/** An expression: this page has queued a frame of `kind` since `__voipc_said` was emptied
 *  (a variant name, or "#27" for a live post, which goes raw). */
export const sentKind = (kind) => `window.__voipc_said.some((m) => m && typeof m === "object" && ${JSON.stringify(kind)} in m)`;

/**
 * Rule 5's barrier: each tab in turn has the relay answer a Ping (the self-test build's
 * `__voipc_barrier`). After it, everything the earlier tabs sent has been handled, and what
 * the relay passed on from it is in the later tabs' queues and recorded (`__voipc_heard`).
 * Only for what an app sends as part of a step: a send behind an app's own timer is not
 * covered. False: a tab had no session there.
 */
export async function barrier(server, ...tabs) {
  for (const tab of tabs) {
    const ok = await Promise.race([
      tab.evaluate(`window.__voipc_barrier(${JSON.stringify(server)})`),
      sleep(HANG_MS).then(() => false),
    ]);
    if (!ok) return false;
  }
  return true;
}

export async function loadPage(tab, url, shown, { retry = false, timeoutMs = 25_000 } = {}) {
  const before = tab.errors.length;
  await tab.send("Page.navigate", { url });
  if (!retry) return waitFor(tab, shown, timeoutMs);
  // The first go is a probe: a blank page past this is tried again, not waited out
  if (await probe(tab, shown, timeoutMs)) return true;
  // What the blank page said goes to the log, not to the page's own error checks
  const why = await diagnose(tab, before);
  tab.errors.splice(before);
  console.log(`NOTE a first page load stayed blank and is tried again\n${why}`);
  await tab.send("Page.navigate", { url });
  return waitFor(tab, shown);
}
