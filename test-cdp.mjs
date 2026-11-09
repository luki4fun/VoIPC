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
import { join } from "node:path";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const clock = () => new Date().toISOString().slice(11, 23);

/**
 * Chromium on `cdpPort` with a profile of its own under `work`, up once its DevTools answer.
 * `args` go between the common flags and the profile. The process joins `children`, for the
 * lane's stop() to end.
 */
export async function startChromium({ chrome, work, cdpPort, children, args = [] }) {
  const c = spawn(
    chrome,
    ["--headless=new", "--no-sandbox", "--ignore-certificate-errors", `--remote-debugging-port=${cdpPort}`,
     ...args, `--user-data-dir=${join(work, `profile-${cdpPort}`)}`, "about:blank"],
    { stdio: "ignore" },
  );
  children.push(c);
  for (let i = 0; i < 60; i++) {
    if (await fetch(`http://127.0.0.1:${cdpPort}/json/version`).then((r) => r.ok, () => false)) return c;
    await sleep(250);
  }
  throw new Error(`chromium on ${cdpPort} did not come up`);
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
  const { console: consoleErrors = false, ownCodeOnly = false, detailed = false, dom = false, onNewDocument, viewport } = opts;
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
  const net = { open: new Map(), failed: [], navigation: null };
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
    } else if (msg.method === "Runtime.exceptionThrown") {
      // A rejection with a plain object describes itself as "Object": its
      // preview and where it was thrown are what make the report readable (detailed)
      const d = p.exceptionDetails;
      const at = d.stackTrace?.callFrames?.[0] ?? (d.url ? { url: d.url, lineNumber: d.lineNumber ?? 0 } : null);
      if (foreign(at?.url)) return;
      // A file that did not load says why it did not, from the network's side
      const why = /dynamically imported module|preload CSS/.test(`${d.exception?.description}`)
        ? ` [failed loads: ${net.failed.join("; ")}]`
        : "";
      errors.push(`${`${d.text ?? ""} ${d.exception?.description ?? ""} ${preview(d.exception)}`.trim()}${where(at)}${why}`);
    } else if (msg.method === "Runtime.consoleAPICalled" && p.type === "error" && consoleErrors) {
      const at = p.stackTrace?.callFrames?.[0];
      if (foreign(at?.url)) return;
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
  return lines.join("\n");
}

/** Waits for `expression` to be truthy in `tab`; on running out, throws with diagnose(). */
export async function waitFor(tab, expression, timeoutMs = 25_000) {
  const started = clock();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await tab.evaluate(`!!(${expression})`)) return true;
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${expression} (from ${started}, ${timeoutMs / 1000}s)\n${await diagnose(tab)}`);
}

/** waitFor as a yes or no, for a check: what it saw is the check's to print. */
export const seen = (tab, expression, timeoutMs = 15_000) =>
  waitFor(tab, expression, timeoutMs).then(() => true, () => false);

/**
 * `url` in `tab`, until `shown`. With `retry`, a first load that stays blank is logged as a
 * NOTE line, with its diagnosis, and tried once more; the lanes that have always done that
 * (move, moderation) keep it, the others fail with the diagnosis instead.
 */
export async function loadPage(tab, url, shown, { retry = false, timeoutMs = 25_000 } = {}) {
  const before = tab.errors.length;
  await tab.send("Page.navigate", { url });
  if (!retry) return waitFor(tab, shown, timeoutMs);
  if (await seen(tab, shown, timeoutMs)) return true;
  // What the blank page said goes to the log, not to the page's own error checks
  const why = await diagnose(tab, before);
  tab.errors.splice(before);
  console.log(`NOTE a first page load stayed blank and is tried again\n${why}`);
  await tab.send("Page.navigate", { url });
  return waitFor(tab, shown, 60_000);
}
