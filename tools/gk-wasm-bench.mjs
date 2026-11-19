// What a keyholder's builds cost in the browser (plan part 6, slice L1b): the real voipc-web
// module's bench steps (crates/voipc-web/src/gk_bench.rs, `gkBench`) in headless Chromium
// (driven over the DevTools protocol, test-cdp.mjs), headless Firefox (its console on
// stdout, as test-web.sh reads it) or Node. Each step is a due the keyholder duty builds
// and a relay in the page checks and takes: Joins that grow a stored text group to each size,
// then at that size Joins of 256, exits openings, refreshes and seed-welcome pages, and the
// exits opening and refresh again built cold (no row bases: a keyholder new to the group, or
// a browser back after a reload); a memory group's first (cold) and second exits openings at
// 10k; Joins into a voice room, its exits openings, and a keyholder's Add and leave (Remove)
// at 250; and the primitives (X25519, Kyber1024, a seat welcome) timed in batches.
//
//   node tools/gk-wasm-bench.mjs build --opt s|3 --into DIR [--plain]
//       cargo + wasm-bindgen for crates/voipc-web, as tools/tasks/wasm.mjs builds it, with
//       VOIPC_GK_BENCH=1 (not with --plain: the production module) and, with --opt 3,
//       libcrux at opt-level 3 (open choice 28) through `--config`, Cargo.toml untouched.
//       CARGO_TARGET_DIR is honoured. Run it under the heavy-job lock like any build.
//   node tools/gk-wasm-bench.mjs sizes DIR...
//       Each module's bytes raw, gzip -9 and brotli q11.
//   node tools/gk-wasm-bench.mjs run --pkg DIR [--engines chromium,firefox,node]
//       [--max 100000] [--budget 2] [--label s] [--out FILE] [--work DIR]
//       The bench. --max is the largest text group (10k and 20k on the way below it), --budget the
//       step budget in ms (session.ts GK_STEP_CALL_MS). Every result line goes to --out
//       (JSON lines), a summary to stdout. CHROME= and FIREFOX= pick the browsers.
//   node tools/gk-wasm-bench.mjs summary FILE...
//       The summary again, from result lines.
//
// Waits: a wait ends when the page says its next result, and only a page that says nothing
// for HANG_MS is hung; a slow step is never a failure.

import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { brotliCompressSync, constants as zc, gzipSync } from "node:zlib";
import { HANG_MS, openTab, startChromium, waitFor } from "../test-cdp.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [cmd, ...rest] = process.argv.slice(2);
const flag = (name) => rest.includes(`--${name}`);
const opt = (name, fallback) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 && i + 1 < rest.length ? rest[i + 1] : fallback;
};
const die = (m) => {
  console.error(`gk-wasm-bench: ${m}`);
  process.exit(1);
};

/** The libcrux packages choice 28 builds at opt-level 3. */
const LIBCRUX = ["libcrux-ml-kem", "libcrux-sha3", "libcrux-intrinsics", "libcrux-secrets"];
const SIZES = [10_000, 20_000, 100_000];

// ── The plan: runs in the page (its source is put there) and in Node ─────────

async function plan(gkBench, emit, o) {
  const call = (op, arg = 0) => JSON.parse(gkBench(op, arg, o.budget));
  const step = async (phase, op, arg) => {
    const r = call(op, arg);
    emit({ phase, ...r });
    await o.yieldNow();
    return r;
  };
  emit({ phase: "env", ...o.env });
  await step("prim", "prim", o.prims);
  // A voice room: one at a time to 4, in 25s to 250, then one more at 250 (plan C5)
  let r = await step("voice", "voice", 1);
  while (r.seats_after < 4) r = await step("voice", "voice", 1);
  while (r.seats_after < 250) r = await step("voice", "voice", Math.min(25, 250 - r.seats_after));
  for (let i = 0; i < 3; i++) r = await step("voice-at", "voice", 1);
  // Leaves at 250: an opening for one, and for a 2 s batch of 25; back to 250
  for (const n of [1, 25]) r = await step("voice-at", "vexits", n);
  r = await step("voice-back", "voice", 250 - r.seats_after);
  // A keyholder leaves: the second keyholder's Add, then its Remove, which rolls the seed
  // (plan C5) and welcomes in its commit every seat the last roll left behind. No seed
  // pages run here, so a Remove finds none behind, the next one every seat; warm, then cold
  for (const op of ["vremove", "cvremove"]) {
    for (const phase of ["voice-rm", "voice-rm-behind"]) {
      await step(phase, "vpromote", 0);
      await step(phase, op, 0);
    }
  }
  // A memory-only text group of guests to the browser's limit: its Joins make no rows, so
  // its first opening makes every row base anew (a cold re-key), the next one mostly not
  const m = Math.min(10_000, o.sizes.at(-1));
  let mseats = 0;
  while (mseats < m) mseats = (await step(`mgrow-${m}`, "mjoin", Math.min(256, m - mseats))).seats_after;
  for (let i = 0; i < 2; i++) await step(`mat-${m}`, "mexits", 720);
  // The text group, grown by Joins of 256, then each due at each size
  let seats = 0;
  for (const size of o.sizes) {
    while (seats < size) seats = (await step(`grow-${size}`, "join", Math.min(256, size - seats))).seats_after;
    for (let i = 0; i < 3; i++) seats = (await step(`at-${size}`, "join", 256)).seats_after;
    for (const n of [1, 100, 720]) seats = (await step(`at-${size}`, "exits", n)).seats_after;
    for (let i = 0; i < 2; i++) await step(`at-${size}`, "refresh", 0);
    for (let i = 0; i < 2; i++) await step(`at-${size}`, "seed", 256);
    // The same dues by a keyholder holding no row bases (a refresh first: an opening of 720
    // exits re-keys most buckets, and leaves a refresh little to do)
    await step(`at-${size}`, "crefresh", 0);
    seats = (await step(`at-${size}`, "cexits", 720)).seats_after;
  }
}

/** The page's clock: its smallest step, in µs (Firefox and Chrome coarsen it). */
function timerUs() {
  let min = Infinity;
  for (let i = 0; i < 50; i++) {
    const a = performance.now();
    let b = a;
    while (b === a) b = performance.now();
    min = Math.min(min, b - a);
  }
  return Math.round(min * 1000 * 100) / 100;
}

const PAGE = (opts) => `<!doctype html>
<meta charset="utf-8"><title>gk wasm bench</title>
<script type="module">
import init, { gkBench } from "./pkg/voipc_web.js";
const lines = [];
window.__gkbench = { n: 0, lines, done: false, error: null };
const emit = (o) => {
  lines.push(o);
  window.__gkbench.n = lines.length;
  console.log("GKBENCH " + encodeURIComponent(JSON.stringify(o)));
};
// A yield no timer clamps (a background tab's setTimeout can wait a second)
const ch = new MessageChannel();
let wake = () => {};
ch.port1.onmessage = () => wake();
const yieldNow = () => new Promise((r) => { wake = r; ch.port2.postMessage(0); });
${timerUs.toString()}
${plan.toString()}
try {
  await init();
  const env = { browser: navigator.userAgent, isolated: self.crossOriginIsolated, timer_us: timerUs() };
  await plan(gkBench, emit, { ...${JSON.stringify(opts)}, env, yieldNow });
  window.__gkbench.done = true;
  console.log("GKBENCH-DONE");
} catch (e) {
  window.__gkbench.error = String(e?.stack ?? e);
  console.log("GKBENCH-ERROR " + encodeURIComponent(String(e?.stack ?? e)));
}
</script>`;

// ── Serving the page ─────────────────────────────────────────────────────────

const TYPES = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html" };

/** The page and the module, cross-origin isolated so both engines give their finest clock. */
function serve(pkg, opts) {
  const server = createServer((req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    const headers = {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cache-Control": "no-store",
    };
    let body;
    if (path === "/") {
      body = PAGE(opts);
      headers["Content-Type"] = TYPES[".html"];
    } else if (/^\/pkg\/[\w.-]+$/.test(path) && existsSync(join(pkg, path.slice(5)))) {
      body = readFileSync(join(pkg, path.slice(5)));
      headers["Content-Type"] = TYPES[extname(path)] ?? "application/octet-stream";
    } else {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, headers).end(body);
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

// ── Engines ──────────────────────────────────────────────────────────────────

async function inNode(pkg, opts, emit) {
  const mod = await import(pathToFileURL(join(pkg, "voipc_web.js")).href);
  mod.initSync({ module: readFileSync(join(pkg, "voipc_web_bg.wasm")) });
  const env = { browser: `node ${process.version}`, isolated: null, timer_us: timerUs() };
  await plan(mod.gkBench, emit, { ...opts, env, yieldNow: () => new Promise((r) => setImmediate(r)) });
}

async function inChromium(url, work, emit) {
  const chrome = process.env.CHROME || "chromium";
  const children = [];
  const cdpPort = 9400 + (process.pid % 500);
  try {
    await startChromium({
      chrome, work, cdpPort, children,
      args: ["--disable-background-timer-throttling", "--disable-renderer-backgrounding"],
    });
    const tab = await openTab(cdpPort);
    await tab.send("Page.navigate", { url });
    let seen = 0;
    for (;;) {
      // Until the page says its next line: a page silent for HANG_MS is hung
      await waitFor(tab, `window.__gkbench && (window.__gkbench.done || window.__gkbench.error || window.__gkbench.n > ${seen})`, HANG_MS);
      const s = await tab.evaluate(`JSON.stringify({ lines: window.__gkbench.lines.slice(${seen}), done: window.__gkbench.done, error: window.__gkbench.error })`);
      const got = JSON.parse(s);
      for (const l of got.lines) emit(l);
      seen += got.lines.length;
      if (got.error) throw new Error(`the page failed: ${got.error}`);
      if (got.done) return;
    }
  } finally {
    for (const c of children) c.kill("SIGTERM");
  }
}

async function inFirefox(url, work, emit) {
  const firefox = process.env.FIREFOX || "firefox";
  const profile = join(work, "profile-firefox");
  rmSync(profile, { recursive: true, force: true });
  mkdirSync(profile, { recursive: true });
  // Its console on stdout (test-web.sh), and its clock unclamped: with `reduceTimerPrecision`
  // alone off, Firefox 159 still steps 20 µs; with `.unconditional` off too, under 0.1 µs.
  // The env line says the step it got; the primitives are timed in batches either way
  writeFileSync(join(profile, "user.js"), [
    'user_pref("devtools.console.stdout.content", true);',
    'user_pref("privacy.reduceTimerPrecision", false);',
    'user_pref("privacy.reduceTimerPrecision.unconditional", false);',
    'user_pref("dom.max_script_run_time", 0);',
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    "",
  ].join("\n"));
  const ff = spawn(firefox, ["-headless", "-no-remote", "-profile", profile, url], { stdio: ["ignore", "pipe", "pipe"] });
  let exited = null;
  ff.on("exit", (code, signal) => { exited = `firefox exited (code ${code}, signal ${signal})`; });
  let buf = "";
  let last = Date.now();
  let state = null;
  const tail = [];
  const take = (chunk) => {
    buf += chunk;
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      tail.push(line);
      if (tail.length > 20) tail.shift();
      let m = line.match(/GKBENCH (\S+)/);
      if (m) {
        emit(JSON.parse(decodeURIComponent(m[1].replace(/["',]+$/, ""))));
        last = Date.now();
      } else if ((m = line.match(/GKBENCH-ERROR (\S+)/))) {
        state = { error: decodeURIComponent(m[1].replace(/["',]+$/, "")) };
      } else if (line.includes("GKBENCH-DONE")) {
        state = { done: true };
      }
    }
  };
  ff.stdout.on("data", (d) => take(String(d)));
  ff.stderr.on("data", (d) => take(String(d)));
  try {
    await new Promise((ok, fail) => {
      const look = setInterval(() => {
        if (state || exited || Date.now() - last > HANG_MS) {
          clearInterval(look);
          if (state?.done) ok();
          else fail(new Error(state?.error ?? exited ?? `no result for ${HANG_MS / 1000} s: hung. Its last lines:\n${tail.join("\n")}`));
        }
      }, 250);
    });
  } finally {
    ff.kill("SIGTERM");
  }
}

// ── Summary ──────────────────────────────────────────────────────────────────

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)] : NaN;
};
const f = (x, d = 1) => (Number.isFinite(x) ? x.toFixed(d) : "–");

function summary(lines, label) {
  const out = [];
  const env = lines.find((l) => l.phase === "env");
  const prim = lines.find((l) => l.phase === "prim");
  if (env) out.push(`${label}: ${env.browser}, isolated ${env.isolated}, clock step ${env.timer_us} µs`);
  if (prim) {
    out.push(`  prim (per call, median of ${prim.n} batches): X25519 ${prim.x25519_us} µs, Kyber1024 encaps ${prim.kyber_encaps_us} / decaps ${prim.kyber_decaps_us} µs, seat welcome ${prim.seat_welcome_us} µs`);
  }
  out.push("  | what | n | at seats | build ms | steps | longest step ms | duty's frames ms (longest) | built ms | uploads ms (longest) | header taken ms | page ms in all | validator ms | rows | seed welcomes | KB |");
  out.push("  |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
  const groups = new Map();
  for (const l of lines) {
    if (!l.op || l.phase === "prim" || l.phase === "env") continue;
    const grow = l.phase.match(/^m?grow-(\d+)$/);
    const room = { "voice-at": " at 250", "voice-rm": " at 250", "voice-rm-behind": " at 250, every seat behind" }[l.phase] ?? "";
    const key = grow ? `grow ${l.op} ${l.n} to ${grow[1]}` : `${l.op} ${l.n}${room}`;
    const at = Number(l.phase.match(/^m?at-(\d+)$/)?.[1]) || null;
    const k = `${key}|${at ?? ""}`;
    if (!groups.has(k)) groups.set(k, { key, at, phase: l.phase, ls: [] });
    groups.get(k).ls.push(l);
  }
  for (const { key, at, ls } of groups.values()) {
    const m = (name) => median(ls.map((l) => l[name] ?? NaN));
    const max = (name) => Math.max(...ls.map((l) => l[name] ?? 0));
    const seats = at ?? `${ls[0].seats_before}–${ls.at(-1).seats_after}`;
    out.push(`  | ${key} (×${ls.length}) | ${ls[0].n} | ${seats} | ${f(m("build_ms"))} | ${max("steps")} | ${f(max("step_max_ms"))} | ${f(m("lock_ms"))} (${f(max("lock_max_ms"))}) | ${f(m("built_ms"))} | ${f(m("upload_ms"))} (${f(max("upload_max_ms"))}) | ${f(m("take_ms"))} | ${f(m("page_ms"))} | ${f(m("check_ms"))} | ${f(m("rows"), 0)} | ${f(m("seed_welcomes"), 0)} | ${f(m("bytes") / 1000, 0)} |`);
  }
  // Cold against warm: a cold build that is not well above the warm one kept its row bases
  for (const [cold, warm] of [["cexits", "exits"], ["crefresh", "refresh"], ["cvremove", "vremove"]]) {
    for (const g of groups.values()) {
      const c = g.ls[0];
      if (c.op !== cold) continue;
      const w = [...groups.values()].find((x) => x.at === g.at && x.phase === g.phase && x.ls[0].op === warm && x.ls[0].n === c.n);
      if (!w) continue;
      // Per row, less the seed welcomes' share (a seat welcome each, `prim`)
      const welcome = (prim?.seat_welcome_us ?? 0) / 1000;
      const per = (ls) => median(ls.map((l) => (l.build_ms - (l.seed_welcomes ?? 0) * welcome) / Math.max(1, l.rows)));
      const ratio = per(g.ls) / per(w.ls);
      // A seat welcomed to a new seed is rowed under it, which no keyholder holds bases for
      const fresh = median(w.ls.map((l) => (l.seed_welcomes ?? 0) / Math.max(1, l.rows))) >= 0.5;
      const verdict = fresh ? " (its rows are under the new seed: cold either way)" : ratio < 2 ? " NOT COLD: the build kept its row bases" : "";
      out.push(`  ${cold} ${c.n} at ${g.at ?? g.phase}: ${f(per(g.ls) * 1000, 1)} µs a row cold, ${f(per(w.ls) * 1000, 1)} warm (${f(ratio, 1)}×)${verdict}`);
    }
  }
  return out.join("\n");
}

// ── Commands ─────────────────────────────────────────────────────────────────

if (cmd === "build") {
  const level = opt("opt", "s");
  const into = resolve(opt("into", "") || die("--into DIR"));
  if (!["s", "3"].includes(level)) die("--opt s or 3");
  const crate = join(ROOT, "crates", "voipc-web");
  const config = level === "3" ? LIBCRUX.flatMap((p) => ["--config", `profile.release.package.${p}.opt-level=3`]) : [];
  const env = { ...process.env };
  if (flag("plain")) delete env.VOIPC_GK_BENCH;
  else env.VOIPC_GK_BENCH = "1";
  const cargo = spawnSync("cargo", ["build", "--release", "--locked", "--target", "wasm32-unknown-unknown", ...config], { cwd: crate, env, stdio: "inherit" });
  if (cargo.status !== 0) die("cargo build failed");
  const target = resolve(crate, process.env.CARGO_TARGET_DIR || "target");
  const bg = spawnSync("wasm-bindgen", ["--target", "web", "--out-dir", into, "--out-name", "voipc_web",
    join(target, "wasm32-unknown-unknown", "release", "voipc_web.wasm")], { stdio: "inherit" });
  if (bg.status !== 0) die("wasm-bindgen failed");
  console.log(`built ${into} (opt-level ${level} for libcrux, ${flag("plain") ? "no bench" : "with the bench"})`);
} else if (cmd === "sizes") {
  if (!rest.length) die("sizes DIR...");
  console.log("| module | bytes | gzip -9 | brotli q11 |\n|---|---:|---:|---:|");
  for (const dir of rest) {
    const wasm = readFileSync(join(dir, "voipc_web_bg.wasm"));
    const gz = gzipSync(wasm, { level: 9 }).length;
    const br = brotliCompressSync(wasm, { params: { [zc.BROTLI_PARAM_QUALITY]: 11, [zc.BROTLI_PARAM_SIZE_HINT]: wasm.length } }).length;
    console.log(`| ${dir} | ${wasm.length} | ${gz} | ${br} |`);
  }
} else if (cmd === "run") {
  const pkg = resolve(opt("pkg", "") || die("--pkg DIR (a wasm-bindgen --target web build of voipc-web)"));
  if (!existsSync(join(pkg, "voipc_web_bg.wasm"))) die(`no voipc_web_bg.wasm in ${pkg}`);
  const max = Number(opt("max", "100000"));
  const label = opt("label", "s");
  const opts = { budget: Number(opt("budget", "2")), prims: 200, sizes: [...SIZES.filter((s) => s < max), max] };
  const work = resolve(opt("work", join(ROOT, "target", "gk-wasm-bench")));
  mkdirSync(work, { recursive: true });
  const outFile = opt("out", join(work, `results-${label}.jsonl`));
  const engines = opt("engines", "chromium,firefox").split(",");
  const server = await serve(pkg, opts);
  const url = `http://127.0.0.1:${server.address().port}/`;
  const summaries = [];
  let failed = false;
  for (const engine of engines) {
    const lines = [];
    const t0 = Date.now();
    const emit = (l) => {
      lines.push(l);
      appendFileSync(outFile, `${JSON.stringify({ engine, label, ...l })}\n`);
      if (l.phase !== "env" && !(/grow-/.test(l.phase) && l.seats_after % 5120 > 256)) {
        console.log(`${engine} ${l.phase} ${l.op ?? ""} ${l.n ?? ""}: ${l.seats_after ?? ""} seats, build ${l.build_ms ?? ""} ms`);
      }
    };
    try {
      if (engine === "node") await inNode(pkg, opts, emit);
      else if (engine === "chromium") await inChromium(url, work, emit);
      else if (engine === "firefox") await inFirefox(url, work, emit);
      else throw new Error(`no engine ${engine}`);
      console.log(`${engine}: done in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
    } catch (e) {
      failed = true;
      console.log(`FAIL ${engine}: ${e.message}`);
    }
    summaries.push(summary(lines, `${engine} (${label}, ${statSync(join(pkg, "voipc_web_bg.wasm")).size} B module)`));
  }
  server.close();
  console.log(`\n${summaries.join("\n\n")}\n\nresult lines: ${outFile}`);
  process.exit(failed ? 1 : 0);
} else if (cmd === "summary") {
  if (!rest.length) die("summary FILE...");
  const runs = new Map();
  for (const file of rest) {
    for (const line of readFileSync(file, "utf8").split("\n").filter(Boolean)) {
      const l = JSON.parse(line);
      const k = `${l.engine} (${l.label})`;
      if (!runs.has(k)) runs.set(k, []);
      runs.get(k).push(l);
    }
  }
  console.log([...runs].map(([k, ls]) => summary(ls, k)).join("\n\n"));
} else {
  die("build | sizes | run | summary (see the head of this file)");
}
