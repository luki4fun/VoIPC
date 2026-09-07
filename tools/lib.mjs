// Shared helpers for the VoIPC build tasks.
//
// Everything here used to be copy-pasted across the root shell and PowerShell
// scripts — the version sync alone existed in seven places in two languages.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repo root, derived from this file's location — never from cwd, because
 *  Tauri invokes the bundle-libs task with cwd set to client/. */
export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const CLIENT = join(ROOT, 'client');
export const IS_WINDOWS = process.platform === 'win32';

const C = {
  green: '\x1b[0;32m',
  yellow: '\x1b[1;33m',
  red: '\x1b[0;31m',
  cyan: '\x1b[0;36m',
  off: '\x1b[0m',
};

export const ok = (...m) => console.log(`${C.green}[ok]${C.off}`, ...m);
export const info = (...m) => console.log(`${C.yellow}[..]${C.off}`, ...m);
export const err = (...m) => console.error(`${C.red}[!!]${C.off}`, ...m);
export const head = (m) => console.log(`\n${C.cyan}=== ${m} ===${C.off}`);

/** Abort the task with a message. */
export class TaskError extends Error {}
export const fail = (...m) => {
  throw new TaskError(m.join(' '));
};

/**
 * Merge overrides into the current environment. A key set to undefined or null
 * is *removed*, which is how the cross build clears host variables that would
 * otherwise poison it.
 */
function mergeEnv(overrides = {}) {
  const env = { ...process.env };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined || v === null) delete env[k];
    else env[k] = String(v);
  }
  return env;
}

/**
 * Run a command, inheriting stdio. Throws if it exits non-zero.
 * npm/npx are batch files on Windows and need a shell there.
 */
export function run(cmd, args = [], opts = {}) {
  const needsShell = IS_WINDOWS && /^(npm|npx|rustup|cargo|choco)$/.test(cmd);
  const res = spawnSync(cmd, args, {
    stdio: opts.stdio ?? 'inherit',
    cwd: opts.cwd ?? ROOT,
    env: mergeEnv(opts.env),
    shell: opts.shell ?? needsShell,
  });
  if (res.error) fail(`failed to start ${cmd}: ${res.error.message}`);
  if (res.status !== 0) {
    if (opts.allowFailure) return res.status ?? 1;
    fail(`${cmd} ${args.join(' ')} exited with ${res.status ?? 'a signal'}`);
  }
  return 0;
}

/** Run a command and capture stdout. Returns '' on failure. */
export function capture(cmd, args = [], opts = {}) {
  const needsShell = IS_WINDOWS && /^(npm|npx|rustup|cargo)$/.test(cmd);
  const res = spawnSync(cmd, args, {
    cwd: opts.cwd ?? ROOT,
    env: mergeEnv(opts.env),
    encoding: 'utf8',
    shell: opts.shell ?? needsShell,
  });
  if (res.status !== 0) return '';
  return (res.stdout ?? '').trim();
}

/** Absolute path of an executable on PATH, or null. */
export function which(tool) {
  const probe = IS_WINDOWS ? 'where' : 'which';
  const res = spawnSync(probe, [tool], { encoding: 'utf8', shell: IS_WINDOWS });
  if (res.status !== 0) return null;
  const first = (res.stdout ?? '').split(/\r?\n/).find(Boolean);
  return first ? first.trim() : null;
}

/**
 * Verify every tool is present, reporting all misses at once rather than
 * failing on the first. `hints` maps a missing set to install instructions.
 */
export function requireTools(tools, hints = []) {
  const missing = tools.filter((t) => !which(t));
  if (missing.length === 0) return;
  err(`missing required tools: ${missing.join(', ')}`);
  for (const hint of hints) console.error(`     ${hint}`);
  fail('install the tools above and retry');
}

/** The single source of truth: [workspace.package] version in the root Cargo.toml. */
export function workspaceVersion() {
  const toml = readFileSync(join(ROOT, 'Cargo.toml'), 'utf8');
  const m = toml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!m) fail('could not read [workspace.package] version from Cargo.toml');
  return m[1];
}

// Files carrying a copy of the version, and how to find it in each.
// The server compares client and server version strings for exact equality
// (crates/voipc-server/src/tcp.rs), so a stale copy here ships a client that
// every server rejects.
const VERSION_SITES = [
  {
    file: join(CLIENT, 'src-tauri', 'tauri.conf.json'),
    // Only the first "version" key — the file has just one, but be explicit.
    re: /"version":\s*"[^"]*"/,
    make: (v) => `"version": "${v}"`,
  },
  {
    file: join(CLIENT, 'package.json'),
    re: /"version":\s*"[^"]*"/,
    make: (v) => `"version": "${v}"`,
  },
  {
    // The download blurb on the website; nothing else syncs it.
    file: join(ROOT, 'website', 'index.html'),
    re: /(<a href="[^"]*CHANGELOG\.md">)v\d+\.\d+\.\d+(<\/a>)/,
    make: (v) => `$1v${v}$2`,
    optional: true,
  },
];

/**
 * Propagate the workspace version into every file that repeats it.
 * With { check: true } nothing is written and a mismatch is an error — that is
 * what CI uses, so a release build never silently rewrites tracked files.
 */
export function syncVersion({ check = false, quiet = false } = {}) {
  const version = workspaceVersion();
  const stale = [];

  for (const site of VERSION_SITES) {
    if (!existsSync(site.file)) {
      if (site.optional) continue;
      fail(`version file missing: ${site.file}`);
    }
    const before = readFileSync(site.file, 'utf8');
    if (!site.re.test(before)) {
      if (site.optional) continue;
      fail(`no version field found in ${site.file}`);
    }
    const after = before.replace(site.re, site.make(version));
    if (after === before) continue;

    const rel = site.file.slice(ROOT.length + 1);
    if (check) {
      stale.push(rel);
    } else {
      writeFileSync(site.file, after);
      if (!quiet) info(`version ${version} → ${rel}`);
    }
  }

  if (check && stale.length) {
    err(`these files disagree with Cargo.toml (${version}): ${stale.join(', ')}`);
    fail('run `npm run version` and commit the result');
  }
  return version;
}

/** Install the client's npm dependencies if they are missing. */
export function npmInstall() {
  if (existsSync(join(CLIENT, 'node_modules'))) return;
  info('installing npm dependencies...');
  run('npm', ['install'], { cwd: CLIENT });
}

/** Add a rustup target unless it is already installed. */
export function ensureRustTarget(target) {
  const installed = capture('rustup', ['target', 'list', '--installed']);
  if (installed.split(/\r?\n/).includes(target)) return;
  info(`adding Rust target ${target}...`);
  run('rustup', ['target', 'add', target]);
}

/** Put ~/.cargo/bin on PATH for this process, as every script used to do. */
export function addCargoBinToPath() {
  const home = process.env.HOME || process.env.USERPROFILE;
  if (!home) return;
  const cargoBin = join(home, '.cargo', 'bin');
  const sep = IS_WINDOWS ? ';' : ':';
  if (!(process.env.PATH ?? '').split(sep).includes(cargoBin)) {
    process.env.PATH = `${cargoBin}${sep}${process.env.PATH ?? ''}`;
  }
}
