// THIRD-PARTY-NOTICES.txt: what VoIPC is built from, under which licence, with
// the texts those licences ask a binary to carry.
//
// Written to client/public/, which Vite copies into every front-end bundle:
// client/dist (the desktop and Android apps embed it) and client/dist-web (the
// browser client, which the relay embeds and serves, and the web tarball). So
// every build carries it at /THIRD-PARTY-NOTICES.txt beside index.html, and
// the About panel can fetch it from there.
//
// No tool of its own: `cargo metadata` for the crates (the shipping roots and
// their normal dependencies, for the platforms VoIPC ships on) and the npm
// lockfile for the front end, with the licence files read from where cargo and
// npm put the packages. The output is sorted and carries no date or path, so
// a rebuild of the same lockfiles writes the same bytes (the nightly `repro`
// job compares two web builds).
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, sep } from 'node:path';
import { CLIENT, IS_WINDOWS, ROOT, fail, ok, workspaceVersion } from '../lib.mjs';

export const NOTICES = join(CLIENT, 'public', 'THIRD-PARTY-NOTICES.txt');

/** The workspaces whose code ships, the crates at their roots, and the
 *  platforms each is built for. */
const WORKSPACES = [
  {
    dir: ROOT,
    roots: ['voipc-client', 'voipc-server'],
    platforms: ['x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl', 'x86_64-pc-windows-msvc', 'aarch64-linux-android'],
  },
  { dir: join(ROOT, 'crates', 'voipc-web'), roots: ['voipc-web'], platforms: ['wasm32-unknown-unknown'] },
  { dir: join(ROOT, 'crates', 'voipc-opus-wasm'), roots: ['voipc-opus-wasm'], platforms: ['wasm32-unknown-unknown'] },
];

/** Packages the bundler copies code from although the lockfile lists them as
 *  build tools: Svelte's runtime and what it imports, and Vite's preload
 *  helper. */
const BUNDLED_DEV = ['svelte', 'esm-env', 'clsx', 'vite'];

/** Where a package offers a choice, the licence with the least to carry comes
 *  first. Apache-2.0 sits before MIT: its text is carried once for all, where
 *  every MIT package needs its own copyright line. */
const COST = {
  'Unlicense': 0, 'CC0-1.0': 0, '0BSD': 0, 'MIT-0': 0, 'WTFPL': 0,
  'BSL-1.0': 1, 'Zlib': 1,
  'Apache-2.0': 2, 'Apache-2.0 WITH LLVM-exception': 2, 'CDLA-Permissive-2.0': 2,
  'MIT': 3, 'ISC': 3,
  'BSD-1-Clause': 4, 'BSD-2-Clause': 4, 'BSD-3-Clause': 4, 'Unicode-3.0': 4,
  'MPL-2.0': 6,
  'LGPL-2.1-or-later': 9, 'AGPL-3.0-only': 9,
};

/** Licences whose text is carried once, for every package under them. */
const SHARED = new Set(['Apache-2.0', 'Apache-2.0 WITH LLVM-exception', 'MPL-2.0', 'AGPL-3.0-only',
  'CDLA-Permissive-2.0', 'BlueOak-1.0.0']);
/** Licences that ask nothing of a binary. */
const NOTHING = new Set(['Unlicense', 'CC0-1.0', '0BSD', 'MIT-0', 'WTFPL', 'BSL-1.0', 'Zlib']);

/** The standard text, for a package that names a licence but ships no file
 *  for it: the copyright line comes from its own metadata. */
const TEMPLATE = {
  MIT: (who) => `Copyright (c) ${who}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`,
  'BSD-3-Clause': (who) => `Copyright (c) ${who}

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`,
};

/** Where to read a shared licence when no package ships its text. */
const URL_OF = {
  'Apache-2.0': 'https://www.apache.org/licenses/LICENSE-2.0',
  'Apache-2.0 WITH LLVM-exception': 'https://llvm.org/LICENSE.txt',
  'MPL-2.0': 'https://mozilla.org/MPL/2.0/',
  'AGPL-3.0-only': 'https://www.gnu.org/licenses/agpl-3.0.txt',
  'CDLA-Permissive-2.0': 'https://cdla.dev/permissive-2-0/',
  'BlueOak-1.0.0': 'https://blueoakcouncil.org/license/1.0.0',
};

// ── SPDX ────────────────────────────────────────────────────────────────

/** The ways an SPDX expression can be met, each a list of licences that all
 *  apply. The old `A/B` spelling is read as `A OR B`. */
export function alternatives(expr) {
  const tokens = String(expr || '').replace(/\//g, ' OR ').match(/\(|\)|[^\s()]+/g) ?? [];
  let i = 0;
  const peek = () => tokens[i];
  const factor = () => {
    if (peek() === '(') {
      i++;
      const inner = or();
      if (tokens[i++] !== ')') throw new Error(`unbalanced licence expression: ${expr}`);
      return inner;
    }
    let id = tokens[i++];
    if (id === undefined) throw new Error(`incomplete licence expression: ${expr}`);
    if (peek() === 'WITH') {
      i++;
      id = `${id} WITH ${tokens[i++]}`;
    }
    return [[id]];
  };
  const and = () => {
    let out = factor();
    while (peek() === 'AND') {
      i++;
      const next = factor();
      out = out.flatMap((a) => next.map((b) => [...a, ...b]));
    }
    return out;
  };
  const or = () => {
    let out = and();
    while (peek() === 'OR') {
      i++;
      out = out.concat(and());
    }
    return out;
  };
  if (!tokens.length) return [];
  const all = or();
  if (i !== tokens.length) throw new Error(`cannot read licence expression: ${expr}`);
  return all.map((a) => [...new Set(a)].sort());
}

/** The alternative VoIPC uses a package under: the least to carry, and of
 *  equals the one listed first. */
export function choose(expr) {
  const options = alternatives(expr);
  if (!options.length) return null;
  const cost = (a) => a.reduce((n, id) => n + (COST[id] ?? 5), 0);
  return options.reduce((best, a) => (cost(a) < cost(best) ? a : best));
}

// ── Licence files ───────────────────────────────────────────────────────

const LICENCE_FILE = /^(licen[cs]e|copying|copyright|notice|unlicense)([-._].*)?$/i;

/** Which licences a file's text is (a combined file can be several). Read
 *  with comment marks and line breaks flattened: some ship it as `// `. */
export function kindsOf(name, raw) {
  if (/^notice/i.test(name)) return ['NOTICE'];
  const text = raw.replace(/^[ \t]*(\/\/+|#+|\*+|;+)[ \t]?/gm, '').replace(/\s+/g, ' ');
  const k = [];
  // Case matters: the MPL names "GNU Affero General Public License" in passing
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/.test(text)) k.push('AGPL-3.0-only');
  if (/Mozilla Public License,?\s+(Version|v\.?)\s*2\.0/i.test(text)) k.push('MPL-2.0');
  if (/Apache License/i.test(text) && /Version 2\.0/.test(text)) {
    k.push(/LLVM Exceptions/i.test(text) ? 'Apache-2.0 WITH LLVM-exception' : 'Apache-2.0');
  }
  if (/Permission is hereby granted, free of charge/i.test(text)) {
    k.push(/above copyright notice and this permission notice shall be included/i.test(text) ? 'MIT' : 'MIT-0');
  }
  if (/Redistribution and use in source and binary forms/i.test(text)) {
    k.push(/Neither the name|names of (its|the) contributors/i.test(text) ? 'BSD-3-Clause' : 'BSD-2-Clause');
  }
  if (/Permission to use, copy, modify,? and\/or distribute this software for any/i.test(text)) {
    k.push(/above copyright notice and this permission notice appear/i.test(text) ? 'ISC' : '0BSD');
  }
  if (/altered from any source distribution/i.test(text)) k.push('Zlib');
  if (/UNICODE LICENSE V3|UNICODE, INC\. LICENSE AGREEMENT/i.test(text)) k.push('Unicode-3.0');
  if (/Boost Software License/i.test(text)) k.push('BSL-1.0');
  if (/free and unencumbered software released into the public domain/i.test(text)) k.push('Unlicense');
  if (/Community Data License Agreement/i.test(text)) k.push('CDLA-Permissive-2.0');
  if (/Blue Oak Model License/i.test(text)) k.push('BlueOak-1.0.0');
  if (/DO WHAT THE FUCK YOU WANT/i.test(text)) k.push('WTFPL');
  return k;
}

/** One text, the same however it was written: LF, no trailing blanks. */
function tidy(text) {
  return text.replace(/\r\n?/g, '\n').split('\n').map((l) => l.replace(/\s+$/, '')).join('\n')
    .replace(/^\n+|\n+$/g, '');
}

function licenceFiles(dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names.filter((n) => LICENCE_FILE.test(n)).sort().flatMap((n) => {
    const path = join(dir, n);
    try {
      if (!statSync(path).isFile()) return [];
      const text = tidy(readFileSync(path, 'utf8'));
      return text ? [{ name: n, text, kinds: kindsOf(n, text) }] : [];
    } catch {
      return [];
    }
  });
}

/** A crate's own files; a git dependency's may sit at its repository's root,
 *  above the crate (libsignal's do). A `-sys` crate also gets the files of
 *  the C library it carries in a folder of its own. */
function crateFiles(pkg) {
  const dir = dirname(pkg.manifest_path);
  let files = licenceFiles(dir);
  if (!files.length && pkg.source?.startsWith('git+')) {
    let up = dir;
    for (let n = 0; n < 4 && !files.length; n++) {
      const parent = dirname(up);
      if (parent === up || !up.includes(`${sep}checkouts${sep}`)) break;
      up = parent;
      files = licenceFiles(up);
    }
  }
  const bundled = [];
  if (/[-_]sys$/.test(pkg.name)) {
    for (const sub of readdirSync(dir).sort()) {
      if (['src', 'tests', 'examples', 'benches', 'target', 'build'].includes(sub)) continue;
      const path = join(dir, sub);
      if (!statSync(path).isDirectory()) continue;
      for (const f of licenceFiles(path)) bundled.push({ ...f, name: `${sub}/${f.name}` });
    }
  }
  return { files, bundled };
}

// ── Packages ────────────────────────────────────────────────────────────

function cargoMetadata(ws) {
  const args = ['metadata', '--format-version', '1', '--locked'];
  for (const p of ws.platforms) args.push('--filter-platform', p);
  const res = spawnSync('cargo', args, {
    cwd: ws.dir, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, shell: IS_WINDOWS,
  });
  if (res.status !== 0) fail(`cargo metadata in ${ws.dir} failed:\n${res.stderr}`);
  return JSON.parse(res.stdout);
}

/** Every crate a shipping root reaches through normal dependencies (not
 *  dev or build ones), ours left out. */
function crates() {
  const out = new Map();
  for (const ws of WORKSPACES) {
    const meta = cargoMetadata(ws);
    const byId = new Map(meta.packages.map((p) => [p.id, p]));
    const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
    const roots = meta.packages.filter((p) => ws.roots.includes(p.name) && !p.source).map((p) => p.id);
    if (roots.length !== ws.roots.length) fail(`notices: ${ws.roots.join(', ')} not found in ${ws.dir}`);
    const seen = new Set(roots);
    const queue = [...roots];
    while (queue.length) {
      for (const dep of nodes.get(queue.pop()).deps) {
        if (!dep.dep_kinds.some((k) => k.kind === null) || seen.has(dep.pkg)) continue;
        seen.add(dep.pkg);
        queue.push(dep.pkg);
      }
    }
    for (const id of seen) {
      const p = byId.get(id);
      if (!p.source) continue; // a path dependency: VoIPC's own
      const key = `${p.name} ${p.version}`;
      if (out.has(key)) continue;
      const { files, bundled } = crateFiles(p);
      // A git dependency's source is that commit (libsignal's, for the AGPL)
      const git = p.source.match(/^git\+([^?#]+)(?:\?[^#]*)?#([0-9a-f]+)$/);
      out.set(key, {
        name: p.name,
        version: p.version,
        licence: p.license ?? (p.license_file ? `see ${p.license_file}` : null),
        home: git
          ? `${git[1].replace(/\.git$/, '')}/tree/${git[2]}`
          : p.repository || `https://crates.io/crates/${p.name}/${p.version}`,
        authors: (p.authors ?? []).map((a) => a.replace(/\s*<[^>]*>/, '')).filter(Boolean),
        files,
        bundled,
      });
    }
  }
  return [...out.values()];
}

function repoUrl(repo) {
  const url = typeof repo === 'string' ? repo : repo?.url;
  if (!url) return null;
  if (/^github:/.test(url) || /^[\w-]+\/[\w.-]+$/.test(url)) return `https://github.com/${url.replace(/^github:/, '')}`;
  return url.replace(/^git\+/, '').replace(/^git:\/\//, 'https://').replace(/^ssh:\/\/git@/, 'https://').replace(/\.git$/, '');
}

/** The front end's production dependencies from the lockfile, plus what the
 *  bundler copies in from its build tools. */
function npmPackages() {
  const lockPath = join(CLIENT, 'package-lock.json');
  if (!existsSync(lockPath)) fail('notices: client/package-lock.json is missing');
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  const paths = Object.entries(lock.packages ?? {})
    .filter(([path, p]) => path && !p.dev && !p.devOptional && !p.link)
    .map(([path]) => path);
  for (const name of BUNDLED_DEV) {
    const path = `node_modules/${name}`;
    if (!lock.packages?.[path]) fail(`notices: ${name} is not in client/package-lock.json`);
    if (!paths.includes(path)) paths.push(path);
  }
  return paths.sort().map((path) => {
    const dir = join(CLIENT, ...path.split('/'));
    const manifest = join(dir, 'package.json');
    if (!existsSync(manifest)) fail(`notices: ${path} is not installed (npm ci in client/ first)`);
    const pkg = JSON.parse(readFileSync(manifest, 'utf8'));
    let licence = typeof pkg.license === 'string' ? pkg.license : pkg.license?.type;
    if (!licence && Array.isArray(pkg.licenses)) {
      licence = pkg.licenses.map((l) => (typeof l === 'string' ? l : l.type)).join(' OR ');
    }
    const who = typeof pkg.author === 'string' ? pkg.author : pkg.author?.name;
    return {
      name: pkg.name ?? path.slice(path.lastIndexOf('node_modules/') + 13),
      version: pkg.version,
      licence: licence ?? null,
      home: repoUrl(pkg.repository) ?? `https://www.npmjs.com/package/${pkg.name}/v/${pkg.version}`,
      authors: who ? [who.replace(/\s*<[^>]*>/, '').replace(/\s*\([^)]*\)/, '')] : [],
      files: licenceFiles(dir),
      bundled: [],
    };
  });
}

/** The Android app's Java libraries, as its Gradle file names them. */
function androidLibraries() {
  const gradle = join(CLIENT, 'src-tauri', 'gen', 'android', 'app', 'build.gradle.kts');
  if (!existsSync(gradle)) return [];
  const text = readFileSync(gradle, 'utf8');
  return [...text.matchAll(/^\s*implementation\("([^":]+):([^":]+):([^"]+)"\)/gm)]
    .map((m) => `${m[1]}:${m[2]} ${m[3]}`).sort();
}

// ── The file ────────────────────────────────────────────────────────────

/** For one package: the licences it is used under, and the texts it brings. */
function resolveTexts(pkg, problems) {
  let chosen = null;
  try {
    chosen = pkg.licence ? choose(pkg.licence) : null;
  } catch (e) {
    problems.push(`${pkg.name} ${pkg.version}: ${e.message}`);
  }
  if (!chosen) {
    problems.push(`${pkg.name} ${pkg.version}: no licence in its metadata`);
    return { chosen: ['(none stated)'], texts: pkg.files.map((f) => ({ label: f.name, text: f.text })) };
  }
  const texts = [];
  for (const id of chosen) {
    if (NOTHING.has(id)) continue;
    if (SHARED.has(id)) {
      // The shared text is carried once; a NOTICE file is the package's own
      if (id.startsWith('Apache-2.0')) {
        for (const f of pkg.files.filter((f) => f.kinds.includes('NOTICE'))) texts.push({ label: f.name, text: f.text });
      }
      continue;
    }
    const own = pkg.files.filter((f) => f.kinds.includes(id));
    const unread = pkg.files.filter((f) => !f.kinds.length);
    const pick = own.length ? own : unread;
    if (pick.length) {
      for (const f of pick) texts.push({ label: f.name, text: f.text });
    } else if (TEMPLATE[id]) {
      const who = pkg.authors.length ? pkg.authors.join(', ') : `the ${pkg.name} authors`;
      const template = TEMPLATE[id] ?? TEMPLATE['BSD-3-Clause'];
      texts.push({ label: `${id}: the standard text, as the package ships none`, text: template(who) });
    } else {
      problems.push(`${pkg.name} ${pkg.version}: no ${id} text in the package`);
    }
  }
  for (const f of pkg.bundled) texts.push({ label: `bundled with it: ${f.name}`, text: f.text });
  return { chosen, texts };
}

/** The most common text of a shared licence across every package's files. */
function sharedText(id, packages) {
  const seen = new Map();
  for (const p of packages) {
    for (const f of p.files) {
      // Only a file that is that licence alone, not a combined one
      if (f.kinds.length === 1 && f.kinds[0] === id) seen.set(f.text, (seen.get(f.text) ?? 0) + 1);
    }
  }
  const best = [...seen].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))[0];
  return best?.[0] ?? null;
}

function section(title, body, ch = '-') {
  return `${title}\n${ch.repeat(title.length)}\n\n${body}`;
}

export function buildNotices() {
  // Plain code-unit order: the same bytes whatever the machine's locale
  const order = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const rust = crates().sort((a, b) => order(a.name, b.name) || order(a.version, b.version));
  const npm = npmPackages().sort((a, b) => order(a.name, b.name));
  const problems = [];
  const all = [...rust, ...npm];
  for (const p of all) Object.assign(p, resolveTexts(p, problems));

  // Identical texts are written once, under every package that brings them
  const byText = new Map();
  for (const p of all) {
    for (const t of p.texts) {
      const entry = byText.get(t.text) ?? { text: t.text, users: [] };
      entry.users.push(`${p.name} ${p.version} (${t.label})`);
      byText.set(t.text, entry);
    }
  }
  const usedShared = [...new Set(all.flatMap((p) => p.chosen).filter((id) => SHARED.has(id)))].sort();

  const line = (p) => `${p.name} ${p.version}  ${p.chosen.join(' AND ')}${p.licence && p.chosen.join(' AND ') !== p.licence ? `  (offered: ${p.licence})` : ''}  ${p.home}`;
  const android = androidLibraries();
  const out = [];
  out.push(section(`VoIPC ${workspaceVersion()}: third-party notices`, `VoIPC's own code is under the MIT licence (https://github.com/luki4fun/voipc,
LICENSE). It is built with the third-party code listed here, under the
licences named, and this file carries the notices those licences ask for.
It is generated at build time from the lockfiles (tools/tasks/notices.mjs),
and the same file goes into every VoIPC build: the desktop and Android apps,
the browser client, and the relay that serves it.

Where a package offers a choice of licences, VoIPC uses it under the one named
first in its line; "offered" shows the package's own expression.`, '='));
  out.push(section('Not packages: what some builds also carry', `- The Windows installer carries FFmpeg (GPL), BtbN's gpl-shared build, with
  x264 and x265 built in.
- The AppImage carries the shared libraries the app links from Ubuntu 24.04:
  FFmpeg, x264 and x265 (GPL), GTK, WebKitGTK and GLib (LGPL), PipeWire, ALSA
  and the libraries under them, each under its own licence. Their source is
  Ubuntu's: apt-get source <package>, or https://launchpad.net/ubuntu/noble.
  The .deb uses the system's own.
- Each release's notes name the exact FFmpeg build and link its source, and
  libsignal's (AGPL-3.0-only, below).${android.length ? `
- The Android app carries these Java libraries (Apache-2.0), with the Kotlin
  standard library (Apache-2.0) and LLVM's libc++ from the Android NDK
  (Apache-2.0 WITH LLVM-exception):
${android.map((l) => `    ${l}`).join('\n')}` : ''}`));
  out.push(section(`Rust crates (${rust.length})`, rust.map(line).join('\n')));
  out.push(section(`npm packages in the front end (${npm.length})`, npm.map(line).join('\n')));
  for (const n of byText.values()) n.users.sort();
  const notices = [...byText.values()].sort((a, b) => (a.users[0] < b.users[0] ? -1 : 1));
  out.push(section('Copyright and licence notices, as each package ships them',
    notices.map((n) => `>>> ${n.users.join('\n>>> ')}\n\n${n.text}`).join('\n\n\n')));
  out.push(section('Licence texts shared by many packages', usedShared.map((id) => {
    const users = all.filter((p) => p.chosen.includes(id)).length;
    const text = sharedText(id, all);
    if (!text) problems.push(`no package ships the text of ${id}; pointing to ${URL_OF[id]}`);
    const head = `>>> ${id} (${users} package${users === 1 ? '' : 's'})`;
    const src = id === 'MPL-2.0' || id === 'AGPL-3.0-only'
      ? `\n\nThe source of each package under ${id} is at the address in its line\nabove, at the version named there.`
      : '';
    return `${head}${src}\n\n${text ?? `The text: ${URL_OF[id]}`}`;
  }).join('\n\n\n')));
  return { text: `${out.join('\n\n\n')}\n`, rust: rust.length, npm: npm.length, problems };
}

/** Write the file; returns its path. Used by the build tasks before Vite runs. */
export function writeNotices({ quiet = false } = {}) {
  const { text, rust, npm, problems } = buildNotices();
  for (const p of problems) console.warn(`notices: ${p}`);
  mkdirSync(dirname(NOTICES), { recursive: true });
  writeFileSync(NOTICES, text);
  if (!quiet) ok(`${basename(NOTICES)}: ${rust} crates, ${npm} npm packages, ${Math.round(text.length / 1024)} KiB`);
  return NOTICES;
}

export default function notices() {
  writeNotices();
}
