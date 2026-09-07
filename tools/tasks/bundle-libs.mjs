// Collect shared libraries so the AppImage is self-contained.
//
// Invoked by Tauri's beforeBundleCommand (see client/src-tauri/tauri.conf.json),
// which runs it with cwd set to client/ — paths here come from the repo root
// constant, never from cwd.
//
// Walks ldd output breadth-first from the compiled binary, drops the libraries
// that must come from the host, and stages the rest in appimage-libs/ with
// their soname symlinks intact. The build task's --config maps that directory
// to /usr/lib inside the AppDir.
import { existsSync, mkdirSync, rmSync, copyFileSync, symlinkSync, readdirSync, lstatSync, realpathSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { CLIENT, ROOT, capture, fail, info, ok } from '../lib.mjs';

// Libraries that must come from the host: the core C/C++ runtime (present
// everywhere), anything coupled to the GPU or display server, and system
// services. Mirrors the AppImage excludelist.
const EXCLUDE = new RegExp([
  'linux-vdso\\.so', 'ld-linux',
  'libc\\.so', 'libdl\\.so', 'libm\\.so', 'libpthread\\.so', 'librt\\.so',
  'libutil\\.so', 'libresolv\\.so', 'libnss_', 'libthread_db\\.so', 'libmvec\\.so',
  'libgcc_s\\.so', 'libstdc\\+\\+\\.so',
  'libGL\\.so', 'libEGL\\.so', 'libGLdispatch\\.so', 'libGLX\\.so', 'libOpenGL\\.so',
  'libdrm\\.so', 'libglapi\\.so', 'libvulkan\\.so', 'libgbm\\.so',
  'libxcb\\.so', 'libX11\\.so', 'libX11-xcb\\.so',
  'libwayland-client\\.so', 'libwayland-server\\.so', 'libwayland-cursor\\.so',
  'libdbus-1\\.so',
  'libz\\.so', 'libexpat\\.so', 'libuuid\\.so',
].join('|'));

// Needed at runtime but skipped by linuxdeploy's own exclude list.
const FORCE_LIBS = ['libpipewire-0.3.so', 'libasound.so'];

/** Direct shared-library dependencies of a binary, as resolved paths. */
function lddDeps(file) {
  const out = capture('ldd', [file]);
  return out
    .split('\n')
    .map((line) => {
      const m = line.match(/=>\s+(\S+)/);
      return m && m[1] !== 'not' ? m[1] : null;
    })
    .filter((p) => p && existsSync(p));
}

/** Resolve a force-included library through the linker cache. */
function findInLdCache(pattern) {
  const out = capture('ldconfig', ['-p']);
  for (const line of out.split('\n')) {
    if (!line.includes(pattern)) continue;
    const path = line.trim().split(/\s+/).pop();
    if (path && existsSync(path)) return path;
  }
  return null;
}

export default function bundleLibs() {
  const staging = join(CLIENT, 'src-tauri', 'appimage-libs');

  const candidates = [
    join(ROOT, 'target', 'release', 'voipc-client'),
    join(CLIENT, 'src-tauri', 'target', 'release', 'voipc-client'),
  ];
  const binary = candidates.find((p) => existsSync(p));
  if (!binary) {
    fail(`compiled binary not found. Looked in:\n  ${candidates.join('\n  ')}`);
  }

  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });

  info(`tracing library dependencies for ${binary}`);

  const queue = [...lddDeps(binary)];
  for (const pattern of FORCE_LIBS) {
    const found = findInLdCache(pattern);
    if (found) queue.push(found);
    else info(`force-included library '${pattern}' not found on this system`);
  }

  const seen = new Set();
  const bundle = new Set();
  while (queue.length) {
    const lib = queue.shift();
    let real;
    try {
      real = realpathSync(lib);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);
    if (EXCLUDE.test(basename(real))) continue;
    bundle.add(real);
    queue.push(...lddDeps(real));
  }

  if (bundle.size === 0) {
    info('no libraries collected — the AppImage may not be portable');
    return;
  }

  let links = 0;
  for (const libPath of [...bundle].sort()) {
    const name = basename(libPath);
    copyFileSync(libPath, join(staging, name));

    // Recreate the soname chain (libfoo.so -> libfoo.so.1 -> libfoo.so.1.2.3),
    // otherwise the dynamic loader will not find the library by its soname.
    const dir = dirname(libPath);
    for (const entry of readdirSync(dir)) {
      const candidate = join(dir, entry);
      let isLink = false;
      try {
        isLink = lstatSync(candidate).isSymbolicLink();
      } catch {
        continue;
      }
      if (!isLink || entry === name) continue;
      try {
        if (realpathSync(candidate) !== libPath) continue;
      } catch {
        continue;
      }
      const dest = join(staging, entry);
      rmSync(dest, { force: true });
      symlinkSync(name, dest);
      links++;
    }
  }

  const bytes = [...bundle].reduce((sum, p) => sum + statSync(p).size, 0);
  ok(`staged ${bundle.size} libraries + ${links} links (${(bytes / 1024 / 1024).toFixed(1)} MB) in appimage-libs/`);
}
