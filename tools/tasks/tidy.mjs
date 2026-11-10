// Debug build results no build can use any more. Cargo never deletes these: each
// version, toolchain, feature set and profile gets its own hashed copy of our crates
// beside the old ones, and they add up to hundreds of GiB.
//
// Only our own crates and their incremental caches, by when they were last written, so
// third-party crates stay built. A mistake costs one recompile of the crate it hit.
import { lstatSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, fail, ok } from '../lib.mjs';

const DEBUG_DIRS = [
  'target/debug',
  'crates/voipc-web/target/debug',
  'crates/voipc-web/target/wasm32-unknown-unknown/debug',
];

const list = (dir) => {
  try {
    return readdirSync(dir).map((name) => join(dir, name));
  } catch {
    return [];
  }
};

/** Bytes on disk under `path`, however deep. */
function bytes(path) {
  const st = lstatSync(path);
  return st.isDirectory() ? list(path).reduce((sum, p) => sum + bytes(p), 0) : st.blocks * 512;
}

const ours = (path) => /^(lib)?voipc/.test(path.split(/[\\/]/).pop());

export default function tidy(_task, args) {
  const at = args.indexOf('--days');
  const days = at < 0 ? 1 : Number(args[at + 1]);
  if (!(days >= 0)) fail('--days takes a number of days');
  const dryRun = args.includes('--dry-run');
  const before = Date.now() - days * 86_400_000;

  const dead = DEBUG_DIRS.flatMap((dir) => {
    const at = join(ROOT, dir);
    return [
      ...list(join(at, 'incremental')),
      ...list(join(at, 'deps')).filter(ours),
      ...list(join(at, 'examples')),
    ];
  }).filter((path) => lstatSync(path).mtimeMs < before);

  let freed = 0;
  for (const path of dead) {
    freed += bytes(path);
    if (!dryRun) rmSync(path, { recursive: true, force: true });
  }
  const gib = (freed / 2 ** 30).toFixed(1);
  ok(`${dryRun ? 'would free' : 'freed'} ${gib} GiB from ${dead.length} old build results`);
}
