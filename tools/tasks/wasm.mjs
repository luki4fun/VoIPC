// The browser's wasm crate (Signal + protocol + media crypto): cargo builds it,
// wasm-bindgen writes the JS glue into client/src/lib/wasm.
//
// This replaced wasm-pack, whose npm package downloaded its own binary and then
// wasm-bindgen-cli with no checksum, in every job that builds the web bundle.
// wasm-bindgen-cli must be exactly the version in crates/voipc-web/Cargo.lock
// (it refuses a wasm file from any other), so it is installed from crates.io
// with --locked whenever it is missing or different.
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CLIENT, ROOT, capture, ensureRustTarget, fail, head, info, run } from '../lib.mjs';
import { writeNotices } from './notices.mjs';

export default function wasm() {
  const crate = join(ROOT, 'crates', 'voipc-web');
  const lock = readFileSync(join(crate, 'Cargo.lock'), 'utf8');
  const version = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)?.[1];
  if (!version) fail('no wasm-bindgen entry in crates/voipc-web/Cargo.lock');
  if (capture('wasm-bindgen', ['--version']) !== `wasm-bindgen ${version}`) {
    info(`installing wasm-bindgen-cli ${version} (crates.io, --locked)...`);
    run('cargo', ['install', '--locked', `wasm-bindgen-cli@${version}`]);
  }
  ensureRustTarget('wasm32-unknown-unknown');

  head('Building the wasm crate');
  // From inside the crate: its .cargo/config.toml sets the getrandom backend.
  run('cargo', ['build', '--release', '--locked', '--target', 'wasm32-unknown-unknown'], { cwd: crate });
  const target = resolve(crate, process.env.CARGO_TARGET_DIR || 'target');
  run('wasm-bindgen', ['--target', 'web', '--out-dir', join(CLIENT, 'src', 'lib', 'wasm'),
    '--out-name', 'voipc_web', join(target, 'wasm32-unknown-unknown', 'release', 'voipc_web.wasm')]);

  // Every web build passes through here (`npm run build:web` runs this task
  // before Vite), the release and nightly jobs included, so the notices land
  // in client/public in time for Vite to copy them into dist-web.
  writeNotices();
}
