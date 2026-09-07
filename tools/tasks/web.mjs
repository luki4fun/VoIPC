// Web client: the wasm crate (Signal + protocol + media crypto) plus the Vite
// bundle, then the release server binary that embeds and serves it.
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { CLIENT, ROOT, ensureRustTarget, head, npmInstall, ok, run, syncVersion } from '../lib.mjs';

export default function web(_task, args) {
  const debug = args.includes('--debug');
  const rest = args.filter((a) => a !== '--debug');
  const version = syncVersion();
  ensureRustTarget('wasm32-unknown-unknown');

  head(`Building web client ${version} (wasm + Vite)`);
  npmInstall();
  run('npm', ['run', 'build:web'], { cwd: CLIENT });

  // Order matters: the server embeds client/dist-web at compile time, so the
  // bundle above has to exist before this.
  head(`Building server with the embedded web client (${debug ? 'debug' : 'release'})`);
  run('cargo', ['build', '-p', 'voipc-server', ...(debug ? [] : ['--release']), ...rest]);

  mkdirSync(join(ROOT, 'release'), { recursive: true });
  const tarball = join('release', `VoIPC-web-${version}.tar.gz`);
  run('tar', ['-czf', tarball, '-C', 'client', 'dist-web']);

  const profile = debug ? 'debug' : 'release';
  head('Web client artifacts');
  ok(`static bundle: ${tarball}`);
  ok(`server binary: target/${profile}/voipc-server (serves https://<host>:9987/)`);
}
