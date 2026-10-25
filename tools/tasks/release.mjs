// The Linux release artifacts a host can build: the web bundle and the server
// that embeds it, copied into release/. The portable ones (the static musl
// server, the AppImage pinned to Ubuntu 24.04's glibc, the .deb) come from the
// release workflow, .github/workflows/release.yml; the Docker image that used
// to copy them was not built by anything and had rotted, so it was removed.
import { copyFileSync, existsSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, fail, head, info, ok } from '../lib.mjs';
import web from './web.mjs';

export default function release(_task, args) {
  if (args.length) fail(`unknown arguments: ${args.join(' ')}`);
  const releaseDir = join(ROOT, 'release');
  mkdirSync(releaseDir, { recursive: true });

  // `web` syncs the version itself and prints its own two build headings.
  const version = web('web', [], { summary: false });

  const binary = join(ROOT, 'target', 'release', 'voipc-server');
  if (!existsSync(binary)) fail(`the server was not built: ${binary} is missing`);
  copyFileSync(binary, join(releaseDir, 'voipc-server'));

  summary(releaseDir, ['voipc-server', `VoIPC-web-${version}.tar.gz`], [
    'the server is linked against this host\'s glibc — the static musl build comes from CI',
    'the AppImage and .deb come from CI too (npm run build makes a host one)',
  ]);
}

/**
 * List what this run produced. Deliberately not a directory listing: release/
 * keeps older versions and the Android APK, and reporting those as fresh output
 * is how you ship last month's build.
 */
function summary(releaseDir, produced, caveats = []) {
  head('Release artifacts');
  for (const name of produced) {
    const path = join(releaseDir, name);
    if (!existsSync(path)) continue;
    const mb = (statSync(path).size / 1024 / 1024).toFixed(1);
    ok(`${join('release', name)} (${mb} MB)`);
  }
  for (const line of caveats) info(line);

  const others = readdirSync(releaseDir).filter(
    (n) => !produced.includes(n) && statSync(join(releaseDir, n)).isFile(),
  );
  if (others.length) {
    info(`release/ also holds ${others.length} older file(s) from earlier builds: ${others.join(', ')}`);
  }
  info('the server serves the embedded web client at https://<host>:9987/');
}
