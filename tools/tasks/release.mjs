// Portable Linux release artifacts, built inside Docker so they only depend on
// Ubuntu 24.04's glibc: a static musl server, the client AppImage and the web
// bundle. Nothing but Docker is needed on the host.
//
// Without Docker there is no "skip one step" — the image builds all three — so
// the task falls back to a host build of what a host can actually make: the web
// bundle and the server that embeds it. The AppImage is the artifact that needs
// the pinned glibc, and it is the one that is dropped. Set VOIPC_NO_DOCKER=1 to
// take that path deliberately.
import { copyFileSync, existsSync, mkdirSync, readdirSync, renameSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, capture, err, fail, head, info, ok, run, syncVersion, which } from '../lib.mjs';
import web from './web.mjs';

const IMAGE = 'voipc-release';

export default function release(_task, args) {
  const releaseDir = join(ROOT, 'release');
  mkdirSync(releaseDir, { recursive: true });

  const noDocker = process.env.VOIPC_NO_DOCKER;
  if (noDocker || !which('docker')) {
    return hostRelease(releaseDir, args, noDocker ? 'VOIPC_NO_DOCKER is set' : 'docker was not found');
  }

  const version = syncVersion();
  head(`Building VoIPC ${version} release`);

  run('docker', ['build', '-f', 'Dockerfile.release', '-t', IMAGE, '.', ...args]);

  // The image's final stage is FROM scratch, so it has no shell — an explicit
  // entrypoint is required just to create a container to copy out of.
  const container = capture('docker', ['create', '--entrypoint', '/bin/true', IMAGE]);
  if (!container) fail('could not create a container from the release image');
  try {
    run('sh', ['-c',
      `docker cp ${container}:/ - | tar --strip-components=0 -xf - -C release/ `
      + "--exclude='dev' --exclude='etc' --exclude='proc' --exclude='sys'"]);
  } finally {
    run('docker', ['rm', container], { allowFailure: true, stdio: 'ignore' });
  }

  // The image carries an unversioned web bundle; name it like the rest.
  const unversioned = join(releaseDir, 'VoIPC-web.tar.gz');
  const tarball = `VoIPC-web-${version}.tar.gz`;
  if (existsSync(unversioned)) renameSync(unversioned, join(releaseDir, tarball));

  // By version, not just by extension: an AppImage from an earlier build is
  // still sitting in release/ and must not be reported as this run's output.
  const appImages = readdirSync(releaseDir)
    .filter((n) => n.endsWith('.AppImage') && n.includes(version));
  summary(releaseDir, ['voipc-server', ...appImages, tarball]);
}

/**
 * What a host without Docker can still produce: the wasm + Vite bundle, the
 * server that embeds it, and the tarball. Everything the `web` task already
 * does, plus a copy of the binary into release/ and an honest summary.
 */
function hostRelease(releaseDir, args, why) {
  err(`${why} — falling back to a host build`);
  info('the AppImage is built in Docker on purpose: the image pins Ubuntu 24.04 (glibc 2.39)');
  info('so one binary runs everywhere. A host AppImage would only run on this machine.');
  if (args.length) {
    info(`ignoring ${args.join(' ')} — those arguments only mean something to \`docker build\``);
  }

  // `web` syncs the version itself and prints its own two build headings.
  const version = web('web', [], { summary: false });

  const binary = join(ROOT, 'target', 'release', 'voipc-server');
  if (!existsSync(binary)) fail(`the server was not built: ${binary} is missing`);
  copyFileSync(binary, join(releaseDir, 'voipc-server'));

  summary(releaseDir, ['voipc-server', `VoIPC-web-${version}.tar.gz`], [
    'the server is linked against this host\'s glibc — it is not the portable build',
    'no AppImage: install docker and re-run `npm run release` for the release artifacts',
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
