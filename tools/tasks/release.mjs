// Portable Linux release artifacts, built inside Docker so they only depend on
// Ubuntu 24.04's glibc: a static musl server, the client AppImage and the web
// bundle. Nothing but Docker is needed on the host.
import { existsSync, mkdirSync, readdirSync, renameSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, capture, fail, head, info, ok, run, syncVersion, which } from '../lib.mjs';

const IMAGE = 'voipc-release';

export default function release(_task, args) {
  if (!which('docker')) {
    fail('this task builds inside Docker and needs the docker CLI.\n'
      + '     Install docker, or use `npm run build` for a native build.');
  }

  const version = syncVersion();
  head(`Building VoIPC ${version} release`);

  run('docker', ['build', '-f', 'Dockerfile.release', '-t', IMAGE, '.', ...args]);

  const releaseDir = join(ROOT, 'release');
  mkdirSync(releaseDir, { recursive: true });

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
  if (existsSync(unversioned)) {
    renameSync(unversioned, join(releaseDir, `VoIPC-web-${version}.tar.gz`));
  }

  head('Release artifacts');
  for (const name of readdirSync(releaseDir).sort()) {
    const path = join(releaseDir, name);
    if (!statSync(path).isFile()) continue;
    const mb = (statSync(path).size / 1024 / 1024).toFixed(1);
    ok(`${join('release', name)} (${mb} MB)`);
  }
  info('the server serves the embedded web client at https://<host>:9987/');
}
