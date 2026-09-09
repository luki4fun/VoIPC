#!/usr/bin/env node
// VoIPC build CLI — one entry point for every build, setup and test task.
//
// Run a task directly:      node tools/voipc.mjs <task> [options]
// or through the aliases:   npm run <task>
//
// setup.sh / setup.ps1 stay separate because they install Rust and Node, which
// have to exist before anything here can run.
import { addCargoBinToPath, err, TaskError } from './lib.mjs';

const TASKS = {
  dev: ['./tasks/desktop.mjs', 'Debug build of the desktop client, then run it'],
  build: ['./tasks/desktop.mjs', 'Release build of the desktop client for this OS'],
  'setup:windows': ['./tasks/windows-cross.mjs', 'One-time setup to cross-build Windows from Linux'],
  'build:windows': ['./tasks/windows-cross.mjs', 'Cross-build the Windows client and installer'],
  web: ['./tasks/web.mjs', 'Build the web client (wasm + Vite) and the server that embeds it'],
  'setup:android': ['./tasks/android.mjs', 'One-time Android SDK/NDK/JDK setup'],
  android: ['./tasks/android.mjs', 'Build the Android APK'],
  release: ['./tasks/release.mjs', 'Portable Linux release artifacts in Docker (host build without it)'],
  'test:web': ['./tasks/test-web.mjs', 'Headless two-browser end-to-end test of the web client'],
  'bundle-libs': ['./tasks/bundle-libs.mjs', 'Stage shared libraries for AppImage bundling'],
  version: ['./tasks/version.mjs', 'Sync the workspace version into every file that repeats it'],
};

function usage() {
  console.log('Usage: node tools/voipc.mjs <task> [options]\n');
  const width = Math.max(...Object.keys(TASKS).map((t) => t.length));
  for (const [name, [, desc]] of Object.entries(TASKS)) {
    console.log(`  ${name.padEnd(width)}  ${desc}`);
  }
  console.log('\nUnrecognised options are passed through to the underlying tool.');
}

const [task, ...rest] = process.argv.slice(2);
// `npm run build -- --foo` strips the separator, but a direct
// `node tools/voipc.mjs build -- --foo` does not; tolerate both.
const args = rest[0] === '--' ? rest.slice(1) : rest;

if (!task || task === '--help' || task === '-h') {
  usage();
  process.exit(task ? 0 : 1);
}

if (!TASKS[task]) {
  err(`unknown task: ${task}\n`);
  usage();
  process.exit(1);
}

addCargoBinToPath();

try {
  const { default: entry } = await import(TASKS[task][0]);
  await entry(task, args);
} catch (e) {
  if (e instanceof TaskError) {
    err(e.message);
    process.exit(1);
  }
  throw e;
}
