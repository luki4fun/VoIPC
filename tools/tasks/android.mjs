// Android: `setup:android` installs a self-contained SDK/NDK/JDK under
// ~/android-sdk, `android` builds the APK.
//
// The Android Gradle plugin needs JDK 17-21, so setup bundles a Temurin 21
// inside the SDK rather than trusting whatever system Java is installed.
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CLIENT, ROOT, capture, fail, head, info, npmInstall, ok, run, syncVersion, which,
} from '../lib.mjs';

const home = () => process.env.HOME ?? '';
const sdkRoot = () => process.env.ANDROID_HOME || join(home(), 'android-sdk');

const CMDTOOLS_URL = process.env.CMDTOOLS_URL
  || 'https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip';
// Latest GA JDK 21 — major pinned because the Android Gradle plugin supports 17-21.
const JDK_URL = process.env.JDK_URL
  || 'https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse';
// Move this pin only together with a tested build.
const NDK_VERSION = process.env.NDK_VERSION || '28.0.13004108';

const RUST_TARGETS = ['aarch64-linux-android', 'armv7-linux-androideabi', 'x86_64-linux-android'];
const ABI_BY_TARGET = {
  aarch64: 'aarch64-linux-android',
  armv7: 'armv7-linux-androideabi',
  x86_64: 'x86_64-linux-android',
};

/** compileSdk from the gradle file Tauri generates, so the installed platform
 *  and build-tools follow it automatically. */
function compileSdk() {
  const gradle = join(CLIENT, 'src-tauri', 'gen', 'android', 'app', 'build.gradle.kts');
  if (existsSync(gradle)) {
    const m = readFileSync(gradle, 'utf8').match(/compileSdk\s*=\s*(\d+)/);
    if (m) return m[1];
  }
  return '36';
}

function setup() {
  const sdk = sdkRoot();
  const sdkVer = compileSdk();
  mkdirSync(sdk, { recursive: true });

  const sdkmanager = join(sdk, 'cmdline-tools', 'latest', 'bin', 'sdkmanager');
  if (!existsSync(sdkmanager)) {
    info('downloading Android commandline-tools...');
    const tmp = mkdtempSync(join(tmpdir(), 'voipc-cmdtools-'));
    try {
      run('curl', ['-fsSL', '-o', join(tmp, 'cmdtools.zip'), CMDTOOLS_URL]);
      run('unzip', ['-q', join(tmp, 'cmdtools.zip'), '-d', tmp]);
      // The zip contains cmdline-tools/, but sdkmanager expects cmdline-tools/latest/.
      mkdirSync(join(sdk, 'cmdline-tools'), { recursive: true });
      renameSync(join(tmp, 'cmdline-tools'), join(sdk, 'cmdline-tools', 'latest'));
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  ok('commandline-tools');

  const javaHome = join(sdk, 'jdk');
  if (!existsSync(join(javaHome, 'bin', 'java'))) {
    info('downloading Temurin JDK 21...');
    const archive = join(sdk, 'jdk21.tar.gz');
    run('curl', ['-fsSL', '-o', archive, JDK_URL]);
    mkdirSync(javaHome, { recursive: true });
    run('tar', ['-xzf', archive, '-C', javaHome, '--strip-components=1']);
    rmSync(archive, { force: true });
  }
  ok('JDK 21');

  info('accepting licenses...');
  // sdkmanager exits early once every licence is accepted, killing `yes` with
  // SIGPIPE — that is expected, so the failure is ignored.
  run('sh', ['-c', `(yes || true) | "${sdkmanager}" --sdk_root="${sdk}" --licenses > /dev/null`],
    { env: { JAVA_HOME: javaHome }, allowFailure: true });

  info(`installing platform-tools, android-${sdkVer}, build-tools;${sdkVer}.0.0, `
    + `ndk;${NDK_VERSION} (large download)...`);
  run(sdkmanager, [`--sdk_root=${sdk}`, 'platform-tools', `platforms;android-${sdkVer}`,
    `build-tools;${sdkVer}.0.0`, `ndk;${NDK_VERSION}`], { env: { JAVA_HOME: javaHome } });
  ok('SDK packages');

  info('adding Rust Android targets...');
  run('rustup', ['target', 'add', ...RUST_TARGETS]);
  ok('Rust targets');

  head(`Android environment ready at ${sdk}`);
  console.log('Build with: npm run android -- [debug|release] [--target aarch64|armv7|x86_64|all]');
}

/** Locate SDK, NDK and JDK, preferring explicit environment variables. */
function resolveToolchain() {
  let sdk = process.env.ANDROID_HOME;
  if (!sdk) {
    sdk = [join(home(), 'Android', 'Sdk'), join(home(), 'android-sdk'), '/opt/android-sdk',
      join(home(), 'Library', 'Android', 'sdk')].find((d) => existsSync(d));
  }
  if (!sdk || !existsSync(sdk)) {
    fail('Android SDK not found.\n'
      + '     Run `npm run setup:android`, or set ANDROID_HOME to an existing SDK.');
  }

  let ndk = process.env.ANDROID_NDK_HOME;
  if (!ndk) {
    const ndkDir = join(sdk, 'ndk');
    const versions = existsSync(ndkDir)
      ? readdirSync(ndkDir).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      : [];
    if (versions.length) ndk = join(ndkDir, versions[versions.length - 1]);
  }
  if (!ndk || !existsSync(ndk)) {
    fail(`Android NDK not found under ${join(sdk, 'ndk')}.\n`
      + `     Run \`npm run setup:android\`, or set ANDROID_NDK_HOME.`);
  }

  let javaHome = process.env.JAVA_HOME;
  if (!javaHome) {
    javaHome = [join(sdk, 'jdk'), '/usr/lib/jvm/java-21-openjdk-amd64', '/usr/lib/jvm/java-21-openjdk',
      '/usr/lib/jvm/java-17-openjdk-amd64', '/usr/lib/jvm/java-17-openjdk', '/usr/lib/jvm/default']
      .find((d) => existsSync(d));
  }
  if (!javaHome && which('javac')) {
    const real = capture('sh', ['-c', 'dirname "$(dirname "$(readlink -f "$(command -v javac)")")"']);
    if (real) javaHome = real;
  }
  if (!javaHome) {
    fail('No JDK found — the Android Gradle plugin needs 17-21. '
      + 'Run `npm run setup:android` or set JAVA_HOME.');
  }

  const toolchain = join(ndk, 'toolchains', 'llvm', 'prebuilt', 'linux-x86_64');
  if (!existsSync(toolchain)) fail(`NDK toolchain missing at ${toolchain}`);

  return { sdk, ndk, javaHome, toolchain };
}

function build(args) {
  let buildType = 'debug';
  let target = 'aarch64';
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === 'debug' || a === 'release') buildType = a;
    else if (a === '--target') target = args[++i] ?? fail('--target needs a value');
    else fail(`unknown argument: ${a}`);
  }

  const { sdk, ndk, javaHome, toolchain } = resolveToolchain();
  // The APK carries APP_VERSION, and the server compares it for exact equality,
  // so a stale version here ships an APK every server rejects.
  const version = syncVersion();

  console.log(`ANDROID_HOME:     ${sdk}`);
  console.log(`ANDROID_NDK_HOME: ${ndk}`);
  console.log(`JAVA_HOME:        ${javaHome}`);

  const env = {
    ANDROID_HOME: sdk,
    ANDROID_NDK_HOME: ndk,
    NDK_HOME: ndk,
    JAVA_HOME: javaHome,
    // CMake 4 removed compatibility with project files declaring < 3.5 (libopus).
    CMAKE_POLICY_VERSION_MINIMUM: '3.5',
    // Forces the correct ABI for Opus cross-compilation.
    CMAKE_TOOLCHAIN_FILE_aarch64_linux_android: join(ROOT, 'ndk-arm64-toolchain.cmake'),
  };

  const bin = join(toolchain, 'bin');
  const clang = { aarch64: 'aarch64-linux-android26', armv7: 'armv7a-linux-androideabi26', x86_64: 'x86_64-linux-android26' };
  for (const [short, rustTarget] of Object.entries(ABI_BY_TARGET)) {
    const key = rustTarget.replace(/-/g, '_');
    env[`CC_${key}`] = join(bin, `${clang[short]}-clang`);
    env[`CXX_${key}`] = join(bin, `${clang[short]}-clang++`);
    env[`AR_${key}`] = join(bin, 'llvm-ar');
    env[`RANLIB_${key}`] = join(bin, 'llvm-ranlib');
  }

  // oboe-sys (C++) pulls in __cxa_pure_virtual and friends, which need the C++
  // runtime present at load time. src-tauri/build.rs links against it so the
  // loader knows to open it; this puts the file in the APK.
  const jniLibs = join(CLIENT, 'src-tauri', 'gen', 'android', 'app', 'src', 'main', 'jniLibs', 'arm64-v8a');
  mkdirSync(jniLibs, { recursive: true });
  const libcxx = join(toolchain, 'sysroot', 'usr', 'lib', 'aarch64-linux-android', 'libc++_shared.so');
  if (!existsSync(libcxx)) fail(`the NDK has no libc++_shared.so at ${libcxx}`);
  copyFileSync(libcxx, join(jniLibs, 'libc++_shared.so'));

  if (buildType === 'release' && !existsSync(join(ROOT, 'keystore.properties'))) {
    fail('keystore.properties not found at the repo root.\n'
      + '     Copy keystore.properties.example to keystore.properties and fill in your values.');
  }

  head(`Building VoIPC ${version} for Android (${buildType}, ${target})`);
  npmInstall();
  const cmd = ['tauri', 'android', 'build', '--target', target];
  if (buildType === 'debug') cmd.push('--debug');
  run('npx', cmd, { cwd: CLIENT, env });

  verifyNativeLib(toolchain, target);

  const outBase = join(CLIENT, 'src-tauri', 'gen', 'android', 'app', 'build', 'outputs', 'apk', 'universal');
  const outDir = join(outBase, buildType);
  const apk = existsSync(outDir) ? readdirSync(outDir).find((f) => f.endsWith('.apk')) : null;
  if (!apk) fail(`no APK produced in ${outDir}`);

  mkdirSync(join(ROOT, 'release'), { recursive: true });
  const dest = join(ROOT, 'release', `VoIPC-android-${buildType}.apk`);
  copyFileSync(join(outDir, apk), dest);

  head('Build complete');
  ok(dest);
}

/**
 * The app dies at startup ("cannot locate symbol __cxa_pure_virtual") if the
 * Rust library does not name libc++_shared.so in DT_NEEDED — shipping the file
 * in the APK is not enough, because Android's loader only opens what a library
 * declares. That failure only shows up on a device, so check it at build time.
 */
function verifyNativeLib(toolchain, target) {
  const so = join(ROOT, 'target', target, 'release', 'libvoipc_client_lib.so');
  if (!existsSync(so)) return; // debug build, or a layout we do not know
  const readelf = join(toolchain, 'bin', 'llvm-readelf');
  if (!existsSync(readelf)) return;
  const dynamic = capture(readelf, ['-d', so]);
  if (!dynamic) return; // readelf could not read it; not a reason to fail the build
  if (!dynamic.includes('libc++_shared.so')) {
    fail('the native library does not link libc++_shared.so — the app would crash\n'
      + '     on launch with "cannot locate symbol __cxa_pure_virtual".\n'
      + '     client/src-tauri/build.rs adds this link for Android targets.');
  }
  ok('native library links the C++ runtime');
}

export default function android(task, args) {
  if (task === 'setup:android') setup();
  else build(args);
}
