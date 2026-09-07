// Build the Windows client from Linux — no Windows machine, VM, Wine or Proton.
//
// clang-cl and lld-link are native Linux binaries that speak the MSVC ABI;
// cargo-xwin fetches the Microsoft CRT and Windows SDK; FFmpeg comes from a
// prebuilt Windows build because vcpkg cannot produce x64-windows off Windows.
//
// `setup:windows` installs the toolchain, `build:windows` builds the installer.
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CLIENT, ROOT, capture, err, fail, head, info, npmInstall, ok, run, syncVersion, which,
} from '../lib.mjs';

const TARGET = 'x86_64-pc-windows-msvc';

// ffmpeg-next 8.1 (see Cargo.lock) targets FFmpeg 8.x / libavcodec 62. Do not
// move this to an n9.x build without bumping the crate first — the generated
// bindings will not compile.
const EXPECTED_AVCODEC_MAJOR = '62';
const DEFAULT_ASSET = 'ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip';

const home = () => process.env.HOME ?? process.env.USERPROFILE ?? '';
const ffmpegDir = () =>
  process.env.VOIPC_FFMPEG_WIN64 || join(home(), '.local', 'share', 'voipc', 'ffmpeg-win64');
const xwinCacheDir = () => process.env.XWIN_CACHE_DIR || join(home(), '.cache', 'cargo-xwin');

const BUILD_TOOLS = ['cargo-xwin', 'clang-cl', 'lld-link', 'llvm-rc', 'llvm-ar',
  'ninja', 'cmake', 'nasm', 'protoc'];
const SETUP_TOOLS = ['clang', 'clang-cl', 'lld-link', 'llvm-rc', 'llvm-lib', 'llvm-ar',
  'ninja', 'cmake', 'nasm', 'protoc', 'unzip', 'curl'];

const INSTALL_HINTS = [
  'Arch:   sudo pacman -S --needed clang lld llvm ninja cmake nasm protobuf unzip curl',
  'Debian: sudo apt install clang lld llvm ninja-build cmake nasm protobuf-compiler unzip curl',
];

function haveFfmpeg(dir) {
  return existsSync(join(dir, 'include', 'libavcodec', 'avcodec.h'))
    && existsSync(join(dir, 'lib', 'avcodec.lib'))
    && readdirSync(join(dir, 'bin')).some((f) => /^avcodec-\d+\.dll$/i.test(f));
}

/** Header and DLL majors must agree with each other and with ffmpeg-next. */
function checkFfmpegAbi(dir) {
  let headerMajor = null;
  for (const f of ['version_major.h', 'version.h']) {
    const p = join(dir, 'include', 'libavcodec', f);
    if (!existsSync(p)) continue;
    const m = readFileSync(p, 'utf8').match(/define\s+LIBAVCODEC_VERSION_MAJOR\s+(\d+)/);
    if (m) { headerMajor = m[1]; break; }
  }
  const dll = readdirSync(join(dir, 'bin')).find((f) => /^avcodec-\d+\.dll$/i.test(f));
  const dllMajor = dll ? dll.match(/(\d+)/)[1] : null;

  if (headerMajor && dllMajor && headerMajor !== dllMajor) {
    fail(`FFmpeg headers (${headerMajor}) and DLLs (${dllMajor}) disagree — mixed downloads?\n`
      + `     Delete ${dir} and re-run setup.`);
  }
  if (headerMajor === EXPECTED_AVCODEC_MAJOR) {
    ok(`FFmpeg 8.x (libavcodec ${headerMajor}) — matches ffmpeg-next 8.1`);
  } else {
    err(`libavcodec major is ${headerMajor}; ffmpeg-next 8.1 expects ${EXPECTED_AVCODEC_MAJOR}.`);
    err('The Rust bindings will most likely fail to compile.');
    info('Set VOIPC_FFMPEG_ASSET to an n8.x "-shared" build and re-run setup.');
  }
}

function installNsis() {
  if (which('makensis')) {
    ok('NSIS already installed');
    return;
  }
  for (const helper of ['paru', 'yay']) {
    if (which(helper)) {
      info(`installing NSIS from the AUR via ${helper}...`);
      run(helper, ['-S', '--needed', 'nsis']);
      return;
    }
  }
  if (which('apt-get')) {
    info('installing NSIS via apt...');
    run('sudo', ['apt-get', 'install', '-y', 'nsis']);
    return;
  }
  fail('NSIS (makensis) not found and no AUR helper or apt available.\n'
    + '     Arch:   paru -S nsis   (https://aur.archlinux.org/packages/nsis)\n'
    + '     Debian: sudo apt install nsis');
}

function downloadFfmpeg() {
  const dir = ffmpegDir();
  if (haveFfmpeg(dir)) {
    ok(`Windows FFmpeg already present at ${dir}`);
    checkFfmpegAbi(dir);
    return;
  }
  const asset = process.env.VOIPC_FFMPEG_ASSET || DEFAULT_ASSET;
  const url = `https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/${asset}`;

  info(`downloading Windows FFmpeg (${asset}, ~76 MiB)...`);
  const tmp = mkdtempSync(join(tmpdir(), 'voipc-ffmpeg-'));
  try {
    if (run('curl', ['-fL', '--progress-bar', '-o', join(tmp, 'ffmpeg.zip'), url],
      { allowFailure: true }) !== 0) {
      fail(`download failed: ${url}\n`
        + '     Pick an asset from https://github.com/BtbN/FFmpeg-Builds/releases/tag/latest\n'
        + '     and re-run with VOIPC_FFMPEG_ASSET=<asset-name.zip>');
    }
    info('extracting...');
    run('unzip', ['-q', join(tmp, 'ffmpeg.zip'), '-d', join(tmp, 'x')]);

    const inner = readdirSync(join(tmp, 'x'), { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
    if (inner.length !== 1) fail(`unexpected archive layout in ${asset}`);

    rmSync(dir, { recursive: true, force: true });
    mkdirSync(join(dir, '..'), { recursive: true });
    renameSync(join(tmp, 'x', inner[0]), dir);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  if (!haveFfmpeg(dir)) {
    fail('FFmpeg extracted but headers or import libraries are missing.\n'
      + '     Use an asset whose name contains "shared" — those ship include/ and lib/*.lib.');
  }
  ok(`Windows FFmpeg installed to ${dir}`);
  checkFfmpegAbi(dir);
}

function reportEncoders() {
  const dir = ffmpegDir();
  const ffmpegExe = join(dir, 'bin', 'ffmpeg.exe');
  if (!which('wine') || !existsSync(ffmpegExe)) return;
  info('checking HEVC encoders in the Windows FFmpeg (via wine)...');
  const out = capture('wine', [ffmpegExe, '-hide_banner', '-encoders'],
    { env: { WINEDEBUG: '-all' } });
  const found = [...new Set(out.match(/hevc_(nvenc|amf|qsv)|libx265/g) ?? [])];
  if (found.length) ok(`HEVC encoders available: ${found.sort().join(' ')}`);
}

function setup() {
  head('VoIPC Windows cross-build setup');
  requireOrHint(SETUP_TOOLS);
  if (which('wine')) ok("wine found (optional: 'cargo xwin test' and exe smoke tests)");
  else info('wine not found — optional, only needed to run the built exe or tests locally');

  installNsis();

  const installed = capture('rustup', ['target', 'list', '--installed']);
  if (installed.split('\n').includes(TARGET)) ok(`Rust target ${TARGET} already installed`);
  else { info(`adding Rust target ${TARGET}...`); run('rustup', ['target', 'add', TARGET]); }

  if (which('cargo-xwin')) {
    ok(`cargo-xwin already installed (${capture('cargo-xwin', ['--version'])})`);
  } else {
    info('installing cargo-xwin (compiles from source, a few minutes)...');
    run('cargo', ['install', '--locked', 'cargo-xwin']);
  }
  console.log(`     cargo-xwin downloads the Microsoft CRT and Windows SDK on first build into\n`
    + `     ${xwinCacheDir()}. By using it you accept\n`
    + '     https://go.microsoft.com/fwlink/?LinkId=2086102 — the SDK is NOT\n'
    + '     redistributable, so never commit or ship that cache directory.');

  downloadFfmpeg();
  reportEncoders();
  npmInstall();

  head('Setup complete');
  console.log('Build the Windows client with:  npm run build:windows');
}

function requireOrHint(tools) {
  const missing = tools.filter((t) => !which(t));
  for (const t of tools) if (!missing.includes(t)) ok(`${t} found`);
  if (!missing.length) return;
  err(`missing host tools: ${missing.join(', ')}`);
  for (const h of INSTALL_HINTS) console.error(`     ${h}`);
  fail('install the tools above and retry');
}

/**
 * .cargo/config.toml links ucrtd.lib for this target unconditionally — a
 * workaround for audiopus_sys' CMake picking the debug CRT in *debug* builds.
 * Here CMake builds Opus with -MD, so no debug-CRT symbol is ever referenced,
 * but the flag still has to resolve, and cargo merges the config rustflags with
 * cargo-xwin's, so it cannot be dropped from the environment.
 *
 * Supplying the real debug CRT is not an option: ucrtd.lib exports the whole
 * CRT mapped to ucrtbased.dll, and being listed ahead of ucrt.lib it captures
 * every ordinary CRT symbol, leaving an exe that depends on a debug DLL which
 * ships with Visual Studio and exists on no end-user machine. An empty archive
 * satisfies the linker and contributes nothing. If C code ever does reference
 * the debug CRT, this fails loudly at link time instead of producing an exe
 * that cannot start.
 */
function ensureUcrtdStub(env) {
  const ucrtDir = join(xwinCacheDir(), 'xwin', 'sdk', 'lib', 'ucrt', 'x86_64');
  if (!existsSync(ucrtDir)) {
    info('priming the MSVC CRT/SDK cache (first run, downloads ~600 MB)...');
    run('cargo', ['xwin', 'build', '--release', '--target', TARGET,
      '--manifest-path', join(ROOT, 'Cargo.toml'), '-p', 'voipc-protocol'],
    { env, stdio: 'ignore' });
  }
  if (!existsSync(ucrtDir)) fail(`expected the xwin CRT at ${ucrtDir} but it is missing`);
  const stub = join(ucrtDir, 'ucrtd.lib');
  rmSync(stub, { force: true });
  run('llvm-ar', ['rcs', stub]);
}

/** Ship the FFmpeg DLLs next to the exe. x265 and libvpl are linked inside
 *  them in these builds, and turbojpeg and Opus are static, so nothing else is
 *  needed. NVENC and AMF load from the GPU driver at runtime. */
function stageDlls() {
  const binDir = join(ffmpegDir(), 'bin');
  const staging = join(CLIENT, 'src-tauri', 'external-dlls');
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });

  const patterns = [/^av.*\.dll$/i, /^sw.*\.dll$/i, /^postproc.*\.dll$/i,
    /^(lib)?x265.*\.dll$/i, /^(lib)?vpl.*\.dll$/i];
  let staged = 0;
  for (const name of readdirSync(binDir)) {
    if (patterns.some((re) => re.test(name))) {
      copyFileSync(join(binDir, name), join(staging, name));
      staged++;
    }
  }
  if (staged === 0) fail(`no FFmpeg DLLs found in ${binDir} — re-run npm run setup:windows`);
  ok(`staged ${staged} DLLs for bundling`);
  return staging;
}

// DLLs that are part of Windows itself and are never bundled.
const SYSTEM_DLLS = /^(api-ms-win-|kernel32|ntdll|user32|gdi32|ole32|oleaut32|shell32|shlwapi|psapi|ws2_32|bcrypt|bcryptprimitives|comctl32|d3d11|dwmapi|advapi32|dbghelp|version|crypt32|secur32|dxgi|winmm|userenv|ucrtbase|msvcrt|combase|propsys)/i;

function auditImports(exe, staging) {
  if (!which('llvm-readobj')) return;
  const out = capture('llvm-readobj', ['--coff-imports', exe]);
  const imports = [...new Set((out.match(/[A-Za-z0-9_.-]+\.dll/gi) ?? [])
    .map((d) => d.toLowerCase()))].sort();

  if (imports.includes('ucrtbased.dll')) {
    fail(`${exe} imports ucrtbased.dll (the debug CRT).\n`
      + '     It would fail to start on any machine without Visual Studio.');
  }
  const missing = imports.filter((d) => !SYSTEM_DLLS.test(d) && !existsSync(join(staging, d)));
  if (missing.length) fail(`imported DLLs missing from the bundle: ${missing.join(' ')}`);

  console.log('    Imported DLLs:');
  for (const d of imports) console.log(`      ${d}`);
  ok('no debug-CRT dependency; all bundled DLLs present');
}

function build(args) {
  const noBundle = process.env.VOIPC_NO_BUNDLE;
  requireOrHint(noBundle ? BUILD_TOOLS : [...BUILD_TOOLS, 'makensis']);
  if (!existsSync(join(ffmpegDir(), 'lib', 'avcodec.lib'))) {
    fail(`Windows FFmpeg not found at ${ffmpegDir()} — run npm run setup:windows first`);
  }

  const version = syncVersion();
  head(`Building VoIPC ${version} for ${TARGET}`);

  // Anything the host Linux build sets would poison the cross build. cargo-xwin
  // exports the MSVC include and lib paths itself, including the target-suffixed
  // BINDGEN_EXTRA_CLANG_ARGS that ffmpeg-sys-next's bindgen needs; a plain
  // BINDGEN_EXTRA_CLANG_ARGS pointing at GCC headers must not shadow it.
  const env = {
    PKG_CONFIG_ALLOW_CROSS: undefined,
    PKG_CONFIG_PATH: undefined,
    BINDGEN_EXTRA_CLANG_ARGS: undefined,
    CC: undefined,
    CXX: undefined,
    CFLAGS: undefined,
    CXXFLAGS: undefined,

    FFMPEG_DIR: ffmpegDir(),
    // audiopus_sys decides static-vs-dynamic Opus from the *host* OS, so on
    // Linux it would link dynamically and probe the host's pkg-config.
    OPUS_STATIC: '1',
    OPUS_NO_PKG: '1',
    // The CMake crates (Opus, libjpeg-turbo) go through cargo-xwin's generated
    // toolchain file, which needs Ninja.
    CMAKE_GENERATOR: 'Ninja',
    // CMake 4 removed compatibility with project files declaring < 3.5, which
    // libopus does. Same workaround as the Android build.
    CMAKE_POLICY_VERSION_MINIMUM: '3.5',
    XWIN_ARCH: 'x86_64',
    XWIN_CACHE_DIR: xwinCacheDir(),
    // Wrap cargo-xwin's generated CMake toolchain to work around Opus'
    // clang-cl incompatibility (see xwin-msvc-toolchain.cmake). cargo-xwin
    // overwrites the underscored spelling of this variable, but the cmake crate
    // looks up the dashed one first, so this wins.
    [`CMAKE_TOOLCHAIN_FILE_${TARGET}`]: join(ROOT, 'xwin-msvc-toolchain.cmake'),
  };

  // A prebuilt libjpeg-turbo escape hatch for when the vendored CMake+NASM
  // build fails under the cross toolchain (see BUILDING.md).
  if (process.env.VOIPC_TURBOJPEG_WIN64) {
    const tj = process.env.VOIPC_TURBOJPEG_WIN64;
    Object.assign(env, {
      TURBOJPEG_SOURCE: 'explicit',
      TURBOJPEG_LIB_DIR: join(tj, 'lib'),
      TURBOJPEG_INCLUDE_DIR: join(tj, 'include'),
      TURBOJPEG_STATIC: '1',
    });
    info(`using prebuilt turbojpeg from ${tj}`);
  }

  ensureUcrtdStub(env);
  const staging = stageDlls();

  // The NSIS target is selected here rather than with --bundles, because the
  // Linux tauri CLI only accepts Linux bundle names on that flag. It has to go
  // through --config either way: the TAURI_CONFIG environment variable of
  // Tauri v1 is ignored by the v2 CLI.
  //
  // beforeBundleCommand is cleared because bundle-libs is Linux-AppImage only.
  const config = {
    build: { beforeBundleCommand: '' },
    bundle: { resources: { 'external-dlls/*': './' } },
  };
  if (!noBundle) Object.assign(config.bundle, { active: true, targets: ['nsis'] });

  npmInstall();
  const cmd = ['tauri', 'build', '--runner', 'cargo-xwin', '--target', TARGET,
    '--config', JSON.stringify(config)];
  if (noBundle) {
    info('VOIPC_NO_BUNDLE set — building the .exe only, no installer');
    cmd.push('--no-bundle');
  }
  run('npx', [...cmd, ...args], { cwd: CLIENT, env });

  head('Build complete');
  const exe = join(ROOT, 'target', TARGET, 'release', 'voipc-client.exe');
  if (existsSync(exe)) {
    auditImports(exe, staging);
    ok(exe);
  }
  const nsisDir = join(ROOT, 'target', TARGET, 'release', 'bundle', 'nsis');
  if (existsSync(nsisDir)) {
    for (const f of readdirSync(nsisDir)) if (f.endsWith('.exe')) ok(join(nsisDir, f));
  }
  console.log('\nUntested on Linux: WASAPI audio, Windows.Graphics.Capture, NVENC/AMF/QSV.');
  console.log('Verify those on real Windows (see .github/workflows/release.yml).');
}

export default function windowsCross(task, args) {
  if (process.platform === 'win32') {
    fail('this task cross-builds from Linux. On Windows use `npm run build`.');
  }
  if (task === 'setup:windows') setup();
  else build(args);
}
