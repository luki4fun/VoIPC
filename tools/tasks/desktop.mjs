// Desktop client: `dev` (debug + run) and `build` (release), for the OS you are on.
//
// Replaces build.sh, dev.sh, build.ps1 and dev.ps1. Those four differed only in
// one verb and, on Windows, in a block of DLL staging.
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  CLIENT, ROOT, IS_WINDOWS, capture, fail, head, info, npmInstall, ok, run, syncVersion,
} from '../lib.mjs';

/** Newest entry of a directory, by name. */
function newestDir(dir) {
  if (!existsSync(dir)) return null;
  const entries = readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
  return entries.length ? entries[entries.length - 1] : null;
}

/**
 * Reproduce what vcvarsall.bat sets up, the way build.ps1 did: locate MSVC and
 * the Windows SDK through vswhere and hand the paths to cl.exe, the linker and
 * bindgen's clang.
 */
function windowsMsvcEnv() {
  const env = {};
  const pf86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
  const pf = process.env['ProgramFiles'] ?? 'C:\\Program Files';

  const vcpkgRoot = process.env.VCPKG_ROOT || join(pf, 'vcpkg');
  const vcpkgInstalled = join(vcpkgRoot, 'installed', 'x64-windows');
  env.VCPKG_ROOT = vcpkgRoot;
  env.FFMPEG_DIR = vcpkgInstalled;
  env.PKG_CONFIG_PATH = join(vcpkgInstalled, 'lib', 'pkgconfig');
  env.LIBCLANG_PATH = process.env.LIBCLANG_PATH || join(pf, 'LLVM', 'bin');

  const vswhere = join(pf86, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
  let vsPath = null;
  let msvcVer = null;
  let vsMajor = null;
  if (existsSync(vswhere)) {
    vsPath = capture(vswhere, [
      '-latest', '-products', '*',
      '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
      '-property', 'installationPath',
    ]);
    const version = capture(vswhere, [
      '-latest', '-products', '*',
      '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
      '-property', 'installationVersion',
    ]);
    vsMajor = version ? Number.parseInt(version.split('.')[0], 10) : null;
    if (vsPath) {
      const verFile = join(vsPath, 'VC', 'Auxiliary', 'Build', 'Microsoft.VCToolsVersion.default.txt');
      if (existsSync(verFile)) msvcVer = readFileSync(verFile, 'utf8').trim();
    }
  }
  if (!vsPath) {
    info('vswhere found no Visual Studio C++ toolset — relying on an already-configured shell');
  }

  const includes = [join(vcpkgInstalled, 'include')];
  const libs = [join(vcpkgInstalled, 'lib')];

  if (vsPath && msvcVer) {
    const msvcRoot = join(vsPath, 'VC', 'Tools', 'MSVC', msvcVer);
    // Force MSVC so the cmake-based crates don't pick up a clang from PATH.
    const cl = join(msvcRoot, 'bin', 'Hostx64', 'x64', 'cl.exe');
    env.CC = cl;
    env.CXX = cl;
    includes.push(join(msvcRoot, 'include'));
    libs.push(join(msvcRoot, 'lib', 'x64'));
  }

  const sdkRoot = join(pf86, 'Windows Kits', '10');
  const sdkVer = newestDir(join(sdkRoot, 'Include'));
  if (sdkVer) {
    includes.push(
      join(sdkRoot, 'Include', sdkVer, 'ucrt'),
      join(sdkRoot, 'Include', sdkVer, 'shared'),
      join(sdkRoot, 'Include', sdkVer, 'um'),
    );
    libs.push(join(sdkRoot, 'Lib', sdkVer, 'ucrt', 'x64'), join(sdkRoot, 'Lib', sdkVer, 'um', 'x64'));
  }

  env.INCLUDE = [...includes, process.env.INCLUDE ?? ''].filter(Boolean).join(';');
  env.LIB = [...libs, process.env.LIB ?? ''].filter(Boolean).join(';');

  // bindgen's clang needs the MSVC/SDK headers spelled out; the paths contain
  // spaces, so each -I is quoted.
  const clangArgs = [join(vcpkgInstalled, 'include')];
  if (vsPath && msvcVer) clangArgs.push(join(vsPath, 'VC', 'Tools', 'MSVC', msvcVer, 'include'));
  if (sdkVer) clangArgs.push(join(sdkRoot, 'Include', sdkVer, 'ucrt'));
  env.BINDGEN_EXTRA_CLANG_ARGS = clangArgs.map((p) => `"-I${p}"`).join(' ');

  // Only pin the CMake generator for VS 2022, whose name we know. On anything
  // newer, leave it unset so CMake picks the newest installed toolset itself
  // instead of failing on a hardcoded name.
  if (!process.env.CMAKE_GENERATOR && vsMajor === 17) {
    env.CMAKE_GENERATOR = 'Visual Studio 17 2022';
  }

  // vcpkg's DLLs must be findable at runtime when the app is started from here.
  const vcpkgBin = join(vcpkgInstalled, 'bin');
  if (!(process.env.PATH ?? '').includes(vcpkgBin)) {
    env.PATH = `${vcpkgBin};${process.env.PATH ?? ''}`;
  }
  return env;
}

/** Copy the vcpkg DLLs the app loads at runtime into the bundle staging dir. */
function stageWindowsDlls(env) {
  const vcpkgBin = join(env.VCPKG_ROOT, 'installed', 'x64-windows', 'bin');
  const staging = join(CLIENT, 'src-tauri', 'external-dlls');
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });

  if (!existsSync(vcpkgBin)) fail(`vcpkg binaries not found at ${vcpkgBin} — run .\\setup.ps1`);

  // FFmpeg, x265 and the Intel oneVPL dispatcher that ffmpeg[qsv] pulls in.
  // NVENC and AMF need no DLLs; they load from the GPU driver at runtime.
  const patterns = [/^av.*\.dll$/i, /^sw.*\.dll$/i, /^(lib)?x265.*\.dll$/i,
    /^postproc.*\.dll$/i, /^(lib)?vpl.*\.dll$/i];
  let staged = 0;
  for (const name of readdirSync(vcpkgBin)) {
    if (patterns.some((re) => re.test(name))) {
      copyFileSync(join(vcpkgBin, name), join(staging, name));
      staged++;
    }
  }
  ok(`staged ${staged} DLLs for bundling`);
}

export default function desktop(task, args) {
  const isDev = task === 'dev';
  const version = syncVersion();
  head(`${isDev ? 'Running' : 'Building'} VoIPC ${version} for ${process.platform}`);

  const env = {};
  let config;
  // tauri.conf.json leaves bundle.active unset, which means "off" — so without
  // this a release build produces the bare binary and silently skips both the
  // installers and the beforeBundleCommand hook.
  const userPickedBundles = args.some((a) => a === '--bundles' || a === '-b');
  // `tauri build --debug` writes to target/debug instead of target/release.
  const profile = args.includes('--debug') ? 'debug' : 'release';

  if (IS_WINDOWS) {
    Object.assign(env, windowsMsvcEnv());
    if (!isDev) stageWindowsDlls(env);
    // Ship the staged DLLs next to the exe, and disable the Linux-only
    // AppImage hook. This has to go through --config: the TAURI_CONFIG
    // environment variable of Tauri v1 is ignored by the v2 CLI.
    config = {
      build: { beforeBundleCommand: '' },
      bundle: { resources: { 'external-dlls/*': './' } },
    };
    if (!isDev) {
      config.bundle.active = true;
      if (!userPickedBundles) config.bundle.targets = ['nsis'];
    }
  } else {
    // bindgen's bundled clang cannot find the GCC system headers on its own.
    const gccInclude = capture('gcc', ['-print-file-name=include']);
    if (gccInclude) env.BINDGEN_EXTRA_CLANG_ARGS = `-I${gccInclude}`;

    if (!isDev) {
      // bundle-libs stages the app's shared libraries into appimage-libs/;
      // this mapping is what copies them into the AppImage. It used to be set
      // through TAURI_CONFIG, which the v2 CLI ignores, so the staged
      // libraries were silently dropped.
      config = {
        bundle: {
          active: true,
          linux: { appimage: { files: { '/usr/lib': 'appimage-libs/' } } },
        },
      };
      // rpm is not built: it needs rpmbuild and nothing in the project ships one.
      if (!userPickedBundles) config.bundle.targets = ['deb', 'appimage'];
      // linuxdeploy and appimagetool cannot use FUSE in a container or on a
      // runner; extracting instead works everywhere.
      env.APPIMAGE_EXTRACT_AND_RUN = process.env.APPIMAGE_EXTRACT_AND_RUN ?? '1';
      // linuxdeploy ships its own binutils, which is older than the libraries
      // on rolling distributions and aborts on the .relr.dyn section that
      // RELR-relocated libraries carry. Distribution libraries arrive stripped
      // anyway, so skipping the step costs almost nothing.
      env.NO_STRIP = process.env.NO_STRIP ?? '1';

      // Copying the mapped files into an AppDir left over from a previous run
      // fails with EEXIST, so a rebuild only works from a clean one.
      for (const dir of ['appimage', 'appimage_deb']) {
        rmSync(join(ROOT, 'target', profile, 'bundle', dir), { recursive: true, force: true });
      }
    }
  }

  npmInstall();

  const cmd = ['tauri', isDev ? 'dev' : 'build'];
  if (config) cmd.push('--config', JSON.stringify(config));
  run('npx', [...cmd, ...args], { cwd: CLIENT, env });

  if (isDev) return;

  head('Build complete');
  const bundleDir = join(ROOT, 'target', profile, 'bundle');
  for (const kind of ['appimage', 'deb', 'rpm', 'nsis', 'msi']) {
    const dir = join(bundleDir, kind);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir)) {
      if (/\.(AppImage|deb|rpm|exe|msi)$/i.test(f)) ok(join(dir, f));
    }
  }
}
