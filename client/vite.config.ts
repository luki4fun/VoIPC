import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Browser build (`vite build --mode web` / `vite --mode web`): the Tauri API
// packages are swapped for the shims in src/web/shims, which route invoke()
// and listen() to the TypeScript backend in src/web/backend. The Tauri build
// (default modes) never touches src/web.
const shim = (name: string) =>
  fileURLToPath(new URL(`./src/web/shims/${name}.ts`, import.meta.url));

const webAliases = [
  { find: /^@tauri-apps\/api\/core$/, replacement: shim("core") },
  { find: /^@tauri-apps\/api\/event$/, replacement: shim("event") },
  { find: /^@tauri-apps\/api\/window$/, replacement: shim("window") },
  { find: /^@tauri-apps\/api\/webviewWindow$/, replacement: shim("webviewWindow") },
  { find: /^@tauri-apps\/plugin-notification$/, replacement: shim("notification") },
];

const here = fileURLToPath(new URL(".", import.meta.url));

/**
 * Which build this is, substituted into the bundle.
 *
 * The version answers "which release" and nothing finer — it moves once per
 * release, and a browser hands back a cached bundle that claims the same one.
 * So two more things are stamped in: the commit says which code, and the build
 * time says which build of that code, which is the only part that still moves
 * while the work is uncommitted — which is most of the time it matters.
 *
 * Under `vite dev` this is the moment the dev server started, not the moment
 * of the last hot reload; there is no build to date in that mode.
 */
function buildStamp() {
  const git = (...args: string[]) => {
    try {
      return execFileSync("git", args, {
        cwd: here,
        stdio: ["ignore", "pipe", "ignore"],
      })
        .toString()
        .trim();
    } catch {
      // No git binary, or no checkout to ask: the release image drops .git
      // (see .dockerignore), so that build stamps VOIPC_BUILD_HASH or nothing.
      return "";
    }
  };
  const pinned = process.env.VOIPC_BUILD_HASH;
  const head = pinned || git("rev-parse", "--short", "HEAD");
  // Tracked edits only — an untracked scratch file is not a different build.
  const dirty =
    !pinned && head && git("status", "--porcelain", "--untracked-files=no");
  return {
    hash: head ? `${head}${dirty ? "+" : ""}` : "no-git",
    // SOURCE_DATE_EPOCH (the commit's time in CI) keeps the bundle
    // reproducible; a local build stamps its own time.
    time: new Date(
      process.env.SOURCE_DATE_EPOCH
        ? Number(process.env.SOURCE_DATE_EPOCH) * 1000
        : Date.now(),
    ).toISOString(),
  };
}

export default defineConfig(({ mode }) => {
  const web = mode === "web";
  const stamp = buildStamp();
  const pkg = JSON.parse(
    readFileSync(new URL("./package.json", import.meta.url), "utf8"),
  );
  return {
    plugins: [svelte()],
    clearScreen: false,
    server: {
      port: 1420,
      strictPort: true,
    },
    envPrefix: ["VITE_", "TAURI_"],
    define: {
      __WEB__: web,
      // The headless self-test (src/web/selftest.ts) connects, joins, writes
      // and opens the microphone with nothing on screen, for any page loaded
      // with `?selftest`. A test build only: `VOIPC_SELFTEST=1 npm run web`.
      __SELFTEST__: web && process.env.VOIPC_SELFTEST === "1",
      __APP_VERSION__: JSON.stringify(pkg.version),
      __BUILD_HASH__: JSON.stringify(stamp.hash),
      __BUILD_TIME__: JSON.stringify(stamp.time),
    },
    resolve: web ? { alias: webAliases } : undefined,
    build: {
      target: "esnext",
      minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
      sourcemap: !!process.env.TAURI_DEBUG,
      // assetsInlineLimit 0: an inlined `data:` URL cannot be passed to
      // audioWorklet.addModule (browsers and our CSP reject it), and the
      // capture worklet is small enough that Vite would inline it.
      ...(web ? { outDir: "dist-web", assetsInlineLimit: 0 } : {}),
    },
  };
});
