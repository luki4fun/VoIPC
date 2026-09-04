import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
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

export default defineConfig(({ mode }) => {
  const web = mode === "web";
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
