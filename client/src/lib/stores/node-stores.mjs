// Lets a test under Node's own runner load a store that normally only a bundler
// can: `await import("./node-stores.mjs")`, then `await import("./chat.ts")`, both
// dynamic, since a static import is resolved before anything here has run.
//
// Relative imports written `.js` or without an extension find their `.ts`, the
// Tauri API is a stand-in whose `invoke` writes down what it was asked (the test
// reads `invoked()`) and answers nothing unless a test sets `globalThis.__answer`,
// and `__WEB__`, which Vite defines, is the desktop's.

import { registerHooks } from "node:module";
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

globalThis.__WEB__ = false;
globalThis.__SELFTEST__ = false;
globalThis.__invoked = [];

/** Every `invoke` so far, as `[command, args]`. */
export const invoked = () => globalThis.__invoked;

const TAURI = `
  export const invoke = async (command, args) => { globalThis.__invoked.push([command, args]); return globalThis.__answer?.(command, args); };
  export const listen = async () => () => {};
  export const emit = async () => {};
  export const convertFileSrc = (path) => path;
  export const getCurrentWindow = () => ({});
  export const isPermissionGranted = async () => false;
`;

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith("@tauri-apps/")) return { url: `tauri-stand-in:${specifier}`, shortCircuit: true };
    if (specifier.startsWith(".") && context.parentURL?.startsWith("file:")) {
      const path = fileURLToPath(new URL(specifier, context.parentURL));
      for (const candidate of [path.replace(/\.js$/, ".ts"), `${path}.ts`]) {
        if (existsSync(candidate)) return { url: pathToFileURL(candidate).href, shortCircuit: true };
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.startsWith("tauri-stand-in:")) return { format: "module", source: TAURI, shortCircuit: true };
    return next(url, context);
  },
});
