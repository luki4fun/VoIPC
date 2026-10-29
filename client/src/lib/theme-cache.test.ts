// The start-up palette cache: it paints what was remembered, and nothing that
// is not a token and a colour — it is read off disk before anything else runs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { paintRememberedTheme, rememberTheme } from "./theme-cache.ts";

function fakePage() {
  const store = new Map<string, string>();
  const props = new Map<string, string>();
  const root = { style: { setProperty: (k: string, v: string) => props.set(k, v) }, dataset: {} as Record<string, string> };
  Object.assign(globalThis, {
    localStorage: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
    },
    document: { documentElement: root },
  });
  return { store, props, root };
}

test("a remembered palette paints at start", () => {
  const { props, root } = fakePage();
  rememberTheme({ "--bg-primary": "#1a1a2e", "--shadow-menu": "0 8px 24px rgba(0, 0, 0, 0.4)" }, true);
  paintRememberedTheme();
  assert.equal(props.get("--bg-primary"), "#1a1a2e");
  assert.equal(props.get("--shadow-menu"), "0 8px 24px rgba(0, 0, 0, 0.4)");
  assert.equal(root.dataset.theme, "dark");
});

test("a light one sets the light theme", () => {
  const { root } = fakePage();
  rememberTheme({ "--bg-primary": "#ffffff" }, false);
  paintRememberedTheme();
  assert.equal(root.dataset.theme, "light");
});

test("nothing remembered, or something damaged, paints nothing", () => {
  const { store, props, root } = fakePage();
  paintRememberedTheme();
  store.set("voipc.theme-cache", "{not json");
  paintRememberedTheme();
  store.set("voipc.theme-cache", JSON.stringify({ tokens: null, dark: true }));
  paintRememberedTheme();
  assert.equal(props.size, 0);
  assert.equal(root.dataset.theme, undefined);
});

test("only token names and plain colour values get through", () => {
  const { store, props } = fakePage();
  store.set(
    "voipc.theme-cache",
    JSON.stringify({
      tokens: {
        "--bg-primary": "#123456",
        color: "red",
        "--bg-secondary": "url(https://example.invalid/x.png)",
        "--accent": "#fff; background: red",
      },
      dark: true,
    }),
  );
  paintRememberedTheme();
  assert.deepEqual([...props.keys()], ["--bg-primary"]);
});

test("a name that is not a palette token is not painted, however plain", () => {
  const { store, props } = fakePage();
  store.set(
    "voipc.theme-cache",
    JSON.stringify({ tokens: { "--hit": "4px", "--z-modal": "1", "--bg-primary": "#123456", "--made-up": "#fff" }, dark: true }),
  );
  paintRememberedTheme();
  assert.deepEqual([...props.keys()], ["--bg-primary"]);
});
