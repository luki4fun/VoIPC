import { mount } from "svelte";
import "./app.css";

const params = new URLSearchParams(window.location.search);

/**
 * Start applying the saved appearance preferences to this window.
 *
 * Every window that renders UI needs this, and the screen-share pop-out is a
 * separate webview with its own document — without its own call it would be the
 * one window still painted in the palette the user just changed away from.
 * Imported lazily so the `?selftest` path, which renders no components, does
 * not pull the theme machinery in at all.
 *
 * `loadOwnConfig` is for the pop-out, which has no App.svelte to hydrate the
 * stores for it. In the main window App.svelte's own `load_config` feeds
 * `hydrateUiPrefs`, so asking a second time would be one more round trip for an
 * answer already on its way. Until it arrives the defaults apply, and the
 * defaults are what app.css already paints.
 */
async function startAppearance(loadOwnConfig = false) {
  const { hydrateUiPrefs, startTheming } = await import("./lib/stores/ui-prefs");
  startTheming();
  if (!loadOwnConfig) return;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const config = await invoke<{ ui_prefs?: unknown }>("load_config");
    hydrateUiPrefs(config.ui_prefs);
  } catch (e) {
    // A config that will not load is a cosmetic loss here, never a reason not
    // to show the stream.
    console.warn("Could not load appearance settings:", e);
  }
}

if (__WEB__ && params.has("selftest")) {
  // Headless end-to-end test of the web client (see test-web.sh); web build only
  import("./web/selftest").then((m) => m.run(params));
} else if (params.get("popout") === "screenshare") {
  startAppearance(true);
  import("./lib/components/ScreenSharePopout.svelte").then(({ default: Comp }) => {
    mount(Comp, {
      target: document.getElementById("app")!,
      props: { sharerName: params.get("sharer_name") || "Unknown" },
    });
  });
} else {
  startAppearance();
  import("./App.svelte").then(({ default: App }) => {
    mount(App, {
      target: document.getElementById("app")!,
    });
  });
}
