import { mount } from "svelte";
import "./app.css";

const params = new URLSearchParams(window.location.search);

if (__WEB__ && params.has("selftest")) {
  // Headless end-to-end test of the web client (see test-web.sh); web build only
  import("./web/selftest").then((m) => m.run(params));
} else if (params.get("popout") === "screenshare") {
  import("./lib/components/ScreenSharePopout.svelte").then(({ default: Comp }) => {
    mount(Comp, {
      target: document.getElementById("app")!,
      props: { sharerName: params.get("sharer_name") || "Unknown" },
    });
  });
} else {
  import("./App.svelte").then(({ default: App }) => {
    mount(App, {
      target: document.getElementById("app")!,
    });
  });
}
