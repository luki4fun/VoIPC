import { mount } from "svelte";
import "./app.css";

const params = new URLSearchParams(window.location.search);

if (params.get("popout") === "screenshare") {
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
