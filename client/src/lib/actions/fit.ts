// `use:fit={up}` on a `position: fixed` pop-up placed at its opening point:
// once it is drawn, its real size moves it onto what is visible (place-rules).
// "Visible" is the visual viewport — a phone's keyboard takes the bottom of
// it (D2-13) — less the system bars an edge-to-edge web view draws under.

import { place } from "../place-rules.js";

const MARGIN = 8;

/** The safe-area insets as the page sees them (zero on a desktop). */
function insets(): { top: number; bottom: number } {
  const probe = document.createElement("div");
  probe.style.cssText =
    "position:fixed;top:0;left:0;visibility:hidden;pointer-events:none;" +
    "padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)";
  document.body.append(probe);
  const s = getComputedStyle(probe);
  const out = { top: parseFloat(s.paddingTop) || 0, bottom: parseFloat(s.paddingBottom) || 0 };
  probe.remove();
  return out;
}

export function fit(node: HTMLElement, up: number) {
  const apply = (above: number) => {
    const r = node.getBoundingClientRect();
    const vv = globalThis.visualViewport;
    const left = vv?.offsetLeft ?? 0;
    const top = vv?.offsetTop ?? 0;
    const safe = insets();
    const at = place(
      { x: r.left, y: r.top, w: r.width, h: r.height, up: above },
      {
        left: left + MARGIN,
        top: top + MARGIN + safe.top,
        right: left + (vv?.width ?? innerWidth) - MARGIN,
        bottom: top + (vv?.height ?? innerHeight) - MARGIN - safe.bottom,
      },
    );
    node.style.left = `${at.x}px`;
    node.style.top = `${at.y}px`;
  };
  apply(up);
  return {
    update(next: number) {
      apply(next);
    },
  };
}
