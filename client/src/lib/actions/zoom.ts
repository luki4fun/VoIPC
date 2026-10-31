// Pinch, wheel and keyboard zoom with pan, for the box a picture is drawn in
// (the screen-share viewer). The maths is lib/zoom-rules.ts; this only turns
// input into it and hands the result back through `onchange` — the component
// owns the transform it draws with.
//
//   two fingers   pinch to zoom, move together to pan
//   one finger    pan, once zoomed in; a double tap zooms in or fits again
//   mouse         wheel zooms at the cursor; drag pans once zoomed in
//   keyboard      + and − zoom, 0 fits, arrows pan (the box is focusable)
//
// The box needs `touch-action: none`, or the browser takes the pinch for page
// zoom before any of this sees it.

import { FIT, clampView, panBy, toggleAt, zoomAt, type View } from "../zoom-rules.js";

export interface ZoomOptions {
  /** Changes when a different picture is shown: the view goes back to fit. */
  key?: unknown;
  onchange: (view: View) => void;
  /** Handed the box's own zoom, for buttons beside it: zoom about its middle
   *  by a factor, or fit it again. */
  controls?: (c: ZoomControls) => void;
}

export interface ZoomControls {
  zoom: (factor: number) => void;
  fit: () => void;
}

/** One press of + or −, or of a zoom button. */
export const ZOOM_STEP = 1.25;
const DOUBLE_TAP_MS = 300;
const DOUBLE_TAP_SLOP = 24;
const MOVE_SLOP = 4;

export function zoomable(node: HTMLElement, opts: ZoomOptions) {
  let options = opts;
  let key = opts.key;
  let view: View = FIT;
  const pointers = new Map<number, { x: number; y: number }>();
  let moved = false;
  let lastTap = { t: 0, x: 0, y: 0 };

  const rect = () => node.getBoundingClientRect();
  const set = (v: View) => {
    view = v;
    options.onchange(v);
  };

  function down(e: PointerEvent) {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    try {
      node.setPointerCapture(e.pointerId);
    } catch {
      // A pointer the browser has already taken back; nothing to capture
    }
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pointers.size === 1) moved = false;
  }

  function move(e: PointerEvent) {
    const prev = pointers.get(e.pointerId);
    if (!prev) return;
    const r = rect();
    if (pointers.size >= 2) {
      const [a, b] = [...pointers.values()];
      const before = { d: Math.hypot(a.x - b.x, a.y - b.y), mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2 };
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      const [c, d] = [...pointers.values()];
      const after = { d: Math.hypot(c.x - d.x, c.y - d.y), mx: (c.x + d.x) / 2, my: (c.y + d.y) / 2 };
      if (before.d > 0) {
        const zoomed = zoomAt(view, after.d / before.d, after.mx - r.left, after.my - r.top, r.width, r.height);
        set(panBy(zoomed, after.mx - before.mx, after.my - before.my, r.width, r.height));
      }
      moved = true;
      return;
    }
    const dx = e.clientX - prev.x;
    const dy = e.clientY - prev.y;
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (Math.abs(dx) + Math.abs(dy) > MOVE_SLOP) moved = true;
    if (view.scale > 1 && (e.pointerType !== "mouse" || (e.buttons & 1) === 1)) {
      set(panBy(view, dx, dy, r.width, r.height));
    }
  }

  function up(e: PointerEvent) {
    const was = pointers.get(e.pointerId);
    if (!was) return;
    pointers.delete(e.pointerId);
    if (e.type !== "pointerup" || e.pointerType !== "touch" || moved || pointers.size > 0) return;
    const now = e.timeStamp;
    if (now - lastTap.t < DOUBLE_TAP_MS && Math.hypot(e.clientX - lastTap.x, e.clientY - lastTap.y) < DOUBLE_TAP_SLOP) {
      const r = rect();
      set(toggleAt(view, e.clientX - r.left, e.clientY - r.top, r.width, r.height));
      lastTap = { t: 0, x: 0, y: 0 };
    } else {
      lastTap = { t: now, x: e.clientX, y: e.clientY };
    }
  }

  function wheel(e: WheelEvent) {
    e.preventDefault();
    const r = rect();
    set(zoomAt(view, Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top, r.width, r.height));
  }

  const zoomMiddle = (factor: number) => {
    const r = rect();
    set(zoomAt(view, factor, r.width / 2, r.height / 2, r.width, r.height));
  };
  opts.controls?.({ zoom: zoomMiddle, fit: () => set(FIT) });

  function keydown(e: KeyboardEvent) {
    const r = rect();
    const cx = r.width / 2;
    const cy = r.height / 2;
    let next: View | null = null;
    if (e.key === "+" || e.key === "=") next = zoomAt(view, ZOOM_STEP, cx, cy, r.width, r.height);
    else if (e.key === "-" || e.key === "_") next = zoomAt(view, 1 / ZOOM_STEP, cx, cy, r.width, r.height);
    else if (e.key === "0") next = FIT;
    else if (view.scale > 1 && e.key.startsWith("Arrow")) {
      const step = 48;
      const dx = e.key === "ArrowLeft" ? step : e.key === "ArrowRight" ? -step : 0;
      const dy = e.key === "ArrowUp" ? step : e.key === "ArrowDown" ? -step : 0;
      next = panBy(view, dx, dy, r.width, r.height);
    }
    if (next) {
      e.preventDefault();
      set(next);
    }
  }

  // A box that changes size (a window resize, the chat opening beside it)
  // keeps a view that still covers it
  const resize = new ResizeObserver(() => {
    const r = rect();
    const fitted = clampView(view, r.width, r.height);
    if (fitted.x !== view.x || fitted.y !== view.y || fitted.scale !== view.scale) set(fitted);
  });
  resize.observe(node);

  node.addEventListener("pointerdown", down);
  node.addEventListener("pointermove", move);
  node.addEventListener("pointerup", up);
  node.addEventListener("pointercancel", up);
  node.addEventListener("lostpointercapture", up);
  node.addEventListener("wheel", wheel, { passive: false });
  node.addEventListener("keydown", keydown);

  return {
    update(next: ZoomOptions) {
      options = next;
      if (next.key !== key) {
        key = next.key;
        set(FIT);
      }
    },
    destroy() {
      resize.disconnect();
      node.removeEventListener("pointerdown", down);
      node.removeEventListener("pointermove", move);
      node.removeEventListener("pointerup", up);
      node.removeEventListener("pointercancel", up);
      node.removeEventListener("lostpointercapture", up);
      node.removeEventListener("wheel", wheel);
      node.removeEventListener("keydown", keydown);
    },
  };
}
