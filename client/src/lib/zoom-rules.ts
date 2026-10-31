// Zoom and pan of a picture in a box — the screen-share viewer's, so a 1080p
// desktop is readable on a phone. Pure maths, tested in zoom-rules.test.ts;
// actions/zoom.ts turns pointers, the wheel and keys into calls to these.
//
// The picture is drawn with `transform: translate(x, y) scale(scale)` and
// `transform-origin: 0 0` on a stage the size of the box, so (x, y) is where
// the stage's top-left corner lands, and it never leaves a gap: at any scale
// the stage still covers the box.

export interface View {
  scale: number;
  x: number;
  y: number;
}

export const MIN_SCALE = 1;
export const MAX_SCALE = 6;
/** What a double tap zooms to from the fitted picture */
export const TAP_SCALE = 2.5;

export const FIT: View = { scale: 1, x: 0, y: 0 };

/** Where in the box the picture itself is drawn, unzoomed. */
export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** A `nw` × `nh` picture fitted into a `w` × `h` box and centred, as
 *  `object-fit: contain` draws it. */
export function containRect(nw: number, nh: number, w: number, h: number): Rect {
  const k = Math.min(w / nw, h / nh);
  return { x: (w - nw * k) / 2, y: (h - nh * k) / 2, w: nw * k, h: nh * k };
}

/** Keep the picture (`c`, by default the whole stage) covering a `w` × `h`
 *  box where it is bigger than it, and centred where it is not: no pan past
 *  its edge into the empty bands beside it. */
export function clampView(v: View, w: number, h: number, c: Rect = { x: 0, y: 0, w, h }): View {
  const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, v.scale));
  return { scale, x: axis(v.x, scale, w, c.x, c.w), y: axis(v.y, scale, h, c.y, c.h) };
}

/** One axis: the picture spans `t + s·o` to `t + s·(o + len)` on screen. */
function axis(t: number, s: number, box: number, o: number, len: number): number {
  if (s * len <= box) return (box - s * len) / 2 - s * o;
  return Math.min(0 - s * o, Math.max(box - s * (o + len), t));
}

/** Zoom by `factor` keeping the point (px, py) of the box where it is. */
export function zoomAt(v: View, factor: number, px: number, py: number, w: number, h: number, c?: Rect): View {
  const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, v.scale * factor));
  const k = scale / v.scale;
  return clampView({ scale, x: px - (px - v.x) * k, y: py - (py - v.y) * k }, w, h, c);
}

/** Move the stage by (dx, dy). */
export function panBy(v: View, dx: number, dy: number, w: number, h: number, c?: Rect): View {
  return clampView({ scale: v.scale, x: v.x + dx, y: v.y + dy }, w, h, c);
}

/** A double tap: in to TAP_SCALE at the tapped point, or back out to fit. */
export function toggleAt(v: View, px: number, py: number, w: number, h: number, c?: Rect): View {
  return v.scale > 1.01 ? FIT : zoomAt(v, TAP_SCALE / v.scale, px, py, w, h, c);
}
