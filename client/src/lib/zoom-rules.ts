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

/** Keep the stage covering a `w` × `h` box: no pan past an edge. */
export function clampView(v: View, w: number, h: number): View {
  const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, v.scale));
  const minX = w - w * scale;
  const minY = h - h * scale;
  return {
    scale,
    x: Math.min(0, Math.max(minX, v.x)),
    y: Math.min(0, Math.max(minY, v.y)),
  };
}

/** Zoom by `factor` keeping the point (px, py) of the box where it is. */
export function zoomAt(v: View, factor: number, px: number, py: number, w: number, h: number): View {
  const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, v.scale * factor));
  const k = scale / v.scale;
  return clampView({ scale, x: px - (px - v.x) * k, y: py - (py - v.y) * k }, w, h);
}

/** Move the stage by (dx, dy). */
export function panBy(v: View, dx: number, dy: number, w: number, h: number): View {
  return clampView({ scale: v.scale, x: v.x + dx, y: v.y + dy }, w, h);
}

/** A double tap: in to TAP_SCALE at the tapped point, or back out to fit. */
export function toggleAt(v: View, px: number, py: number, w: number, h: number): View {
  return v.scale > 1.01 ? FIT : zoomAt(v, TAP_SCALE / v.scale, px, py, w, h);
}
