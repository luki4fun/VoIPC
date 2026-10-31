// Where a pop-up goes (a message's menu, the reactions picker, an emote's
// card): at the point it was opened from, kept on what is visible. Pure, so
// the arithmetic is tested; actions/fit.ts measures and applies it.

export interface Box {
  /** Where it would open: its top-left corner. */
  x: number;
  y: number;
  /** Its measured size. */
  w: number;
  h: number;
  /** The line it goes above instead when there is no room under `y`
   *  (the top of what opened it). */
  up: number;
}

/** What is visible, already inset by the margin and the system bars. */
export interface View {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

/** Below if it fits, else above `up`, else as low as it can be while its top
 *  stays on screen; sideways, moved in from either edge. */
export function place(b: Box, v: View): { x: number; y: number } {
  const x = Math.max(v.left, Math.min(b.x, v.right - b.w));
  let y = b.y;
  if (y + b.h > v.bottom) y = b.up - b.h >= v.top ? b.up - b.h : Math.max(v.top, v.bottom - b.h);
  return { x: Math.round(x), y: Math.round(Math.max(v.top, y)) };
}
