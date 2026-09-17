// Discord's phone layout: three panes side by side, dragged with a thumb.
//
// No gesture library. Pointer events plus one rule — do not take over until the
// movement is clearly horizontal — and `touch-action: pan-y` on the track so the
// browser keeps vertical scrolling native and at full speed. That lever is the
// same one ChannelList pulls with `touch-action: manipulation`, whose comment
// names the Android bug that made it impossible to join a channel at all.
//
// The decision of where to settle is a pure function, exported and tested,
// because it is the part with arithmetic in it and none of it needs a browser.

/** 0 = the channel drawer, 1 = chat, 2 = the member drawer. */
export type Pane = 0 | 1 | 2;

/** Movement before we decide whether this is our gesture or the scroller's. */
const SLOP_PX = 8;
/** Past this fraction of a pane, a slow drag still changes pane. */
const COMMIT_FRACTION = 0.25;
/** Or a flick this fast does, however short. px per millisecond. */
const FLICK_VELOCITY = 0.4;

/**
 * Which pane a gesture ends on.
 *
 * `dx` is the total movement (positive = dragged right, revealing the pane on
 * the left), `vx` its velocity at release, `width` the viewport width.
 */
export function settle(from: Pane, dx: number, vx: number, width: number): Pane {
  const far = Math.abs(dx) > width * COMMIT_FRACTION;
  const fast = Math.abs(vx) > FLICK_VELOCITY;
  if (!far && !fast) return from;
  // A flick and a drag can disagree — flinging left while having dragged right
  // happens at the end of a correction. The velocity is the more recent
  // intention, so it wins where there is one.
  const direction = fast ? Math.sign(vx) : Math.sign(dx);
  const next = from - direction;
  return Math.min(2, Math.max(0, next)) as Pane;
}

/**
 * Velocity, smoothed as the finger moves.
 *
 * Exported so it can be tested without a browser, and because getting it wrong
 * is invisible until somebody is holding a phone: measuring at release instead
 * reads zero for a flick (the finger has already stopped) and reads a flick for
 * a slow drag that happens to end without one last move.
 */
export function sampleVelocity(previous: number, dx: number, dt: number): number {
  if (dt <= 0) return previous;
  return 0.7 * (dx / dt) + 0.3 * previous;
}

export interface SwipeOptions {
  /** Which pane is showing. */
  pane: () => Pane;
  /** Live offset in px while dragging; null means "back to the pane". */
  onmove: (offsetPx: number | null) => void;
  onsettle: (pane: Pane) => void;
  /** Off on a desktop-width window, where the panes are all visible at once. */
  enabled: () => boolean;
}

export function swipeable(node: HTMLElement, options: SwipeOptions) {
  let opts = options;
  let startX = 0;
  let startY = 0;
  let lastX = 0;
  let lastAt = 0;
  let deciding = false;
  let dragging = false;
  /** See sampleVelocity — smoothed while moving, read at release. */
  let velocity = 0;

  function onPointerDown(e: PointerEvent) {
    if (!opts.enabled() || e.pointerType === "mouse") return;
    // Anything that does its own dragging says so. The mixer's faders are
    // vertical range inputs inside a pane, and the room's avatars take pointer
    // capture of their own.
    if ((e.target as HTMLElement).closest("[data-no-swipe]")) return;
    startX = lastX = e.clientX;
    startY = e.clientY;
    lastAt = e.timeStamp;
    velocity = 0;
    deciding = true;
    dragging = false;
  }

  function onPointerMove(e: PointerEvent) {
    if (!deciding && !dragging) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;

    if (deciding) {
      if (Math.abs(dx) < SLOP_PX && Math.abs(dy) < SLOP_PX) return;
      deciding = false;
      // More vertical than horizontal: it was a scroll. Let go entirely rather
      // than fighting the scroller for the rest of the gesture.
      if (Math.abs(dy) >= Math.abs(dx)) return;
      dragging = true;
      node.setPointerCapture(e.pointerId);
    }

    const dt = e.timeStamp - lastAt;
    velocity = sampleVelocity(velocity, e.clientX - lastX, dt);
    lastX = e.clientX;
    lastAt = e.timeStamp;
    opts.onmove(dx);
  }

  function onPointerUp(e: PointerEvent) {
    deciding = false;
    if (!dragging) return;
    dragging = false;
    if (node.hasPointerCapture(e.pointerId)) node.releasePointerCapture(e.pointerId);

    const dx = e.clientX - startX;
    opts.onmove(null);
    opts.onsettle(settle(opts.pane(), dx, velocity, node.clientWidth || window.innerWidth));
  }

  node.addEventListener("pointerdown", onPointerDown, { passive: true });
  node.addEventListener("pointermove", onPointerMove, { passive: true });
  node.addEventListener("pointerup", onPointerUp);
  node.addEventListener("pointercancel", onPointerUp);

  return {
    update(next: SwipeOptions) {
      opts = next;
    },
    destroy() {
      node.removeEventListener("pointerdown", onPointerDown);
      node.removeEventListener("pointermove", onPointerMove);
      node.removeEventListener("pointerup", onPointerUp);
      node.removeEventListener("pointercancel", onPointerUp);
    },
  };
}
