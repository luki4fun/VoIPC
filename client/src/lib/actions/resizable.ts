// Drag a panel wider or narrower.
//
// An action rather than a component: the handle is one div, the behaviour is
// thirty lines, and a component would need a wrapper element in every shell
// that uses it.
//
// Real pointer capture throughout. The house rule in test-ui.mjs exists because
// a bug was once papered over by *stubbing* setPointerCapture in a test; using
// it properly is exactly what that file's realDrag is built to exercise.

export interface ResizeOptions {
  /** Element carrying the CSS variable — normally the shell root. */
  target: HTMLElement | null;
  /** The custom property to write, e.g. "--sidebar-width". */
  prop: string;
  min: number;
  max: number;
  /** Dragging left (or up) grows the panel: a handle on its left (top) edge. */
  invert?: boolean;
  /** "y" sizes a height, dragged up and down. Default "x", a width. */
  axis?: "x" | "y";
  /** Current width, read when a drag starts. */
  current: () => number;
  /** What a double-click on the handle goes back to. */
  defaultWidth: number;
  /** Called once, on release. Persist here — never on every move. */
  onsettle: (px: number) => void;
}

export function resizeHandle(node: HTMLElement, options: ResizeOptions) {
  let opts = options;
  let start = 0;
  let startWidth = 0;
  let width = 0;
  let dragging = false;

  const pos = (e: PointerEvent) => (opts.axis === "y" ? e.clientY : e.clientX);

  function clamp(px: number): number {
    return Math.min(opts.max, Math.max(opts.min, Math.round(px)));
  }

  function onPointerDown(e: PointerEvent) {
    if (e.button !== 0) return;
    e.preventDefault();
    node.setPointerCapture(e.pointerId);
    dragging = true;
    start = pos(e);
    startWidth = opts.current();
    width = startWidth;
    // The centre column is not covered by app.css's user-select rule, so a
    // drag across it would otherwise select the whole conversation.
    document.body.style.userSelect = "none";
    document.body.style.cursor = opts.axis === "y" ? "row-resize" : "col-resize";
  }

  function onPointerMove(e: PointerEvent) {
    if (!dragging) return;
    const delta = opts.invert ? start - pos(e) : pos(e) - start;
    width = clamp(startWidth + delta);
    // Straight to the element, deliberately bypassing Svelte: pushing sixty
    // updates a second through a store would re-run every $derived that reads
    // the panel sizes, on every frame of the drag.
    opts.target?.style.setProperty(opts.prop, `${width}px`);
  }

  function onPointerUp(e: PointerEvent) {
    if (!dragging) return;
    dragging = false;
    if (node.hasPointerCapture(e.pointerId)) node.releasePointerCapture(e.pointerId);
    document.body.style.userSelect = "";
    document.body.style.cursor = "";
    opts.onsettle(width);
  }

  /** Double-click puts it back to the layout's own default. */
  function onDoubleClick() {
    width = opts.defaultWidth;
    opts.target?.style.setProperty(opts.prop, `${width}px`);
    opts.onsettle(width);
  }

  // The keyboard's way to do the same: the handle is a focusable separator
  // that reports its size, and the arrows move it 16px at a time (64px with
  // Shift), Home and End to the limits, Enter back to the default. A drag
  // was the only way before, so a keyboard could not resize anything.
  function describe(px: number) {
    node.setAttribute("aria-valuenow", String(px));
    node.setAttribute("aria-valuemin", String(opts.min));
    node.setAttribute("aria-valuemax", String(opts.max));
  }
  node.tabIndex = 0;
  node.setAttribute("aria-orientation", opts.axis === "y" ? "horizontal" : "vertical");
  describe(opts.current());

  function onKeyDown(e: KeyboardEvent) {
    const step = e.shiftKey ? 64 : 16;
    const grow = opts.axis === "y" ? (opts.invert ? "ArrowUp" : "ArrowDown") : opts.invert ? "ArrowLeft" : "ArrowRight";
    const shrink = opts.axis === "y" ? (opts.invert ? "ArrowDown" : "ArrowUp") : opts.invert ? "ArrowRight" : "ArrowLeft";
    let next: number | null = null;
    if (e.key === grow) next = opts.current() + step;
    else if (e.key === shrink) next = opts.current() - step;
    else if (e.key === "Home") next = opts.min;
    else if (e.key === "End") next = opts.max;
    else if (e.key === "Enter") next = opts.defaultWidth;
    if (next === null) return;
    e.preventDefault();
    width = clamp(next);
    opts.target?.style.setProperty(opts.prop, `${width}px`);
    describe(width);
    opts.onsettle(width);
  }

  node.addEventListener("pointerdown", onPointerDown);
  node.addEventListener("pointermove", onPointerMove);
  node.addEventListener("pointerup", onPointerUp);
  node.addEventListener("pointercancel", onPointerUp);
  node.addEventListener("dblclick", onDoubleClick);
  node.addEventListener("keydown", onKeyDown);

  return {
    update(next: ResizeOptions) {
      opts = next;
      describe(opts.current());
    },
    destroy() {
      node.removeEventListener("keydown", onKeyDown);
      node.removeEventListener("pointerdown", onPointerDown);
      node.removeEventListener("pointermove", onPointerMove);
      node.removeEventListener("pointerup", onPointerUp);
      node.removeEventListener("pointercancel", onPointerUp);
      node.removeEventListener("dblclick", onDoubleClick);
    },
  };
}
