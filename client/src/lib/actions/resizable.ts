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
  /** Dragging left grows the panel (a handle on the panel's left edge). */
  invert?: boolean;
  /** Current width, read when a drag starts. */
  current: () => number;
  /** What a double-click on the handle goes back to. */
  defaultWidth: number;
  /** Called once, on release. Persist here — never on every move. */
  onsettle: (px: number) => void;
}

export function resizeHandle(node: HTMLElement, options: ResizeOptions) {
  let opts = options;
  let startX = 0;
  let startWidth = 0;
  let width = 0;
  let dragging = false;

  function clamp(px: number): number {
    return Math.min(opts.max, Math.max(opts.min, Math.round(px)));
  }

  function onPointerDown(e: PointerEvent) {
    if (e.button !== 0) return;
    e.preventDefault();
    node.setPointerCapture(e.pointerId);
    dragging = true;
    startX = e.clientX;
    startWidth = opts.current();
    width = startWidth;
    // The centre column is not covered by app.css's user-select rule, so a
    // drag across it would otherwise select the whole conversation.
    document.body.style.userSelect = "none";
    document.body.style.cursor = "col-resize";
  }

  function onPointerMove(e: PointerEvent) {
    if (!dragging) return;
    const delta = opts.invert ? startX - e.clientX : e.clientX - startX;
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

  node.addEventListener("pointerdown", onPointerDown);
  node.addEventListener("pointermove", onPointerMove);
  node.addEventListener("pointerup", onPointerUp);
  node.addEventListener("pointercancel", onPointerUp);
  node.addEventListener("dblclick", onDoubleClick);

  return {
    update(next: ResizeOptions) {
      opts = next;
    },
    destroy() {
      node.removeEventListener("pointerdown", onPointerDown);
      node.removeEventListener("pointermove", onPointerMove);
      node.removeEventListener("pointerup", onPointerUp);
      node.removeEventListener("pointercancel", onPointerUp);
      node.removeEventListener("dblclick", onDoubleClick);
    },
  };
}
