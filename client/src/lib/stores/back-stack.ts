// What "back" closes: every layer that sits over the app, topmost last.
//
// Android's Back button and gesture used to leave the app whatever was open: a
// drawer, the voice popover, a dialog half filled in, a share being watched.
// Each of those registers here while it is open, and Back closes the one on
// top. Escape inside a dialog already does the same through actions/dialog.ts;
// this is the same idea for a key that arrives from outside the page.
//
// A layer that must be answered (a first-run question, a dialog given no
// `onclose`) still registers, with no way to close: Back is then *consumed* by
// it and does nothing, rather than closing whatever lies underneath a dialog
// the person is still looking at.
//
// One that must be answered but is the app's own start, with nothing of the
// person's under it (the connect screen with no server yet, the chat history
// unlock gate), *leaves*: Back puts the app in the background, as it would
// with nothing open, and still closes nothing underneath.
//
// Pure on purpose — no Svelte, no DOM — so back-stack.test.ts can drive it.

interface Layer {
  /** null: this layer cannot be dismissed, it can only be answered */
  close: (() => void) | null;
  /** Asked at each press: true sends Back on to the app (see above). */
  leaves?: () => boolean;
}

const layers: Layer[] = [];

/**
 * Register an open layer. Returns the function that unregisters it, for the
 * layer's own teardown — call it however the layer closed.
 */
export function pushLayer(close: (() => void) | null, leaves?: () => boolean): () => void {
  const layer: Layer = { close, leaves };
  layers.push(layer);
  return () => {
    const i = layers.indexOf(layer);
    if (i >= 0) layers.splice(i, 1);
  };
}

/**
 * Close the topmost layer. True when a layer took the press (closed or not);
 * false when nothing is open, and the caller decides what Back means then —
 * on Android, putting the app in the background with the call still running.
 */
export function back(): boolean {
  const top = layers[layers.length - 1];
  if (!top || top.leaves?.()) return false;
  top.close?.();
  return true;
}

/** How many layers are open. For tests and for the shell's own bookkeeping. */
export function depth(): number {
  return layers.length;
}
