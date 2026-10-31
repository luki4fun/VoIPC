// `use:focusNow` on a field that appears in place of what was pressed (a
// rename box where its name was): it takes the focus, its text selected.
// Svelte's `autofocus` does nothing there, because the pressed button still
// has the focus when the field mounts.

export function focusNow(node: HTMLInputElement | HTMLTextAreaElement) {
  queueMicrotask(() => {
    node.focus({ preventScroll: false });
    node.select();
  });
}
