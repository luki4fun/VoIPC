// `use:focusNow` on a field that appears in place of what was pressed (a
// rename box where its name was): it takes the focus, its text selected.
// Svelte's `autofocus` does nothing there, because the pressed button still
// has the focus when the field mounts.

import { tick } from "svelte";

export function focusNow(node: HTMLInputElement | HTMLTextAreaElement) {
  queueMicrotask(() => {
    node.focus({ preventScroll: false });
    node.select();
  });
}

/** A row's ✕ that takes its row away (a closed conversation): the focus goes
 *  to the row after it, else the one before, instead of falling to <body>. */
export async function closeRow(e: MouseEvent, close: () => void): Promise<void> {
  const button = e.currentTarget as HTMLElement;
  const row = button.closest(".channel-row");
  const near = [row?.nextElementSibling, row?.previousElementSibling];
  close();
  await tick();
  if (button.isConnected) return;
  for (const n of near) {
    const to = n?.isConnected ? n.querySelector<HTMLElement>("button") : null;
    if (to) return to.focus();
  }
}
