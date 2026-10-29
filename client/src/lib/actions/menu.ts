// One behaviour for every pop-up menu — the member menu, the server rail's,
// the server header's — the way actions/dialog.ts is one behaviour for every
// dialog. A menu used to be a positioned div of buttons: focus stayed behind
// it even when the keyboard opened it, the arrow keys did nothing, Tab walked
// into the page underneath, and closing it lost your place.
//
// `use:menu` on the menu's box gives it role="menu" and its buttons
// role="menuitem"; puts focus on the first item; moves with the arrow keys,
// Home and End; closes on Escape or Tab and hands focus back to what opened
// it; and is a layer on the back stack, so Android's Back closes it too.

import { pushLayer } from "../stores/back-stack.js";

export interface MenuOptions {
  /** How the menu closes. Required: a menu nobody can close is a dialog. */
  onclose: () => void;
  /** Its accessible name, e.g. the person it is about. */
  label?: string;
}

const ITEMS = 'button:not([disabled]), input:not([disabled]), [role="menuitem"]:not([aria-disabled="true"])';

export function menu(node: HTMLElement, opts: MenuOptions) {
  let options = opts;
  const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;

  node.setAttribute("role", "menu");
  if (opts.label) node.setAttribute("aria-label", opts.label);
  const items = () =>
    [...node.querySelectorAll<HTMLElement>(ITEMS)].filter((el) => el.getClientRects().length > 0);
  for (const b of node.querySelectorAll<HTMLElement>("button")) {
    if (!b.hasAttribute("role")) b.setAttribute("role", "menuitem");
  }

  queueMicrotask(() => {
    if (!node.contains(document.activeElement)) items()[0]?.focus();
  });

  function onkeydown(e: KeyboardEvent) {
    const list = items();
    const at = list.indexOf(document.activeElement as HTMLElement);
    const go = (i: number) => {
      e.preventDefault();
      list[(i + list.length) % list.length]?.focus();
    };
    // A slider keeps its own arrows
    const onSlider = (document.activeElement as HTMLInputElement | null)?.type === "range";
    if (e.key === "ArrowDown" && !onSlider) go(at + 1);
    else if (e.key === "ArrowUp" && !onSlider) go(at - 1);
    else if (e.key === "Home") go(0);
    else if (e.key === "End") go(list.length - 1);
    else if (e.key === "Escape" || e.key === "Tab") {
      e.preventDefault();
      e.stopPropagation();
      options.onclose();
    }
  }
  node.addEventListener("keydown", onkeydown);
  const offBack = pushLayer(() => options.onclose());

  return {
    update(next: MenuOptions) {
      options = next;
      if (next.label) node.setAttribute("aria-label", next.label);
    },
    destroy() {
      offBack();
      node.removeEventListener("keydown", onkeydown);
      if (before?.isConnected) before.focus();
    },
  };
}
