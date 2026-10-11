// A member row opens the member menu: right click, left click, or Enter/Space
// once it has focus.
//
// One action for every list that shows people — the modern member list, the
// members nested under voice channels and the classic list — so they cannot
// drift on which clicks open it. Your own row opens nothing (openUserMenu
// refuses yourself), so it gets neither the pointer nor a tab stop.

import { openUserMenu } from "../stores/user-menu.js";
import type { UserInfo } from "../types.js";

export interface MemberMenuOptions {
  user: UserInfo;
  /** From the "Online" group: see `UserMenu.idle`. */
  idle?: boolean;
  /** Our own row. */
  self: boolean;
}

export function memberMenu(node: HTMLElement, options: MemberMenuOptions) {
  let opts = options;

  function open(e: Event, x: number, y: number) {
    e.preventDefault();
    e.stopPropagation();
    openUserMenu(opts.user, x, y, opts.idle);
  }

  function onClick(e: MouseEvent) {
    // A button in the row (⋮, watch) is its own click. Svelte 5 delegates
    // `onclick` to the document root, so this listener runs first, and
    // stopping the event here would swallow that button's handler whole.
    if (opts.self || (e.target as Element).closest("button") !== null) return;
    open(e, e.clientX, e.clientY);
  }

  function onContextMenu(e: MouseEvent) {
    open(e, e.clientX, e.clientY);
  }

  function onKeyDown(e: KeyboardEvent) {
    // The row's own keys only: Enter on the ⋮ button inside it is that
    // button's click, and would otherwise open the menu twice.
    if (opts.self || e.target !== node || (e.key !== "Enter" && e.key !== " ")) return;
    // A key has no position; the menu opens under the row instead.
    const r = node.getBoundingClientRect();
    open(e, r.left + 16, r.bottom);
  }

  function sync() {
    node.classList.toggle("has-menu", !opts.self);
    if (opts.self) {
      node.removeAttribute("role");
      node.removeAttribute("tabindex");
    } else {
      node.setAttribute("role", "button");
      node.setAttribute("tabindex", "0");
    }
  }

  sync();
  node.addEventListener("click", onClick);
  node.addEventListener("contextmenu", onContextMenu);
  node.addEventListener("keydown", onKeyDown);

  return {
    update(next: MemberMenuOptions) {
      opts = next;
      sync();
    },
    destroy() {
      node.removeEventListener("click", onClick);
      node.removeEventListener("contextmenu", onContextMenu);
      node.removeEventListener("keydown", onKeyDown);
    },
  };
}
