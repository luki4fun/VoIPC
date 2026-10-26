// One modal behaviour for every overlay (H5-04).
//
// Each dialog used to be a styled `div`: nothing announced it, focus stayed
// wherever it was behind the overlay, Tab walked out of it into the page
// underneath, and Escape did nothing. `use:dialog` on the dialog's box gives it
// the role, `aria-modal` and a name taken from its title; puts focus inside
// (on what asks for it, else the first control); keeps Tab inside; closes on
// Escape when it is given an `onclose`; and hands focus back on the way out.
// It is also a layer on the back stack (stores/back-stack.ts), so Android's
// Back closes it the way Escape does — or, with no `onclose`, does nothing.

import { pushLayer } from "../stores/back-stack.js";

export interface DialogOptions {
  /** What Escape does. Without it Escape is left alone: a step that must be answered. */
  onclose?: () => void;
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const TITLE = "h1, h2, h3, h4, .dialog-title";

let titles = 0;

/** A backdrop's click handler: it closes only for a click on the backdrop
 *  itself, so the box on top needs no handler of its own to stop the click. */
export function backdrop(close: () => void) {
  return (e: MouseEvent) => {
    if (e.target === e.currentTarget) close();
  };
}

export function dialog(node: HTMLElement, opts: DialogOptions = {}) {
  let options = opts;
  const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;

  node.setAttribute("role", "dialog");
  node.setAttribute("aria-modal", "true");
  const named = node.hasAttribute("aria-label") || node.hasAttribute("aria-labelledby");
  // Named after its title, again whenever a step swaps the title out
  const label = () => {
    const title = node.querySelector<HTMLElement>(TITLE);
    if (!title) return node.removeAttribute("aria-labelledby");
    title.id ||= `dialog-title-${++titles}`;
    node.setAttribute("aria-labelledby", title.id);
  };
  const relabel = named ? null : new MutationObserver(label);
  if (relabel) {
    label();
    relabel.observe(node, { childList: true, subtree: true });
  }
  // Focusable itself, for a dialog with nothing else to focus
  if (!node.hasAttribute("tabindex")) node.tabIndex = -1;

  const focusables = () =>
    [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.getClientRects().length > 0);

  // After the content's own autofocus has had its turn
  queueMicrotask(() => {
    if (node.contains(document.activeElement)) return;
    (node.querySelector<HTMLElement>("[autofocus]") ?? focusables()[0] ?? node).focus();
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && options.onclose) {
      e.preventDefault();
      e.stopPropagation(); // the innermost dialog only
      options.onclose();
      return;
    }
    if (e.key !== "Tab") return;
    const list = focusables();
    if (list.length === 0) {
      e.preventDefault();
      return;
    }
    const first = list[0];
    const last = list[list.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === node)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  }
  node.addEventListener("keydown", onkeydown);
  // Read through `options` at close time: `update` can hand it a new onclose
  const offBack = pushLayer(() => options.onclose?.());

  return {
    update(next: DialogOptions) {
      options = next;
    },
    destroy() {
      offBack();
      relabel?.disconnect();
      node.removeEventListener("keydown", onkeydown);
      if (before?.isConnected) before.focus();
    },
  };
}
