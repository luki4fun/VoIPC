// When the webview's own right-click menu may show.
//
// Both shells used to cancel it everywhere, which also took Copy, Paste and
// spelling suggestions out of the message box and off selected message text.
// In app chrome it stays cancelled: there the native menu only offers Back,
// Reload and the like, which break a single-page app. Rows with a menu of
// their own (actions/member-menu.ts) cancel it themselves either way.

/**
 * True where the native menu is useful: a text field, or over selected text.
 *
 * `touch`: the menu came from a long press. On a touch screen the press itself
 * selects the word under the finger before the menu is asked for, so a
 * selection says nothing there: outside a text field the app's own menu
 * opens, which has Copy text (D1-01, the owner's call).
 */
export function nativeMenuWanted(target: EventTarget | null, selection: string, touch = false): boolean {
  // Duck-typed rather than `instanceof Element`: the unit tests run in Node,
  // which has no DOM classes
  const el = target && typeof (target as Element).closest === "function" ? (target as Element) : null;
  if (el?.closest("input, textarea, [contenteditable=''], [contenteditable='true']")) return true;
  return !touch && selection.trim() !== "";
}

/** The shells' `oncontextmenu`. */
export function shellContextMenu(e: MouseEvent): void {
  if (nativeMenuWanted(e.target, globalThis.getSelection?.()?.toString() ?? "")) return;
  e.preventDefault();
}
