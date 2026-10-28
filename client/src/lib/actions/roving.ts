// Arrow keys along a tab list or a radio group (R5-11).
//
// Every tab and every radio was a Tab stop of its own, and the arrows did
// nothing: the opposite of what a screen reader or keyboard user expects from
// those roles. `use:roving` on the group makes the chosen item its one Tab
// stop; the arrows, Home and End move along the items and pick the one they
// land on, as the WAI-ARIA tabs (automatic activation) and radio group
// patterns do. Picking is the item's own click, so nothing about what a pick
// means moves in here. A disabled item is passed over.

const ITEM = '[role="tab"], [role="radio"]';

/** Where `key` moves from item `at` of `count`, or null for a key that is not ours. */
export function step(at: number, count: number, key: string): number | null {
  if (count === 0) return null;
  switch (key) {
    case "ArrowRight":
    case "ArrowDown":
      return (at + 1) % count;
    case "ArrowLeft":
    case "ArrowUp":
      return (at - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

export function roving(node: HTMLElement) {
  const items = () =>
    [...node.querySelectorAll<HTMLElement>(ITEM)].filter((el) => !(el as HTMLButtonElement).disabled);
  const chosen = (el: HTMLElement) =>
    el.getAttribute("aria-selected") === "true" || el.getAttribute("aria-checked") === "true";

  // One Tab stop: the chosen item, or the first while none is
  function sync() {
    const all = [...node.querySelectorAll<HTMLElement>(ITEM)];
    const stop = all.find(chosen) ?? items()[0];
    for (const el of all) el.tabIndex = el === stop ? 0 : -1;
  }

  function onkeydown(e: KeyboardEvent) {
    const list = items();
    const at = list.indexOf(e.target as HTMLElement);
    if (at < 0) return;
    const to = step(at, list.length, e.key);
    if (to === null) return;
    e.preventDefault();
    list[to].focus();
    list[to].click();
  }

  sync();
  const watch = new MutationObserver(sync);
  watch.observe(node, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["aria-selected", "aria-checked", "disabled"],
  });
  node.addEventListener("keydown", onkeydown);

  return {
    destroy() {
      watch.disconnect();
      node.removeEventListener("keydown", onkeydown);
    },
  };
}
