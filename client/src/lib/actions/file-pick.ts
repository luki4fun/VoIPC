// A label wrapping a hidden file input, as a button (W3-12).
//
// `<label>Choose…<input type="file" hidden></label>` opens the picker on a click, but
// neither the hidden input nor the label takes focus, so a keyboard or a screen reader
// could not set a picture or bring in emotes at all. `use:filePick` on the label makes
// it one Tab stop that reads as a button and opens the picker on Enter or Space.

/** Whether `key` presses a button. */
export const pressesButton = (key: string): boolean => key === "Enter" || key === " ";

export function filePick(label: HTMLElement) {
  label.tabIndex = 0;
  label.setAttribute("role", "button");
  const onKey = (e: KeyboardEvent) => {
    if (!pressesButton(e.key)) return;
    e.preventDefault();
    label.querySelector<HTMLInputElement>('input[type="file"]')?.click();
  };
  label.addEventListener("keydown", onKey);
  return {
    destroy() {
      label.removeEventListener("keydown", onKey);
    },
  };
}
