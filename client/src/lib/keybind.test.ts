// The key-capture rules, which two screens now share (Settings and the
// first-run audio setup). Worth pinning because the interesting half is the
// one nobody tries by hand: binding a bare modifier, and binding something
// that also mutes you.

import { test } from "node:test";
import assert from "node:assert/strict";
import { KeyCapture, formatBinding, shadows } from "./keybind.ts";

/** Enough of a KeyboardEvent for these rules. */
function ev(key: string, code: string, mods: Partial<Record<"ctrl" | "alt" | "shift", boolean>> = {}) {
  return {
    key,
    code,
    ctrlKey: !!mods.ctrl,
    altKey: !!mods.alt,
    shiftKey: !!mods.shift,
  } as KeyboardEvent;
}

test("a binding names the physical key, with its modifiers in a fixed order", () => {
  assert.equal(formatBinding(ev("v", "KeyV")), "KeyV");
  assert.equal(formatBinding(ev(" ", "Space", { ctrl: true })), "Ctrl+Space");
  // Always Ctrl, Alt, Shift — whatever order they were pressed in
  assert.equal(
    formatBinding(ev("V", "KeyV", { shift: true, ctrl: true, alt: true })),
    "Ctrl+Alt+Shift+KeyV",
  );
});

test("a normal key commits on the way down", () => {
  const c = new KeyCapture();
  assert.deepEqual(c.keydown(ev(" ", "Space")), { kind: "binding", binding: "Space" });
});

test("a lone modifier commits on the way up", () => {
  // The case that exists for push-to-talk: "my key is right Ctrl". It cannot
  // commit on keydown, because the user may still be reaching for a letter.
  const c = new KeyCapture();
  const held = c.keydown(ev("Control", "ControlRight", { ctrl: true }));
  assert.deepEqual(held, { kind: "hint", hint: "Ctrl+..." });
  assert.deepEqual(c.keyup(ev("Control", "ControlRight")), {
    kind: "binding",
    binding: "ControlRight",
  });
});

test("a modifier on the way to a real key does not commit by itself", () => {
  const c = new KeyCapture();
  c.keydown(ev("Control", "ControlLeft", { ctrl: true }));
  assert.deepEqual(c.keydown(ev("v", "KeyV", { ctrl: true })), {
    kind: "binding",
    binding: "Ctrl+KeyV",
  });
  // Releasing the Ctrl afterwards must not bind Ctrl over the top of it
  assert.equal(c.keyup(ev("Control", "ControlLeft")), null);
});

test("a push-to-talk key that also mutes you is named before it is chosen", () => {
  assert.equal(shadows("Ctrl+KeyM"), "mute");
  assert.equal(shadows("Ctrl+KeyD"), "deafen");
  assert.equal(shadows("Ctrl+Shift+KeyM"), "mute");
  // Without the Ctrl they are ordinary keys
  assert.equal(shadows("KeyM"), null);
  assert.equal(shadows("Space"), null);
  assert.equal(shadows("Alt+KeyD"), null);
});

test("a field being typed in owns every key", async () => {
  const { keyOwner } = await import("./keybind.ts");
  assert.equal(keyOwner({ tagName: "INPUT", type: "text" }), "text");
  assert.equal(keyOwner({ tagName: "INPUT" }), "text");
  assert.equal(keyOwner({ tagName: "TEXTAREA" }), "text");
  assert.equal(keyOwner({ tagName: "DIV", isContentEditable: true }), "text");
});

test("a slider is not a text field: push-to-talk survives dragging the mic gain", async () => {
  const { keyOwner } = await import("./keybind.ts");
  const mouseFocused = { tagName: "INPUT", type: "range", matches: () => false };
  assert.equal(keyOwner(mouseFocused), "none");
});

test("a control reached by keyboard keeps Space; one a click left focused does not", async () => {
  const { keyOwner } = await import("./keybind.ts");
  const button = (keyboard: boolean) => ({ tagName: "BUTTON", matches: (s: string) => s === ":focus-visible" && keyboard });
  assert.equal(keyOwner(button(true)), "control");
  assert.equal(keyOwner(button(false)), "none");
  const row = { tagName: "DIV", getAttribute: (n: string) => (n === "role" ? "button" : null), matches: () => true };
  assert.equal(keyOwner(row), "control");
  assert.equal(keyOwner({ tagName: "DIV", matches: () => true }), "none");
  assert.equal(keyOwner(null), "none");
});

test("Escape cancels a capture and Tab passes through; with a modifier both still bind", () => {
  const c = new KeyCapture();
  assert.deepEqual(c.keydown(ev("Escape", "Escape") as never), { kind: "cancel" });
  assert.deepEqual(c.keydown(ev("Tab", "Tab") as never), { kind: "pass" });
  assert.deepEqual(c.keydown(ev("Tab", "Tab", { shift: true }) as never), { kind: "pass" });
  const d = new KeyCapture();
  assert.deepEqual(d.keydown(ev("Escape", "Escape", { ctrl: true }) as never), { kind: "binding", binding: "Ctrl+Escape" });
});
