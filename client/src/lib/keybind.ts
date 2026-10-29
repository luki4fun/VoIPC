// Capturing a key binding, and knowing when one collides with something else.
//
// Lifted out of SettingsPanel so the first-run audio setup can ask for a
// push-to-talk key with the same behaviour rather than a second, slightly
// different one — and so the rules below can be tested without a browser.
//
// The shape a caller uses is: hand every keydown and keyup to a `KeyCapture`
// while it is open, and act on whatever it hands back.

/** What a capture wants the UI to do after one event. */
export type CaptureStep =
  /** Nothing yet; show `hint` ("Ctrl+Alt+…") so the user sees it listening. */
  | { kind: "hint"; hint: string }
  /** Done: this is the binding. */
  | { kind: "binding"; binding: string }
  /** Escape: stop listening, keep the old binding. */
  | { kind: "cancel" }
  /** Tab: not a binding — let it move the focus on (which ends the capture). */
  | { kind: "pass" };

const MODIFIER_KEYS = ["Control", "Shift", "Alt", "Meta"];

/**
 * A binding string as the rest of the app spells it: modifiers in a fixed
 * order, then the physical key code — `"Ctrl+Space"`, `"KeyV"`, `"ShiftLeft"`.
 *
 * `e.code`, not `e.key`: the binding has to survive a keyboard layout change,
 * and the global hook on the Rust side matches physical keys too.
 */
export function formatBinding(e: KeyboardEvent): string {
  const parts: string[] = [];
  if (e.ctrlKey) parts.push("Ctrl");
  if (e.altKey) parts.push("Alt");
  if (e.shiftKey) parts.push("Shift");
  parts.push(e.code);
  return parts.join("+");
}

/**
 * One key-capture session.
 *
 * Two ways to finish, and both are wanted: a normal key ends it on keydown
 * with whatever modifiers were held, and a *lone* modifier ends it on keyup —
 * which is how "push-to-talk is my right Ctrl" gets bound at all. A modifier
 * pressed on the way to a normal key must not commit, hence `sawKey`.
 */
export class KeyCapture {
  private sawKey = false;

  /** The prompt to show before anything has been pressed. */
  static readonly PROMPT = "Press any key or combo...";

  keydown(e: KeyboardEvent): CaptureStep {
    // Escape and Tab are how a keyboard gets out of the field. Bound, they
    // trapped it there: Escape became push-to-talk instead of cancelling, and
    // Tab could never leave. With a modifier held they are still bindable.
    const bare = !e.ctrlKey && !e.altKey && !e.metaKey;
    if (bare && !e.shiftKey && e.key === "Escape") return { kind: "cancel" };
    if (bare && e.key === "Tab") return { kind: "pass" };
    if (MODIFIER_KEYS.includes(e.key)) {
      // `e.ctrlKey` is already true for the modifier being pressed in most
      // browsers, but not all, so the key itself is checked as well.
      const parts: string[] = [];
      if (e.ctrlKey || e.key === "Control") parts.push("Ctrl");
      if (e.altKey || e.key === "Alt") parts.push("Alt");
      if (e.shiftKey || e.key === "Shift") parts.push("Shift");
      return { kind: "hint", hint: parts.join("+") + "+..." };
    }
    this.sawKey = true;
    return { kind: "binding", binding: formatBinding(e) };
  }

  /** `null` while the capture is still waiting for something bindable. */
  keyup(e: KeyboardEvent): { kind: "binding"; binding: string } | null {
    if (MODIFIER_KEYS.includes(e.key) && !this.sawKey) {
      return { kind: "binding", binding: e.code };
    }
    return null;
  }
}

/**
 * Does this binding also trigger one of the app's fixed shortcuts?
 *
 * Ctrl+M mutes and Ctrl+D deafens, wherever the focus is. Binding push-to-talk
 * to one of them used to open the microphone and mute it with the same press,
 * which is the sort of thing somebody discovers mid-sentence. VoiceControls
 * now lets the push-to-talk key win, so this is a warning rather than a
 * refusal — but it should be said before it is chosen, not discovered.
 */
export function shadows(binding: string): "mute" | "deafen" | null {
  const parts = binding.split("+");
  const code = parts[parts.length - 1];
  const withCtrl = parts.includes("Ctrl");
  if (!withCtrl) return null;
  if (code === "KeyM") return "mute";
  if (code === "KeyD") return "deafen";
  return null;
}

/** The part of an element `keyOwner` reads; a real element has all of it. */
export interface KeyTarget {
  tagName: string;
  type?: string;
  isContentEditable?: boolean;
  getAttribute?(name: string): string | null;
  matches?(selector: string): boolean;
}

/** Inputs that take a key for themselves rather than typing it. */
const CONTROL_INPUTS = new Set(["range", "checkbox", "radio", "color", "button", "submit", "reset", "file"]);
const CONTROL_ROLES = new Set(["button", "menuitem", "tab", "checkbox", "switch", "option", "radio"]);

/**
 * Who a key pressed on `target` belongs to, before the window-level shortcuts
 * see it (VoiceKeys):
 *
 * - `"text"`: a field being typed in. Every key is the field's.
 * - `"control"`: a button, select, checkbox, slider… that the keyboard moved
 *   to (`:focus-visible`). Space and Enter are its, so it can be pressed.
 * - `"none"`: anything else, including a control a mouse click left focused —
 *   a click leaves focus on the button it pressed, and push-to-talk on Space
 *   must not stop working because the last click was the mute button.
 *
 * A slider or checkbox used to count as a text field (it is an INPUT), so
 * after dragging the mic gain push-to-talk did nothing until a click elsewhere.
 */
export function keyOwner(target: KeyTarget | null): "text" | "control" | "none" {
  if (!target) return "none";
  const tag = target.tagName;
  if (target.isContentEditable || tag === "TEXTAREA") return "text";
  if (tag === "INPUT" && !CONTROL_INPUTS.has((target.type ?? "text").toLowerCase())) return "text";
  const role = target.getAttribute?.("role") ?? "";
  const control =
    tag === "INPUT" || tag === "BUTTON" || tag === "SELECT" || tag === "SUMMARY" ||
    (tag === "A" && !!target.getAttribute?.("href")) || CONTROL_ROLES.has(role);
  if (!control) return "none";
  let keyboard = false;
  try {
    keyboard = target.matches?.(":focus-visible") ?? false;
  } catch {
    // An engine without :focus-visible: treat focus as the mouse's
  }
  return keyboard ? "control" : "none";
}
