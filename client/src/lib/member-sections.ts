// The member list's sections and a badge's look, from the server's group order
// (`GroupStyles`, 1.9). A colour is a number on the wire and a hex string only
// here, so nothing a relay says ever reaches a style attribute as text.

import { avatarInk } from "./avatar.ts";

export interface GroupStyle {
  badge: string;
  color: number | null;
}

export interface MemberSection<T> {
  /** Not the label: a group may call its badge "Online". */
  key: string;
  label: string;
  members: T[];
}

/** Each badge's place. Two groups with one badge: the higher one. */
function ranks(styles: readonly GroupStyle[]): Map<string, number> {
  const out = new Map<string, number>();
  styles.forEach((s, i) => {
    if (!out.has(s.badge)) out.set(s.badge, i);
  });
  return out;
}

/** A row's badges in the server's order; any it did not name last. */
export function badgesInOrder(badges: readonly string[], styles: readonly GroupStyle[]): string[] {
  const rank = ranks(styles);
  const at = (b: string) => rank.get(b) ?? Infinity;
  // Once each: a row draws them keyed by their text, and a repeat stops the page
  return [...new Set(badges)].sort((a, b) => at(a) - at(b));
}

/**
 * Everybody under their top group, top groups first, and whoever has none under
 * `rest` at the end. An empty section is not listed.
 */
export function sectionsOf<T extends { badges?: string[] }>(
  members: readonly T[],
  styles: readonly GroupStyle[],
  rest: string,
): MemberSection<T>[] {
  const rank = ranks(styles);
  const held = new Map<number, T[]>();
  const others: T[] = [];
  for (const m of members) {
    const top = Math.min(...(m.badges ?? []).map((b) => rank.get(b) ?? Infinity));
    if (top === Infinity) {
      others.push(m);
    } else {
      held.set(top, [...(held.get(top) ?? []), m]);
    }
  }
  const out: MemberSection<T>[] = [...held.keys()]
    .sort((a, b) => a - b)
    .map((r) => ({ key: `group-${r}`, label: styles[r].badge, members: held.get(r)! }));
  if (others.length > 0) out.push({ key: "rest", label: rest, members: others });
  return out;
}

export function hexOf(color: number): string {
  return `#${(color & 0xffffff).toString(16).padStart(6, "0")}`;
}

export function colorOf(hex: string): number | null {
  return /^#[0-9a-f]{6}$/i.test(hex) ? parseInt(hex.slice(1), 16) : null;
}

/** A pill in this colour, in the ink that reads on it. */
export function pillStyle(color: number): string {
  const bg = hexOf(color);
  return `background: ${bg}; color: ${avatarInk(bg)};`;
}

/** The pill's style. Empty: the theme's own. */
export function badgeStyle(badge: string, styles: readonly GroupStyle[]): string {
  const color = styles.find((s) => s.badge === badge)?.color;
  return color === null || color === undefined ? "" : pillStyle(color);
}
