// Deterministic avatar colour from a username, shared by the channel list,
// the direct-message list, the member list, the server rail and the virtual
// room.
//
// No greens and no mint: mint is the speaking ring drawn around an avatar, and
// a green face inside a green ring is a ring nobody sees. Every colour carries
// its initials in whichever ink reads on it (avatarInk), which for this set is
// the dark one throughout — white on any of them is under 3.6:1, and on the
// old yellow it was 1.3:1, the initials of a server in the rail with nothing
// else to name it.

import { contrastRatio } from "./theme.ts";

const AVATAR_COLORS = [
  "#ff7a6b", // coral
  "#f5b041", // amber
  "#5aa9f0", // sky
  "#9b7cf0", // violet
  "#e56aa6", // rose
  "#c9a77c", // sand
  "#6c86c9", // slate blue
  "#d98a4e", // copper
];

const INK_DARK = "#0b0d12";
const INK_LIGHT = "#ffffff";

export function avatarColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

/** The ink for initials on `background`: whichever of dark and white reads better. */
export function avatarInk(background: string): string {
  return contrastRatio(INK_DARK, background) >= contrastRatio(INK_LIGHT, background)
    ? INK_DARK
    : INK_LIGHT;
}

/** `background` and `color` for an avatar, as one inline style. */
export function avatarStyle(name: string): string {
  const bg = avatarColor(name);
  return `background: ${bg}; color: ${avatarInk(bg)};`;
}
