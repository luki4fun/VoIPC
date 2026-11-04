// A display name as a relay sent it (1.9). The relay refuses these from members,
// and a client does not take its word for it: a name goes on screen beside the
// real `@name`, so what it must not do is hide that, reorder it or pass for it.

/** Control, zero-width and bidi characters: session.rs `bad_name_char`. */
const BAD_CHAR =
  /[\p{Cc}\u00ad\u115f\u1160\u3164\uffa0\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u;
/** The same for a display name: what joins an emoji or spells a word in some scripts
 *  stays, and is read without when comparing (profile.rs `refused_in_a_display_name`). */
const BAD_IN_A_NAME = /[\p{Cc}\u00ad\u115f\u1160\u3164\uffa0\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u;
const MAX_CHARS = 32;

/** Draws nothing, so it is read without these: profile.rs `draws_nothing`. */
const DRAWS_NOTHING =
  /[\u034f\u17b4\u17b5\u180b-\u180f\u200c\u200d\u2800\ufe00-\ufe0f\ufff0-\ufff8\u{13430}-\u{1343f}\u{1bca0}-\u{1bca3}\u{e0000}-\u{e0fff}]/gu;

/** The name to show, or null to show only the `@name`. */
export function cleanDisplayName(name: unknown): string | null {
  if (typeof name !== "string") return null;
  const shown = name.trim();
  if (!shown || [...shown].length > MAX_CHARS || BAD_IN_A_NAME.test(shown)) return null;
  const bare = shown.replace(DRAWS_NOTHING, "").trim();
  if (!bare) return null;
  // Beside the real `@name`, these would pass for one
  if (/[@\uff20\ufe6b]/.test(bare) || /[#\uff03\ufe5f]\p{N}{4}$/u.test(bare)) return null;
  return shown;
}

/** A word that reads as where a server is: `chat.example.org`, `10.0.0.1:9987`, `:443`,
 *  `[::1]:9987`, `https://anything`, `chat.example.org/join`. `v1.2`, `St.` and `A:B` do
 *  not. profile.rs `looks_like_an_address` is this, and both are tested on one list. */
export function looksLikeAnAddress(raw: string): boolean {
  const word = raw.replace(/^[()[\],;.<>"']+|[()[\],;.<>"']+$/g, "");
  if (word.includes("://")) return true;
  const path = word.split("/")[0];
  if ((path.match(/:/g) ?? []).length >= 2) return true;
  const colon = path.lastIndexOf(":");
  const host = colon >= 0 ? path.slice(0, colon) : path;
  const port = colon >= 0 ? path.slice(colon + 1) : "";
  if (/^\d+$/.test(port)) return true;
  const labels = host.split(".");
  if (labels.length < 2 || !labels.every((l) => /^[A-Za-z0-9-]+$/.test(l))) return false;
  const quad = labels.length === 4 && labels.every((l) => /^\d+$/.test(l));
  return quad || /^[A-Za-z]{2,}$/.test(labels[labels.length - 1]);
}

/** What a server calls itself, or null to go by its address and bookmark alone. A
 *  name that looks like an address, or like another server here, is ignored: the
 *  point of it is to tell this one apart from those. */
export function cleanServerName(name: unknown, others: readonly string[]): string | null {
  if (typeof name !== "string") return null;
  const shown = name.trim();
  if (!shown || [...shown].length > 32 || BAD_CHAR.test(shown)) return null;
  if (shown.split(/\s+/).some(looksLikeAnAddress)) return null;
  return others.some((o) => o.toLowerCase() === shown.toLowerCase()) ? null : shown;
}

export interface WireProfile {
  account: number[];
  name?: string | null;
  picture?: number[] | null;
}

/** Bytes of a stored picture: types.rs `MAX_PROFILE_PICTURE`. */
export const MAX_PICTURE_BYTES = 32 * 1024;

/** What to ask the sanitizer for when only its PNG is wanted, not a file to upload:
 *  as much as it keeps of any picture this size (voipc-media `Profile::Emote`). Asking
 *  for less refuses a detailed picture before anything has tried to make it smaller. */
export const SANITIZE_ONLY_BYTES = 2 << 20;

/** How the upload is tried, largest first, until one fits. */
export const PICTURE_TRIES: readonly { side: number; quality: number }[] = [
  { side: 128, quality: 0.85 },
  { side: 128, quality: 0.6 },
  { side: 96, quality: 0.6 },
  { side: 64, quality: 0.6 },
];

/** The middle square of a picture, for drawing it into a square avatar. */
export function centerSquare(w: number, h: number): { x: number; y: number; side: number } {
  const side = Math.min(w, h);
  return { x: Math.floor((w - side) / 2), y: Math.floor((h - side) / 2), side };
}
