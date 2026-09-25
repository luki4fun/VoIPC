// A username is "name#1234": the four-digit tag is what lets two people on a
// server go by the same name. It is part of the name everywhere a name is kept
// or compared — the server's uniqueness, a conversation's key — and shown only
// where somebody asks who exactly this is.

const TAG = /^(.*)#(\d{4})$/s;

/** The name and its tag; `tag` is "" for a name without one (a `Guest-1234`
 *  pseudonym, a name from before tags). */
export function splitName(full: string): { name: string; tag: string } {
  const m = TAG.exec(full);
  return m ? { name: m[1], tag: m[2] } : { name: full, tag: "" };
}

/** The name as shown: without its tag. */
export function shortName(full: string): string {
  return splitName(full).name;
}

export function randomTag(): string {
  return String(Math.floor(Math.random() * 10000)).padStart(4, "0");
}

/** `name` with `tag`, or with a random tag when `tag` is not four digits. */
export function withTag(name: string, tag: string): string {
  return `${name.trim()}#${/^\d{4}$/.test(tag) ? tag : randomTag()}`;
}
