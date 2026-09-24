/**
 * Which build of the client this is.
 *
 * The version on its own cannot answer the question this exists for — after a
 * rebuild, is the code in front of me the code I just built? It moves once per
 * release, so between two releases every build claims the same one, and a
 * protocol version that has not moved says nothing either. In the browser the
 * question is sharper still: a bundle served from cache is indistinguishable
 * from a fresh one, and the page looks exactly the same either way.
 *
 * So: the commit says which code, and the build time says which build of it —
 * the only part that still moves while the work is uncommitted.
 *
 * All three are substituted at build time by vite.config.ts.
 */
export const appVersion: string = __APP_VERSION__;

/**
 * Short commit the bundle was built from, with a trailing `+` when the tree
 * had uncommitted edits — or `no-git` when it was built outside a checkout.
 */
export const buildHash: string = __BUILD_HASH__;

/** When the bundle was built, ISO 8601, by the clock of the machine that built it. */
export const buildTime: string = __BUILD_TIME__;

/** The build time in the reader's own timezone, to the minute. */
export function buildTimeLocal(): string {
  const at = new Date(buildTime);
  if (Number.isNaN(at.getTime())) return buildTime;
  return at.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** The whole identity on one line — what a bug report should carry. */
export function buildLine(): string {
  return `VoIPC ${appVersion} · ${buildHash} · built ${buildTimeLocal()}`;
}
