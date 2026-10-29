// The names a palette sets, apart from the rest of theme.ts: theme-cache.ts
// checks a remembered palette against them at start, before main.ts loads
// the theme machinery (lazily, on purpose). theme.ts re-exports both.

/** A custom property this module owns. Sizing tokens are not palette. */
export type TokenName =
  | "--bg-primary"
  | "--bg-secondary"
  | "--bg-tertiary"
  | "--bg-hover"
  | "--text-primary"
  | "--text-secondary"
  | "--accent"
  | "--accent-hover"
  | "--success"
  | "--danger"
  | "--warning"
  | "--border"
  | "--speaking"
  | "--well"
  | "--scrollbar"
  | "--shadow-menu"
  | "--shadow-dialog"
  | "--on-accent"
  | "--on-danger"
  | "--on-success"
  | "--on-warning"
  | "--text-muted"
  | "--scrim"
  | "--focus-ring"
  | "--code-keyword"
  | "--code-string"
  | "--code-comment"
  | "--code-number"
  | "--code-fn";

/** Every token a palette must define. A palette missing one is a type error. */
export const TOKENS: readonly TokenName[] = [
  "--bg-primary",
  "--bg-secondary",
  "--bg-tertiary",
  "--bg-hover",
  "--text-primary",
  "--text-secondary",
  "--accent",
  "--accent-hover",
  "--success",
  "--danger",
  "--warning",
  "--border",
  "--speaking",
  "--well",
  "--scrollbar",
  "--shadow-menu",
  "--shadow-dialog",
  "--on-accent",
  "--on-danger",
  "--on-success",
  "--on-warning",
  "--text-muted",
  "--scrim",
  "--focus-ring",
  "--code-keyword",
  "--code-string",
  "--code-comment",
  "--code-number",
  "--code-fn",
];
