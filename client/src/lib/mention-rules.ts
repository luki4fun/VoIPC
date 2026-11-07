// `@everyone`, `@here` and `@&badge` (1.9): tokens in the end-to-end text, which
// a relay cannot read and so cannot check. Each client honours them from a member
// the relay says holds `voipc:mention_all`, decides once when a message arrives,
// and keeps the answer on the message (`power`): who held it then is gone by the
// time the conversation is read again. A stored copy, or history another member
// hands over, never carries it, so nothing rings for what happened while away.

import { mentionNames, mentionsName, parse } from "./markdown.ts";
import { shortName } from "./username.ts";

/** `@&Mod Team` is that badge, and not `&Mod` followed by a word. */
const longestFirst = (a: string, b: string) => b.length - a.length;

/** Every token a holder may use here. A badge goes by `&`, so it is never mistaken
 *  for somebody's name, and the group behind it stays unnamed. */
export function powerTokens(styles: readonly { badge: string }[]): string[] {
  return ["everyone", "here", ...[...new Set(styles.map((s) => `&${s.badge}`))].sort(longestFirst)];
}

/**
 * The names of ours a message can ring on: the full one, and the short one where only we go
 * by it (R2-11). Where the list is everyone online rather than who is in the channel
 * (`everyoneOnline`), one stranger with the same short name would silence it in every
 * channel at once, so then it rings for both of them.
 */
export function ownMentionNames(own: string, people: readonly string[], everyoneOnline: boolean): string[] {
  const short = shortName(own);
  if (everyoneOnline) return short === own ? [own] : [own, short];
  return mentionNames([...people, own]).filter((n) => n === own || n === short);
}

/** The tokens that mean this person. */
export function tokensForMe(myBadges: readonly string[]): string[] {
  return ["everyone", "here", ...myBadges.map((b) => `&${b}`)];
}

/** Whether `content` uses any of `tokens` outside code, read as `known` reads it
 *  (what the server has: a longer badge must not read as a shorter one of ours).
 *  A quote only repeats what somebody else said: quoting an `@everyone` must not
 *  ring everyone again. */
export function callsOn(content: string, tokens: readonly string[], known: readonly string[] = tokens): boolean {
  if (tokens.length === 0 || !content.includes("@")) return false;
  const names = [...new Set([...known, ...tokens])].sort(longestFirst);
  const tree = parse(content, { names });
  return tokens.some((n) => mentionsName(tree, n, false));
}

/**
 * Whether a message just arrived with its sender's power behind it: from a holder,
 * using a token, in a channel where people have names at all.
 */
export function hasPower(
  content: string,
  sender: { holder: boolean; isAdmin: boolean },
  channel: { anonymous: boolean },
  tokens: readonly string[],
): boolean {
  return !channel.anonymous && (sender.holder || sender.isAdmin) && callsOn(content, tokens);
}
