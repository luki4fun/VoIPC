// When a message was written, as the message list shows it: a divider where
// the day changes, and the whole date on hover. Times were HH:MM only, so a
// conversation kept across days read as one afternoon. Pure, for
// chat-time.test.ts; the locale and "now" are parameters there.

/** The local calendar day a timestamp falls on, comparable with `===`. */
export function dayKey(timestamp: number): string {
  const d = new Date(timestamp);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

/** "Today", "Yesterday", or the date — with the year only when it is not this one. */
export function dayLabel(timestamp: number, now = Date.now(), locale?: string): string {
  if (dayKey(timestamp) === dayKey(now)) return "Today";
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (dayKey(timestamp) === dayKey(yesterday.getTime())) return "Yesterday";
  const d = new Date(timestamp);
  const sameYear = d.getFullYear() === new Date(now).getFullYear();
  return d.toLocaleDateString(locale, {
    weekday: "long",
    day: "numeric",
    month: "long",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

/** The whole moment, for a title: date and time to the second. */
export function fullTime(timestamp: number, locale?: string): string {
  return new Date(timestamp).toLocaleString(locale, { dateStyle: "full", timeStyle: "medium" });
}
