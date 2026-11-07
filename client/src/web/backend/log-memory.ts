// How far this browser has read an account's stored log. The browser keeps no
// messages between page loads, so a read cursor from an earlier page says
// nothing about what this page holds: a fresh page reads the conversations
// back from the server's copies (docs/ACCOUNTS.md). What that page had read
// still counts for one thing: those messages are not news.

/** The cursors of a `LogMemory` (voipc_crypto::sync), per conversation. */
type Cursors = Record<string, number>;

export interface PageMemory {
  /** The `LogMemory` this page's sessions go on from (JSON), or none, without who was named. */
  json: string | null;
  /** Who was named (`readers` and `named`, JSON), kept apart: log-named.ts. */
  named: string | null;
  /** What earlier pages had read: frozen at page load. */
  seen: Cursors;
}

function parse(json: string): (Record<string, unknown> & { cursors?: Cursors }) | null {
  try {
    const o = JSON.parse(json);
    return o && typeof o === "object" ? o : null;
  } catch {
    return null;
  }
}

/** A fresh page, from what `localStorage` kept: no cursors to go on from, and
 *  everything else (the vault's generations) as it was, with who was named as
 *  `named` holds it. A memory from before they moved holds them itself. */
export function freshPage(stored: string | null, named: string | null = null): PageMemory {
  const memory = stored === null ? null : parse(stored);
  if (!memory) return { json: null, named, seen: {} };
  const { readers, named: lists, ...rest } = memory;
  const inside = readers || lists ? JSON.stringify({ readers: readers ?? {}, named: lists ?? {} }) : null;
  return { json: JSON.stringify({ ...rest, cursors: {} }), named: named ?? inside, seen: memory.cursors ?? {} };
}

/** The whole `LogMemory` a session starts from. */
export function wholeMemory(page: PageMemory): string | null {
  if (!page.named) return page.json;
  return JSON.stringify({ cursors: {}, ...parse(page.json ?? "{}"), ...parse(page.named) });
}

/** What `localStorage` keeps of a session's memory: per conversation the
 *  further of it and what earlier pages read, or a reload right after a
 *  partial read would call the rest new. */
export function keepMemory(json: string, seen: Cursors): string {
  const memory = parse(json);
  if (!memory) return json;
  const cursors: Cursors = { ...seen };
  for (const [conv, at] of Object.entries(memory.cursors ?? {})) cursors[conv] = Math.max(at, cursors[conv] ?? 0);
  return JSON.stringify({ ...memory, cursors });
}

/** A stored message an earlier page already read is flagged `replay`: it raises
 *  no unread. Everything else passes as it is. */
export function markReplay(name: string, payload: unknown, seen: Cursors): unknown {
  if (name !== "stored-dm" && name !== "stored-channel-message") return payload;
  const m = payload as { conv?: string; seq?: number };
  const upTo = m.conv === undefined ? undefined : seen[m.conv];
  return upTo !== undefined && m.seq !== undefined && m.seq <= upTo ? { ...m, replay: true } : payload;
}
