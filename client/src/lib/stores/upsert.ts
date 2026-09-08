// Idempotent list updates for the stores the server feeds.
//
// The server builds per-client snapshots (UserList, ChannelList) and its
// incremental broadcasts (UserJoined, ChannelCreated) in separate critical
// sections, so a client can legitimately receive an item it already has —
// two people joining the same channel at once, or connecting while someone
// creates a channel. A blind append then puts the same id in the list twice
// and Svelte's keyed {#each} throws each_key_duplicate, which leaves the
// store holding the duplicate and every later update throwing again: the UI
// is stuck for good. Replacing in place instead is always correct, because
// the incremental message carries the newer state.

/** Replace the entry with the same id, or append. `added` is false for a replace. */
export function upsertById<T>(list: T[], item: T, id: (v: T) => number): { list: T[]; added: boolean } {
  const key = id(item);
  const known = list.some((v) => id(v) === key);
  return {
    list: known ? list.map((v) => (id(v) === key ? item : v)) : [...list, item],
    added: !known,
  };
}
