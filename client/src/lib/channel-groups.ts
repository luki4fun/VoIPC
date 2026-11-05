// The channel list as the sidebar draws it: the channels nobody put in a category
// first, under the headings they always had, then each category in order. Within
// each, in the order `ServerMessage::ChannelLayout` gives; what it does not name
// (a channel somebody made for now, or everything on an older relay) follows.
// Pure, for channel-groups.test.ts.

import type { ChannelCategory, ChannelInfo, ChannelPlace } from "./types.js";

export interface ChannelGroup {
  /** `null`: not in a category. */
  category: ChannelCategory | null;
  text: ChannelInfo[];
  voice: ChannelInfo[];
}

export interface ChannelLayout {
  categories: ChannelCategory[];
  channels: ChannelPlace[];
}

/**
 * A layout as a relay sent it, as it may be drawn. One row per id: a keyed list
 * stops the whole page at a repeat, and a relay's word is no promise there is none.
 * And "no category" as null: the browser's decoder gives undefined.
 */
export function cleanLayout(raw: Partial<ChannelLayout>): ChannelLayout {
  const seen = new Set<number>();
  const once = (id: number) => !seen.has(id) && !!seen.add(id);
  const categories = (raw.categories ?? []).filter((c) => once(c.id));
  seen.clear();
  const channels = (raw.channels ?? [])
    .filter((p) => once(p.channel_id))
    .map((p) => ({ ...p, category: p.category ?? null }));
  return { categories, channels };
}

export function groupChannels(visible: ChannelInfo[], layout: ChannelLayout): ChannelGroup[] {
  const rank = new Map(layout.channels.map((p, i) => [p.channel_id, i]));
  const placed = new Map(layout.channels.map((p) => [p.channel_id, p.category]));
  const known = new Set(layout.categories.map((c) => c.id));
  const ordered = [...visible].sort(
    (a, b) => (rank.get(a.channel_id) ?? Infinity) - (rank.get(b.channel_id) ?? Infinity) || a.channel_id - b.channel_id,
  );
  const inGroup = (id: number | null) =>
    ordered.filter((c) => {
      const at = placed.get(c.channel_id) ?? null;
      return (at !== null && known.has(at) ? at : null) === id;
    });
  const group = (category: ChannelCategory | null): ChannelGroup => {
    const channels = inGroup(category?.id ?? null);
    return { category, text: channels.filter((c) => c.text), voice: channels.filter((c) => !c.text) };
  };
  return [group(null), ...layout.categories.map(group)];
}

/** `channels` with one moved a step among those in its own category. */
export function movedInCategory(channels: ChannelPlace[], id: number, step: -1 | 1): ChannelPlace[] {
  const at = channels.findIndex((p) => p.channel_id === id);
  if (at < 0) return channels;
  const peers = channels.flatMap((p, i) => (p.category === channels[at].category ? [i] : []));
  const to = peers[peers.indexOf(at) + step];
  if (to === undefined) return channels;
  const out = [...channels];
  [out[at], out[to]] = [out[to], out[at]];
  return out;
}

/** `list` with one element moved a step, as far as it goes. */
export function movedBy<T>(list: T[], at: number, step: -1 | 1): T[] {
  const to = at + step;
  if (at < 0 || to < 0 || to >= list.length) return list;
  const out = [...list];
  [out[at], out[to]] = [out[to], out[at]];
  return out;
}

/** What the sidebar shows of a group: all of it, or if folded only what is open. */
export function shownOf(channels: ChannelInfo[], folded: boolean, open: (c: ChannelInfo) => boolean): ChannelInfo[] {
  return folded ? channels.filter(open) : channels;
}
