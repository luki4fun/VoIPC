// Who the member list shows, and what you are allowed to do to them.
//
// All of this used to be `$derived` inside UserList, which was fine while there
// was one member list. There are two now, and these are rules rather than
// styling: whether a channel hides its members, who may kick, who may invite.
// A second component re-deriving them is a second chance to get them wrong, and
// the hide-members one is the kind of wrong that leaks a roster somebody asked
// to keep private.
//
// Nothing here is component-local — every input is a global store — so it all
// moves without changing what it computes.

import { derived, get, writable, type Readable } from "svelte/store";

import { channels, currentChannelId, previewChannelId, previewUsers } from "./channels.js";
import { isAdmin, userId } from "./connection.js";
import { speakingUsers, users, visibleMembers } from "./users.js";
import type { ChannelInfo, UserInfo } from "../types.js";

/** Looking at a channel we are not in. */
export const isPreviewing: Readable<boolean> = derived(
  [previewChannelId, currentChannelId],
  ([$preview, $current]) => $preview !== null && $preview !== $current,
);

/** The channel the member list is showing: the previewed one, else our own. */
export const displayChannelId: Readable<number> = derived(
  [isPreviewing, previewChannelId, currentChannelId],
  ([$previewing, $preview, $current]) => ($previewing ? $preview! : $current),
);

export const displayChannel: Readable<ChannelInfo | undefined> = derived(
  [channels, displayChannelId],
  ([$channels, $id]) => $channels.find((c) => c.channel_id === $id),
);

export const displayChannelName: Readable<string> = derived(
  displayChannel,
  ($channel) => $channel?.name ?? "",
);

export const displayChannelCreatorId: Readable<number | null> = derived(
  displayChannel,
  ($channel) => $channel?.created_by ?? null,
);

/** This channel hides its roster from us. Admins always see it. */
export const hideMembers: Readable<boolean> = derived(
  [isAdmin, displayChannel],
  ([$admin, $channel]) => !$admin && ($channel?.hide_members ?? false),
);

// ── Recent speakers ────────────────────────────────────────────────────────
//
// In a hide-members channel whoever speaks appears for a while, so their volume
// can still be turned down, then fades out of the list again.
//
// This is a store rather than component state because the member list is a
// panel that can be collapsed, and in the Discord layout usually is. As local
// state the linger timers died with the component, so every collapse wiped the
// list of who had just spoken and reopening it showed an empty channel.

const SPEAKER_LINGER_MS = 10_000;

export const recentSpeakers = writable<Set<number>>(new Set());

const speakerTimers = new Map<number, ReturnType<typeof setTimeout>>();

derived([speakingUsers, hideMembers], ([$speaking, $hide]) => ({ $speaking, $hide })).subscribe(
  ({ $speaking, $hide }) => {
    if (!$hide) return;
    for (const id of $speaking) {
      clearTimeout(speakerTimers.get(id));
      if (!get(recentSpeakers).has(id)) {
        recentSpeakers.update((s) => new Set(s).add(id));
      }
      speakerTimers.set(
        id,
        setTimeout(() => {
          recentSpeakers.update((s) => {
            const next = new Set(s);
            next.delete(id);
            return next;
          });
          speakerTimers.delete(id);
        }, SPEAKER_LINGER_MS),
      );
    }
  },
);

/** Everyone the member list may draw, in either layout. */
export const displayUsers: Readable<UserInfo[]> = derived(
  [isPreviewing, previewUsers, users, userId, recentSpeakers, hideMembers],
  ([$previewing, $previewUsers, $users, $userId, $recent, $hide]) =>
    visibleMembers(
      $previewing ? $previewUsers : $users,
      $userId,
      $recent,
      // Never applied to a preview: the rule is about the channel you are in.
      $hide && !$previewing,
    ),
);

/** Creator of the channel we are actually in — what invites are gated on. */
const currentChannelCreatorId: Readable<number | null> = derived(
  [channels, currentChannelId],
  ([$channels, $id]) => $channels.find((c) => c.channel_id === $id)?.created_by ?? null,
);

const isCurrentChannelCreator: Readable<boolean> = derived(
  [currentChannelCreatorId, userId, currentChannelId],
  ([$creator, $userId, $current]) => $creator === $userId && $current !== 0,
);

/** Channel kick: the creator in their own channel, an admin in any channel. */
export const canKick: Readable<boolean> = derived(
  [displayChannelId, isPreviewing, displayChannelCreatorId, userId, isAdmin],
  ([$id, $previewing, $creator, $userId, $admin]) =>
    $id !== 0 && ((!$previewing && $creator === $userId) || $admin),
);

/** Invite: while previewing another channel, if you own the one you are in. */
export const canInvite: Readable<boolean> = derived(
  [isPreviewing, isCurrentChannelCreator],
  ([$previewing, $owner]) => $previewing && $owner,
);

/**
 * Is this member one the game is currently leaving out of the mix?
 *
 * `null` means no game is culling. Never applies to the preview of another
 * channel, which the game is not driving. See `audibleIds` for why a game
 * silencing somebody is shown rather than hidden.
 */
export function isCulled(
  id: number,
  audible: Set<number> | null,
  selfId: number,
  previewing: boolean,
): boolean {
  return !previewing && audible !== null && id !== selfId && !audible.has(id);
}
