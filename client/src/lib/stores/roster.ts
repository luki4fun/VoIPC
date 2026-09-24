// Who the member list shows, and what you are allowed to do to them.
//
// All of this used to be `$derived` inside UserList, which was fine while there
// was one member list. There are two now, and these are rules rather than
// styling: whether a channel hides its members, who may kick, who may invite.
// A second component re-deriving them is a second chance to get them wrong, and
// the hide-members one is the kind of wrong that leaks a roster somebody asked
// to keep private.
//
// Nothing here is component-local — every input is a store — so it all moves
// without changing what it computes. The member list is of the server on
// screen, so these read the bare stores; who is *speaking* is the call's, and
// only counts when the call is on the server on screen.

import { derived, get, writable, type Readable } from "svelte/store";

import {
  channels,
  currentChannelId,
  previewChannelId,
  previewUsers,
  viewingVoice,
  voice,
  voiceChannel,
} from "./channels.js";
import { activeTextChannelId, joinedTextChannelIds } from "./chat.js";
import { isAdmin, userId, voiceIsAdmin } from "./connection.js";
import { channelRosters } from "./rosters.js";
import { speakingUsers, users, visibleMembers } from "./users.js";
import { rosterOf } from "../roster-rules.js";
import type { ChannelInfo, UserInfo } from "../types.js";

/**
 * Looking at a channel we are not in.
 *
 * A text channel we joined is not a preview: we are in it, its roster is
 * pushed to us, and the pane it fills is one we may write in.
 */
export const isPreviewing: Readable<boolean> = derived(
  [previewChannelId, currentChannelId, joinedTextChannelIds],
  ([$preview, $current, $joinedText]) =>
    $preview !== null && $preview !== $current && !$joinedText.has($preview),
);

/**
 * The channel the member list is showing: the previewed one, else the text
 * channel whose chat is open, else the one we stand in.
 */
export const displayChannelId: Readable<number> = derived(
  [isPreviewing, previewChannelId, activeTextChannelId, currentChannelId],
  ([$previewing, $preview, $text, $current]) =>
    $previewing ? $preview! : ($text ?? $current),
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
// panel that can be collapsed, and in the modern layout usually is. As local
// state the linger timers died with the component, so every collapse wiped the
// list of who had just spoken and reopening it showed an empty channel.

const SPEAKER_LINGER_MS = 10_000;

export const recentSpeakers = writable<Set<number>>(new Set());

const speakerTimers = new Map<number, ReturnType<typeof setTimeout>>();

/**
 * Forget who has spoken recently.
 *
 * Nothing else does: the set and its timers are module-level, so the only thing
 * that ever removes an id is that id's own linger timer, and the set therefore
 * outlives channel switches, disconnects and moves to another server. User ids
 * are reused — the server hands a departed member's id to the next person to
 * connect — so without this a fresh arrival can inherit a speaker's id and be
 * listed inside a `hide_members` channel having never said a word.
 */
export function clearRecentSpeakers(): void {
  for (const timer of speakerTimers.values()) clearTimeout(timer);
  speakerTimers.clear();
  recentSpeakers.set(new Set());
}

// Whoever spoke did so in the channel we were in at the time. Standing
// somewhere else makes the list meaningless rather than merely stale, so it
// goes: on a join, on being moved, on leaving voice or taking it to another
// server. Not when the view changes: looking at another server moves nobody.
voice.subscribe(() => clearRecentSpeakers());

/** The channel we talk in hides its members from us. The rule of the call,
 *  not of whatever the member list shows. */
const voiceHidesMembers: Readable<boolean> = derived(
  [voiceIsAdmin, voiceChannel],
  ([$admin, $channel]) => !$admin && ($channel?.hide_members ?? false),
);

derived([speakingUsers, voiceHidesMembers], ([$speaking, $hide]) => ({ $speaking, $hide })).subscribe(
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
  [
    isPreviewing,
    previewUsers,
    displayChannelId,
    channelRosters,
    currentChannelId,
    users,
    userId,
    recentSpeakers,
    hideMembers,
    viewingVoice,
  ],
  ([
    $previewing,
    $previewUsers,
    $displayId,
    $rosters,
    $current,
    $users,
    $userId,
    $recent,
    $hide,
    $viewingVoice,
  ]) =>
    visibleMembers(
      // A text channel's members are its own: `rosterOf` hands back the
      // pushed list for the channel we stand in and the asked-for one
      // otherwise, which is exactly the distinction here.
      $previewing ? $previewUsers : rosterOf($displayId, $rosters, $current, $users),
      $userId,
      // Speakers are ids from the call's server; on another one they are
      // somebody else's numbers.
      $viewingVoice ? $recent : new Set(),
      // Never applied to a preview: the rule is about the channel you are in.
      $hide && !$previewing,
    ),
);

/**
 * Everyone on the server who is in no voice channel — the lobby's roster, which
 * the UI no longer lists as a channel. Still reachable for a direct message, a
 * poke or an admin action. Empty while the pane is showing the lobby itself:
 * they are the member list then, and listing them twice says nothing.
 */
export const idleUsers: Readable<UserInfo[]> = derived(
  [displayChannelId, channelRosters, currentChannelId, users],
  ([$displayId, $rosters, $current, $users]) =>
    $displayId === 0 ? [] : rosterOf(0, $rosters, $current, $users),
);

/** Creator of the channel we are actually in — what invites are gated on. */
const currentChannelCreatorId: Readable<number | null> = derived(
  [channels, currentChannelId],
  ([$channels, $id]) => $channels.find((c) => c.channel_id === $id)?.created_by ?? null,
);

export const isCurrentChannelCreator: Readable<boolean> = derived(
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
