//! Every timer and cap the relay, its validator and the clients share
//! (docs/GROUP-KEY.md §9 "Relay timers and validator", plan part 2e). One
//! place, so the relay's pace and what a member enforces never drift apart.
//! Milliseconds end in `_MS`, seconds in `_SECS`; a count says what it counts.
//!
//! The ones C1 already has stay there: `CLOCK_SLACK`, `EPOCH_MIN_GAP`,
//! `REGENESIS_WAIT` (and `REGENESIS_FAST_WAIT`, `REGENESIS_FAST_GAP`),
//! `ROLL_GAP`, `SEED_MAX_AGE`, `NAMES_KEPT`, `HEADER_MAX_BYTES`,
//! `MAX_REMOVED`, `MAX_KEYHOLDERS`, `BUCKET_SEATS`.

use super::ctx::GroupKind;
use super::header::HeaderV1;
use super::{CLOCK_SLACK, EPOCH_MIN_GAP, REGENESIS_FAST_WAIT, REGENESIS_WAIT};

const SEC: u64 = 1000;
const MIN: u64 = 60 * SEC;
const DAY_SECS: u64 = 24 * 60 * 60;

// ── Joins ─────────────────────────────────────────────────────────────────

/// A text join batch closes this long after its first joiner.
pub const JOIN_BATCH_MS: u64 = 2 * SEC;
/// A voice join batch closes sooner (open choice 7): a relay-only timer.
pub const JOIN_BATCH_VOICE_MS: u64 = 250;
/// A join batch closes at once with this many waiting, and no Join commit
/// seats more.
pub const JOIN_BATCH_MAX: usize = 256;

/// When a join batch closes after its first joiner.
pub fn join_batch_ms(kind: GroupKind) -> u64 {
    match kind {
        GroupKind::Text => JOIN_BATCH_MS,
        GroupKind::Voice => JOIN_BATCH_VOICE_MS,
    }
}

// ── Exits ─────────────────────────────────────────────────────────────────

/// `exit_gap(N)`: 20 ms per seat of the group…
pub const EXIT_GAP_PER_SEAT_MS: u64 = 20;
/// …and never more than this (§5.4 `EXIT_GAP_MAX_MS`).
pub const EXIT_GAP_MAX_MS: u64 = 36 * SEC;
/// A voice exit batch closes after 2 s, whatever the room's size.
pub const EXIT_GAP_VOICE_MS: u64 = 2 * SEC;
/// A gated exit batch also closes at this many exits: a gated opening
/// header names each removed seat, and its body is at most 32 KiB.
pub const GATED_EXIT_BATCH: usize = super::header::MAX_REMOVED;

/// How long an exit batch stays open after its first exit, for a group of
/// `seats` seats. A voice keyholder's leave closes it at once (the relay's).
pub fn exit_gap_ms(kind: GroupKind, seats: u64) -> u64 {
    match kind {
        GroupKind::Text => seats
            .saturating_mul(EXIT_GAP_PER_SEAT_MS)
            .min(EXIT_GAP_MAX_MS),
        GroupKind::Voice => EXIT_GAP_VOICE_MS,
    }
}

// ── Opening commits and deadlines ─────────────────────────────────────────

/// Opening commits of one group are at least this far apart (§4.1).
pub const EPOCH_MIN_GAP_MS: u64 = EPOCH_MIN_GAP * SEC;
/// A keyholder's deadline for a Join due.
pub const DEADLINE_JOIN_MS: u64 = 5 * SEC;
/// For an exits due: two of them fit inside `CHECK_WAIT_MS`.
pub const DEADLINE_EXITS_MS: u64 = 4 * SEC;
/// For a refresh, promotion, removal, replacement or seed-welcome page.
pub const DEADLINE_SLOW_MS: u64 = MIN;
/// For a Genesis or a Regenesis.
pub const DEADLINE_GENESIS_MS: u64 = 30 * SEC;
/// All online keyholders missed: the relay asks again this often.
pub const RETRY_ALL_MISSED_MS: u64 = 30 * SEC;

/// An open commit is dropped this long after its first part, or when the
/// head moves.
pub const OPEN_COMMIT_MS: u64 = 30 * SEC;
/// One commit, seed welcomes included, at most (§9: a full re-key at 100k is
/// about 6.4 MB encoded).
pub const COMMIT_MAX_BYTES: usize = 12 * 1000 * 1000;
/// Open commits of one connection, all groups together.
pub const OPEN_PER_CONN_BYTES: usize = COMMIT_MAX_BYTES;
/// Open commits on one relay.
pub const OPEN_PER_RELAY_BYTES: usize = 64 * 1000 * 1000;
/// Senders cut every multi-part message at this many encoded bytes, under
/// the 64 KiB frame (plan 1e `PIECE_MAX_BYTES`).
pub const PIECE_MAX_BYTES: usize = 56 * 1024;

// ── Refresh, age, keyholders ──────────────────────────────────────────────

/// The relay asks for a Fresh epoch this often…
pub const REFRESH_MS: u64 = 5 * MIN;
/// …or this often while the group has a single bucket.
pub const REFRESH_ONE_BUCKET_MS: u64 = MIN;

/// When the next refresh is due after an opening, for a head of `buckets`.
pub fn refresh_ms(buckets: u32) -> u64 {
    if buckets <= 1 {
        REFRESH_ONE_BUCKET_MS
    } else {
        REFRESH_MS
    }
}

/// Every opening commit re-keys by rows each version older than this, by
/// the keyring's `made` (§5.5).
pub const BUCKET_AGE_MAX_SECS: u64 = 60 * 60;
/// A refresh also re-keys at least `⌈B / REFRESH_SLICE⌉` of the buckets.
pub const REFRESH_SLICE: usize = 12;

/// No keyholder online on a relay with accounts: a Regenesis may be asked
/// after this long (§5.6)…
pub const REGENESIS_AFTER_MS: u64 = REGENESIS_WAIT * SEC;
/// …or after this long when every entry of the set in force is a connection
/// entry, none of which can come back online ("Fast new start", owner
/// 2026-11-19), unless a Regenesis started that set in the last hour: none
/// (J10-B option A, owner 2026-11-22), the Regenesis is asked as soon as no
/// keyholder is online and a seat waits.
pub const REGENESIS_FAST_AFTER_MS: u64 = REGENESIS_FAST_WAIT * SEC;

/// How long the relay waits with no keyholder online before it asks a
/// Regenesis, at `now_ms`, under `set`, the keyholder header in force: the
/// wait every member holds the Regenesis to (`rules::regenesis_wait`).
pub fn regenesis_after_ms(set: &HeaderV1, now_ms: u64) -> u64 {
    super::regenesis_wait(set, now_ms / SEC) * SEC
}
/// Misses or declines in an hour that propose a keyholder's removal.
pub const REMOVAL_MISSES: usize = 3;
/// The hour those are counted in.
pub const REMOVAL_WINDOW_MS: u64 = 60 * MIN;
/// A desktop keyholder away this long is proposed for removal.
pub const REMOVAL_AWAY_SECS: u64 = 7 * DAY_SECS;
/// An entry whose counter has been below its account's newest this long.
pub const COUNTER_STALE_SECS: u64 = 7 * DAY_SECS;
/// A browser holds text keys only in groups of at most this many seats.
pub const BROWSER_MAX_SEATS: u32 = 10_000;
/// At most this many guest keyholders in a text group; none when gated.
pub const MAX_GUEST_KEYHOLDERS: usize = 2;
/// The relay promotes while fewer keyholders than this are online.
pub const KEYHOLDERS_ONLINE_MIN: usize = 2;

// ── Seed rolls ────────────────────────────────────────────────────────────

/// A seed-welcome page holds at most this many seats…
pub const SEED_PAGE_SEATS: usize = 256;
/// …and the relay asks one this often while a keyholder is online (open
/// choice 15: 100k seats in about 65 min).
pub const SEED_PAGE_EVERY_MS: u64 = 10 * SEC;
/// Every seat is given its seed welcome within this long of a roll start.
pub const SEED_ROLL_WITHIN_SECS: u64 = DAY_SECS;
/// At most this many seed welcomes in one `EpochWelcomes` frame.
pub const SEED_WELCOMES_A_FRAME: usize = 33;

// ── What the relay keeps ──────────────────────────────────────────────────

/// A seat not used (fetch or post) this long exits (daily sweep).
pub const SEAT_EXPIRY_SECS: u64 = 90 * DAY_SECS;
/// An account's seat keys rotate at this age, and at a sign-in once older (§5.11): keys
/// first published longer ago than this and `SEAT_EXPIRY_SECS` together belong to an account
/// that has not signed in for `SEAT_EXPIRY_SECS`, which a new start seats no more.
pub const SEAT_KEYS_ROTATE_SECS: u64 = 30 * DAY_SECS;
/// A seat's last use is written at most this often.
pub const SEAT_USE_WRITE_SECS: u64 = DAY_SECS;
/// At most this many writer blobs per writer and epoch…
pub const BLOBS_PER_WRITER: usize = 2;
/// …each at most this large.
pub const BLOB_MAX_BYTES: usize = 1024;
/// Epoch material is swept this often…
pub const MATERIAL_SWEEP_MS: u64 = 10 * MIN;
/// …never closer than `HOLD_MS` plus this to the next opening (C4).
pub const MATERIAL_SWEEP_MARGIN_MS: u64 = 2 * MIN;
/// Material of a commit that never became head is swept this often.
pub const ORPHAN_SWEEP_MS: u64 = 10 * MIN;
/// At most one new generation per group in this long from floor-ahead proofs.
pub const FLOOR_AHEAD_GAP_SECS: u64 = 60 * 60;
/// A group's actor stops after this long with no online seat and no due.
pub const ACTOR_IDLE_MS: u64 = 10 * MIN;
/// A group's inbox holds at most this many bytes; past it fetches and posts
/// are refused `RATE`.
pub const INBOX_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Past epochs one `EpochFetch` may ask for (`at`).
pub const PAST_A_FETCH: usize = 16;

// ── Client side ───────────────────────────────────────────────────────────

/// A held post drops after this long (unchanged from the live path).
pub const HOLD_MS: u64 = 60 * SEC;
/// How long a member waits for keys a keyholder was asked for.
pub const CHECK_WAIT_MS: u64 = 10 * SEC;
/// A writer told of an exit holds its posts once no opening header covering
/// it came within this long (§5.4: `EXIT_GAP_MAX_MS + CHECK_WAIT_MS`).
pub const EXIT_HOLD_MS: u64 = EXIT_GAP_MAX_MS + CHECK_WAIT_MS;
/// `EPOCH_AGE_MAX` of §5.5…
pub const EPOCH_AGE_BASE_SECS: u64 = 60 * 60;
/// …and what a writer holds at: no post under an epoch whose opening header
/// is older than this by its own clock.
pub const EPOCH_AGE_MAX_SECS: u64 = EPOCH_AGE_BASE_SECS + CLOCK_SLACK;
/// A writer's sender-key chain ends after this long within an epoch.
pub const CHAIN_AGE_MAX_MS: u64 = 60 * MIN;
/// A keyholder whose clock is this far off the relay's refuses to sign.
pub const KEYHOLDER_SKEW_SECS: u64 = 5 * 60;
/// Voice senders switch to a new epoch's key this long after taking it
/// (open choice 8).
pub const VOICE_KEY_SWITCH_MS: u64 = 300;
/// Old seat keys and an old keyholder pair are kept at most this long.
pub const OLD_KEYS_SECS: u64 = 7 * DAY_SECS;
/// A browser's build steps take at most this long…
pub const BROWSER_STEP_MS: u64 = 8;
/// …and this long while it is in a call.
pub const BROWSER_STEP_CALL_MS: u64 = 2;

/// The deadline a keyholder gets for a commit due.
pub fn deadline_ms(due: super::commit::DueKind) -> u64 {
    use super::commit::DueKind;
    match due {
        DueKind::Join => DEADLINE_JOIN_MS,
        DueKind::Exits => DEADLINE_EXITS_MS,
        DueKind::Genesis | DueKind::Regenesis => DEADLINE_GENESIS_MS,
        DueKind::Refresh
        | DueKind::Promote
        | DueKind::Remove
        | DueKind::Replace
        | DueKind::Gate => DEADLINE_SLOW_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::commit::DueKind;

    #[test]
    fn an_exit_batch_waits_twenty_ms_a_seat_up_to_thirty_six_seconds_and_two_in_voice() {
        assert_eq!(exit_gap_ms(GroupKind::Text, 0), 0);
        assert_eq!(exit_gap_ms(GroupKind::Text, 1), 20);
        assert_eq!(exit_gap_ms(GroupKind::Text, 1800), 36_000);
        assert_eq!(exit_gap_ms(GroupKind::Text, 1801), 36_000);
        assert_eq!(exit_gap_ms(GroupKind::Text, u64::MAX), 36_000);
        assert_eq!(exit_gap_ms(GroupKind::Voice, 100_000), 2_000);
        assert_eq!(exit_gap_ms(GroupKind::Voice, 1), 2_000);
    }

    #[test]
    fn two_exit_deadlines_fit_inside_the_check_wait_and_a_writer_holds_at_forty_six_seconds() {
        const { assert!(2 * DEADLINE_EXITS_MS <= CHECK_WAIT_MS) };
        const { assert!(DEADLINE_JOIN_MS + DEADLINE_EXITS_MS <= CHECK_WAIT_MS) };
        assert_eq!(EXIT_HOLD_MS, 46_000);
        assert_eq!(EPOCH_AGE_MAX_SECS, 70 * 60);
        assert_eq!(EPOCH_MIN_GAP_MS, 2_000);
        assert_eq!(REGENESIS_AFTER_MS, 3_600_000);
        assert_eq!(REGENESIS_FAST_AFTER_MS, 0);
        assert_eq!(GATED_EXIT_BATCH, 768);
    }

    /// "Fast new start": the relay asks a Regenesis at once under a set of connection
    /// entries alone (J10-B option A, owner 2026-11-22; 2 minutes before), after the hour
    /// under a set with a desktop's pair, and after the hour too while the set is one a
    /// Regenesis started less than an hour ago.
    #[test]
    fn a_regenesis_is_asked_at_once_under_connection_entries_alone_else_after_the_hour() {
        use crate::group_key::{Keyholder, Kind, MemberId, Origin};
        let entry = |origin: Origin, b: u8| Keyholder {
            m: MemberId::Account([b; 16]),
            u: None,
            origin: origin as u8,
            n: 1,
            ik: [b; 32],
            kx: [b; 32],
            tag_kk: [b; 8],
        };
        let t0 = 1_800_000_000u64;
        let set = |kind: Kind, keyholders: Vec<Keyholder>| HeaderV1 {
            group_kind: GroupKind::Text,
            group: "c:lounge-1".into(),
            gen: [1; 16],
            epoch: 3,
            join: 0,
            kind,
            time: t0,
            parent: [2; 32],
            epoch_parent: [0; 32],
            kh_parent: [3; 32],
            signer: keyholders[0].m,
            keyholders,
            gated: false,
            seed: 1,
            seed_floor: 1,
            exits_upto: 0,
            seats: 1,
            buckets: 1,
            conn_seats: 0,
            bucket_root: [4; 32],
            keyring_hash: [5; 32],
            names_hash: [0; 32],
            added: crate::group_key::Added::Count(0),
            removed: crate::group_key::Removed::Count(0),
            confirm: [6; 32],
        };
        let now = (t0 + 300) * 1000;
        let conn = vec![entry(Origin::Connection, 1), entry(Origin::Connection, 2)];
        let mixed = vec![entry(Origin::Connection, 1), entry(Origin::Desktop, 3)];
        assert_eq!(
            regenesis_after_ms(&set(Kind::KeyholdersAdd, conn.clone()), now),
            0
        );
        assert_eq!(
            regenesis_after_ms(&set(Kind::Genesis, conn.clone()), now),
            0
        );
        assert_eq!(
            regenesis_after_ms(&set(Kind::KeyholdersAdd, mixed), now),
            3_600_000
        );
        assert_eq!(
            regenesis_after_ms(
                &set(Kind::KeyholdersAdd, vec![entry(Origin::Desktop, 3)]),
                now
            ),
            3_600_000
        );
        // The churn bound: a set a Regenesis started keeps the hour for an hour
        let regen = set(Kind::Regenesis, conn);
        assert_eq!(regenesis_after_ms(&regen, now), 3_600_000);
        assert_eq!(regenesis_after_ms(&regen, (t0 + 3599) * 1000), 3_600_000);
        assert_eq!(regenesis_after_ms(&regen, (t0 + 3600) * 1000), 0);
    }

    #[test]
    fn each_due_has_its_deadline() {
        assert_eq!(deadline_ms(DueKind::Join), 5_000);
        assert_eq!(deadline_ms(DueKind::Exits), 4_000);
        for d in [
            DueKind::Refresh,
            DueKind::Promote,
            DueKind::Remove,
            DueKind::Replace,
            DueKind::Gate,
        ] {
            assert_eq!(deadline_ms(d), 60_000, "{d:?}");
        }
        assert_eq!(deadline_ms(DueKind::Genesis), 30_000);
        assert_eq!(deadline_ms(DueKind::Regenesis), 30_000);
    }

    #[test]
    fn a_join_batch_closes_sooner_in_voice_and_a_single_bucket_refreshes_every_minute() {
        assert_eq!(join_batch_ms(GroupKind::Text), 2_000);
        assert_eq!(join_batch_ms(GroupKind::Voice), 250);
        assert_eq!(refresh_ms(0), 60_000);
        assert_eq!(refresh_ms(1), 60_000);
        assert_eq!(refresh_ms(2), 300_000);
    }

    #[test]
    fn a_seed_roll_of_a_hundred_thousand_seats_pages_through_inside_a_day() {
        let pages = 100_000usize.div_ceil(SEED_PAGE_SEATS) as u64;
        assert!(pages * SEED_PAGE_EVERY_MS < SEED_ROLL_WITHIN_SECS * 1000);
        assert!(pages * SEED_PAGE_EVERY_MS <= 66 * 60 * 1000, "about 65 min");
    }
}
