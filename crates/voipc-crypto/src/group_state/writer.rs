//! A writer's posts under the epoch key (3f, §5.8): a post goes when the head is held and its
//! `CK` open, else it is held (`HOLD_MS`) and the keys fetched. It is held too while an exit
//! older than 46 s waits for the opening header that covers it, while the head epoch is over
//! 70 min old, and while a gated group's names do not fold. One libsignal sender-key chain a
//! writer per epoch, new at the epoch's first post and after 1 h (spec 5.2, 5.4: a writer told
//! of an exit keeps posting in the current epoch, so the relay's two blobs per writer and
//! epoch hold), and after the relay refused a post that started one; its first post carries
//! the writer blob.

use std::collections::VecDeque;

use libsignal_protocol::{
    create_sender_key_distribution_message, group_encrypt, DeviceId, ProtocolAddress,
};
use voipc_protocol::gk;
use voipc_protocol::messages::ClientMessage;

use super::member::Member;
use super::names::{self, Folded};
use super::{ready, Dropped, GkCtx, GkEvent, GkOut, GkState, HeldWhy, Who};
use crate::group_key::timers::{CHAIN_AGE_MAX_MS, EXIT_HOLD_MS, HOLD_MS};
use crate::group_key::{dist, post_plaintext, writer_blob, Epoch, Group, MemberId, Writer};
use crate::stores::SignalStores;

/// The most a post's ciphertext may be, on every path a post takes: under the epoch key or
/// with the key off, in a text channel or a voice room. The relay refuses one past it
/// (session.rs `MAX_TEXT_POST`, `POST_TOO_LARGE`; owner, 2026-11-19), so the writer refuses it
/// first, with its id: a post the relay refused names none, and the writer's row would stay
/// shown as sent.
pub(super) const POST_MAX_BYTES: usize = 16 * 1024;
const _: () = assert!(POST_MAX_BYTES == crate::log::MAX_ENTRY_BYTES);

/// The relay's own words for such a post (session.rs `POST_TOO_LARGE`), which the app shows
/// plainly (chat-rules.ts `TOO_LARGE_REASON`).
pub(super) const TOO_LARGE: &str = "post too large: one message holds at most 16 KiB";

/// What `post_plaintext` puts before a post's envelope: its generation, epoch and `D_e`.
const POST_PREFIX_BYTES: usize = 16 + 4 + 32;

/// The most bytes a libsignal sender-key message sealing `plain` bytes takes: a version byte;
/// the protobuf's distribution id (2 + 16), chain id and iteration (each a tag and a varint of
/// at most 5 bytes: the chain id is random, the iteration counts up) and ciphertext (a tag, a
/// varint length and AES-256-CBC with PKCS#7, so the next multiple of 16 past `plain`); and
/// the 64-byte signature. At most 8 bytes over the real size (chain id and iteration short).
pub(super) fn sealed_most(plain: usize) -> usize {
    let ct = (plain / 16 + 1) * 16;
    let varint = |n: usize| (usize::BITS - n.max(1).leading_zeros()).div_ceil(7) as usize;
    1 + (2 + 16) + (1 + 5) + (1 + 5) + (1 + varint(ct) + ct) + 64
}

/// Whether a post of `envelope` bytes, sealed as it goes (`under_key`: an `EpochPost`'s
/// ciphertext, behind `post_plaintext`'s prefix; else the old path's
/// `SendEncryptedChannelMessage`, the envelope alone), stays within `POST_MAX_BYTES`.
pub(super) fn post_fits(envelope: usize, under_key: bool) -> bool {
    let plain = envelope.saturating_add(if under_key { POST_PREFIX_BYTES } else { 0 });
    sealed_most(plain) <= POST_MAX_BYTES
}

/// A post of ours waiting for the keys.
struct HeldPost {
    post_id: [u8; 16],
    envelope: Vec<u8>,
    since: u64,
}

/// A post that went, kept for `HOLD_MS` in case the relay says its epoch was too old.
struct SentPost {
    post_id: [u8; 16],
    envelope: Vec<u8>,
    at: u64,
    /// It started a chain: it carried the writer blob.
    blob: bool,
}

/// Why the first held post waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    NoKey,
    Late,
    Names(Option<HeldWhy>),
}

/// The sender-key chain this writer is on.
struct Chain {
    gen: [u8; 16],
    epoch: u32,
    started: u64,
}

/// One group's writing.
#[derive(Default)]
pub(super) struct Writing {
    held: VecDeque<HeldPost>,
    /// Exits named to writers (`EpochExit`): generation, sequence, when (ms), and how many
    /// exits had been heard before it.
    exits: Vec<([u8; 16], u64, u64, u64)>,
    /// How many exits were heard (the order they came in).
    heard: u64,
    /// How many exits had been heard when the head piece being taken came in: one put off (a
    /// fetch for its keyholder header, the vault) is taken after exits that came behind it.
    piece_at: Option<u64>,
    chain: Option<Chain>,
    sent: VecDeque<SentPost>,
    hold: Option<Hold>,
    /// Posts refused as too large (`post_fits`) since the last flush, to be told there.
    too_large: usize,
}

impl Writing {
    pub(super) fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// A post of ours, held until it may go. One that would pass `POST_MAX_BYTES` sealed is
    /// not held: it never goes, and the flush that follows says so. (The hosts check
    /// `EarlyPost::fits` before, with the post's id, to mark its row; this is the rule itself.)
    pub(super) fn hold(&mut self, post_id: [u8; 16], envelope: Vec<u8>, now: u64) {
        if !post_fits(envelope.len(), true) {
            self.too_large += 1;
            return;
        }
        self.held.push_back(HeldPost {
            post_id,
            envelope,
            since: now,
        });
    }

    /// `EpochExit`: posts hold once it is 46 s old without an opening header that covers it.
    /// The chain goes on: the leaver holds this epoch's key anyway (spec 5.4).
    pub(super) fn exit(&mut self, gen: [u8; 16], seq: u64, now: u64) {
        if !self.exits.iter().any(|(g, s, _, _)| *g == gen && *s == seq) {
            self.exits.push((gen, seq, now, self.heard));
            self.heard += 1;
        }
    }

    /// A head piece came in, to take now or once what it waits for is in: the first one
    /// not yet taken marks which exits came before it (`started_anew`).
    pub(super) fn piece_in(&mut self) {
        self.piece_at.get_or_insert(self.heard);
    }

    /// A head piece was taken.
    pub(super) fn piece_taken(&mut self) {
        self.piece_at = None;
    }

    /// An opening header (or a new generation) was taken: the exits it covers are done. A new
    /// generation drops every exit of another one: a Genesis carries `exits_upto` 0, and an
    /// exit of the old generation would otherwise hold every post.
    pub(super) fn opened(&mut self, gen: [u8; 16], exits_upto: u64, new_gen: bool) {
        if new_gen {
            self.exits.retain(|(g, _, _, _)| *g == gen);
            self.chain = None;
        }
        self.exits
            .retain(|(g, seq, _, _)| *g != gen || *seq > exits_upto);
    }

    /// A Regenesis of `gen` was taken: it seats its volunteer alone, and every other seat
    /// comes back only through a Join, so each exit of `gen` heard before it is dealt with.
    /// The relay drops those it did not carry (none can be carried once its seat sits in
    /// no leaf), and its `exits_upto` stays below them: kept, they would hold every post.
    /// An exit heard after the piece that brought it came in is one of a seat seated since
    /// (the relay pushes a new start before it tells any later exit) and stays.
    pub(super) fn started_anew(&mut self, gen: [u8; 16]) {
        let before = self.piece_at.unwrap_or(self.heard);
        self.exits.retain(|(g, _, _, n)| *g != gen || *n >= before);
    }

    /// The relay refused a post as under too old an epoch: whatever went under it in the last
    /// `HOLD_MS` goes again under the head, first (1f.1). A reader drops a repeated envelope.
    pub(super) fn resend_after_old_epoch(&mut self) {
        while let Some(s) = self.sent.pop_back() {
            self.held.push_front(HeldPost {
                post_id: s.post_id,
                envelope: s.envelope,
                since: s.at,
            });
        }
        self.chain = None;
    }

    /// The relay's inbox was full (`RATE`): only a post that started a chain is refused so,
    /// and what went on that chain since is unreadable without its blob. Everything sent in
    /// the last `HOLD_MS` goes again on a new chain, at the next flush.
    pub(super) fn resend_after_rate(&mut self) {
        self.resend_after_old_epoch();
    }

    /// The relay refused a post for good (`EpochRefused{POST}` names none): the latest that
    /// started a chain, which is the one a relay refuses for its blob (`THIRD_BLOB`,
    /// `NOT_MEMBER`), else the latest. The chain it started is not one readers can open, so
    /// the next post starts another. Whether there was one.
    pub(super) fn drop_refused(&mut self) -> bool {
        self.chain = None;
        match self.sent.iter().rposition(|s| s.blob) {
            Some(i) => self.sent.remove(i).is_some(),
            None => self.sent.pop_back().is_some(),
        }
    }

    /// Whether an exit older than 46 s waits for its opening header.
    pub(super) fn exit_holds(&self, gen: &[u8; 16], now: u64) -> bool {
        self.exits
            .iter()
            .any(|(g, _, at, _)| g == gen && now >= at.saturating_add(EXIT_HOLD_MS))
    }
}

/// The member id a writer posts as: its seat's, or in an anonymous room that is not gated its
/// connection's, so no account id goes behind a pseudonym (1c, open choice 11).
pub(super) fn writer_m(m: &Member, who: &Who) -> MemberId {
    let gated = m.floor.as_ref().is_some_and(|f| f.gated);
    match who.account {
        Some(a) if gated || !m.t.anonymous => MemberId::Account(a),
        _ => MemberId::Conn(who.user_id),
    }
}

/// Whether the first held post may go, and if not why (fetching what it waits for).
fn ready_to_post(
    m: &mut Member,
    who: &mut Who,
    c: &mut GkCtx,
    out: &mut GkOut,
) -> Result<(), Hold> {
    let Some(key) = m.current_key() else {
        m.fetch(who, c.now, out);
        return Err(Hold::NoKey);
    };
    let (gen, late) = (key.gen, key.late(c.secs()));
    if late || m.writer.exit_holds(&gen, c.now) {
        m.fetch(who, c.now, out);
        return Err(Hold::Late);
    }
    match names::fold(m, who, c, out) {
        Folded::Ok => Ok(()),
        Folded::Held(why) => Err(Hold::Names(Some(why))),
        Folded::Wait => Err(Hold::Names(None)),
    }
}

/// Every held post that may go, in order.
pub(super) fn flush(
    m: &mut Member,
    who: &mut Who,
    st: &mut SignalStores,
    c: &mut GkCtx,
    out: &mut GkOut,
) {
    // A post too large never went: told as the relay tells it, the refusal first (U1)
    let too_large = std::mem::take(&mut m.writer.too_large);
    if too_large > 0 {
        m.tell(GkState::Refused(TOO_LARGE.to_string()), out);
        for _ in 0..too_large {
            out.events.push(GkEvent::PostDropped {
                channel_id: m.t.channel_id,
                why: Dropped::Refused,
            });
        }
    }
    if m.writer.held.is_empty() {
        return;
    }
    while !m.writer.held.is_empty() {
        if let Err(hold) = ready_to_post(m, who, c, out) {
            m.writer.hold = Some(hold);
            let state = match hold {
                Hold::Names(Some(why)) => GkState::Held(why),
                _ => match (m.wait, &m.refused) {
                    (_, Some(reason)) => GkState::Refused(reason.clone()),
                    (Some(gk::wait::NO_KEYHOLDER), _) => GkState::NoKeyholder,
                    _ => GkState::Late { waiting: true },
                },
            };
            m.tell(state, out);
            return;
        }
        let p = m.writer.held.pop_front().expect("not empty");
        if let Err(why) = send(m, who, st, &p, c, out) {
            tracing::warn!(group = %m.t.group, ?why, "a post did not go");
        }
    }
    m.writer.hold = None;
    // The refusal's line stands until a post goes after it
    if too_large == 0 {
        m.tell(GkState::Ok, out);
    }
}

/// One post under the head epoch.
fn send(
    m: &mut Member,
    who: &Who,
    st: &mut SignalStores,
    p: &HeldPost,
    c: &GkCtx,
    out: &mut GkOut,
) -> anyhow::Result<()> {
    let epoch = m.current().expect("checked");
    let g = Group::new(m.t.kind, &m.t.group, epoch.gen)?;
    let ep = Epoch {
        e: epoch.epoch,
        d_e: epoch.d_e,
    };
    let w = Writer {
        m: writer_m(m, who),
        u: who.user_id,
    };
    let addr = ProtocolAddress::new(w.ctx(), DeviceId::new(1).expect("1 is a device id"));
    let id = dist(&g, &ep);
    let fresh = m.writer.chain.as_ref().is_none_or(|ch| {
        (ch.gen, ch.epoch) != (epoch.gen, epoch.epoch)
            || c.now >= ch.started.saturating_add(CHAIN_AGE_MAX_MS)
    });
    let blob = if fresh {
        st.sender_key.forget(&addr, id);
        let skdm = ready(async {
            Ok(create_sender_key_distribution_message(
                &addr,
                id,
                &mut st.sender_key,
                &mut crate::rng(),
            )
            .await?)
        })?;
        Some(writer_blob(
            &g,
            &ep,
            &w,
            &epoch.ck,
            &who.identity,
            skdm.serialized(),
        )?)
    } else {
        None
    };
    let plain = post_plaintext(&epoch.gen, &ep, &p.envelope);
    let ct = ready(async {
        Ok(group_encrypt(&mut st.sender_key, &addr, id, &plain, &mut crate::rng()).await?)
    })?;
    // `hold` let by none past `post_fits`, which this size is under; never past the relay's cap
    if ct.serialized().len() > POST_MAX_BYTES {
        anyhow::bail!("sealed past {POST_MAX_BYTES} bytes");
    }
    if fresh {
        m.writer.chain = Some(Chain {
            gen: epoch.gen,
            epoch: epoch.epoch,
            started: c.now,
        });
    }
    out.send.push(ClientMessage::EpochPost {
        channel_id: m.t.channel_id,
        group: m.t.group.clone(),
        gen: epoch.gen,
        epoch: epoch.epoch,
        blob,
        ciphertext: ct.serialized().to_vec(),
    });
    m.writer.sent.push_back(SentPost {
        post_id: p.post_id,
        envelope: p.envelope.clone(),
        at: c.now,
        blob: fresh,
    });
    out.released.push((m.t.channel_id, p.post_id, epoch));
    Ok(())
}

/// Held posts past `HOLD_MS` are given up, each told why; a refusal is told first by its
/// own state (U1). Posts that went are kept `HOLD_MS`.
pub(super) fn tick(m: &mut Member, _who: &mut Who, c: &mut GkCtx, out: &mut GkOut) {
    let now = c.now;
    while m
        .writer
        .sent
        .front()
        .is_some_and(|s| now >= s.at.saturating_add(HOLD_MS))
    {
        m.writer.sent.pop_front();
    }
    let mut dropped = 0;
    while m
        .writer
        .held
        .front()
        .is_some_and(|p| now >= p.since.saturating_add(HOLD_MS))
    {
        m.writer.held.pop_front();
        dropped += 1;
    }
    give_up(m, dropped, out);
}

/// Every held post given up: the group is left, or the connection ended (3f).
pub(super) fn drop_held(m: &mut Member, out: &mut GkOut) {
    let dropped = m.writer.held.len();
    m.writer.held.clear();
    give_up(m, dropped, out);
}

/// `dropped` held posts given up, each told why.
fn give_up(m: &mut Member, dropped: usize, out: &mut GkOut) {
    if dropped == 0 {
        return;
    }
    let why = match (m.writer.hold, &m.refused) {
        (_, Some(reason)) => {
            m.tell(GkState::Refused(reason.clone()), out);
            Dropped::Refused
        }
        (Some(Hold::Names(_)), _) => Dropped::Unchecked,
        (Some(Hold::NoKey), _) if m.wait == Some(gk::wait::NO_KEYHOLDER) => Dropped::NoKeyholder,
        _ => Dropped::Late,
    };
    for _ in 0..dropped {
        out.events.push(GkEvent::PostDropped {
            channel_id: m.t.channel_id,
            why,
        });
    }
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::{IdentityKeyPair, SenderKeyMessage};

    use super::super::{GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor};
    use super::*;
    use crate::group_key::GroupKind;

    const GROUP: &str = "c:size-1";
    const CHANNEL: u32 = 4;
    const T: u64 = 1_700_000_000_000;

    /// A device of a guest on a relay with the key on, its text channel tracked (no key yet).
    fn tracked() -> (GroupKeying, SignalStores, MemoryPins) {
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: true,
            run: [0x33; 16],
            relay_clock: T / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: 20,
            identity: ik,
            account: None,
            seat_keys: None,
            local: None,
            visible: true,
        });
        let t = GkTrack {
            channel_id: CHANNEL,
            group: GROUP.into(),
            kind: GroupKind::Text,
            anonymous: false,
            hide_members: false,
            viewer_admin: false,
            keeps_history: false,
        };
        let _ = keying.track(t, VaultFloor::None);
        (keying, SignalStores::new(&ik, 20), MemoryPins::default())
    }

    fn post(
        k: &mut (GroupKeying, SignalStores, MemoryPins),
        id: u8,
        len: usize,
        now: u64,
    ) -> GkOut {
        let (keying, st, pins) = k;
        let c = GkCtx { pins, now };
        keying.post(st, CHANNEL, [id; 16], &vec![b'z'; len], c)
    }

    fn dropped(out: &GkOut) -> Vec<&GkEvent> {
        out.events
            .iter()
            .filter(|e| matches!(e, GkEvent::PostDropped { .. }))
            .collect()
    }

    /// Item J9W-1 (owner, 2026-11-19: one message holds at most 16 KiB): a post whose sealed
    /// `EpochPost` would pass the relay's cap is refused before it goes, told as the relay
    /// tells it (its words, the refusal first, U1), and never held: on the old code it was
    /// held, went once the key came, and the relay's refusal named no post, so the writer's
    /// row stayed shown as sent. A post that fits is held as any other.
    #[test]
    fn a_post_past_the_cap_is_refused_before_it_goes_and_told_as_the_relay_tells_it() {
        let mut k = tracked();
        let out = post(&mut k, 1, 16 * 1024, T);
        let refused = GkState::Refused("post too large: one message holds at most 16 KiB".into());
        assert_eq!(
            out.events,
            vec![
                GkEvent::State {
                    channel_id: CHANNEL,
                    state: refused.clone()
                },
                GkEvent::PostDropped {
                    channel_id: CHANNEL,
                    why: Dropped::Refused
                }
            ],
            "refused at once, the refusal first"
        );
        assert!(out
            .send
            .iter()
            .all(|m| !matches!(m, ClientMessage::EpochPost { .. })));
        assert!(out.released.is_empty());
        // Not held: nothing more is given up for it at `HOLD_MS`
        let (keying, st, pins) = &mut k;
        let later = keying.tick(
            st,
            GkCtx {
                pins,
                now: T + HOLD_MS,
            },
        );
        assert!(dropped(&later).is_empty(), "{:?}", later.events);
        // The largest that fits waits for the key as any post does
        let edge = (0..16 * 1024).rev().find(|&n| post_fits(n, true)).unwrap();
        let out = post(&mut k, 2, edge, T + HOLD_MS);
        assert!(!out.events.iter().any(|e| matches!(
            e,
            GkEvent::State {
                state: GkState::Refused(_),
                ..
            }
        )));
        assert!(dropped(&out).is_empty());
    }

    /// The bound every check stands on: a sender-key message sealing `n` bytes is never longer
    /// than `sealed_most(n)`, and at most 8 bytes shorter, over the lengths a post has (each
    /// side of a 16-byte block, and of the cap), chain ids and iterations from small to large.
    #[test]
    fn the_sealed_size_bound_holds_and_is_close() {
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let mut st = SignalStores::new(&ik, 20);
        let addr = ProtocolAddress::new("w".into(), DeviceId::new(1).unwrap());
        let mut lens: Vec<usize> = (0..64).collect();
        for edge in [1024, 15 * 1024, POST_MAX_BYTES - 120, POST_MAX_BYTES] {
            lens.extend(edge - 40..edge + 40);
        }
        let mut worst = (0, usize::MAX);
        for round in 0..3u8 {
            let id = uuid::Uuid::from_bytes([round; 16]);
            ready(async {
                Ok(create_sender_key_distribution_message(
                    &addr,
                    id,
                    &mut st.sender_key,
                    &mut crate::rng(),
                )
                .await?)
            })
            .unwrap();
            // Iterations past one varint byte too
            for _ in 0..(round as usize * 100) {
                ready(async {
                    Ok(
                        group_encrypt(&mut st.sender_key, &addr, id, b"x", &mut crate::rng())
                            .await?,
                    )
                })
                .unwrap();
            }
            for &n in &lens {
                let plain = vec![7u8; n];
                let ct: SenderKeyMessage = ready(async {
                    Ok(
                        group_encrypt(&mut st.sender_key, &addr, id, &plain, &mut crate::rng())
                            .await?,
                    )
                })
                .unwrap();
                let real = ct.serialized().len();
                let most = sealed_most(n);
                assert!(
                    real <= most,
                    "{n} bytes sealed to {real}, over the bound {most}"
                );
                assert!(
                    most - real <= 8,
                    "{n} bytes sealed to {real}, the bound {most}"
                );
                worst = worst.max((most - real, n));
            }
        }
        // What the hosts' checks come to: under the key a post's prefix counts too
        assert!(post_fits(
            POST_MAX_BYTES - 100 - POST_PREFIX_BYTES - 16,
            true
        ));
        assert!(!post_fits(POST_MAX_BYTES - 96 - POST_PREFIX_BYTES, true));
        assert!(post_fits(POST_MAX_BYTES - 100 - 16, false));
        assert!(!post_fits(POST_MAX_BYTES - 96, false));
    }

    // ── A gated writer's new readers (item J9W-3) ──

    mod gated {
        use libsignal_protocol::IdentityKeyPair;
        use voipc_protocol::gk;
        use voipc_protocol::messages::ServerMessage;

        use super::super::super::seat_keys;
        use super::super::super::{
            GkPins, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
        };
        use super::super::*;
        use crate::group_key::build::world::{Member as Someone, World, T0, TEXT_ID};
        use crate::group_key::build::Built;
        use crate::group_key::commit::{Due, DueKind, Joiner};
        use crate::group_key::{
            inclusion_path, Endorsement, GroupKind, Kind, Leaf, Origin, SeatKeys, SeatRef,
            SignedHeader,
        };

        const TEXT: u32 = 1;

        fn header_in(h: &SignedHeader) -> gk::HeaderIn {
            gk::HeaderIn {
                body: h.body().to_vec(),
                sig: h.sig().to_vec(),
            }
        }

        fn link(h: &SignedHeader) -> gk::WalkLinkIn {
            gk::WalkLinkIn {
                header: header_in(h),
                parent: None,
            }
        }

        /// An account's device in a text channel, as group_state/tests.rs's.
        struct Device {
            keying: GroupKeying,
            st: SignalStores,
            pins: MemoryPins,
            ik: IdentityKeyPair,
        }

        impl Device {
            fn account(u: u32, a: [u8; 16], keys: SeatKeys) -> Device {
                let ik = IdentityKeyPair::generate(&mut crate::rng());
                let mut keying = GroupKeying::default();
                let _ = keying.start(GkStart {
                    on: true,
                    run: [0x11; 16],
                    relay_clock: T0,
                    platform: Platform::Desktop,
                    help_hold_keys: false,
                    user_id: u,
                    identity: ik,
                    account: Some(a),
                    seat_keys: Some(keys),
                    local: None,
                    visible: true,
                });
                let t = GkTrack {
                    channel_id: TEXT,
                    group: TEXT_ID.into(),
                    kind: GroupKind::Text,
                    anonymous: false,
                    hide_members: false,
                    viewer_admin: false,
                    keeps_history: false,
                };
                let _ = keying.track(t, VaultFloor::None);
                Device {
                    keying,
                    st: SignalStores::new(&ik, u),
                    pins: MemoryPins::default(),
                    ik,
                }
            }

            fn joiner(&self, a: [u8; 16], k: &SeatKeys) -> Joiner {
                let public = k.pair.public();
                let m = MemberId::Account(a);
                let endorsement =
                    Endorsement::sign(&self.ik, Origin::VaultSeat, m, k.n, k.made, &public)
                        .unwrap();
                Joiner {
                    seat: public.seat(m),
                    ik: self.ik.public_key().public_key_bytes().try_into().unwrap(),
                    keys: public,
                    endorsement,
                    returning: false,
                }
            }

            fn take(&mut self, piece: gk::InPiece, now: u64) -> GkOut {
                let msg = ServerMessage::EpochIn {
                    group: TEXT_ID.into(),
                    part: 0,
                    last: true,
                    piece: Box::new(piece),
                };
                let c = GkCtx {
                    pins: &mut self.pins,
                    now: now * 1000,
                };
                self.keying.frame(&mut self.st, &msg, c)
            }

            fn post(&mut self, id: u8, now_ms: u64) -> GkOut {
                let c = GkCtx {
                    pins: &mut self.pins,
                    now: now_ms,
                };
                self.keying.post(&mut self.st, TEXT, [id; 16], b"hello", c)
            }
        }

        fn join(w: &mut World, joiners: Vec<Joiner>) -> Built {
            let due = Due {
                joiners,
                ..w.due(DueKind::Join)
            };
            let b = w.build_join(&due, None).unwrap();
            w.step(&due, &b);
            b
        }

        /// What the relay sends `seat` at the head (group_state/tests.rs `piece`).
        fn piece(w: &World, b: &Built, seat: &SeatRef, walk: &[&SignedHeader]) -> gk::InPiece {
            let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
            let i = w
                .leaves
                .iter()
                .position(|l| l.seats.contains(seat))
                .unwrap();
            let leaf = leaves[i];
            let from: gk::HolderRef = w.holders[0].by().into();
            let seat_keying =
                b.commit
                    .welcomes
                    .iter()
                    .find(|x| x.seat == *seat)
                    .map(|x| gk::SeatKeying {
                        b: x.b,
                        base_v: x.v,
                        s: x.s,
                        from,
                        welcome: Some(x.bytes.clone()),
                        row: None,
                        ratchets: vec![],
                    });
            let seal = b
                .commit
                .seals
                .iter()
                .find(|s| (s.b, s.v) == (leaf.b, leaf.v))
                .map(|s| s.bytes.clone());
            let hd = w.head.header();
            let opening =
                (hd.kind == Kind::Join && hd.epoch_parent == w.kh.d()).then(|| header_in(&w.kh));
            gk::InPiece {
                walk: walk.iter().map(|h| link(h)).collect(),
                head: Some(link(&w.head)),
                opening,
                leaf: Some(leaf.into()),
                path: Some(inclusion_path(&leaves, i).unwrap().try_into().unwrap()),
                seal,
                seat: seat_keying,
                ..Default::default()
            }
        }

        /// Item J9W-3 (community lane, "a gated channel's writer is shown who reads it now"):
        /// §4.4 rule 4 and §11 claim 5, a gated writer's app is named every new reader; rule 6,
        /// an entry this device cannot check against the pin as it stood then (a pin taken
        /// within `CLOCK_SLACK` of the Join, as of anyone met minutes before) is shown, not
        /// refused. names.rs `readers` names only the checked ones and counts the rest as
        /// "no name to show", so the writer of the lane, which met paula minutes before, got
        /// `gk-readers {names: [], unchecked: 1}`, and the app says nothing of no names.
        /// The fix is in names.rs (not this slice's file): see slice W's report.
        #[test]
        fn a_gated_writer_is_named_a_reader_whose_pin_it_cannot_check_yet() {
            let mut w = World::text(false, true);
            let a = [7; 16];
            let keys = SeatKeys::generate(1, T0);
            let copy = seat_keys::copy(&keys);
            let mut d = Device::account(20, a, keys);
            let j = d.joiner(a, &copy);
            let seat = j.seat;
            let b = join(&mut w, vec![j]);
            let genesis = w.kh.clone();
            d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
            assert!(d.keying.current_epoch(TEXT_ID).is_some());
            // The writer posts once: its names floor is the head
            assert!(!d.post(1, w.now * 1000).send.is_empty());
            // paula, met just now: her pin is younger than `CLOCK_SLACK` at her Join
            let paula = Someone::account(9);
            d.pins.pin_new([9; 16], paula.ik_raw(), w.now * 1000);
            assert_eq!(
                d.pins.pin_then(&[9; 16], w.now),
                crate::group_key::PinThen::Unknown
            );
            w.join(&[&paula]);
            let push = gk::InPiece {
                head: Some(link(&w.head)),
                pushed: true,
                ..Default::default()
            };
            d.take(push, w.now);
            let out = d.post(2, w.now * 1000 + 10);
            let readers: Vec<_> = out
                .events
                .iter()
                .filter_map(|e| match e {
                    GkEvent::Readers {
                        named, unchecked, ..
                    } => Some((named.clone(), *unchecked)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                readers,
                vec![(vec![MemberId::Account([9; 16])], 0)],
                "{:?}",
                out.events
            );
        }
    }
}
