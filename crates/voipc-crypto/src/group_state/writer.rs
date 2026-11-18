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
    /// Exits named to writers (`EpochExit`): generation, sequence, when (ms).
    exits: Vec<([u8; 16], u64, u64)>,
    chain: Option<Chain>,
    sent: VecDeque<SentPost>,
    hold: Option<Hold>,
}

impl Writing {
    pub(super) fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    pub(super) fn hold(&mut self, post_id: [u8; 16], envelope: Vec<u8>, now: u64) {
        self.held.push_back(HeldPost {
            post_id,
            envelope,
            since: now,
        });
    }

    /// `EpochExit`: posts hold once it is 46 s old without an opening header that covers it.
    /// The chain goes on: the leaver holds this epoch's key anyway (spec 5.4).
    pub(super) fn exit(&mut self, gen: [u8; 16], seq: u64, now: u64) {
        if !self.exits.iter().any(|(g, s, _)| *g == gen && *s == seq) {
            self.exits.push((gen, seq, now));
        }
    }

    /// An opening header (or a new generation) was taken: the exits it covers are done. A new
    /// generation drops every exit of another one: a Genesis carries `exits_upto` 0, and an
    /// exit of the old generation would otherwise hold every post.
    pub(super) fn opened(&mut self, gen: [u8; 16], exits_upto: u64, new_gen: bool) {
        if new_gen {
            self.exits.retain(|(g, _, _)| *g == gen);
            self.chain = None;
        }
        self.exits
            .retain(|(g, seq, _)| *g != gen || *seq > exits_upto);
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
            .any(|(g, _, at)| g == gen && now >= at.saturating_add(EXIT_HOLD_MS))
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
    m.tell(GkState::Ok, out);
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
