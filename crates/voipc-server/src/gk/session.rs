//! The group key's client messages (plan 2a): `handle` takes every new `ClientMessage`
//! but `EpochPost`, whose post rules are session.rs's (R2's post helper calls
//! `Groups::post_check`). Nothing here waits on another session.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::Arc;

use tokio::sync::oneshot;
use voipc_crypto::group_key::commit::{Pair, ReplaceAsk};
use voipc_crypto::group_key::wire;
use voipc_crypto::group_key::{GroupKind, MemberId};
use voipc_protocol::gk::{
    self, platform, refused_what, refused_why, stale, EndorsedPair, GkMember,
};
use voipc_protocol::messages::ClientMessage;
use voipc_protocol::types::UserId;

use super::group::Fetch;
use super::holders::Volunteer;
use super::{answer_seated, lane_refused, past_refused, push, Groups, Msg, SMALL};
use crate::control::ControlTx;
use crate::state::ServerState;

/// A session's identity key, raw (the 0x05 type byte dropped).
fn ik_of(key: Option<&[u8]>) -> Option<[u8; 32]> {
    match key? {
        [0x05, rest @ ..] if rest.len() == 32 => rest.try_into().ok(),
        k if k.len() == 32 => k.try_into().ok(),
        _ => None,
    }
}

/// A connection's own pair (0x02): it must name this session's user id.
fn conn_pair(p: &EndorsedPair, sid: UserId) -> Option<Pair> {
    if p.origin != gk::origin::CONNECTION || p.u != sid {
        return None;
    }
    wire::pair(p, GkMember::Conn(sid)).ok()
}

/// The session's account and identity key.
fn who(state: &ServerState, sid: UserId) -> (Option<[u8; 16]>, Option<[u8; 32]>) {
    state.sessions.get(&sid).map_or((None, None), |s| {
        (s.account_id(), ik_of(s.identity_key.as_deref()))
    })
}

impl Groups {
    /// The seat pair a fetch may seat this session with (2d): an account's published seat
    /// keys in text, else the connection pair the frame carries.
    async fn fetch_pair(
        &self,
        kind: GroupKind,
        account: Option<[u8; 16]>,
        seat: Option<&EndorsedPair>,
        sid: UserId,
    ) -> Option<Pair> {
        match (kind, account) {
            (GroupKind::Text, Some(a)) => self.account_pair(a).await,
            _ => conn_pair(seat?, sid),
        }
    }

    /// A post's group-key checks (1f.1, 1f.2), for session.rs's post helper: the epoch
    /// rule, and a blob stored (making the session a writer of the epoch) before the post
    /// goes out. `Err` is a `refused_why` code. Only a post carrying a blob is refused
    /// `RATE`, `THIRD_BLOB` or (by the actor) `NOT_MEMBER`: C3b restarts its chain at such a
    /// refusal, sends again at `RATE`, and drops the latest post that started a chain
    /// otherwise (writer.rs `drop_refused`), since `EpochRefused` names no post.
    pub async fn post_check(
        &self,
        sid: UserId,
        group: &str,
        gen: [u8; 16],
        epoch: u32,
        blob: Option<Vec<u8>>,
    ) -> Result<(), u8> {
        if !self.on {
            return Err(refused_why::OFF);
        }
        let Some(blob) = blob else {
            return if self.post_ok(group, &gen, epoch) {
                Ok(())
            } else {
                Err(refused_why::OLD_EPOCH)
            };
        };
        let (reply, answer) = oneshot::channel();
        let bytes = SMALL + blob.len();
        let msg = Msg::PostBlob {
            sid,
            gen,
            epoch,
            blob,
            reply,
        };
        if !self.post(group, msg, bytes, false) {
            return Err(refused_why::RATE);
        }
        answer.await.unwrap_or(Err(refused_why::RATE))
    }

    /// Every group-key `ClientMessage` but `EpochPost`.
    pub async fn handle(
        &self,
        state: &Arc<ServerState>,
        sid: UserId,
        msg: ClientMessage,
        tx: &ControlTx,
    ) {
        if !self.shared.conns.contains_key(&sid) {
            self.on_connect(sid, tx.clone());
        }
        let off = |what: u8, group: &str| self.refuse(sid, group, what, refused_why::OFF);
        match msg {
            ClientMessage::EpochFetch {
                group,
                have,
                at,
                seat,
            } => {
                if !self.on {
                    return off(refused_what::FETCH, &group);
                }
                // Past epochs are C4's: refused; a follower's live fetch is still answered
                if past_refused(self, sid, &group, &at)
                    && !self.follows.get(&sid).is_some_and(|f| f.contains(&group))
                {
                    return;
                }
                let Some(h) = self.get(&group) else {
                    return self.refuse(sid, &group, refused_what::FETCH, refused_why::NOT_MEMBER);
                };
                if answer_seated(&self.shared, &h, sid, have.as_ref()).await {
                    return;
                }
                let (account, ik) = who(state, sid);
                let pair = self.fetch_pair(h.kind, account, seat.as_ref(), sid).await;
                let bytes = SMALL + seat.as_ref().map_or(0, push::len);
                let msg = Msg::Fetch {
                    sid,
                    f: Fetch { have, pair, ik },
                };
                if !self.post(&group, msg, bytes, false) {
                    self.refuse(sid, &group, refused_what::FETCH, refused_why::RATE);
                }
            }
            ClientMessage::EpochCommit {
                group,
                due,
                part,
                last,
                piece,
            } => {
                if !self.on {
                    return off(refused_what::COMMIT, &group);
                }
                // Only a session with a due out queues parts, ≤ 12 MB a connection (1e)
                if !self.get(&group).is_some_and(|h| h.asked.contains(&sid)) {
                    return lane_refused(self, sid, &group, due, stale::NOT_DUE);
                }
                let bytes = push::len(&piece);
                if !self.shared.lane_take(sid, bytes) {
                    return lane_refused(self, sid, &group, due, stale::TOO_LARGE);
                }
                let msg = Msg::Commit {
                    sid,
                    due,
                    part,
                    last,
                    piece,
                    bytes,
                };
                if !self.post(&group, msg, bytes, true) {
                    self.shared.lane_free(sid, bytes);
                    lane_refused(self, sid, &group, due, stale::TOO_LARGE);
                }
            }
            ClientMessage::EpochDecline {
                group, due, why, ..
            } => {
                self.post(&group, Msg::Decline { sid, due, why }, SMALL, true);
            }
            ClientMessage::EpochListsWanted {
                group,
                gen,
                versions,
            } => {
                // A keyholder's asks are refused as `COMMIT`'s (mod.rs `Msg::Keyring`)
                if !self.post(&group, Msg::Lists { sid, gen, versions }, SMALL, false) {
                    self.refuse(sid, &group, refused_what::COMMIT, refused_why::RATE);
                }
            }
            ClientMessage::KeyringWanted { group, gen, have } => {
                if !self.post(&group, Msg::Keyring { sid, gen, have }, SMALL, false) {
                    self.refuse(sid, &group, refused_what::COMMIT, refused_why::RATE);
                }
            }
            ClientMessage::EpochBlobWanted {
                group,
                gen,
                epoch,
                writer,
            } => {
                let msg = Msg::Blobs {
                    sid,
                    gen,
                    epoch,
                    writer,
                };
                if !self.post(&group, msg, SMALL, false) {
                    self.refuse(sid, &group, refused_what::BLOB, refused_why::RATE);
                }
            }
            ClientMessage::EpochNames {
                group,
                from,
                to,
                removals,
            } => {
                let msg = Msg::Names {
                    sid,
                    from,
                    to,
                    removals,
                };
                if !self.post(&group, msg, SMALL, false) {
                    self.refuse(sid, &group, refused_what::NAMES, refused_why::RATE);
                }
            }
            ClientMessage::EpochFloorAhead { group, header } => {
                let bytes = SMALL + header.body.len();
                self.post(&group, Msg::FloorAhead { sid, header }, bytes, false);
            }
            ClientMessage::KeyholdVolunteer { on, platform, pair } => {
                if !self.on {
                    return off(refused_what::VOLUNTEER, "");
                }
                let v = if on {
                    match self.volunteer(state, sid, platform, pair.as_ref()).await {
                        Some(v) => Some(v),
                        None => {
                            return self.refuse(
                                sid,
                                "",
                                refused_what::VOLUNTEER,
                                refused_why::NOT_MEMBER,
                            )
                        }
                    }
                } else {
                    None
                };
                match &v {
                    Some(v) => {
                        self.vols.insert(sid, v.clone());
                    }
                    None => {
                        self.vols.remove(&sid);
                    }
                }
                for id in self
                    .follows
                    .get(&sid)
                    .map(|f| f.clone())
                    .unwrap_or_default()
                {
                    self.post(&id, Msg::Volunteer { sid, v: v.clone() }, 0, true);
                }
            }
            ClientMessage::KeyholdResign { group, entry } => {
                self.post(&group, Msg::Resign { sid, entry }, SMALL, true);
            }
            ClientMessage::KeyholdReplace { old, pair } => {
                let (Some(account), _) = who(state, sid) else {
                    return;
                };
                let Ok(pair) = wire::pair(&pair, GkMember::Account(account)) else {
                    return;
                };
                let ask = ReplaceAsk { old, pair };
                for id in self
                    .follows
                    .get(&sid)
                    .map(|f| f.clone())
                    .unwrap_or_default()
                {
                    self.post(
                        &id,
                        Msg::Replace {
                            sid,
                            ask: ask.clone(),
                        },
                        SMALL,
                        true,
                    );
                }
            }
            // Seed-welcome pages are asked by no due yet (see the slice notes); the post is
            // session.rs's
            ClientMessage::EpochWelcomes { .. } | ClientMessage::EpochPost { .. } => {}
            _ => {}
        }
    }

    /// A `KeyholdVolunteer` checked (1b): a desktop's 0x03 pair for its account, or the
    /// connection's 0x02 pair; its own seat for a Genesis is the account's seat keys or
    /// that connection pair. The endorsement is the keyholder's to check (JoinRefused).
    async fn volunteer(
        &self,
        state: &ServerState,
        sid: UserId,
        platform: u8,
        pair: Option<&EndorsedPair>,
    ) -> Option<Volunteer> {
        let (account, ik) = who(state, sid);
        let ik = ik?;
        let p = pair?;
        let (m, pair) = match (account, p.origin) {
            (Some(a), gk::origin::DESKTOP) if platform == platform::DESKTOP => (
                MemberId::Account(a),
                wire::pair(p, GkMember::Account(a)).ok()?,
            ),
            (Some(a), gk::origin::CONNECTION) => (MemberId::Account(a), conn_pair(p, sid)?),
            (None, gk::origin::CONNECTION) => (MemberId::Conn(sid), conn_pair(p, sid)?),
            _ => return None,
        };
        let seat_pair = match account {
            Some(a) => self.account_pair(a).await,
            None => Some(pair.clone()),
        };
        let seat = seat_pair.map(|sp| voipc_crypto::group_key::commit::Joiner {
            seat: sp.keys.seat(m),
            ik,
            keys: sp.keys,
            endorsement: sp.endorsement,
            returning: false,
        });
        Some(Volunteer {
            sid,
            platform,
            m,
            ik,
            pair,
            seat,
        })
    }
}
