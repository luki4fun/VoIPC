//! Voice rooms under the group key on the relay (plan part 5, spec §5.9). A room is a group
//! of its own, `r:<run>:<channel id>`, in memory only; the lobby (channel 0) carries no voice
//! and has none. state.rs calls `on_room_join` and `on_room_leave` wherever a session's room
//! changes (a join, a create's auto-join, a leave, a kick, a voice kick to the lobby, the
//! connection's end), and the group goes with its keyring once the room empties.
//!
//! - **Seats.** A member's seat is its connection's pair (0x02), taken at its first fetch
//!   after the join (the app fetches once the room change is confirmed). The seat is named by
//!   the account, or by the connection for a guest and in an anonymous room that is not gated
//!   (open choice 11). When that naming moves (an anonymous flip, a gate on, a gate's end
//!   once the head is open again) every seat named otherwise is swapped for its pair's under
//!   the new name (`room_rename`), so no roster ties a pseudonym to an account and no gated
//!   head keeps a connection seat.
//! - **Roster** (`VoiceSeats`): the whole roster to a member at its seat, its own seat in it
//!   (a sender names its key by what the roster says); each new seat and each going to every
//!   member who has the roster.
//! - **Keyholders.** Every member may hold the room's keys with the same pair, named by the
//!   account (`Conn(u)` for a guest) as the app names its own entry, whatever its platform or
//!   its Settings switch (§5.6): a room of phones and browsers has keyholders too. The lowest
//!   user id with a seat starts a generation; below 2 online, the lowest seated member that is
//!   no entry is promoted, if it is among the 4 lowest of the roster (members refuse any
//!   other); a later joiner with a lower id displaces nobody. A keyholder's leave closes the
//!   exit batch at once, so its Remove (which rolls the seed, §5.6) goes now; with none left
//!   the lowest id makes a Genesis and every member whose pair the relay holds is queued for
//!   it (`room_reseat`), so nobody has to fetch.

use std::collections::HashMap;

use voipc_crypto::group_key::commit::{Joiner, Pair};
use voipc_crypto::group_key::timers::KEYHOLDERS_ONLINE_MIN;
use voipc_crypto::group_key::{GroupKind, MemberId, SeatRef, SignedHeader, MAX_KEYHOLDERS};
use voipc_protocol::gk::{self, platform, VoiceSeatsPiece, VOICE_SEATS_PER_FRAME};
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{ChannelId, UserId};

use super::due::Waiting;
use super::group::{cause, GroupState, Out};
use super::holders::Volunteer;
use super::{Groups, Msg};

/// A new voice keyholder's user id is one of the roster's this many lowest (§5.9): members
/// check it against their own roster (`check_voice_keyholders`), and so does the validator.
const LOWEST: usize = 4;

impl Groups {
    /// A voice room's group id: always `r:` (§11.1), whatever the relay stores.
    pub fn room_id(&self, channel: ChannelId) -> String {
        format!("r:{}:{channel}", super::hex(&self.run))
    }

    /// A session came into voice room `channel` (a join, a create's auto-join, an invite's
    /// accept): it follows the room's group and may fetch it. `anonymous`: the room's flag
    /// now, which names the seats taken from here on.
    pub fn on_room_join(
        &self,
        channel: ChannelId,
        sid: UserId,
        account: Option<[u8; 16]>,
        anonymous: bool,
    ) {
        if !self.on || channel == 0 {
            return;
        }
        let id = self.room_id(channel);
        self.follow_in(channel, &id, GroupKind::Voice, sid, account, anonymous);
    }

    /// Out of voice room `channel`, with its `cause` (a leave, a kick, a voice kick to the
    /// lobby, a move to another room): its seat exits. `empty`: nobody is left, and the group
    /// goes with its keyring (§5.9): the next joiner starts a new generation.
    pub fn on_room_leave(&self, channel: ChannelId, sid: UserId, cause: u8, empty: bool) {
        if !self.on || channel == 0 {
            return;
        }
        self.leave_channel(channel, sid, cause);
        if empty {
            self.retire(&self.room_id(channel));
        }
    }

    /// Voice room `channel`'s `anonymous` flag changed (the channel's options): its seats are
    /// named anew (`GroupState::room_anonymous`).
    pub fn on_room_anonymous(&self, channel: ChannelId, anonymous: bool) {
        if !self.on || channel == 0 {
            return;
        }
        self.post(
            &self.room_id(channel),
            Msg::Anonymous { anonymous },
            0,
            true,
        );
    }

    /// Whether the room epoch `(gen, epoch)` a post names is gated, as its header says: a
    /// writer names itself by the head it holds (writer.rs `writer_m`), not by the channel's
    /// gate now, which an opening follows late (plan 2d).
    pub fn room_gated(&self, group: &str, gen: &[u8; 16], epoch: u32) -> bool {
        let Some(h) = self.get(group) else {
            return false;
        };
        let snap = h.snap.read().unwrap_or_else(|e| e.into_inner()).clone();
        snap.is_some_and(|s| gated_at(&s.head, s.recent.iter(), gen, epoch))
    }
}

/// Whether epoch `(gen, epoch)` is gated, by the newest header of it among the head and the
/// headers kept (`gated` moves only at an opening); the head's when none is kept.
fn gated_at<'a>(
    head: &'a SignedHeader,
    recent: impl DoubleEndedIterator<Item = &'a SignedHeader>,
    gen: &[u8; 16],
    epoch: u32,
) -> bool {
    std::iter::once(head)
        .chain(recent.rev())
        .map(|h| h.header())
        .find(|h| h.gen == *gen && h.epoch == epoch)
        .unwrap_or(head.header())
        .gated
}

impl GroupState {
    /// Whom a member's voice seat names: its account, or its connection for a guest and in
    /// an anonymous room that is not gated (open choice 11). Gated means the channel's gate
    /// or a head still gated: a gated head seats no connection (rule 6), and a gate's end
    /// opens the head only at the next opening (plan 2d).
    pub fn room_seat_m(&self, sid: UserId, account: Option<[u8; 16]>) -> MemberId {
        match account {
            Some(a) if self.gate || self.head_gated() || !self.anonymous => MemberId::Account(a),
            _ => MemberId::Conn(sid),
        }
    }

    /// Whom a member's post in the room names as its writer (`EpochPostIn.writer`, the key
    /// its blob is kept under): as the writer's app names it (writer.rs `writer_m`), by the
    /// account unless the room is anonymous and the post's epoch is not gated.
    pub fn room_writer(
        &self,
        sid: UserId,
        account: Option<[u8; 16]>,
        gen: &[u8; 16],
        epoch: u32,
    ) -> MemberId {
        let gated = self
            .head
            .as_ref()
            .is_some_and(|h| gated_at(&h.sh, self.recent.iter(), gen, epoch));
        match account {
            Some(a) if gated || !self.anonymous => MemberId::Account(a),
            _ => MemberId::Conn(sid),
        }
    }

    /// The room's `anonymous` flag, as a join or the channel's options tell it: a change names
    /// the seats anew.
    pub fn room_anonymous(&mut self, anonymous: bool, now: u64, out: &mut Vec<Out>) {
        if self.anonymous == anonymous {
            return;
        }
        self.anonymous = anonymous;
        self.room_rename(cause::REJOIN, now, out);
        self.ask(now, out);
    }

    /// The room's naming moved (`room_seat_m`): each member whose seat is named otherwise
    /// takes its pair's seat under the new name, queued as a joiner, and its old seat exits
    /// with `cause`; every member who has the roster, the member itself among them, hears the
    /// new seat. A member with no seat now keeps the name for its next one.
    pub fn room_rename(&mut self, cause: u8, now: u64, out: &mut Vec<Out>) {
        let mut sids: Vec<UserId> = self.vols.keys().copied().collect();
        sids.sort_unstable();
        let mut moved = vec![];
        for sid in sids {
            let member = self.members.get(&sid).cloned().unwrap_or_default();
            let name = self.room_seat_m(sid, member.account);
            let Some(v) = self.vols.get_mut(&sid) else {
                continue;
            };
            let seat = v.pair.keys.seat(name);
            let Some(j) = v.seat.as_mut().filter(|j| j.seat != seat) else {
                continue;
            };
            let old = std::mem::replace(&mut j.seat, seat);
            let joiner = j.clone();
            moved.push((sid, gk::GkSeat::from(seat)));
            if member.seat != Some(old) {
                continue;
            }
            self.exit(old, cause, now, out);
            if let Some(m) = self.members.get_mut(&sid) {
                m.seat = Some(seat);
            }
            let w = Waiting {
                joiner,
                sids: vec![sid],
                account: member.account,
            };
            self.joins.add(w, now);
        }
        if moved.is_empty() {
            return;
        }
        let piece = VoiceSeatsPiece {
            seats: moved,
            ..VoiceSeatsPiece::default()
        };
        for (s, m) in &self.members {
            if m.roster {
                out.push(Out(*s, seats_frames(&self.id, piece.clone())));
            }
        }
    }

    /// A member's fetch brought its connection pair: its seat, and its offer to hold the
    /// room's keys with that pair. The roster goes to it whole, its seat to every other
    /// member who has the roster.
    pub fn room_seat(
        &mut self,
        sid: UserId,
        account: Option<[u8; 16]>,
        pair: &Pair,
        ik: [u8; 32],
        now: u64,
        out: &mut Vec<Out>,
    ) -> SeatRef {
        let seat = pair.keys.seat(self.room_seat_m(sid, account));
        self.vols.insert(
            sid,
            Volunteer {
                sid,
                // No platform rule holds in a voice room
                platform: platform::DESKTOP,
                m: account.map_or(MemberId::Conn(sid), MemberId::Account),
                ik,
                pair: pair.clone(),
                seat: Some(Joiner {
                    seat,
                    ik,
                    keys: pair.keys.clone(),
                    endorsement: pair.endorsement.clone(),
                    returning: false,
                }),
            },
        );
        self.holders.seen(&self.vols, now);
        let one = VoiceSeatsPiece {
            seats: vec![(sid, seat.into())],
            ..VoiceSeatsPiece::default()
        };
        for (s, m) in &self.members {
            if *s != sid && m.roster {
                out.push(Out(*s, seats_frames(&self.id, one.clone())));
            }
        }
        if let Some(m) = self.members.get_mut(&sid) {
            m.roster = true;
        }
        let whole = VoiceSeatsPiece {
            seats: self.room_seats(),
            gone: vec![],
            whole: true,
        };
        out.push(Out(sid, seats_frames(&self.id, whole)));
        seat
    }

    /// `sid` left the room: every member who has the roster hears it.
    pub fn room_gone(&self, sid: UserId, out: &mut Vec<Out>) {
        let gone = VoiceSeatsPiece {
            gone: vec![sid],
            ..VoiceSeatsPiece::default()
        };
        for (s, m) in &self.members {
            if m.roster {
                out.push(Out(*s, seats_frames(&self.id, gone.clone())));
            }
        }
    }

    /// The roster: each member's seat by user id, in id order.
    fn room_seats(&self) -> Vec<(UserId, gk::GkSeat)> {
        let mut seats: Vec<(UserId, gk::GkSeat)> = self
            .vols
            .iter()
            .filter_map(|(u, v)| Some((*u, v.seat.as_ref()?.seat.into())))
            .collect();
        seats.sort_unstable_by_key(|(u, _)| *u);
        seats
    }

    /// The roster's user ids, lowest first.
    pub fn room_roster(&self) -> Vec<UserId> {
        let mut ids: Vec<UserId> = self.vols.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// The member to promote, if the room wants one: fewer than 2 entries online, and the
    /// lowest seated member that is no entry, if it is among the 4 lowest of the roster.
    pub fn room_candidate(&self) -> Option<Volunteer> {
        let set = &self.holders.set;
        if set.is_empty()
            || set.len() >= MAX_KEYHOLDERS
            || self.holders.online(&self.vols).len() >= KEYHOLDERS_ONLINE_MIN
        {
            return None;
        }
        let seated = |v: &Volunteer| {
            self.members
                .get(&v.sid)
                .and_then(|m| m.seat)
                .is_some_and(|s| self.seats.contains_key(&s))
        };
        let lowest = self.room_roster();
        self.vols
            .values()
            .filter(|v| !set.iter().any(|k| k.kx == v.pair.kx()))
            .filter(|v| seated(v) && v.entry(GroupKind::Voice).is_some())
            .min_by_key(|v| v.sid)
            .filter(|v| lowest.iter().take(LOWEST).any(|u| *u == v.sid))
            .cloned()
    }

    /// After a voice Genesis: every member whose pair the relay holds is queued for the new
    /// generation, its seat named as the new head names it (`room_seat_m`).
    pub fn room_reseat(&mut self, now: u64, out: &mut Vec<Out>) {
        self.room_rename(cause::REJOIN, now, out);
        let mut sids: Vec<UserId> = self.vols.keys().copied().collect();
        sids.sort_unstable();
        for sid in sids {
            let Some(j) = self.vols.get(&sid).and_then(|v| v.seat.clone()) else {
                continue;
            };
            if self.seats.contains_key(&j.seat) || self.joins.has(&j.seat) {
                continue;
            }
            let Some(m) = self.members.get_mut(&sid) else {
                continue;
            };
            m.seat = Some(j.seat);
            let w = Waiting {
                account: j.seat.m.account(),
                joiner: j,
                sids: vec![sid],
            };
            self.joins.add(w, now);
        }
    }

    /// The seats a voice Remove's seed roll owes a seed welcome in its own commit (those on
    /// a seed the new floor drops, `held`), with the keys of their joins.
    pub fn room_seed_seats(&self, held: &HashMap<SeatRef, u32>) -> Vec<gk::SeedSeat> {
        held.keys()
            .filter_map(|s| {
                let (ik, pair) = self.conn_keys.get(s)?;
                Some(gk::SeedSeat {
                    seat: (*s).into(),
                    ik: *ik,
                    keys: pair.into(),
                })
            })
            .collect()
    }
}

/// `VoiceSeats` for room group `group`, in parts of `VOICE_SEATS_PER_FRAME` entries: the seats
/// first, then the gone. `whole` rides on the first part only (a receiver clears its roster at
/// a part that carries it).
pub fn seats_frames(group: &str, piece: VoiceSeatsPiece) -> Vec<ServerMessage> {
    let channel_id = group
        .rsplit(':')
        .next()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let VoiceSeatsPiece { seats, gone, whole } = piece;
    let mut parts: Vec<VoiceSeatsPiece> = seats
        .chunks(VOICE_SEATS_PER_FRAME)
        .map(|c| VoiceSeatsPiece {
            seats: c.to_vec(),
            ..VoiceSeatsPiece::default()
        })
        .chain(gone.chunks(VOICE_SEATS_PER_FRAME).map(|c| VoiceSeatsPiece {
            gone: c.to_vec(),
            ..VoiceSeatsPiece::default()
        }))
        .collect();
    if parts.is_empty() {
        parts.push(VoiceSeatsPiece::default());
    }
    parts[0].whole = whole;
    let n = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(i, piece)| ServerMessage::VoiceSeats {
            channel_id,
            group: group.to_string(),
            part: i as u16,
            last: i + 1 == n,
            piece,
        })
        .collect()
}
