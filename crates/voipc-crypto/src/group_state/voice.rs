//! Voice keys from the room's epoch key (plan part 5, spec §5.9, §3.10). A voice room is a
//! group of its own, and nobody mints or sends a media key: each time the room's head epoch
//! key is new, the host gets the epochs held (`GkOut::voice`), and the `MediaKeyRing` in
//! group-key mode derives every sender's key from `CK_e` and that sender's seat: ours from our
//! own pair, each other one's from the room's roster (`VoiceSeats`). Ours goes under the name
//! the roster gives our pair, as every receiver derives it, once the roster names us.
//!
//! Voice never stops: an exit no opening covered within 46 s is told (`leaver_may_hear`), and
//! a gated room's names fold as its Joins come, whether this member writes or not, a failed
//! fold telling why while voice goes on (chat in the room still holds, as a text writer's
//! does).

use std::collections::HashMap;

use super::member::Member;
use super::{names, writer, GkCtx, GkEvent, GkOut, VoiceKeys, Warn, Who};
use crate::group_key::{GroupKind, MemberId};

/// A sender moves to a new epoch this long after taking it, so a receiver a little slower to
/// take it loses no packet (open choice 8).
pub(super) const SWITCH_MS: u64 = 300;

/// This connection's voice rooms, by channel.
#[derive(Default)]
pub(super) struct Voice {
    rooms: HashMap<u32, Room>,
}

#[derive(Default)]
struct Room {
    /// The generation, newest epoch and switch time last handed out.
    sent: Option<([u8; 16], u32, u64)>,
    /// `leaver_may_hear` was told for the exits holding now.
    warned: bool,
    /// The roster moved while no key was held (a refused post clears them): the keys go
    /// again once one is, though their epoch went out before.
    owed: bool,
}

impl Voice {
    /// After a frame or a tick (`moved`: a header was taken). The keys go out whenever the
    /// head epoch's key is one not handed out yet, not only with a header: a refetch can
    /// bring the key of a head already taken. A new epoch is sent under `SWITCH_MS` after,
    /// the first keys and a new generation's at once.
    pub(super) fn after_take(
        &mut self,
        who: &Who,
        m: &mut Member,
        moved: bool,
        c: &mut GkCtx,
        out: &mut GkOut,
    ) {
        let fresh = std::mem::take(&mut m.names.fresh);
        if m.t.kind != GroupKind::Voice {
            return;
        }
        let room = self.rooms.entry(m.t.channel_id).or_default();
        let late = m
            .floor
            .as_ref()
            .is_some_and(|f| m.writer.exit_holds(&f.gen, c.now));
        if late && !room.warned {
            out.events.push(GkEvent::Warning {
                channel_id: m.t.channel_id,
                kind: Warn::LeaverMayHear,
                n: 0,
            });
        }
        room.warned = late;
        if (moved || fresh) && m.head.as_ref().is_some_and(|h| h.header().gated) {
            names::fold(m, who, c, out);
        }
        let Some(k) = m.current_key() else {
            return;
        };
        let (gen, epoch) = (k.gen, k.epoch);
        let same = room.sent.filter(|(g, e, _)| (*g, *e) == (gen, epoch));
        if same.is_some() && !room.owed {
            return;
        }
        let new_generation = room.sent.is_none_or(|(g, _, _)| g != gen);
        let switch_at = match same {
            Some((_, _, at)) => at,
            None if new_generation => c.now,
            None => c.now.saturating_add(SWITCH_MS),
        };
        if let Some(v) = keys(who, m, switch_at, new_generation) {
            room.sent = Some((gen, epoch, switch_at));
            room.owed = false;
            out.voice.push(v);
        }
    }

    /// The room's roster moved (`m.voice_seats`): once keys went out, they go again with it,
    /// at the switch time they had; while none is held, once one is.
    pub(super) fn seats_in(&mut self, who: &Who, m: &Member, out: &mut GkOut) {
        let Some(room) = self.rooms.get_mut(&m.t.channel_id) else {
            return;
        };
        let Some((_, _, switch_at)) = room.sent else {
            return;
        };
        match keys(who, m, switch_at, false) {
            Some(v) => out.voice.push(v),
            None => room.owed = true,
        }
    }

    /// Out of the room: what was handed out goes with it, so a return hands it out again.
    pub(super) fn untrack(&mut self, channel_id: u32) {
        self.rooms.remove(&channel_id);
    }
}

/// The room's keys as the ring takes them: the epochs held of the newest key's generation
/// (at most two), our own seat and the roster.
fn keys(who: &Who, m: &Member, switch_at: u64, new_generation: bool) -> Option<VoiceKeys> {
    let gen = m.keys.last()?.gen;
    let mut epochs: Vec<_> = m
        .keys
        .iter()
        .filter(|k| k.gen == gen)
        .map(|k| (k.epoch, k.d_e, k.ck.clone()))
        .collect();
    epochs.sort_by_key(|(e, _, _)| *e);
    let tag = who.conn.pair()?.public().tag_dh();
    Some(VoiceKeys {
        channel_id: m.t.channel_id,
        group: m.t.group.clone(),
        gen,
        epochs,
        own: (own_m(who, m, tag), tag),
        seats: m
            .voice_seats
            .iter()
            .map(|(u, s)| (*u, MemberId::from(s.m), s.sx))
            .collect(),
        switch_at,
        new_generation,
    })
}

/// Our seat's name: the connection's pair is named by the account, or by the connection for a
/// guest and in an anonymous room that is not gated (open choice 11). The relay names it when
/// it seats it and the room's flags may change since, so ours is the name the roster gives our
/// pair, which every receiver derives our key under; one of our own two only, so no roster
/// moves it elsewhere. Before the roster names us, the name our posts go under (`writer_m`).
fn own_m(who: &Who, m: &Member, tag: [u8; 8]) -> MemberId {
    let ours = |n: &MemberId| match n {
        MemberId::Conn(u) => *u == who.user_id,
        MemberId::Account(a) => who.account == Some(*a),
    };
    m.voice_seats
        .get(&who.user_id)
        .filter(|s| s.sx == tag)
        .map(|s| MemberId::from(s.m))
        .filter(ours)
        .unwrap_or_else(|| writer::writer_m(m, who))
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::IdentityKeyPair;
    use voipc_protocol::gk;
    use voipc_protocol::messages::{ClientMessage, ServerMessage};

    use super::super::{
        GkPins, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, SeatKeys, VaultFloor,
    };
    use super::*;
    use crate::group_key::build::world::{same_ik, Holder, World, T0, VOICE_ID};
    use crate::group_key::build::Built;
    use crate::group_key::commit::{Due, DueKind, Joiner};
    use crate::group_key::timers::{CHECK_WAIT_MS, EXIT_HOLD_MS};
    use crate::group_key::{
        inclusion_path, Endorsement, Kind, Leaf, Origin, SeatPair, SeatRef, SignedHeader,
    };
    use crate::stores::SignalStores;
    use crate::{build_aad, media_decrypt, media_encrypt, MediaKeyRing};

    /// The run and channel of `VOICE_ID`.
    const RUN: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const ROOM: u32 = 7;

    struct Device {
        keying: GroupKeying,
        st: SignalStores,
        pins: MemoryPins,
        u: u32,
        ik: IdentityKeyPair,
        account: Option<[u8; 16]>,
    }

    impl Device {
        /// In the room: its first fetch carries its connection pair.
        fn new(u: u32, account: Option<[u8; 16]>, anonymous: bool) -> (Device, GkOut) {
            let ik = IdentityKeyPair::generate(&mut crate::rng());
            let mut keying = GroupKeying::default();
            let _ = keying.start(GkStart {
                on: true,
                run: RUN,
                relay_clock: T0,
                platform: Platform::Desktop,
                help_hold_keys: false,
                user_id: u,
                identity: ik,
                account,
                seat_keys: account.map(|_| SeatKeys::generate(1, T0)),
                local: None,
                visible: true,
            });
            let t = GkTrack {
                channel_id: ROOM,
                group: VOICE_ID.into(),
                kind: GroupKind::Voice,
                anonymous,
                hide_members: false,
                viewer_admin: false,
                keeps_history: false,
            };
            let out = keying.track(t, VaultFloor::None);
            let d = Device {
                keying,
                st: SignalStores::new(&ik, u),
                pins: MemoryPins::default(),
                u,
                ik,
                account,
            };
            (d, out)
        }

        /// Its seat as the relay hands it to a keyholder: the connection pair its fetch
        /// carried, named by its account where it has one.
        fn joiner(&self, out: &GkOut) -> Joiner {
            let seat = out
                .send
                .iter()
                .find_map(|m| match m {
                    ClientMessage::EpochFetch { seat, .. } => seat.clone(),
                    _ => None,
                })
                .expect("a voice fetch carries the connection pair");
            let pair = crate::group_key::wire::pair(&seat, gk::GkMember::Conn(self.u)).unwrap();
            let m = self
                .account
                .map_or(MemberId::Conn(self.u), MemberId::Account);
            Joiner {
                seat: pair.keys.seat(m),
                ik: self.ik.public_key().public_key_bytes().try_into().unwrap(),
                keys: pair.keys,
                endorsement: pair.endorsement,
                returning: false,
            }
        }

        fn frame(&mut self, msg: &ServerMessage, now_ms: u64) -> GkOut {
            let c = GkCtx {
                pins: &mut self.pins,
                now: now_ms,
            };
            self.keying.frame(&mut self.st, msg, c)
        }

        fn take(&mut self, piece: gk::InPiece, now: u64) -> GkOut {
            let msg = ServerMessage::EpochIn {
                group: VOICE_ID.into(),
                part: 0,
                last: true,
                piece: Box::new(piece),
            };
            self.frame(&msg, now * 1000)
        }

        fn tick(&mut self, now_ms: u64) -> GkOut {
            let c = GkCtx {
                pins: &mut self.pins,
                now: now_ms,
            };
            self.keying.tick(&mut self.st, c)
        }
    }

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

    /// Keyholder user 3, as `m`: a guest's endorsement carries counter 0 (C1 note 2), which
    /// members check (`World::voice`'s keyholder carries 1); an account's carries its own.
    fn holder(m: MemberId) -> Holder {
        let n = u32::from(m.account().is_some());
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let pair = SeatPair::generate();
        let endorsement = Endorsement::sign(
            &ik,
            Origin::Connection,
            MemberId::Conn(3),
            n,
            T0,
            &pair.public(),
        )
        .unwrap();
        let seat = crate::group_key::build::world::Member {
            seat: pair.public().seat(m),
            pair: pair.clone(),
            ik: same_ik(&ik),
            endorsement: endorsement.clone(),
        };
        Holder {
            m,
            pair,
            ik,
            endorsement,
            seat,
        }
    }

    /// A voice room whose keyholder is guest 3.
    fn room() -> World {
        World::start(
            GroupKind::Voice,
            VOICE_ID,
            false,
            false,
            holder(MemberId::Conn(3)),
        )
    }

    /// A gated voice room whose keyholder is account 3 on user 3. `World::start` puts only
    /// a guest keyholder in the roster its Genesis is checked against.
    fn gated_room() -> World {
        use crate::group_key::build::world::copy_ring;
        let holder = holder(MemberId::Account([3; 16]));
        let due = World::genesis_due(&holder, true);
        let (kind, id) = (GroupKind::Voice, VOICE_ID);
        let built = World::build_start(&holder, kind, id, false, &due, T0, None).unwrap();
        let by = holder.by();
        let a = World::check_start(kind, id, false, &due, by, &built.commit, T0, &[3]).unwrap();
        let gen = a.header.header().gen;
        let mut w = World {
            kind,
            id,
            stored: false,
            g: crate::group_key::Group::new(kind, id, gen).unwrap(),
            head: a.header.clone(),
            kh: a.header.clone(),
            leaves: vec![],
            keys: Default::default(),
            held: Default::default(),
            used_v: Default::default(),
            rolls: a.rolls,
            gens: vec![],
            ring: copy_ring(&built.ring),
            krk: built.krk.clone(),
            holders: vec![holder],
            cache: crate::group_key::build::RowBases::new(),
            now: T0,
            roster: vec![3],
            no_keyholder_since: None,
            seq: 0,
            seed_keys: true,
        };
        w.take(&due, a, &built);
        w
    }

    /// Seats `joiners` by an honest Join.
    fn join(w: &mut World, joiners: Vec<Joiner>) -> Built {
        let due = Due {
            joiners,
            ..w.due(DueKind::Join)
        };
        let b = w.build_join(&due, None).unwrap();
        w.step(&due, &b);
        b
    }

    /// What the relay sends `seat` at the head: the walk, the head's opening, its leaf and
    /// path, its welcome (none once it holds its version's key) and the seal.
    fn piece(w: &World, b: &Built, seat: &SeatRef, walk: &[&SignedHeader]) -> gk::InPiece {
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let i = w
            .leaves
            .iter()
            .position(|l| l.seats.contains(seat))
            .unwrap();
        let leaf = leaves[i];
        let seat_keying =
            b.commit
                .welcomes
                .iter()
                .find(|x| x.seat == *seat)
                .map(|x| gk::SeatKeying {
                    b: x.b,
                    base_v: x.v,
                    s: x.s,
                    from: w.holders[0].by().into(),
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

    /// A guest seated at the head of `w`, its seat, and what taking it handed out.
    fn seated(w: &mut World, u: u32) -> (Device, SeatRef, GkOut) {
        let (mut d, out) = Device::new(u, None, false);
        let j = d.joiner(&out);
        let seat = j.seat;
        let b = join(w, vec![j]);
        let genesis = w.kh.clone();
        let out = d.take(piece(w, &b, &seat, &[&genesis]), w.now);
        (d, seat, out)
    }

    fn voice_seats(seats: Vec<(u32, gk::GkSeat)>) -> ServerMessage {
        ServerMessage::VoiceSeats {
            channel_id: ROOM,
            group: VOICE_ID.into(),
            part: 0,
            last: true,
            piece: gk::VoiceSeatsPiece {
                seats,
                gone: vec![],
                whole: true,
            },
        }
    }

    fn gk_seat(s: &SeatRef) -> gk::GkSeat {
        gk::GkSeat {
            m: match s.m {
                MemberId::Account(a) => gk::GkMember::Account(a),
                MemberId::Conn(u) => gk::GkMember::Conn(u),
            },
            sk: s.tag_sk,
            sx: s.tag_sx,
        }
    }

    /// §5.9: a joiner's first key goes out at once, its own seat the connection pair its
    /// fetch carried. The same key is not handed out again.
    #[test]
    fn a_seated_member_hands_out_the_epoch_key_to_send_under_at_once() {
        let mut w = room();
        let (mut d, seat, out) = seated(&mut w, 20);
        let [v] = out.voice.as_slice() else {
            panic!("one handout: {}", out.voice.len());
        };
        let hd = w.head.header();
        assert_eq!(
            (v.channel_id, v.group.as_str(), v.gen),
            (ROOM, VOICE_ID, hd.gen)
        );
        let ck = d.keying.current_epoch(VOICE_ID).unwrap().ck;
        assert_eq!(v.epochs.len(), 1);
        assert_eq!((v.epochs[0].0, v.epochs[0].1), (hd.epoch, w.head.d_e()));
        assert_eq!(*v.epochs[0].2, *ck);
        assert_eq!(v.own, (MemberId::Conn(20), seat.tag_sx));
        assert_eq!(v.switch_at, w.now * 1000, "at once");
        assert!(v.new_generation);
        assert!(d.tick(w.now * 1000 + 1).voice.is_empty());
    }

    /// Open choice 8: a new epoch is sent under 300 ms after it is taken, with the one
    /// before kept; a Join that opens no epoch hands out nothing.
    #[test]
    fn a_new_epoch_is_sent_under_300_ms_after_it_is_taken() {
        let mut w = room();
        let (mut d, seat, _) = seated(&mut w, 20);
        let before = w.head.header().epoch;
        let b = w.open(&w.due(DueKind::Refresh));
        let out = d.take(piece(&w, &b, &seat, &[]), w.now);
        let [v] = out.voice.as_slice() else {
            panic!("one handout: {}", out.voice.len());
        };
        let epochs: Vec<u32> = v.epochs.iter().map(|(e, _, _)| *e).collect();
        assert_eq!(epochs, vec![before, w.head.header().epoch]);
        assert_eq!(v.switch_at, w.now * 1000 + SWITCH_MS);
        assert!(!v.new_generation);
        let (other, out2) = Device::new(21, None, false);
        let _ = join(&mut w, vec![other.joiner(&out2)]);
        let out = d.take(piece(&w, &b, &seat, &[]), w.now);
        assert_eq!(
            d.keying.groups[VOICE_ID].floor.as_ref().unwrap().d,
            w.head.d()
        );
        assert!(out.voice.is_empty(), "the epoch did not move");
    }

    /// §5.9: the roster goes with the keys, and again at each `VoiceSeats`, at the switch
    /// time the keys had; before any key nothing goes.
    #[test]
    fn the_roster_goes_with_the_keys_and_again_with_each_voice_seats() {
        let mut w = room();
        let (mut early, out) = Device::new(20, None, false);
        let seats = voice_seats(vec![]);
        assert!(early.frame(&seats, w.now * 1000).voice.is_empty());
        let j = early.joiner(&out);
        let seat = j.seat;
        let b = join(&mut w, vec![j]);
        let genesis = w.kh.clone();
        let first = early.take(piece(&w, &b, &seat, &[&genesis]), w.now);
        let switch_at = first.voice[0].switch_at;
        let them = w.holders[0].seat.seat;
        let out = early.frame(
            &voice_seats(vec![(20, gk_seat(&seat)), (3, gk_seat(&them))]),
            w.now * 1000 + 5000,
        );
        let [v] = out.voice.as_slice() else {
            panic!("one handout: {}", out.voice.len());
        };
        assert_eq!(
            v.seats,
            vec![(3, them.m, them.tag_sx), (20, seat.m, seat.tag_sx)]
        );
        assert_eq!(v.switch_at, switch_at);
        assert!(!v.new_generation);
    }

    /// §5.9, §3.10: two devices of one account in a room are two seats, named by the account,
    /// with two keys; each derives its own key and the other's from the roster alike, and a
    /// packet from one opens at the other.
    #[test]
    fn two_devices_of_one_account_get_two_seats_and_two_keys() {
        let mut w = room();
        let (mut a, out_a) = Device::new(20, Some([7; 16]), false);
        let (mut b, out_b) = Device::new(21, Some([7; 16]), false);
        let (ja, jb) = (a.joiner(&out_a), b.joiner(&out_b));
        let (sa, sb) = (ja.seat, jb.seat);
        let built = join(&mut w, vec![ja, jb]);
        let genesis = w.kh.clone();
        a.take(piece(&w, &built, &sa, &[&genesis]), w.now);
        b.take(piece(&w, &built, &sb, &[&genesis]), w.now);
        let roster = voice_seats(vec![(20, gk_seat(&sa)), (21, gk_seat(&sb))]);
        let ka = a.frame(&roster, w.now * 1000).voice.pop().unwrap();
        let kb = b.frame(&roster, w.now * 1000).voice.pop().unwrap();
        assert_eq!(ka.own.0, MemberId::Account([7; 16]));
        assert_eq!(kb.own.0, MemberId::Account([7; 16]));
        assert_ne!(ka.own.1, kb.own.1, "two connection pairs");
        let (mut ra, mut rb) = (MediaKeyRing::default(), MediaKeyRing::default());
        assert!(ra.install_gk(&ka, ROOM) && rb.install_gk(&kb, ROOM));
        let (mine, theirs) = (ra.current().unwrap(), rb.current().unwrap());
        assert_eq!(mine.key_id, w.head.header().epoch as u16);
        assert_ne!(mine.key_bytes, theirs.key_bytes);
        let aad = build_aad(ROOM, 0x05, 20);
        let packet = media_encrypt(mine, ra.stream_id(), 1, 0, &aad, b"hello").unwrap();
        let key = rb
            .get_for(ROOM, 20, ra.stream_id(), mine.key_id)
            .expect("the roster seats 20")
            .clone();
        assert_eq!(
            media_decrypt(&key, ra.stream_id(), 1, 0, &aad, &packet).unwrap(),
            b"hello"
        );
    }

    /// Open choice 11: in an anonymous room that is not gated our seat is named by the
    /// connection, signed in or not, so no account id goes behind a pseudonym; elsewhere a
    /// signed-in member's is its account's.
    #[test]
    fn an_anonymous_room_names_our_seat_by_the_connection() {
        for (anonymous, account, named) in [
            (true, Some([7; 16]), MemberId::Conn(20)),
            (true, None, MemberId::Conn(20)),
            (false, Some([7; 16]), MemberId::Account([7; 16])),
            (false, None, MemberId::Conn(20)),
        ] {
            let (mut d, _) = Device::new(20, account, anonymous);
            let m = d.keying.groups.get_mut(VOICE_ID).unwrap();
            m.keys.push(super::super::member::EpochKey {
                gen: [1; 16],
                epoch: 1,
                d_e: [2; 32],
                ck: [3; 32].into(),
                opened: None,
            });
            let who = d.keying.who.as_ref().unwrap();
            let v = keys(who, &d.keying.groups[VOICE_ID], 0, false).unwrap();
            assert_eq!(v.own.0, named, "anonymous {anonymous}, account {account:?}");
        }
    }

    /// §3.10: the relay names our seat when it seats it. When the room turns anonymous later,
    /// our key still goes under the name the roster gives our pair, as the others derive it,
    /// and a packet of ours opens; a roster naming our pair as someone else moves nothing.
    #[test]
    fn our_key_goes_under_the_seat_the_roster_names_when_the_room_turns_anonymous() {
        let mut w = room();
        let (mut a, out_a) = Device::new(20, Some([7; 16]), false);
        let (mut b, out_b) = Device::new(21, None, false);
        let (ja, jb) = (a.joiner(&out_a), b.joiner(&out_b));
        let (sa, sb) = (ja.seat, jb.seat);
        let built = join(&mut w, vec![ja, jb]);
        let genesis = w.kh.clone();
        a.take(piece(&w, &built, &sa, &[&genesis]), w.now);
        b.take(piece(&w, &built, &sb, &[&genesis]), w.now);
        let mut t = a.keying.groups[VOICE_ID].t.clone();
        t.anonymous = true;
        let _ = a.keying.track(t, VaultFloor::None);
        let roster = voice_seats(vec![(20, gk_seat(&sa)), (21, gk_seat(&sb))]);
        let ka = a.frame(&roster, w.now * 1000).voice.pop().unwrap();
        let kb = b.frame(&roster, w.now * 1000).voice.pop().unwrap();
        assert_eq!(ka.own, (MemberId::Account([7; 16]), sa.tag_sx));
        let (mut ra, mut rb) = (MediaKeyRing::default(), MediaKeyRing::default());
        assert!(ra.install_gk(&ka, ROOM) && rb.install_gk(&kb, ROOM));
        let mine = ra.current().unwrap();
        let aad = build_aad(ROOM, 0x05, 20);
        let packet = media_encrypt(mine, ra.stream_id(), 1, 0, &aad, b"hello").unwrap();
        let key = rb.get_for(ROOM, 20, ra.stream_id(), mine.key_id).unwrap();
        assert_eq!(
            media_decrypt(key, ra.stream_id(), 1, 0, &aad, &packet).unwrap(),
            b"hello"
        );
        let mut other = gk_seat(&sa);
        other.m = gk::GkMember::Account([8; 16]);
        let lie = a.frame(&voice_seats(vec![(20, other)]), w.now * 1000);
        assert_eq!(lie.voice[0].own.0, MemberId::Conn(20), "not ours: writer_m");
    }

    /// With no key held (as after a take that brought none, until the refetch brings it), a
    /// roster that moved meanwhile goes with the keys then, though their epoch went out
    /// before, at its switch time. A refused post (`OLD_EPOCH`) no longer drops the keys
    /// (RV r-members:55): a roster that moves after one goes at once.
    #[test]
    fn a_roster_that_moved_while_no_key_was_held_goes_once_the_key_is_back() {
        let mut w = room();
        let (mut d, out) = Device::new(20, None, false);
        let j = d.joiner(&out);
        let seat = j.seat;
        let b = join(&mut w, vec![j]);
        let genesis = w.kh.clone();
        let first = d.take(piece(&w, &b, &seat, &[&genesis]), w.now).voice;
        d.keying.groups.get_mut(VOICE_ID).unwrap().keys.clear();
        let them = w.holders[0].seat.seat;
        let roster = voice_seats(vec![(3, gk_seat(&them)), (20, gk_seat(&seat))]);
        assert!(
            d.frame(&roster, w.now * 1000).voice.is_empty(),
            "no key held"
        );
        let out = d.take(piece(&w, &b, &seat, &[]), w.now + 1);
        let [v] = out.voice.as_slice() else {
            panic!("one handout: {}", out.voice.len());
        };
        assert_eq!(v.seats.len(), 2);
        assert_eq!(v.switch_at, first[0].switch_at);
        assert!(d.tick(w.now * 1000 + 2000).voice.is_empty(), "once");
        let refused = ServerMessage::EpochRefused {
            group: VOICE_ID.into(),
            what: gk::refused_what::POST,
            why: gk::refused_why::OLD_EPOCH,
            detail: String::new(),
        };
        d.frame(&refused, w.now * 1000 + 3000);
        assert_eq!(
            d.frame(&roster, w.now * 1000 + 3000).voice.len(),
            1,
            "a refused post keeps the keys"
        );
    }

    /// §5.9 "voice never stops": an exit no opening covered in 46 s is told once; the keys
    /// stay where they are.
    #[test]
    fn an_exit_left_uncovered_for_46_s_warns_once() {
        let mut w = room();
        let (mut d, _, _) = seated(&mut w, 20);
        let t = w.now * 1000;
        let exit = ServerMessage::EpochExit {
            group: VOICE_ID.into(),
            gen: w.head.header().gen,
            seq: 1,
        };
        d.frame(&exit, t);
        let warned = |out: &GkOut| {
            out.events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        GkEvent::Warning {
                            kind: Warn::LeaverMayHear,
                            ..
                        }
                    )
                })
                .count()
        };
        assert_eq!(warned(&d.tick(t + EXIT_HOLD_MS - 1)), 0);
        assert_eq!(warned(&d.tick(t + EXIT_HOLD_MS)), 1);
        assert_eq!(warned(&d.tick(t + EXIT_HOLD_MS + 1000)), 0, "once");
        assert!(d.keying.current_epoch(VOICE_ID).is_some());
    }

    /// §5.9, §4.4 rule 4: in a gated room every member folds each pushed Join's names as it
    /// comes, writing or not. A fold that fails tells why, and the keys still go out.
    #[test]
    fn a_gated_room_folds_each_pushed_joins_names_and_voice_goes_on() {
        let mut w = gated_room();
        let (mut d, out) = Device::new(20, Some([7; 16]), false);
        let j = d.joiner(&out);
        let seat = j.seat;
        let b = join(&mut w, vec![j]);
        let genesis = w.kh.clone();
        assert_eq!(
            d.take(piece(&w, &b, &seat, &[&genesis]), w.now).voice.len(),
            1
        );
        let push = |w: &World| gk::InPiece {
            head: Some(link(&w.head)),
            pushed: true,
            ..Default::default()
        };
        let (e, out_e) = Device::new(21, Some([9; 16]), false);
        let _ = join(&mut w, vec![e.joiner(&out_e)]);
        let out = d.take(push(&w), w.now);
        let shown = out.events.iter().find_map(|e| match e {
            GkEvent::Readers { named, .. } => Some(named.clone()),
            _ => None,
        });
        assert_eq!(
            shown,
            Some(vec![MemberId::Account([9; 16])]),
            "{:?}",
            out.events
        );
        // One whose key is not the one this device pinned: told, and voice goes on
        d.pins.pin_new([8; 16], [0xee; 32], 0);
        let (f, out_f) = Device::new(22, Some([8; 16]), false);
        let _ = join(&mut w, vec![f.joiner(&out_f)]);
        let out = d.take(push(&w), w.now);
        let held = super::super::GkState::Held(super::super::HeldWhy::Pin);
        assert!(
            out.events
                .iter()
                .any(|e| matches!(e, GkEvent::State { state, .. } if *state == held)),
            "{:?}",
            out.events
        );
        let b = w.open(&w.due(DueKind::Refresh));
        assert_eq!(d.take(piece(&w, &b, &seat, &[]), w.now).voice.len(), 1);
    }

    /// A fold that waits for a Join's list this member never took asks for it, and goes on
    /// when the answer comes, though no header comes with it.
    #[test]
    fn a_gated_rooms_fold_goes_on_when_the_lists_it_asked_for_come() {
        let mut w = gated_room();
        let (mut d, out) = Device::new(20, Some([7; 16]), false);
        let j = d.joiner(&out);
        let seat = j.seat;
        let b = join(&mut w, vec![j]);
        let genesis = w.kh.clone();
        d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
        let mut lists = Vec::new();
        for (u, a) in [(21, [9; 16]), (22, [10; 16])] {
            let (e, out_e) = Device::new(u, Some(a), false);
            let _ = join(&mut w, vec![e.joiner(&out_e)]);
            lists.push(gk::NamesListIn::from(&crate::group_key::NamesList::of(
                w.head.header(),
            )));
        }
        let out = d.take(
            gk::InPiece {
                head: Some(link(&w.head)),
                ..Default::default()
            },
            w.now,
        );
        assert!(
            out.send
                .iter()
                .any(|m| matches!(m, ClientMessage::EpochNames { .. })),
            "the list it lacks is asked"
        );
        let answer = ServerMessage::EpochNamesIn {
            group: VOICE_ID.into(),
            part: 0,
            last: true,
            piece: gk::NamesPiece {
                lists,
                joins: vec![],
                gone: None,
            },
        };
        let out = d.frame(&answer, w.now * 1000);
        let shown = out.events.iter().find_map(|e| match e {
            GkEvent::Readers { named, .. } => Some(named.clone()),
            _ => None,
        });
        assert_eq!(
            shown,
            Some(vec![
                MemberId::Account([9; 16]),
                MemberId::Account([10; 16])
            ]),
            "{:?}",
            out.events
        );
    }

    /// Review: a voice room folds at every names answer, and an answer that did not settle
    /// the fold asked the same again at once, once per round trip for as long as the member
    /// stayed. The same ask goes again only at the pace of an unanswered one.
    #[test]
    fn a_names_answer_that_does_not_fold_is_asked_again_only_after_10_s() {
        let mut w = gated_room();
        let (mut d, out) = Device::new(20, Some([7; 16]), false);
        let j = d.joiner(&out);
        let seat = j.seat;
        let b = join(&mut w, vec![j]);
        let genesis = w.kh.clone();
        d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
        for (u, a) in [(21, [9; 16]), (22, [10; 16])] {
            let (e, out_e) = Device::new(u, Some(a), false);
            let _ = join(&mut w, vec![e.joiner(&out_e)]);
        }
        let asks = |out: &GkOut| {
            out.send
                .iter()
                .filter(|m| matches!(m, ClientMessage::EpochNames { .. }))
                .count()
        };
        let head = gk::InPiece {
            head: Some(link(&w.head)),
            ..Default::default()
        };
        assert_eq!(asks(&d.take(head, w.now)), 1, "the lists it lacks");
        // Lists that do not reach the head, as a relay out of step answers
        let answer = ServerMessage::EpochNamesIn {
            group: VOICE_ID.into(),
            part: 0,
            last: true,
            piece: gk::NamesPiece::default(),
        };
        let t = w.now * 1000;
        assert_eq!(asks(&d.frame(&answer, t)), 1, "the fold starts over");
        assert_eq!(asks(&d.frame(&answer, t + 1)), 0);
        assert_eq!(asks(&d.frame(&answer, t + 2)), 0);
        assert_eq!(asks(&d.frame(&answer, t + CHECK_WAIT_MS)), 1);
    }

    /// Open choice 11: in an anonymous room the relay seats a signed-in member by its
    /// connection (V2); its welcome opens, and its media key names the same seat.
    #[test]
    fn an_anonymous_room_seats_a_signed_in_member_by_its_connection() {
        let mut w = room();
        let (mut d, out) = Device::new(20, Some([7; 16]), true);
        let mut j = d.joiner(&out);
        j.seat.m = MemberId::Conn(20);
        let seat = j.seat;
        let b = join(&mut w, vec![j]);
        let genesis = w.kh.clone();
        let out = d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
        assert_eq!(out.voice[0].own, (MemberId::Conn(20), seat.tag_sx));
    }

    /// An answer that brought no key is asked again at the fetch pace though nothing of ours
    /// waits: a voice room always waits for its keys.
    #[test]
    fn a_voice_room_asks_again_for_keys_an_answer_did_not_bring() {
        let w = room();
        let (mut d, _) = Device::new(20, None, false);
        let answer = gk::InPiece {
            head: Some(link(&w.head)),
            ..Default::default()
        };
        d.take(answer, w.now);
        assert!(d.keying.groups[VOICE_ID].floor.is_some());
        assert!(d.keying.current_epoch(VOICE_ID).is_none());
        let fetched = |out: &GkOut| {
            out.send
                .iter()
                .any(|m| matches!(m, ClientMessage::EpochFetch { .. }))
        };
        let t = w.now * 1000;
        assert!(!fetched(&d.tick(t + 1)));
        assert!(fetched(&d.tick(t + CHECK_WAIT_MS)));
    }
}
