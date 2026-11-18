//! A member's group keys against an honest relay and keyholder (C1's test `World`), and
//! against what a relay may send instead.

use libsignal_protocol::IdentityKeyPair;
use serde_json::json;
use voipc_protocol::gk;
use voipc_protocol::messages::{ClientMessage, ServerMessage};

use super::*;
use crate::group_key::build::world::{World, T0, TEXT_ID};
use crate::group_key::build::Built;
use crate::group_key::commit::{Due, DueKind, Joiner};
use crate::group_key::timers::{CHECK_WAIT_MS, EXIT_HOLD_MS, HOLD_MS};
use crate::group_key::{
    inclusion_path, Added, Endorsement, HeaderV1, Keyholder, Kind, Leaf, Origin, Removed, SeatRef,
    SignedHeader,
};

const RUN: [u8; 16] = [0x11; 16];
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

/// One device on one connection.
struct Device {
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    u: u32,
    ik: IdentityKeyPair,
    account: Option<[u8; 16]>,
}

impl Device {
    fn guest(u: u32) -> Device {
        Device::new(u, IdentityKeyPair::generate(&mut crate::rng()), None, None)
    }

    fn account(u: u32, a: [u8; 16], keys: SeatKeys) -> Device {
        Device::new(
            u,
            IdentityKeyPair::generate(&mut crate::rng()),
            Some(a),
            Some(keys),
        )
    }

    fn new(
        u: u32,
        ik: IdentityKeyPair,
        account: Option<[u8; 16]>,
        keys: Option<SeatKeys>,
    ) -> Device {
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
            seat_keys: keys,
            local: None,
            visible: true,
        });
        Device {
            keying,
            st: SignalStores::new(&ik, u),
            pins: MemoryPins::default(),
            u,
            ik,
            account,
        }
    }

    fn track(&mut self, group: &str, kind: GroupKind, vault: VaultFloor) -> GkOut {
        self.keying.track(track(TEXT, group, kind), vault)
    }

    fn frame(&mut self, msg: &ServerMessage, now: u64) -> GkOut {
        let c = GkCtx {
            pins: &mut self.pins,
            now: now * 1000,
        };
        self.keying.frame(&mut self.st, msg, c)
    }

    fn take(&mut self, piece: gk::InPiece, now: u64) -> GkOut {
        let msg = ServerMessage::EpochIn {
            group: TEXT_ID.into(),
            part: 0,
            last: true,
            piece: Box::new(piece),
        };
        self.frame(&msg, now)
    }

    fn post(&mut self, id: u8, text: &[u8], now_ms: u64) -> GkOut {
        let c = GkCtx {
            pins: &mut self.pins,
            now: now_ms,
        };
        self.keying.post(&mut self.st, TEXT, [id; 16], text, c)
    }

    fn tick(&mut self, now_ms: u64) -> GkOut {
        let c = GkCtx {
            pins: &mut self.pins,
            now: now_ms,
        };
        self.keying.tick(&mut self.st, c)
    }

    /// Its seat as a joiner, from the pair its first fetch carried (a guest), or from its
    /// account's seat keys.
    fn joiner(&self, out: &GkOut, keys: Option<&SeatKeys>) -> Joiner {
        let ik = self.ik.public_key().public_key_bytes().try_into().unwrap();
        if let (Some(a), Some(k)) = (self.account, keys) {
            let public = k.pair.public();
            let m = MemberId::Account(a);
            let endorsement =
                Endorsement::sign(&self.ik, Origin::VaultSeat, m, k.n, k.made, &public).unwrap();
            return Joiner {
                seat: public.seat(m),
                ik,
                keys: public,
                endorsement,
                returning: false,
            };
        }
        let seat = fetched_seat(out).expect("a guest's fetch carries its seat pair");
        let pair = crate::group_key::wire::pair(&seat, gk::GkMember::Conn(self.u)).unwrap();
        Joiner {
            seat: pair.keys.seat(MemberId::Conn(self.u)),
            ik,
            keys: pair.keys,
            endorsement: pair.endorsement,
            returning: false,
        }
    }
}

fn track(channel_id: u32, group: &str, kind: GroupKind) -> GkTrack {
    GkTrack {
        channel_id,
        group: group.into(),
        kind,
        anonymous: false,
        hide_members: false,
        viewer_admin: false,
        keeps_history: false,
    }
}

fn fetched_seat(out: &GkOut) -> Option<gk::EndorsedPair> {
    out.send.iter().find_map(|m| match m {
        ClientMessage::EpochFetch { seat, .. } => seat.clone(),
        _ => None,
    })
}

fn fetches(out: &GkOut) -> usize {
    out.send
        .iter()
        .filter(|m| matches!(m, ClientMessage::EpochFetch { .. }))
        .count()
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

/// What the relay sends `seat` at the head: the walk from the Genesis (with no floor), the
/// opening header of a Join's epoch (1c; here the keyholder header, where it opened it), its
/// leaf and path, its welcome or row, and the seal.
fn piece(w: &World, b: &Built, seat: &SeatRef, walk: &[&SignedHeader]) -> gk::InPiece {
    let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
    let i = w
        .leaves
        .iter()
        .position(|l| l.seats.contains(seat))
        .unwrap();
    let leaf = leaves[i];
    let path = inclusion_path(&leaves, i).unwrap();
    let from: gk::HolderRef = w.holders[0].by().into();
    let welcome = b.commit.welcomes.iter().find(|x| x.seat == *seat);
    let rows = b
        .commit
        .rows
        .iter()
        .find(|r| (r.b, r.v) == (leaf.b, leaf.v));
    let seat_keying = match (welcome, rows) {
        (Some(x), _) => Some(gk::SeatKeying {
            b: x.b,
            base_v: x.v,
            s: x.s,
            from,
            welcome: Some(x.bytes.clone()),
            row: None,
            ratchets: vec![],
        }),
        (None, Some(r)) => {
            let at = w.leaves[i].seats.iter().position(|x| x == seat).unwrap();
            let (row, s) = r.row(at).unwrap();
            Some(gk::SeatKeying {
                b: r.b,
                base_v: r.v,
                s: s as u32,
                from,
                welcome: None,
                row: Some(row.to_vec()),
                ratchets: vec![],
            })
        }
        (None, None) => None,
    };
    let seal = b
        .commit
        .seals
        .iter()
        .find(|s| (s.b, s.v) == (leaf.b, leaf.v))
        .map(|s| s.bytes.clone());
    let hd = w.head.header();
    let opening = (hd.kind == Kind::Join && hd.epoch_parent == w.kh.d()).then(|| header_in(&w.kh));
    gk::InPiece {
        walk: walk.iter().map(|h| link(h)).collect(),
        head: Some(link(&w.head)),
        opening,
        leaf: Some(leaf.into()),
        path: Some(path.try_into().unwrap()),
        seal,
        seat: seat_keying,
        ..Default::default()
    }
}

/// The relay's push of the head to a member that holds the parent.
fn push(w: &World) -> gk::InPiece {
    gk::InPiece {
        head: Some(link(&w.head)),
        pushed: true,
        ..Default::default()
    }
}

fn posted(out: &GkOut) -> Vec<(Option<Vec<u8>>, Vec<u8>, u32)> {
    out.send
        .iter()
        .filter_map(|m| match m {
            ClientMessage::EpochPost {
                blob,
                ciphertext,
                epoch,
                ..
            } => Some((blob.clone(), ciphertext.clone(), *epoch)),
            _ => None,
        })
        .collect()
}

fn post_in(
    w: &World,
    from: &Device,
    blob: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    epoch: u32,
) -> ServerMessage {
    ServerMessage::EpochPostIn {
        channel_id: TEXT,
        group: TEXT_ID.into(),
        gen: w.head.header().gen,
        epoch,
        user_id: from.u,
        username: "writer".into(),
        account: None,
        is_admin: false,
        is_moderator: false,
        writer: gk::GkMember::Conn(from.u),
        blob,
        ciphertext,
        timestamp: 1,
    }
}

/// A guest seated in an open text group, at the head, and its seat.
fn seated(w: &mut World, u: u32) -> (Device, SeatRef) {
    let mut d = Device::guest(u);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, None);
    let seat = j.seat;
    let b = join(w, vec![j]);
    let genesis = w.kh.clone();
    let out = d.take(piece(w, &b, &seat, &[&genesis]), w.now);
    assert!(
        d.keying.current_epoch(TEXT_ID).is_some(),
        "{:?}",
        out.events
    );
    (d, seat)
}

fn seated_guest(w: &mut World, u: u32) -> Device {
    seated(w, u).0
}

// ── taking headers and keys ──

/// §4.4 rule 3 and 3c: a member with no floor walks the keyholder chain back to the Genesis,
/// opens its welcome to `BK`, the seal to `CK`, and `CK` confirms. Its floor is the head.
#[test]
fn a_member_with_no_floor_walks_to_the_genesis_and_opens_the_epoch_key() {
    let mut w = World::text(false, false);
    let mut d = Device::guest(20);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    assert_eq!(fetches(&out), 1);
    let j = d.joiner(&out, None);
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    let out = d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
    let e = d.keying.current_epoch(TEXT_ID).expect("the epoch key");
    assert_eq!(
        (e.gen, e.epoch),
        (w.head.header().gen, w.head.header().epoch)
    );
    assert_eq!(*e.ck, *b.ck);
    assert!(out.vault_floors.is_empty(), "a guest keeps no vault floor");
    assert!(
        d.pins.pin(&[1; 16]).is_some(),
        "the Genesis signer is pinned on its word"
    );
    // A second member's Join is pushed: taken on the floor, the key kept and confirmed
    let mut other = Device::guest(21);
    let out2 = other.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let _ = join(&mut w, vec![other.joiner(&out2, None)]);
    d.take(push(&w), w.now);
    assert_eq!(
        d.keying.groups[TEXT_ID].floor.as_ref().unwrap().d,
        w.head.d()
    );
    assert!(d.keying.current_epoch(TEXT_ID).is_some());
}

/// Rule 5: a seal that opens to a key the header's `confirm` does not name is not taken.
#[test]
fn a_key_the_header_does_not_confirm_is_not_taken() {
    let mut w = World::text(false, false);
    let mut d = Device::guest(20);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, None);
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    let mut p = piece(&w, &b, &seat, &[&genesis]);
    // The seal of another epoch's key under the same bucket key: it opens, and confirms nothing
    let leaf = Leaf::try_from(p.leaf.unwrap()).unwrap();
    let ep = crate::group_key::Epoch {
        e: w.head.header().epoch,
        d_e: w.head.d_e(),
    };
    let at = crate::group_key::Version {
        b: leaf.b,
        v: leaf.v,
    };
    let bk = {
        let x = b.commit.welcomes.iter().find(|x| x.seat == seat).unwrap();
        let from = w.holders[0].holder();
        let keys = d.keying.who.as_ref().unwrap().conn.pair().unwrap().clone();
        let me = crate::group_key::Me {
            m: MemberId::Conn(20),
            keys: &keys,
        };
        crate::group_key::open_seat_welcome(&w.g, x.s, at, &me, &from, &x.bytes)
            .unwrap()
            .1
    };
    p.seal = Some(crate::group_key::seal(&w.g, &ep, at, &bk, &[9; 32]));
    d.take(p, w.now);
    assert!(d.keying.current_epoch(TEXT_ID).is_none());
}

/// 3c: a stored group takes no header while its vault floor is pending; the pages in, it
/// fetches, from the higher of the two floors.
#[test]
fn a_stored_group_takes_no_header_while_its_vault_floor_is_pending() {
    let mut d = Device::guest(20);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::Pending);
    assert_eq!(fetches(&out), 0);
    let w = World::text(true, false);
    d.take(push(&w), w.now);
    assert!(d.keying.groups[TEXT_ID].floor.is_none(), "not taken");
    let out = d.keying.floors_in(TEXT_ID, None);
    assert_eq!(fetches(&out), 1);
    assert!(
        d.keying.floors_in("c:other", None).send.is_empty(),
        "not tracked"
    );
}

/// A book that is not in yet.
struct NotReady(MemoryPins, bool);

impl GkPins for NotReady {
    fn ready(&self) -> bool {
        self.1
    }
    fn pin(&self, a: &[u8; 16]) -> Option<[u8; 32]> {
        self.0.pin(a)
    }
    fn pin_then(&self, a: &[u8; 16], t: u64) -> PinThen {
        self.0.pin_then(a, t)
    }
    fn seen(&self, a: &[u8; 16]) -> Option<Seen> {
        self.0.seen(a)
    }
    fn pin_new(&mut self, a: [u8; 16], ik: [u8; 32], now: u64) {
        self.0.pin_new(a, ik, now)
    }
    fn raise(&mut self, a: [u8; 16], s: Seen, r: bool) {
        self.0.raise(a, s, r)
    }
}

/// 3d: no header is taken before the pins and counters are in (`Pending`), in any group;
/// what came waits, and is taken once they are.
#[test]
fn no_header_is_taken_before_the_pins_and_counters_are_in() {
    let mut w = World::text(false, false);
    let mut d = Device::guest(20);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, None);
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    let msg = ServerMessage::EpochIn {
        group: TEXT_ID.into(),
        part: 0,
        last: true,
        piece: Box::new(piece(&w, &b, &seat, &[&genesis])),
    };
    let mut book = NotReady(MemoryPins::default(), false);
    let c = GkCtx {
        pins: &mut book,
        now: w.now * 1000,
    };
    d.keying.frame(&mut d.st, &msg, c);
    assert!(d.keying.current_epoch(TEXT_ID).is_none());
    book.1 = true;
    let c = GkCtx {
        pins: &mut book,
        now: w.now * 1000,
    };
    d.keying.tick(&mut d.st, c);
    assert!(d.keying.current_epoch(TEXT_ID).is_some());
}

/// C1 note 3, 3c: a voice room's id is `r:` of this run and channel; a text channel's is its
/// log's or the same `r:`. Anything else is not tracked.
#[test]
fn a_group_id_must_have_the_shape_its_channel_may_have() {
    let mut d = Device::guest(20);
    let voice = group_id(GroupKind::Voice, "c:log", &RUN, 5);
    assert_eq!(voice, format!("r:{}:5", voipc_protocol::conv::hex(&RUN)));
    let ok = d
        .keying
        .track(track(5, &voice, GroupKind::Voice), VaultFloor::None);
    assert_eq!(fetches(&ok), 1);
    for (channel, id, kind) in [
        (6, "c:log".to_string(), GroupKind::Voice),
        (7, format!("r:{}:7", "22".repeat(16)), GroupKind::Voice),
        (
            8,
            format!("r:{}:9", voipc_protocol::conv::hex(&RUN)),
            GroupKind::Text,
        ),
    ] {
        let out = d.keying.track(track(channel, &id, kind), VaultFloor::None);
        assert!(out.send.is_empty(), "{id}");
        assert!(!d.keying.groups.contains_key(&id), "{id}");
    }
}

/// 3c, part 7: a member restarted with only its local floor takes the header the relay
/// answers at that floor as its head, and opens the epoch key under it.
#[test]
fn a_restarted_member_takes_the_header_at_its_floor_as_head_and_opens_the_key() {
    let mut w = World::text(true, false);
    let a = [7; 16];
    let keys = SeatKeys::generate(1, T0);
    let copy = seat_keys::copy(&keys);
    let mut d = Device::account(20, a, keys);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, Some(&copy));
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
    assert!(d.keying.current_epoch(TEXT_ID).is_some());
    // The app restarts: a new connection with what this device kept
    let mut again = Device::account(20, a, seat_keys::copy(&copy));
    again.keying.local = d.keying.local().cloned();
    again.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    assert!(again.keying.groups[TEXT_ID].head.is_none());
    again.take(piece(&w, &b, &seat, &[]), w.now);
    assert!(again.keying.current_epoch(TEXT_ID).is_some());
}

/// §4.4 rule 6, 3c: a member whose floor is gated reports the group open when a walk
/// reaches an open head, not only when it takes the opening header that turned it.
#[test]
fn a_gated_floor_reports_the_group_open_when_a_walk_reaches_an_open_head() {
    let mut w = World::text(true, true);
    let keys = SeatKeys::generate(1, T0);
    let copy = seat_keys::copy(&keys);
    let mut d = Device::account(20, [7; 16], keys);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, Some(&copy));
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
    assert!(d.keying.groups[TEXT_ID].floor.as_ref().unwrap().gated);
    w.tick(2);
    w.open(&Due {
        gated: false,
        ..w.due(DueKind::Gate)
    });
    assert!(!w.gated());
    // Not on that header's push: the next head is a Join past it, reached by a walk
    let late = crate::group_key::build::world::Member::account(9);
    w.join(&[&late]);
    let out = d.take(
        gk::InPiece {
            head: Some(link(&w.head)),
            ..Default::default()
        },
        w.now,
    );
    assert_eq!(
        d.keying.groups[TEXT_ID].floor.as_ref().unwrap().d,
        w.head.d(),
        "taken"
    );
    assert!(out.events.contains(&GkEvent::Warning {
        channel_id: TEXT,
        kind: Warn::GatedOpened,
        n: 0
    }));
}

/// A channel tracked again under the same group (`ChannelUpdated`, which the relay sends at
/// will) keeps its head and keys: it does not start over.
#[test]
fn a_channel_tracked_again_under_its_group_keeps_its_keys() {
    let mut w = World::text(false, false);
    let mut d = seated_guest(&mut w, 20);
    let t = GkTrack {
        anonymous: true,
        ..track(TEXT, TEXT_ID, GroupKind::Text)
    };
    let out = d.keying.track(t, VaultFloor::None);
    assert_eq!(fetches(&out), 0);
    assert!(d.keying.current_epoch(TEXT_ID).is_some());
    assert!(d.keying.groups[TEXT_ID].t.anonymous);
}

/// 3d: with no local file (the browser) the floors are kept in memory, `r:` groups' too.
#[test]
fn floors_are_kept_in_memory_without_a_local_file() {
    let mut w = World::text(false, false);
    let d = seated_guest(&mut w, 20);
    let kept = d.keying.local().expect("kept in memory");
    assert_eq!(kept.floors[TEXT_ID].floor.d, w.head.d());
}

/// An account in a voice room before its seat keys are in has no pair to send: after
/// `NO_SEAT_KEYS` it asks again at the pace of an unanswered fetch, not at once.
#[test]
fn a_fetch_with_no_pair_to_send_is_asked_again_only_at_the_fetch_pace() {
    let ik = IdentityKeyPair::generate(&mut crate::rng());
    let mut d = Device::new(20, ik, Some([7; 16]), None);
    let voice = group_id(GroupKind::Voice, "", &RUN, 5);
    let out = d
        .keying
        .track(track(5, &voice, GroupKind::Voice), VaultFloor::None);
    assert_eq!(fetches(&out), 1);
    assert!(fetched_seat(&out).is_none());
    let wait = ServerMessage::EpochWait {
        group: voice,
        why: gk::wait::NO_SEAT_KEYS,
        detail: String::new(),
    };
    assert_eq!(fetches(&d.frame(&wait, T0)), 0);
    assert_eq!(fetches(&d.tick(T0 * 1000 + CHECK_WAIT_MS)), 1);
}

/// Rule 8: a promotion naming a keyholder entry under an older counter than this device saw
/// for that account, in a header made after that, is refused and the floor stays; with no
/// newer counter seen it is taken.
#[test]
fn a_keyholder_entry_under_an_old_counter_is_refused() {
    for seen in [
        Some(Seen {
            n: 5,
            made: T0 - 3600,
        }),
        None,
    ] {
        let mut w = World::text(false, false);
        let mut d = seated_guest(&mut w, 20);
        let before = d.keying.groups[TEXT_ID].floor.as_ref().unwrap().d;
        if let Some(s) = seen {
            d.pins.raise([2; 16], s, true);
        }
        w.promote(crate::group_key::build::world::Holder::desktop(2));
        assert_eq!(w.head.header().kind, Kind::KeyholdersAdd);
        d.take(push(&w), w.now);
        let floor = d.keying.groups[TEXT_ID].floor.as_ref().unwrap().d;
        match seen {
            Some(_) => assert_eq!(floor, before, "refused"),
            None => assert_eq!(floor, w.head.d(), "taken"),
        }
    }
}

// ── posts ──

/// §5.8: a post goes under the head epoch, its first with the writer's blob, and opens for
/// another member of the epoch; the next goes on the same chain without one. Each is
/// released under its epoch.
#[test]
fn a_post_goes_under_the_head_and_opens_for_another_member() {
    let mut w = World::text(false, false);
    let mut a = seated_guest(&mut w, 20);
    let mut b = seated_guest(&mut w, 21);
    a.take(push(&w), w.now);
    let out = a.post(1, b"hello", w.now * 1000);
    let sent = posted(&out);
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].0.is_some(),
        "the chain's first post carries the blob"
    );
    assert_eq!(out.released.len(), 1);
    assert_eq!(out.released[0].0, TEXT);
    assert_eq!(out.released[0].1, [1; 16]);
    let (blob, ct, epoch) = sent[0].clone();
    let got = b.frame(&post_in(&w, &a, blob, ct, epoch), w.now);
    assert_eq!(got.posts.len(), 1);
    assert_eq!(got.posts[0].envelope, b"hello");
    let out = a.post(2, b"again", w.now * 1000 + 10);
    let sent = posted(&out);
    assert!(sent[0].0.is_none(), "the same chain carries no blob");
    let (blob, ct, epoch) = sent[0].clone();
    let got = b.frame(&post_in(&w, &a, blob, ct, epoch), w.now);
    assert_eq!(got.posts[0].envelope, b"again");
}

/// §5.8: a reader takes a connection writer's blob only under the key that connection first
/// signed with.
#[test]
fn a_connection_writer_signs_with_the_key_it_first_signed_with() {
    let mut w = World::text(false, false);
    let mut a = seated_guest(&mut w, 20);
    let mut b = seated_guest(&mut w, 21);
    a.take(push(&w), w.now);
    let first = posted(&a.post(1, b"one", w.now * 1000));
    let (blob, ct, epoch) = first[0].clone();
    assert_eq!(
        b.frame(&post_in(&w, &a, blob, ct, epoch), w.now)
            .posts
            .len(),
        1
    );
    // Another identity under the same user id, on a new chain
    let mut imposter = Device::guest(20);
    imposter.keying = std::mem::take(&mut a.keying);
    imposter.keying.who.as_mut().unwrap().identity = imposter.ik;
    let m = imposter.keying.groups.get_mut(TEXT_ID).unwrap();
    m.writer.resend_after_old_epoch();
    let forged = posted(&imposter.post(2, b"two", w.now * 1000));
    let (blob, ct, epoch) = forged[0].clone();
    assert!(blob.is_some());
    assert!(b
        .frame(&post_in(&w, &imposter, blob, ct, epoch), w.now)
        .posts
        .is_empty());
}

/// 3f: with no key a post is held and the keys fetched, the user told the keys are late
/// while it waits; at `HOLD_MS` it is dropped as late.
#[test]
fn a_post_without_the_key_waits_then_is_dropped_as_late() {
    let mut d = Device::guest(20);
    d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let t = T0 * 1000;
    let out = d.post(1, b"hi", t);
    assert!(posted(&out).is_empty());
    assert!(out.events.contains(&GkEvent::State {
        channel_id: TEXT,
        state: GkState::Late { waiting: true }
    }));
    let out = d.tick(t + HOLD_MS - 1);
    assert!(!out
        .events
        .iter()
        .any(|e| matches!(e, GkEvent::PostDropped { .. })));
    let out = d.tick(t + HOLD_MS);
    assert_eq!(
        out.events,
        vec![GkEvent::PostDropped {
            channel_id: TEXT,
            why: Dropped::Late
        }]
    );
}

/// U1: a held post dropped because the relay refused the group is told by the refusal's own
/// state first, then dropped as refused.
#[test]
fn a_refused_post_is_told_with_its_reason_before_it_is_dropped() {
    let mut d = Device::guest(20);
    d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let t = T0 * 1000;
    d.post(1, b"hi", t);
    let wait = ServerMessage::EpochWait {
        group: TEXT_ID.into(),
        why: gk::wait::REFUSED,
        detail: "No room.".into(),
    };
    d.frame(&wait, T0);
    let out = d.tick(t + HOLD_MS);
    let refused = GkState::Refused("No room.".into());
    // Told once: at the wait. The drop says it was refused, and the state stands
    assert_eq!(
        out.events,
        vec![GkEvent::PostDropped {
            channel_id: TEXT,
            why: Dropped::Refused
        }]
    );
    assert_eq!(d.keying.groups[TEXT_ID].told, Some(refused));
}

/// 3f: an exit holds posts once it is 46 s old without an opening header that covers it;
/// the opening that does lets them go, under its new epoch.
#[test]
fn an_exit_holds_posts_until_an_opening_header_covers_it() {
    let mut w = World::text(false, false);
    let mut x = Device::guest(30);
    let out = x.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let leaver = x.joiner(&out, None).seat;
    join(&mut w, vec![x.joiner(&out, None)]);
    let (mut d, seat) = seated(&mut w, 20);
    let gen = w.head.header().gen;
    let t = w.now * 1000;
    let exit = ServerMessage::EpochExit {
        group: TEXT_ID.into(),
        gen,
        seq: 1,
    };
    d.frame(&exit, w.now);
    assert_eq!(
        posted(&d.post(1, b"soon", t)).len(),
        1,
        "a young exit holds nothing"
    );
    let out = d.post(2, b"late", t + EXIT_HOLD_MS);
    assert!(posted(&out).is_empty());
    let due = w.exits(&[leaver], DueKind::Exits);
    assert_eq!(due.exits_upto, 1);
    let b = w.open(&due);
    let out = d.take(piece(&w, &b, &seat, &[]), w.now);
    let sent = posted(&out);
    assert_eq!(sent.len(), 1, "{:?}", out.events);
    assert_eq!(sent[0].2, w.head.header().epoch);
    assert!(sent[0].0.is_some(), "a new epoch, a new chain");
}

/// The plan's review: an exit of an older generation never holds a writer of a new one (a
/// Genesis carries `exits_upto` 0).
#[test]
fn a_new_generation_drops_pending_exits() {
    let mut writing = writer::Writing::default();
    writing.exit([1; 16], 9, 0);
    assert!(writing.exit_holds(&[1; 16], EXIT_HOLD_MS));
    writing.opened([2; 16], 0, true);
    assert!(!writing.exit_holds(&[1; 16], EXIT_HOLD_MS));
    assert!(!writing.exit_holds(&[2; 16], EXIT_HOLD_MS));
    // Within a generation only what `exits_upto` covers goes
    writing.exit([2; 16], 4, 0);
    writing.exit([2; 16], 6, 0);
    writing.opened([2; 16], 5, false);
    assert!(writing.exit_holds(&[2; 16], EXIT_HOLD_MS));
    writing.opened([2; 16], 6, false);
    assert!(!writing.exit_holds(&[2; 16], EXIT_HOLD_MS));
}

/// The group names no channel: a post the relay files under another channel than the
/// group's is not shown there.
#[test]
fn a_post_the_relay_files_under_another_channel_is_not_shown() {
    let mut w = World::text(false, false);
    let mut a = seated_guest(&mut w, 20);
    let mut b = seated_guest(&mut w, 21);
    a.take(push(&w), w.now);
    let (blob, ct, epoch) = posted(&a.post(1, b"private", w.now * 1000))[0].clone();
    let mut moved = post_in(&w, &a, blob.clone(), ct.clone(), epoch);
    if let ServerMessage::EpochPostIn { channel_id, .. } = &mut moved {
        *channel_id = TEXT + 1;
    }
    assert!(b.frame(&moved, w.now).posts.is_empty());
    let got = b.frame(&post_in(&w, &a, blob, ct, epoch), w.now);
    assert_eq!(got.posts[0].channel_id, TEXT);
}

/// §5.5: a writer starts no post under an epoch whose opening time it does not know (a
/// relay that leaves the opening header out of an answer); that header lets it go.
#[test]
fn a_writer_holds_its_posts_under_an_epoch_of_unknown_age() {
    let mut w = World::text(false, false);
    let mut d = Device::guest(20);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, None);
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    let mut p = piece(&w, &b, &seat, &[&genesis]);
    let opening = p.opening.take().expect("a Join head's opening header");
    d.take(p, w.now);
    assert!(d.keying.current_epoch(TEXT_ID).is_some());
    let out = d.post(1, b"hi", w.now * 1000);
    assert!(posted(&out).is_empty());
    assert!(out.events.contains(&GkEvent::State {
        channel_id: TEXT,
        state: GkState::Late { waiting: true }
    }));
    let answer = gk::InPiece {
        head: Some(link(&w.head)),
        opening: Some(opening),
        ..Default::default()
    };
    assert_eq!(posted(&d.take(answer, w.now)).len(), 1);
}

/// 3f: posts still held when the channel is left or the connection ends are given up, each
/// told why.
#[test]
fn held_posts_are_told_dropped_when_the_channel_is_left_or_the_connection_ends() {
    let t = T0 * 1000;
    let dropped = |out: &GkOut| {
        out.events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    GkEvent::PostDropped {
                        why: Dropped::Late,
                        ..
                    }
                )
            })
            .count()
    };
    let mut d = Device::guest(20);
    d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    d.post(1, b"hi", t);
    assert_eq!(dropped(&d.keying.untrack(TEXT)), 1);
    d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    d.post(2, b"a", t);
    d.post(3, b"b", t);
    assert_eq!(dropped(&d.keying.end()), 2);
}

// ── accounts ──

/// 3c, §3.11: an account writes a self-row for `s_m` once its welcome opened and `confirm`
/// passed, in a stored group, once; and hands the vault its floor.
#[test]
fn an_account_writes_a_self_row_once_its_seat_opened_and_confirm_passed() {
    let mut w = World::text(true, false);
    let a = [7; 16];
    let keys = SeatKeys::generate(1, T0);
    let copy = seat_keys::copy(&keys);
    let mut d = Device::account(20, a, keys);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    assert!(
        fetched_seat(&out).is_none(),
        "an account is seated by its seat keys"
    );
    let j = d.joiner(&out, Some(&copy));
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    let out = d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
    assert_eq!(out.self_rows.len(), 1);
    let row = &out.self_rows[0];
    assert_eq!(
        (row.group.as_str(), row.kind),
        (TEXT_ID, gk::self_row::SELF_ROW)
    );
    assert_eq!((row.sk, row.sx), (seat.tag_sk, seat.tag_sx));
    let s_m = crate::group_key::open_self_row(&w.g, row.seed, &seat, copy.self_key(), &row.sealed);
    assert!(s_m.is_ok());
    assert_eq!(out.vault_floors.len(), 1);
    assert_eq!(out.vault_floors[0].1.d, w.head.d());
    // Pushed on: no second self-row for the same seed
    let mut other = Device::guest(21);
    let o = other.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    join(&mut w, vec![other.joiner(&o, None)]);
    assert!(d.take(push(&w), w.now).self_rows.is_empty());
}

/// §5.11 step 3: after a rotation the relay serves the account's old seat until it re-seats
/// it; that seat's welcome opens under the old keys, and no self-row is written for it.
#[test]
fn a_rotated_account_opens_its_old_seats_welcome_until_reseated() {
    let mut w = World::text(true, false);
    let old = SeatKeys::generate(1, T0);
    let old_copy = seat_keys::copy(&old);
    let rotated = old.rotate(T0 + 60).unwrap();
    let mut d = Device::account(20, [7; 16], rotated);
    let out = d.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let j = d.joiner(&out, Some(&old_copy));
    let seat = j.seat;
    let b = join(&mut w, vec![j]);
    let genesis = w.kh.clone();
    let out = d.take(piece(&w, &b, &seat, &[&genesis]), w.now);
    assert!(d.keying.current_epoch(TEXT_ID).is_some());
    assert!(
        out.self_rows.is_empty(),
        "the old seat's self-rows are K1's"
    );
}

/// Plan 13: an endorsement is taken under the counter rules — a guest's counter is 0, a
/// pair (0x02, 0x03) made more than `CLOCK_SLACK` from its join time is refused, and a pair
/// moves no counter its rotation (0x01) dated.
#[test]
fn an_endorsement_far_from_its_join_time_is_refused_and_a_rotation_keeps_its_made() {
    let ik = IdentityKeyPair::generate(&mut crate::rng());
    let keys = crate::group_key::SeatPair::generate().public();
    let a = [5; 16];
    let at = T0 + 100_000;
    let e = |origin, m, n, made| Endorsement::sign(&ik, origin, m, n, made, &keys).unwrap();
    let mut book = MemoryPins::default();
    let guest = e(Origin::Connection, MemberId::Conn(9), 1, at);
    assert_eq!(
        take_endorsement(&mut book, None, &guest, at),
        Err(EndorsementBad::GuestCounter)
    );
    let guest = e(Origin::Connection, MemberId::Conn(9), 0, at);
    assert_eq!(take_endorsement(&mut book, None, &guest, at), Ok(()));
    let far = e(
        Origin::Connection,
        MemberId::Conn(9),
        3,
        at - CLOCK_SLACK - 1,
    );
    assert_eq!(
        take_endorsement(&mut book, Some(a), &far, at),
        Err(EndorsementBad::Time)
    );
    assert_eq!(book.seen(&a), None, "nothing raised");
    let pair = e(Origin::Connection, MemberId::Conn(9), 3, at - 60);
    assert_eq!(take_endorsement(&mut book, Some(a), &pair, at), Ok(()));
    assert_eq!(
        book.seen(&a),
        Some(Seen {
            n: 3,
            made: at - 60
        })
    );
    // Its rotation, a month before, dates the counter from then on
    let vault = e(Origin::VaultSeat, MemberId::Account(a), 3, T0);
    assert_eq!(take_endorsement(&mut book, Some(a), &vault, at), Ok(()));
    assert_eq!(book.seen(&a), Some(Seen { n: 3, made: T0 }));
    let later = e(Origin::Desktop, MemberId::Account(a), 3, at + 5);
    assert_eq!(take_endorsement(&mut book, Some(a), &later, at), Ok(()));
    assert_eq!(
        book.seen(&a),
        Some(Seen { n: 3, made: T0 }),
        "a pair moves it not"
    );
    // Rule 8: below it, made after it
    let old = e(Origin::VaultSeat, MemberId::Account(a), 2, T0 - 1);
    assert_eq!(
        take_endorsement(&mut book, Some(a), &old, at),
        Err(EndorsementBad::OldCounter { n: 2, highest: 3 })
    );
}

fn keyholder(m: MemberId, n: u32, ik: u8) -> Keyholder {
    Keyholder {
        m,
        u: Some(9),
        origin: 0x02,
        n,
        ik: [ik; 32],
        kx: [ik; 32],
        tag_kk: [ik; 8],
    }
}

/// C1 note 2: a guest keyholder entry new to its set carries counter 0; an account's may
/// carry its own, and rule 8 checks that.
#[test]
fn a_guest_keyholder_entry_new_to_its_set_carries_counter_zero() {
    let h = |keyholders: Vec<Keyholder>| HeaderV1 {
        group_kind: GroupKind::Voice,
        group: format!("r:{}:3", voipc_protocol::conv::hex(&RUN)),
        gen: [1; 16],
        epoch: 2,
        join: 0,
        kind: Kind::KeyholdersAdd,
        time: T0,
        parent: [2; 32],
        epoch_parent: [0; 32],
        kh_parent: [3; 32],
        signer: MemberId::Conn(3),
        keyholders,
        gated: false,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 2,
        buckets: 1,
        conn_seats: 2,
        bucket_root: [4; 32],
        keyring_hash: [5; 32],
        names_hash: [0; 32],
        added: Added::Count(0),
        removed: Removed::Count(0),
        confirm: [6; 32],
    };
    let none = |_: &[u8; 16]| None;
    let old = keyholder(MemberId::Conn(3), 0, 1);
    let guest = keyholder(MemberId::Conn(4), 1, 2);
    let r = member::new_entries_ok(&h(vec![old, guest]), &[old], &none, None);
    assert!(r.is_err());
    let guest = keyholder(MemberId::Conn(4), 0, 2);
    assert!(member::new_entries_ok(&h(vec![old, guest]), &[old], &none, None).is_ok());
    let account = Keyholder {
        m: MemberId::Account([8; 16]),
        n: 4,
        ..keyholder(MemberId::Conn(5), 0, 3)
    };
    assert!(member::new_entries_ok(&h(vec![old, account]), &[old], &none, None).is_ok());
    let seen = |_: &[u8; 16]| {
        Some(Seen {
            n: 5,
            made: T0 - 3600,
        })
    };
    assert!(member::new_entries_ok(&h(vec![old, account]), &[old], &seen, None).is_err());
}

// ── start and events ──

/// 3c: at `GroupKeys`, local floors of `r:` groups of another run go; stored groups stay.
#[test]
fn local_floors_of_another_run_go_at_start() {
    let w = World::text(false, false);
    let floor = crate::group_key::Floor::after(None, &w.head, w.head.header().time);
    let local_floor = LocalFloor {
        floor,
        kh: None,
        head: None,
        names: None,
        taken: T0,
    };
    let run = voipc_protocol::conv::hex(&RUN);
    let mut local = LocalGk::default();
    for g in [
        TEXT_ID.to_string(),
        format!("r:{run}:4"),
        format!("r:{}:4", "22".repeat(16)),
    ] {
        local.floors.insert(g, local_floor.clone());
    }
    let mut keying = GroupKeying::default();
    let out = keying.start(GkStart {
        on: true,
        run: RUN,
        relay_clock: T0,
        platform: Platform::Browser,
        help_hold_keys: false,
        user_id: 1,
        identity: IdentityKeyPair::generate(&mut crate::rng()),
        account: None,
        seat_keys: None,
        local: Some(local),
        visible: true,
    });
    assert!(out.local_dirty);
    let kept: Vec<&String> = keying.local().unwrap().floors.keys().collect();
    assert_eq!(kept, vec![TEXT_ID, &format!("r:{run}:4")]);
}

struct Roster;

impl GkNames for Roster {
    fn name(&self, m: &MemberId) -> Option<String> {
        match m {
            MemberId::Account([1, ..]) => Some("ann#1".into()),
            MemberId::Account([2, ..]) => Some("bob#2".into()),
            _ => None,
        }
    }
    fn online(&self, m: &MemberId) -> bool {
        *m == MemberId::Account([2; 16])
    }
}

/// U1's contract: each event's name and payload, names as sent, those with none counted.
#[test]
fn events_reach_the_front_end_as_u1_names_them() {
    let (ann, bob, guest) = (
        MemberId::Account([1; 16]),
        MemberId::Account([2; 16]),
        MemberId::Conn(9),
    );
    let w = |e: GkEvent| e.to_wire(&Roster);
    assert_eq!(
        w(GkEvent::State {
            channel_id: 4,
            state: GkState::Held(HeldWhy::OldCounter(Some(ann)))
        }),
        (
            "gk-state",
            json!({"channel_id": 4, "state": "held", "why": "old_counter", "name": "ann#1"})
        )
    );
    assert_eq!(
        w(GkEvent::State {
            channel_id: 4,
            state: GkState::Late { waiting: true }
        })
        .1,
        json!({"channel_id": 4, "state": "late", "why": "waiting"})
    );
    assert_eq!(
        w(GkEvent::State {
            channel_id: 4,
            state: GkState::Refused("No room.".into())
        })
        .1["why"],
        "No room."
    );
    assert_eq!(
        w(GkEvent::PostDropped {
            channel_id: 4,
            why: Dropped::NoKeyholder
        }),
        (
            "gk-post-dropped",
            json!({"channel_id": 4, "why": "no_keyholder"})
        )
    );
    assert_eq!(
        w(GkEvent::Readers {
            channel_id: 4,
            named: vec![ann, guest],
            unchecked: 2,
            older_unnamed: true
        }),
        (
            "gk-readers",
            json!({"channel_id": 4, "names": ["ann#1"], "unchecked": 3, "older_unnamed": true})
        )
    );
    assert_eq!(
        w(GkEvent::Keyholders {
            channel_id: 4,
            holders: vec![Some(ann), None, Some(bob)]
        })
        .1["holders"],
        json!([
            {"name": "bob#2", "online": true, "kind": ""},
            {"name": "ann#1", "online": false, "kind": ""},
            {"name": "", "online": false, "kind": ""},
        ])
    );
    assert_eq!(
        w(GkEvent::Anew {
            channel_id: 4,
            by: None
        })
        .1,
        json!({"channel_id": 4, "by": ""})
    );
    assert_eq!(
        w(GkEvent::Warning {
            channel_id: 4,
            kind: Warn::OldSeatKey,
            n: 3
        }),
        (
            "gk-warning",
            json!({"channel_id": 4, "kind": "old_seat_key", "n": 3})
        )
    );
}

/// 3h: an anonymous room names nobody, not even the keyholders or who made it anew.
#[test]
fn an_anonymous_room_names_nobody() {
    let t = GkTrack {
        anonymous: true,
        ..track(1, TEXT_ID, GroupKind::Text)
    };
    assert!(!t.shows_names());
    let hidden = GkTrack {
        hide_members: true,
        ..track(1, TEXT_ID, GroupKind::Text)
    };
    assert!(!hidden.shows_names());
    assert!(GkTrack {
        viewer_admin: true,
        ..hidden
    }
    .shows_names());
}

// ── Cross-check of R1 and C3b (2026-11-18) ────────────────────────────────

fn refused(what: u8, why: u8) -> ServerMessage {
    ServerMessage::EpochRefused {
        group: TEXT_ID.into(),
        what,
        why,
        detail: String::new(),
    }
}

fn floor_aheads(out: &GkOut) -> Vec<gk::HeaderIn> {
    out.send
        .iter()
        .filter_map(|m| match m {
            ClientMessage::EpochFloorAhead { header, .. } => Some(header.clone()),
            _ => None,
        })
        .collect()
}

fn blob_asks(out: &GkOut) -> usize {
    out.send
        .iter()
        .filter(|m| matches!(m, ClientMessage::EpochBlobWanted { .. }))
        .count()
}

/// Finding: a writer started a new chain at every `EpochExit`, and the relay tells one
/// again after each blob while the exit is pending: the third blob of the epoch was refused
/// and the chain after it unreadable. Told of an exit, a writer keeps its chain (spec 5.4).
#[test]
fn a_writer_told_of_an_exit_keeps_its_chain_so_its_posts_carry_one_blob() {
    let mut w = World::text(false, false);
    let mut x = Device::guest(30);
    let out = x.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    join(&mut w, vec![x.joiner(&out, None)]);
    let (mut d, _) = seated(&mut w, 20);
    let gen = w.head.header().gen;
    let t = w.now * 1000;
    let exit = ServerMessage::EpochExit {
        group: TEXT_ID.into(),
        gen,
        seq: 1,
    };
    let mut blobs = 0;
    for i in 0..3u8 {
        // The relay tells the pending exit again after each blob post
        d.frame(&exit, w.now);
        let sent = posted(&d.post(i, b"x", t + u64::from(i)));
        assert_eq!(sent.len(), 1);
        blobs += sent.iter().filter(|p| p.0.is_some()).count();
    }
    assert_eq!(blobs, 1, "one chain in the epoch");
}

/// Finding: the head epoch's opening that came in an answer (its head a Join after it) did
/// not end the exit hold it covers: only an opening taken as the head did.
#[test]
fn an_opening_in_an_answer_ends_the_exit_hold_it_covers() {
    let mut w = World::text(false, false);
    let mut x = Device::guest(30);
    let out = x.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let leaver = x.joiner(&out, None).seat;
    join(&mut w, vec![x.joiner(&out, None)]);
    let (mut d, _) = seated(&mut w, 20);
    let gen = w.head.header().gen;
    d.frame(
        &ServerMessage::EpochExit {
            group: TEXT_ID.into(),
            gen,
            seq: 1,
        },
        w.now,
    );
    let later = w.now * 1000 + EXIT_HOLD_MS;
    assert!(d.keying.groups[TEXT_ID].writer.exit_holds(&gen, later));
    // The opening covering it went by (its push lost), then a Join
    let due = w.exits(&[leaver], DueKind::Exits);
    w.open(&due);
    let opening = w.head.clone();
    let late = crate::group_key::build::world::Member::conn(40);
    w.join(&[&late]);
    d.take(
        gk::InPiece {
            head: Some(link(&w.head)),
            opening: Some(header_in(&opening)),
            ..Default::default()
        },
        w.now,
    );
    assert_eq!(
        d.keying.groups[TEXT_ID].floor.as_ref().unwrap().d,
        w.head.d()
    );
    assert!(
        !d.keying.groups[TEXT_ID].writer.exit_holds(&gen, later),
        "the head's own opening covers the exit"
    );
}

/// Finding: a refused post that started a chain left that chain current, so every later post
/// went with no blob under a chain no reader can open; and `RATE` was ignored outright. A
/// refusal restarts the chain and drops the post that started it; `RATE` sends again.
#[test]
fn a_refused_blob_post_restarts_the_chain_and_a_rate_refusal_sends_again() {
    let mut w = World::text(false, false);
    let mut d = seated_guest(&mut w, 20);
    let t = w.now * 1000;
    let first = posted(&d.post(1, b"one", t));
    let second = posted(&d.post(2, b"two", t + 1));
    assert!(first[0].0.is_some() && second[0].0.is_none());
    let out = d.frame(
        &refused(gk::refused_what::POST, gk::refused_why::THIRD_BLOB),
        w.now,
    );
    assert!(out.events.contains(&GkEvent::PostDropped {
        channel_id: TEXT,
        why: Dropped::Refused
    }));
    let third = posted(&d.post(3, b"three", t + 2));
    assert!(third[0].0.is_some(), "a new chain, its blob with it");
    // The inbox was full: what went goes again at the next tick, on a new chain
    let out = d.frame(
        &refused(gk::refused_what::POST, gk::refused_why::RATE),
        w.now,
    );
    assert!(out.events.is_empty() && posted(&out).is_empty());
    let again = posted(&d.tick(t + 1_000));
    assert_eq!(again.len(), 2, "two and three again");
    assert!(again[0].0.is_some());
}

/// Finding: an `EpochBlob` that installed nothing cleared its ask, so the post waiting on
/// it asked again at once, once per round trip. It is asked again once the ask ages out.
#[test]
fn an_answer_with_no_blob_is_not_asked_again_before_its_ask_ages_out() {
    let mut w = World::text(false, false);
    let mut a = seated_guest(&mut w, 20);
    let mut b = seated_guest(&mut w, 21);
    a.take(push(&w), w.now);
    b.take(push(&w), w.now);
    let t = w.now * 1000;
    let (_, ct, epoch) = posted(&a.post(1, b"hi", t))[0].clone();
    // The post reaches b without its blob: asked for
    let out = b.frame(&post_in(&w, &a, None, ct, epoch), w.now);
    assert_eq!(blob_asks(&out), 1);
    let none = ServerMessage::EpochBlob {
        group: TEXT_ID.into(),
        gen: w.head.header().gen,
        epoch,
        writer: gk::GkWriter {
            m: gk::GkMember::Conn(a.u),
            u: a.u,
        },
        blobs: vec![],
    };
    assert_eq!(blob_asks(&b.frame(&none, w.now)), 0, "not at once");
    assert_eq!(blob_asks(&b.tick(t + CHECK_WAIT_MS)), 1, "once it aged out");
}

/// Finding: an answer built before a push it overtook (the snapshot answer queued after
/// the push) was below the floor and read as a relay behind its members. A header this
/// connection took already is no such sign; after a restart, one below the floor is, and
/// it is told with the floor's header this device kept.
#[test]
fn a_floor_ahead_of_the_relay_is_told_once_an_hour() {
    let mut w = World::text(false, false);
    let mut d = seated_guest(&mut w, 20);
    let old = w.head.clone();
    let mut x = Device::guest(21);
    let out = x.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    join(&mut w, vec![x.joiner(&out, None)]);
    d.take(push(&w), w.now);
    let stale = gk::InPiece {
        head: Some(link(&old)),
        ..Default::default()
    };
    let warned = |out: &GkOut| {
        out.events.contains(&GkEvent::Warning {
            channel_id: TEXT,
            kind: Warn::FloorAhead,
            n: 0,
        })
    };
    let out = d.take(stale.clone(), w.now);
    assert!(floor_aheads(&out).is_empty() && !warned(&out), "taken here");
    // The app restarts; the relay answers below the floor
    let mut again = Device::new(20, d.ik, None, None);
    again.keying.local = d.keying.local().cloned();
    again.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let out = again.take(stale.clone(), w.now);
    let told = floor_aheads(&out);
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].body, w.head.body(), "with the floor's own header");
    assert!(warned(&out));
    assert!(floor_aheads(&again.take(stale.clone(), w.now + 60)).is_empty());
    assert_eq!(floor_aheads(&again.take(stale, w.now + 3601)).len(), 1);
}

/// Finding: an answer that opened no key cleared the pending fetch, and a held post asked
/// again at once: one fetch per round trip until the post was dropped. It asks again at the
/// pace of an unanswered fetch.
#[test]
fn an_answer_that_opens_no_key_is_asked_again_at_the_fetch_pace() {
    let mut w = World::text(false, false);
    let mut d = seated_guest(&mut w, 20);
    w.tick(2);
    w.open(&w.due(DueKind::Refresh));
    // Pushed, the opening moves the floor with no key: asked once
    let out = d.take(push(&w), w.now);
    assert_eq!(fetches(&out), 1);
    let t = w.now * 1000;
    assert!(posted(&d.post(1, b"held", t)).is_empty());
    let answer = gk::InPiece {
        head: Some(link(&w.head)),
        ..Default::default()
    };
    let out = d.take(answer, w.now);
    assert_eq!(fetches(&out), 0, "not again at once");
    assert_eq!(fetches(&d.tick(t + CHECK_WAIT_MS / 2)), 0);
    assert_eq!(fetches(&d.tick(t + CHECK_WAIT_MS)), 1, "a post still waits");
}

/// Finding: every fetch refusal was final for the group, `RATE` and `NOT_STORED` (an `at`
/// entry's) included: a false "refused", and no fetch again. `RATE` paces, `NOT_STORED`
/// leaves the live state alone, and a key held afterwards clears a refusal told.
#[test]
fn a_fetch_refused_for_now_is_asked_again_and_tells_no_refusal() {
    let mut w = World::text(false, false);
    let mut d = seated_guest(&mut w, 20);
    w.tick(2);
    w.open(&w.due(DueKind::Refresh));
    d.take(push(&w), w.now);
    let t = w.now * 1000;
    d.post(1, b"held", t);
    let out = d.frame(
        &refused(gk::refused_what::FETCH, gk::refused_why::RATE),
        w.now,
    );
    let no_refusal = |out: &GkOut| {
        !out.events.iter().any(|e| {
            matches!(
                e,
                GkEvent::State {
                    state: GkState::Refused(_),
                    ..
                }
            )
        })
    };
    assert!(no_refusal(&out));
    let out = d.frame(
        &refused(gk::refused_what::FETCH, gk::refused_why::NOT_STORED),
        w.now,
    );
    assert!(no_refusal(&out) && out.send.is_empty());
    let out = d.tick(t + CHECK_WAIT_MS);
    assert!(no_refusal(&out));
    assert_eq!(fetches(&out), 1, "asked again at the fetch pace");
}

/// Finding: a missing `kh` made the member fetch again at once on every answer that lacked
/// it, with nothing to stop it. Once at once, then at the fetch pace.
#[test]
fn a_missing_kh_is_asked_once_at_once_then_at_the_fetch_pace() {
    let mut w = World::text(false, false);
    let d = seated_guest(&mut w, 20);
    let mut local = d.keying.local().cloned().unwrap();
    local.floors.get_mut(TEXT_ID).unwrap().kh = None;
    let mut again = Device::new(20, d.ik, None, None);
    again.keying.local = Some(local);
    again.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    let mut x = Device::guest(21);
    let out = x.track(TEXT_ID, GroupKind::Text, VaultFloor::None);
    join(&mut w, vec![x.joiner(&out, None)]);
    let answer = gk::InPiece {
        head: Some(link(&w.head)),
        ..Default::default()
    };
    assert_eq!(fetches(&again.take(answer.clone(), w.now)), 1);
    assert_eq!(
        fetches(&again.take(answer, w.now)),
        0,
        "not once per answer"
    );
}
