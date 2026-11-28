//! Dive 1 (hostile relay), finding F6: a channel's group id is the relay's word (its `log`,
//! `group_state::group_id`), and everything a device keeps against a rollback or a quiet new
//! start is kept per group id: the floor, the generations it took, the names floor, and with
//! them the "keys for this channel were made anew by X" notice. A relay that tells an app the
//! channel now has another `c:` id gets a device with no floor for it. That device takes any
//! Genesis there on trust and tells its user nothing: no "made anew", no "gate opened", and
//! in a gated channel a names floor that starts at the head, with nobody shown.
//!
//! §5.7: "On a relay with accounts, a new generation, whatever the relay says caused it, is
//! shown to every member with its signer." §5.6: "Every member shows 'keys for this channel
//! were made anew by X'". THREAT-MODEL, hostile relay, Can: "Start a new generation ...
//! Members are told each time."
//!
//! The device is a real `GroupKeying`, the headers are signed with the public
//! `SignedHeader::sign`, and this test is the relay. The second `track` is what both hosts do
//! when a `ChannelUpdated` brings another log for the channel (`GroupKeying::track`: "the
//! channel's group, from now").
//!
//! Run: cargo test -p voipc-crypto --test d1_group_moved

use voipc_crypto::group_key::commit::Pair;
use voipc_crypto::group_key::{
    names_hash, Added, Endorsement, GroupKind, HeaderV1, Keyholder, Kind, MemberId, Origin,
    Removed, SeatKeys, SeatPair, SignedHeader,
};
use voipc_crypto::group_state::{
    GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{HeaderIn, InPiece};
use voipc_protocol::messages::ServerMessage;

const CHANNEL: u32 = 1;
const GROUP: &str = "c:lounge-4";
/// The id the relay gives the same channel later.
const MOVED: &str = "c:lounge-4b";
const WRITER: [u8; 16] = [0x33; 16];

fn now_ms() -> u64 {
    voipc_crypto::time::now_millis()
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// A desktop keyholder: an account's identity and its keyholder pair (origin 0x03).
struct Holder {
    m: MemberId,
    ik: IdentityKeyPair,
    entry: Keyholder,
}

fn holder(account: [u8; 16], made: u64) -> Holder {
    let ik = voipc_crypto::generate_identity_key_pair();
    let pair = SeatPair::generate();
    let m = MemberId::Account(account);
    let endorsement = Endorsement::sign(&ik, Origin::Desktop, m, 1, made, &pair.public()).unwrap();
    let entry = Pair {
        keys: pair.public(),
        endorsement,
    }
    .entry(GroupKind::Text, m, raw(&ik))
    .expect("a desktop keyholder entry");
    Holder { m, ik, entry }
}

/// A gated header of `group` in generation `gen`, signed by `by`: a Genesis with no parent,
/// else a Fresh after `parent`.
fn header(
    group: &str,
    gen: [u8; 16],
    epoch: u32,
    time: u64,
    parent: Option<&SignedHeader>,
    by: &Holder,
) -> SignedHeader {
    let mut hd = HeaderV1 {
        group_kind: GroupKind::Text,
        group: group.into(),
        gen,
        epoch,
        join: 0,
        kind: if parent.is_some() {
            Kind::Fresh
        } else {
            Kind::Genesis
        },
        time,
        parent: parent.map_or([0; 32], |p| p.d()),
        epoch_parent: [0; 32],
        kh_parent: parent.map_or([0; 32], |p| p.kh()),
        signer: by.m,
        keyholders: if parent.is_some() {
            vec![]
        } else {
            vec![by.entry]
        },
        gated: true,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 2,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [epoch as u8; 32],
        keyring_hash: [epoch as u8; 32],
        names_hash: [0; 32],
        added: Added::List(vec![]),
        removed: Removed::List(vec![]),
        confirm: [epoch as u8; 32],
    };
    hd.names_hash = names_hash(parent.map(|p| p.header()), &hd);
    SignedHeader::sign(hd, &by.ik).expect("a header of a valid shape")
}

fn wire(h: &SignedHeader) -> HeaderIn {
    HeaderIn {
        body: h.body().to_vec(),
        sig: h.sig().to_vec(),
    }
}

/// The writer's desktop app on this relay, with everything it told its user.
struct Device {
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    events: Vec<GkEvent>,
    ik: voipc_crypto::IdentityKeyPair,
}

impl Device {
    fn new() -> Device {
        let ik = voipc_crypto::generate_identity_key_pair();
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: true,
            run: [0x11; 16],
            relay_clock: now_ms() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: 20,
            identity: ik,
            account: Some(WRITER),
            seat_keys: Some(SeatKeys::generate(1, now_ms() / 1000)),
            local: None,
            visible: true,
        });
        let mut d = Device {
            keying,
            st: SignalStores::new(&ik, 20),
            pins: MemoryPins::default(),
            events: vec![],
            ik,
        };
        d.track(GROUP);
        d
    }

    fn took(&mut self, out: GkOut) {
        self.events.extend(out.events);
    }

    /// The connection ends and a new one starts with what this device kept.
    fn reconnect(&mut self) {
        let local = self.keying.local().cloned();
        let _ = self.keying.end();
        let out = self.keying.start(GkStart {
            on: true,
            run: [0x11; 16],
            relay_clock: now_ms() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: 20,
            identity: self.ik,
            account: Some(WRITER),
            seat_keys: Some(SeatKeys::generate(1, now_ms() / 1000)),
            local,
            visible: true,
        });
        self.took(out);
    }

    /// The channel's group, with the account's vault floor for it.
    fn track_vault(&mut self, group: &str, vault: VaultFloor) {
        let out = self.keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: group.into(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: true,
            },
            vault,
        );
        self.took(out);
    }

    /// The channel's group, as the relay's channel list names it now.
    fn track(&mut self, group: &str) {
        let out = self.keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: group.into(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: true,
            },
            VaultFloor::None,
        );
        self.took(out);
    }

    /// An `EpochIn` of `group` from the relay: these headers, link by link.
    fn chain(&mut self, group: &str, headers: &[&SignedHeader]) {
        let msg = ServerMessage::EpochIn {
            group: group.into(),
            part: 0,
            last: true,
            piece: Box::new(InPiece {
                chain: headers.iter().map(|h| wire(h)).collect(),
                ..InPiece::default()
            }),
        };
        let c = GkCtx {
            pins: &mut self.pins,
            now: now_ms(),
        };
        let out = self.keying.frame(&mut self.st, &msg, c);
        self.took(out);
    }

    /// Whether the app holds a floor for `group` at `h`.
    fn at(&self, group: &str, h: &SignedHeader) -> bool {
        self.keying
            .local()
            .and_then(|l| l.floors.get(group))
            .is_some_and(|f| f.floor.d == h.d())
    }

    /// Who the app said made the channel's keys anew, each time it said so.
    fn made_anew(&self) -> Vec<Option<MemberId>> {
        self.events
            .iter()
            .filter_map(|e| match e {
                GkEvent::Anew { by, .. } => Some(*by),
                _ => None,
            })
            .collect()
    }
}

/// The channel as the writer's app has followed it: a Genesis and one more epoch, by the
/// keyholder it knows, K1.
fn followed(d: &mut Device) -> u64 {
    let t = now_ms() / 1000;
    let k1 = holder([0x11; 16], t - 4000);
    let genesis = header(GROUP, [7; 16], 1, t - 3000, None, &k1);
    let e2 = header(GROUP, [7; 16], 2, t - 2000, Some(&genesis), &k1);
    d.chain(GROUP, &[&genesis, &e2]);
    assert!(d.at(GROUP, &e2), "the app follows the channel's group");
    assert_eq!(d.made_anew(), vec![], "nothing made anew so far");
    t
}

/// The control: the relay shows the app a new generation of the channel's group, signed by
/// an account of its own. The app takes it, as §5.7 lets it, and tells its user who made
/// the channel's keys anew. It passes today.
#[test]
fn control_a_new_generation_of_the_channels_group_is_told_as_made_anew() {
    let mut d = Device::new();
    let t = followed(&mut d);
    let x = holder([0x99; 16], t - 60);
    let anew = header(GROUP, [8; 16], 1, t - 30, None, &x);
    d.chain(GROUP, &[&anew]);
    assert!(d.at(GROUP, &anew), "the app took the new generation");
    assert_eq!(
        d.made_anew(),
        vec![Some(x.m)],
        "and told its user who made the keys anew"
    );
}

/// F6: the same new start, but the relay first tells the app that the channel has another
/// group id. The app holds no floor under that id, takes the relay's Genesis there on trust,
/// and tells its user nothing about the channel's keys having been made anew.
#[test]
fn f6_a_new_start_under_another_group_id_for_the_channel_is_told_as_made_anew() {
    let mut d = Device::new();
    let t = followed(&mut d);
    let x = holder([0x99; 16], t - 60);
    let anew = header(MOVED, [8; 16], 1, t - 30, None, &x);
    d.track(MOVED);
    d.chain(MOVED, &[&anew]);
    assert!(d.at(MOVED, &anew), "the app took the new start");
    let names = d
        .keying
        .local()
        .and_then(|l| l.floors.get(MOVED))
        .and_then(|f| f.names)
        .map(|n| (n.epoch, n.join));
    assert_eq!(
        d.made_anew(),
        vec![Some(x.m)],
        "the app followed channel {CHANNEL} under {GROUP} and now holds its keys from a \
         Genesis that {:?} signed under {MOVED}, with its names floor at {names:?} and nothing \
         folded. It told its user of no new start. Everything it told: {:?}",
        x.m,
        d.events
    );
}

/// Review A-P1: the relay names the new id, gives no header of it, and ends the connection.
/// After the reconnect the device still knows the channel's old id (its new group holds no
/// floor yet), so the relay's start there is told as made anew.
#[test]
fn a_move_is_told_after_a_reconnect_that_came_before_any_header_of_the_new_id() {
    let mut d = Device::new();
    let t = followed(&mut d);
    d.track(MOVED);
    d.reconnect();
    d.track(MOVED);
    let x = holder([0x99; 16], t - 60);
    let anew = header(MOVED, [8; 16], 1, t - 30, None, &x);
    d.chain(MOVED, &[&anew]);
    assert!(d.at(MOVED, &anew), "the app took the new start");
    assert_eq!(d.made_anew(), vec![Some(x.m)], "told: {:?}", d.events);
}

/// Review A-P2: another device of the account (a fresh page, which knows no old id) took the
/// relay's start under the new id on trust, and its floor is in the vault. The device that
/// followed the old id does not start from that floor: its first header there is told as
/// made anew.
#[test]
fn a_move_is_told_though_the_vault_holds_a_floor_of_the_new_id() {
    let t = now_ms() / 1000;
    let x = holder([0x99; 16], t - 60);
    let anew = header(MOVED, [8; 16], 1, t - 30, None, &x);
    let e2 = header(MOVED, [8; 16], 2, t - 20, Some(&anew), &x);
    // The fresh device
    let mut fresh = Device::new();
    fresh.track(MOVED);
    fresh.chain(MOVED, &[&anew]);
    let kept = fresh.keying.local().unwrap().floors[MOVED].clone();
    // The device that followed the old id
    let mut d = Device::new();
    let _ = followed(&mut d);
    d.track_vault(MOVED, VaultFloor::Some(Box::new(kept.floor), kept.names));
    d.chain(MOVED, &[&anew, &e2]);
    assert!(d.at(MOVED, &e2), "the app follows the new id");
    assert_eq!(d.made_anew(), vec![Some(x.m)], "told: {:?}", d.events);
}
