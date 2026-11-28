//! Dive 1 (hostile relay), finding F2: the vault-floor merge (`Member::vault_in`,
//! `sync::higher_floor`) puts a device with a local floor onto whatever another device of
//! the account took, by `(epoch, join)` alone. A device of the account with no floor (a new
//! browser page, a new install, or one the relay withheld the vault floor from) takes the
//! head on trust, on any keyholder chain. So a keyholder the desktop app saw removed can, with
//! the relay, have its fork taken by the desktop after all: the fresh device takes the fork on
//! trust, its vault floor names the keyholder header from before the removal, and the merge
//! moves the desktop's floor, and the keyholder header it names, back behind the removal.
//! From then on the desktop takes headers the removed keyholder signs.
//!
//! Both devices are real `GroupKeying`s; the headers are signed with the public
//! `SignedHeader::sign`; this test is the relay. No key material is needed: the take rules
//! (§4.4 rules 2 and 3) are the boundary.
//!
//! Run: cargo test -p voipc-crypto --test d1_vault_merge

use voipc_crypto::group_key::commit::Pair;
use voipc_crypto::group_key::{
    Added, Endorsement, Floor, GroupKind, HeaderV1, Keyholder, Kind, MemberId, NamesFloor, Origin,
    Removed, SeatKeys, SeatPair, SignedHeader,
};
use voipc_crypto::group_state::{
    GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{HeaderIn, InPiece, WalkLinkIn};
use voipc_protocol::messages::ServerMessage;

const GROUP: &str = "c:lounge-4";
const GEN: [u8; 16] = [7; 16];
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

/// A header of the open text group, signed by `by`. `keyholders`: the set it makes, for the
/// kinds that set one.
#[allow(clippy::too_many_arguments)]
fn header(
    kind: Kind,
    epoch: u32,
    time: u64,
    parent: Option<&SignedHeader>,
    kh_parent: Option<&SignedHeader>,
    keyholders: &[&Holder],
    by: &Holder,
) -> SignedHeader {
    header_in(GEN, 1, kind, epoch, time, parent, kh_parent, keyholders, by)
}

/// `header` in generation `gen` under seed `seed` (a Regenesis starts the next seed).
#[allow(clippy::too_many_arguments)]
fn header_in(
    gen: [u8; 16],
    seed: u32,
    kind: Kind,
    epoch: u32,
    time: u64,
    parent: Option<&SignedHeader>,
    kh_parent: Option<&SignedHeader>,
    keyholders: &[&Holder],
    by: &Holder,
) -> SignedHeader {
    let hd = HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen,
        epoch,
        join: 0,
        kind,
        time,
        parent: parent.map_or([0; 32], |p| p.d()),
        epoch_parent: [0; 32],
        kh_parent: kh_parent.map_or([0; 32], |k| k.d()),
        signer: by.m,
        keyholders: keyholders.iter().map(|k| k.entry).collect(),
        gated: false,
        seed,
        seed_floor: seed,
        exits_upto: 0,
        seats: 1,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [epoch as u8; 32],
        keyring_hash: [epoch as u8; 32],
        names_hash: [0; 32],
        added: Added::Count(0),
        removed: Removed::Count(0),
        confirm: [epoch as u8; 32],
    };
    SignedHeader::sign(hd, &by.ik).expect("a header of a valid shape")
}

fn wire(h: &SignedHeader) -> HeaderIn {
    HeaderIn {
        body: h.body().to_vec(),
        sig: h.sig().to_vec(),
    }
}

fn link(h: &SignedHeader) -> WalkLinkIn {
    WalkLinkIn {
        header: wire(h),
        parent: None,
    }
}

/// One device of the writer's account on this relay.
struct Device {
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    events: Vec<GkEvent>,
    vault: Option<(Floor, Option<NamesFloor>)>,
}

impl Device {
    fn new(ik: IdentityKeyPair, user_id: u32, platform: Platform) -> Device {
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: true,
            run: [0x11; 16],
            relay_clock: now_ms() / 1000,
            platform,
            help_hold_keys: false,
            user_id,
            identity: ik,
            account: Some(WRITER),
            seat_keys: Some(SeatKeys::generate(1, now_ms() / 1000)),
            local: None,
            visible: true,
        });
        let _ = keying.track(
            GkTrack {
                channel_id: 1,
                group: GROUP.into(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: true,
            },
            VaultFloor::None,
        );
        Device {
            keying,
            st: SignalStores::new(&ik, user_id),
            pins: MemoryPins::default(),
            events: vec![],
            vault: None,
        }
    }

    fn took(&mut self, out: GkOut) {
        self.events.extend(out.events);
        if let Some((_, floor, names)) = out.vault_floors.into_iter().last() {
            self.vault = Some((floor, names));
        }
    }

    /// An `EpochIn` from the relay.
    fn take(&mut self, piece: InPiece) {
        let msg = ServerMessage::EpochIn {
            group: GROUP.into(),
            part: 0,
            last: true,
            piece: Box::new(piece),
        };
        let c = GkCtx {
            pins: &mut self.pins,
            now: now_ms(),
        };
        let out = self.keying.frame(&mut self.st, &msg, c);
        self.took(out);
    }

    /// The floor this device keeps locally (`gk_local.bin` on a desktop).
    fn floor(&self) -> Floor {
        self.keying.local().expect("started").floors[GROUP]
            .floor
            .clone()
    }

    /// The keyholder sets it told its user, as member ids.
    fn sets_told(&self) -> Vec<Vec<Option<MemberId>>> {
        self.events
            .iter()
            .filter_map(|e| match e {
                GkEvent::Keyholders { holders, .. } => Some(holders.clone()),
                _ => None,
            })
            .collect()
    }
}

/// The group's history: a Genesis by K1, K1 adds R, K1 removes R, K1 goes on. And R's fork
/// from before its removal, which only R signs.
struct Chain {
    k1: Holder,
    r: Holder,
    genesis: SignedHeader,
    add: SignedHeader,
    remove: SignedHeader,
    after: SignedHeader,
    /// R's fork: three epochs on the set from before its removal, and one more.
    fork_head: SignedHeader,
    fork_next: SignedHeader,
}

fn chain() -> Chain {
    let t = now_ms() / 1000;
    let k1 = holder([0x11; 16], t - 4000);
    let r = holder([0x22; 16], t - 4000);
    let genesis = header(Kind::Genesis, 1, t - 3000, None, None, &[&k1], &k1);
    let add = header(
        Kind::KeyholdersAdd,
        2,
        t - 2000,
        Some(&genesis),
        Some(&genesis),
        &[&k1, &r],
        &k1,
    );
    let remove = header(
        Kind::KeyholdersRemove,
        3,
        t - 1000,
        Some(&add),
        Some(&add),
        &[&k1],
        &k1,
    );
    let after = header(
        Kind::Fresh,
        4,
        t - 900,
        Some(&remove),
        Some(&remove),
        &[],
        &k1,
    );
    // The removed keyholder signs on, on the set that still names it
    let f3 = header(Kind::Fresh, 3, t - 800, Some(&add), Some(&add), &[], &r);
    let f4 = header(Kind::Fresh, 4, t - 700, Some(&f3), Some(&add), &[], &r);
    let fork_head = header(Kind::Fresh, 5, t - 600, Some(&f4), Some(&add), &[], &r);
    let fork_next = header(
        Kind::Fresh,
        6,
        t - 500,
        Some(&fork_head),
        Some(&add),
        &[],
        &r,
    );
    Chain {
        k1,
        r,
        genesis,
        add,
        remove,
        after,
        fork_head,
        fork_next,
    }
}

/// The writer's desktop app, having followed the group through R's removal.
fn desktop(c: &Chain, ik: IdentityKeyPair) -> Device {
    let mut d = Device::new(ik, 20, Platform::Desktop);
    d.take(InPiece {
        chain: vec![
            wire(&c.genesis),
            wire(&c.add),
            wire(&c.remove),
            wire(&c.after),
        ],
        ..InPiece::default()
    });
    let f = d.floor();
    assert_eq!(f.d, c.after.d(), "the desktop took the chain to its head");
    assert_eq!(f.kh, c.remove.d(), "its floor names R's removal");
    assert_eq!(
        d.sets_told().last().unwrap(),
        &vec![Some(c.k1.m)],
        "and it told its user the set without R"
    );
    d
}

/// What the relay sends the desktop to bring it onto R's fork: the keyholder header from
/// before the removal, and R's next header.
fn onto_the_fork(c: &Chain) -> InPiece {
    InPiece {
        kh: Some(wire(&c.add)),
        walk: vec![link(&c.add)],
        head: Some(link(&c.fork_next)),
        ..InPiece::default()
    }
}

/// The control: a desktop that saw R removed refuses R's fork, whatever the relay sends with
/// it. It passes today.
#[test]
fn control_a_desktop_that_saw_a_keyholder_removed_refuses_that_keyholders_fork() {
    let c = chain();
    let ik = voipc_crypto::generate_identity_key_pair();
    let mut d = desktop(&c, ik);
    d.take(onto_the_fork(&c));
    d.take(InPiece {
        kh: Some(wire(&c.add)),
        walk: vec![link(&c.add)],
        head: Some(link(&c.fork_head)),
        ..InPiece::default()
    });
    assert_eq!(d.floor().d, c.after.d(), "the floor did not move");
    assert_eq!(d.floor().kh, c.remove.d());
}

/// F2: the same desktop, after another device of the account took R's fork on trust and the
/// vault floor it saved reached the desktop (`floors_in`, as `gk_net.rs` calls it for a
/// floor "another device raised", and `track` at the next start). The desktop then takes a
/// header only R signed, and tells its user R holds the channel's keys again.
///
/// §6, a removed keyholder: "With the relay, fork members who have not yet seen its removal".
/// This member saw it. THREAT-MODEL, hostile relay, Cannot: "Roll a desktop or phone app
/// below its local floor".
#[test]
fn f2_a_vault_floor_from_a_fresh_device_does_not_bring_a_desktop_onto_a_removed_keyholders_fork() {
    let c = chain();
    let ik = voipc_crypto::generate_identity_key_pair();
    let mut d = desktop(&c, ik);

    // A new browser page of the same account, with no floor (the relay left the vault's
    // group-key index out of its sign-in frame, which a device with no memory cannot tell):
    // the relay shows it R's fork, and it takes the head on trust, as §5.7 lets a device
    // with no floor do
    let mut fresh = Device::new(ik, 21, Platform::Browser);
    fresh.take(InPiece {
        walk: vec![link(&c.add), link(&c.genesis)],
        head: Some(link(&c.fork_head)),
        ..InPiece::default()
    });
    let (floor, names) = fresh
        .vault
        .clone()
        .expect("it saves its floor to the vault");
    assert_eq!(floor.d, c.fork_head.d(), "the fresh device took R's fork");
    assert_eq!(floor.kh, c.add.d(), "under the set from before R's removal");

    // That floor reaches the desktop through the account's vault
    let out = d.keying.floors_in(GROUP, Some((floor, names)));
    d.took(out);
    d.take(onto_the_fork(&c));

    let f = d.floor();
    assert!(
        f.d != c.fork_next.d() && f.kh == c.remove.d(),
        "a desktop that saw R removed must not take a header only R signed; its floor is now \
         at epoch {} (R's header: {}), naming the keyholder header of epoch {} (the removal is \
         epoch 3, the set with R epoch 2), and it told its user these sets: {:?} (R is {:?})",
        f.epoch,
        f.d == c.fork_next.d(),
        if f.kh == c.add.d() { 2 } else { 3 },
        d.sets_told(),
        c.r.m,
    );
}

/// F2, the generation variant, with no hostile keyholder at all: the desktop followed
/// generation X and then took generation Y (told as "made anew"). The relay keeps X going
/// with a volunteer it never showed Y, who signs an honest Regenesis of X an hour after X's
/// last header. A fresh device of the account takes that Regenesis on trust; its floor's
/// `gen_time` is the Regenesis's `time`, which is later than Y's Genesis, so the merge puts
/// the desktop back into X: a generation it took before and left, with no "made anew", past
/// the rule that refuses a generation this device took already (§5.7; THREAT-MODEL, hostile
/// relay, Cannot: "Roll a desktop or phone app ... back into ... one of the last 8
/// [generations] it took").
#[test]
fn f2_a_vault_floor_from_a_fresh_device_does_not_bring_a_desktop_back_into_a_generation_it_left() {
    const X: [u8; 16] = [0xaa; 16];
    const Y: [u8; 16] = [0xbb; 16];
    let t = now_ms() / 1000;
    let k1 = holder([0x11; 16], t - 20000);
    let v = holder([0x44; 16], t - 20000);
    let gx = header_in(X, 1, Kind::Genesis, 1, t - 10000, None, None, &[&k1], &k1);
    let gy = header_in(Y, 1, Kind::Genesis, 1, t - 300, None, None, &[&k1], &k1);
    // X goes on behind the desktop's back: a Regenesis by a volunteer, over an hour after
    // its parent and after Y began, and a header after it
    let rx = header_in(
        X,
        2,
        Kind::Regenesis,
        2,
        t - 100,
        Some(&gx),
        Some(&gx),
        &[&v],
        &v,
    );
    let fx = header_in(X, 2, Kind::Fresh, 3, t - 50, Some(&rx), Some(&rx), &[], &v);

    let ik = voipc_crypto::generate_identity_key_pair();
    let mut d = Device::new(ik, 20, Platform::Desktop);
    d.take(InPiece {
        head: Some(link(&gx)),
        ..InPiece::default()
    });
    assert_eq!(d.floor().gen, X);
    d.take(InPiece {
        head: Some(link(&gy)),
        ..InPiece::default()
    });
    assert_eq!(d.floor().gen, Y, "the desktop took the new generation");
    let anew = |d: &Device| {
        d.events
            .iter()
            .filter(|e| matches!(e, GkEvent::Anew { .. }))
            .count()
    };
    assert_eq!(anew(&d), 1, "and told its user the keys were made anew");
    // The control: the relay cannot bring it back into X by itself
    d.take(InPiece {
        walk: vec![link(&gx)],
        head: Some(WalkLinkIn {
            header: wire(&rx),
            parent: Some(wire(&gx)),
        }),
        ..InPiece::default()
    });
    assert_eq!(
        d.floor().gen,
        Y,
        "a generation this device took already is refused"
    );

    let mut fresh = Device::new(ik, 21, Platform::Browser);
    fresh.take(InPiece {
        head: Some(WalkLinkIn {
            header: wire(&rx),
            parent: Some(wire(&gx)),
        }),
        ..InPiece::default()
    });
    let (floor, names) = fresh
        .vault
        .clone()
        .expect("it saves its floor to the vault");
    assert_eq!(
        (floor.gen, floor.d),
        (X, rx.d()),
        "the fresh device took X on trust"
    );

    let out = d.keying.floors_in(GROUP, Some((floor, names)));
    d.took(out);
    d.take(InPiece {
        head: Some(WalkLinkIn {
            header: wire(&rx),
            parent: Some(wire(&gx)),
        }),
        ..InPiece::default()
    });
    d.take(InPiece {
        head: Some(link(&fx)),
        ..InPiece::default()
    });
    let f = d.floor();
    assert!(
        f.gen == Y,
        "a desktop that left generation X for Y must not be back in X; its floor is in {} at          epoch {}, and it told its user of {} new start(s) in all",
        if f.gen == X { "X" } else { "another generation" },
        f.epoch,
        anew(&d),
    );
}
