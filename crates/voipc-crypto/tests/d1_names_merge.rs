//! Dive 1 (hostile relay), finding F3: the vault merge moves a writer's names floor to the
//! highest names floor any device of its account saved (`sync::gk_floors::later_names`),
//! and a device with no names floor sets its own to the first head it takes, folding nothing
//! (`group_state/names.rs` `header_taken`). So one sign-in of the account on a device with
//! no floor (a new browser page, a new install, or one the relay left the vault's group-key
//! index out for) carries every device of the account past the names it never folded: a
//! seat the relay had an honest keyholder add in between is never named to the writer.
//!
//! §4.4 rule 4: "A writer keeps a names floor: the header position and `names_hash` it last
//! folded to ... skips none". §5.7: the names floor "moves only when the device folds".
//! THREAT-MODEL, hostile relay about the group key, Cannot: "Skip, move or cut short a
//! writer's list of new readers".
//!
//! Both devices are real `GroupKeying`s, the headers are signed with the public
//! `SignedHeader::sign`, and this test is the relay. The fresh device's own
//! `GkOut::vault_floors` is what goes into the desktop's `floors_in`, as `gk_net.rs` hands a
//! vault row "another device raised" to it. The fold at the end is C1's `fold_names`, called
//! as `group_state/names.rs` `fold` calls it: from the names floor the device keeps, over the
//! lists of the headers after that place.
//!
//! Run: cargo test -p voipc-crypto --test d1_names_merge

use voipc_crypto::group_key::commit::Pair;
use voipc_crypto::group_key::{
    fold_names, names_hash, Added, AddedSeat, Endorsement, Floor, Fold, GroupKind, HeaderV1,
    Keyholder, Kind, Known, MemberId, NamesFloor, NamesFrom, NamesList, Origin, PinThen, Removed,
    SeatKeys, SeatPair, SignedHeader,
};
use voipc_crypto::group_state::{
    GkCtx, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{HeaderIn, InPiece, WalkLinkIn};
use voipc_protocol::messages::ServerMessage;

const GROUP: &str = "c:lounge-4";
const GEN: [u8; 16] = [7; 16];
const WRITER: [u8; 16] = [0x33; 16];
/// The account the relay made up and had a keyholder seat.
const GHOST: [u8; 16] = [0x66; 16];

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

/// A header of the gated text group after `parent`, signed by the keyholder `by`, with the
/// `names_hash` its place and its `added` list give (§11.3).
fn header(
    kind: Kind,
    (epoch, join): (u32, u32),
    time: u64,
    parent: Option<&SignedHeader>,
    kh: Option<&SignedHeader>,
    added: Vec<AddedSeat>,
    by: &Holder,
) -> SignedHeader {
    let opening = join == 0;
    let mut hd = HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen: GEN,
        epoch,
        join,
        kind,
        time,
        parent: parent.map_or([0; 32], |p| p.d()),
        epoch_parent: match parent {
            Some(p) if !opening => p.d_e(),
            _ => [0; 32],
        },
        kh_parent: kh.map_or([0; 32], |k| k.d()),
        signer: by.m,
        keyholders: if kind == Kind::Genesis {
            vec![by.entry]
        } else {
            vec![]
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
        added: Added::List(added),
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
            vault: None,
        }
    }

    fn took(&mut self, out: GkOut) {
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

    fn chain(&mut self, headers: &[&SignedHeader]) {
        self.take(InPiece {
            chain: headers.iter().map(|h| wire(h)).collect(),
            ..InPiece::default()
        });
    }

    /// What this device keeps locally (`gk_local.bin` on a desktop): its floor, and the
    /// names floor a writer's next fold starts at.
    fn kept(&self) -> (Floor, NamesFloor) {
        let l = &self.keying.local().expect("started").floors[GROUP];
        (l.floor.clone(), l.names.expect("a names floor"))
    }
}

/// The gated group's history, every header by its one honest keyholder K1: a Genesis, an
/// epoch, the Join the relay asked K1 for that seats the ghost, and three more epochs.
struct Chain {
    genesis: SignedHeader,
    e2: SignedHeader,
    join: SignedHeader,
    e3: SignedHeader,
    e4: SignedHeader,
    e5: SignedHeader,
    ghost: AddedSeat,
}

impl Chain {
    fn all(&self) -> [&SignedHeader; 6] {
        [
            &self.genesis,
            &self.e2,
            &self.join,
            &self.e3,
            &self.e4,
            &self.e5,
        ]
    }
}

fn chain() -> Chain {
    let t = now_ms() / 1000;
    let k1 = holder([0x11; 16], t - 4000);
    let ghost = AddedSeat {
        m: MemberId::Account(GHOST),
        ik: raw(&voipc_crypto::generate_identity_key_pair()),
        tag_sk: [0x61; 8],
        tag_sx: [0x62; 8],
        n: 1,
        made: t - 1600,
    };
    let genesis = header(Kind::Genesis, (1, 0), t - 3000, None, None, vec![], &k1);
    let g = Some(&genesis);
    let e2 = header(Kind::Fresh, (2, 0), t - 2000, g, g, vec![], &k1);
    let join = header(Kind::Join, (2, 1), t - 1500, Some(&e2), g, vec![ghost], &k1);
    let e3 = header(Kind::Fresh, (3, 0), t - 1000, Some(&join), g, vec![], &k1);
    let e4 = header(Kind::Fresh, (4, 0), t - 500, Some(&e3), g, vec![], &k1);
    let e5 = header(Kind::Fresh, (5, 0), t - 100, Some(&e4), g, vec![], &k1);
    Chain {
        genesis,
        e2,
        join,
        e3,
        e4,
        e5,
        ghost,
    }
}

/// The fold a writer runs before its post (`names.rs` `fold`): from the names floor it
/// keeps, over the lists of the headers it took after that place, to the head. The new
/// readers its app is shown.
fn readers_shown(from: NamesFloor, c: &Chain, head: &SignedHeader) -> Vec<MemberId> {
    let hd = head.header();
    let lists: Vec<NamesList> = c
        .all()
        .iter()
        .map(|h| NamesList::of(h.header()))
        .filter(|l| (l.epoch, l.join) > (from.epoch, from.join))
        .filter(|l| (l.epoch, l.join) <= (hd.epoch, hd.join))
        .collect();
    let pins = |_: &[u8; 16], _: u64| PinThen::None;
    let counters = |_: &[u8; 16]| None;
    let known = Known {
        pins: &pins,
        counters: &counters,
        own: Some(WRITER),
        now: now_ms() / 1000,
    };
    match fold_names(&NamesFrom::Floor(from), &lists, hd, &known).expect("the lists fold") {
        Fold::Take { shown, .. } => shown.named.iter().map(|a| a.m).collect(),
        Fold::Hold { .. } => panic!("no entry fails here"),
    }
}

/// The control: the writer's desktop app took the group's headers as they came and has
/// not posted since the Genesis. Its names floor stays where it last folded, however far
/// its floor moved, and its next fold names the ghost. It passes today.
#[test]
fn control_a_writers_names_floor_stays_where_it_folded_and_its_next_fold_names_the_ghost() {
    let c = chain();
    let ik = voipc_crypto::generate_identity_key_pair();
    let mut d = Device::new(ik, 20, Platform::Desktop);
    d.chain(&c.all());
    let (floor, names) = d.kept();
    assert_eq!(floor.d, c.e5.d(), "the desktop took the chain to its head");
    assert_eq!(
        (names.epoch, names.join),
        (1, 0),
        "its names floor is where it started: it folded nothing since"
    );
    assert_eq!(
        readers_shown(names, &c, &c.e5),
        vec![c.ghost.m],
        "so the fold before its next post names the ghost"
    );
}

/// F3: the same desktop, at the same head. The account signs in once on a device with no
/// floor (a new browser page; the relay left the vault's group-key index out of its sign-in
/// frame). That device takes the head on trust and sets its names floor there, as §5.7 lets
/// a device with no names floor do: it folded nothing and showed nobody. Its vault row
/// reaches the desktop, and the desktop's names floor jumps past the Join that seated the
/// ghost. No device of the account ever folded that Join's list, and the desktop's next
/// fold names nobody.
#[test]
fn f3_a_fresh_devices_vault_row_does_not_carry_a_writer_past_names_it_never_folded() {
    let c = chain();
    let ik = voipc_crypto::generate_identity_key_pair();
    let mut d = Device::new(ik, 20, Platform::Desktop);
    d.chain(&[&c.genesis, &c.e2, &c.join, &c.e3, &c.e4]);
    let (floor, names) = d.kept();
    assert_eq!(floor.d, c.e4.d(), "the desktop is at the head");
    assert_eq!((names.epoch, names.join), (1, 0), "and folded nothing yet");

    // The account's new browser page, with no floor: the relay shows it the head
    let mut fresh = Device::new(ik, 21, Platform::Browser);
    fresh.take(InPiece {
        walk: vec![link(&c.genesis)],
        head: Some(link(&c.e4)),
        ..InPiece::default()
    });
    let (floor, names) = fresh
        .vault
        .clone()
        .expect("it saves its floor to the vault");
    assert_eq!(floor.d, c.e4.d(), "the fresh device took the same head");
    assert_eq!(
        names.map(|n| (n.epoch, n.join)),
        Some((4, 0)),
        "and its names floor is that head, with nothing folded"
    );

    // Its row reaches the desktop through the account's vault; the next header comes
    let out = d.keying.floors_in(GROUP, Some((floor, names)));
    d.took(out);
    d.chain(&[&c.e5]);

    let (floor, names) = d.kept();
    assert_eq!(
        floor.d,
        c.e5.d(),
        "the desktop follows the same chain as before"
    );
    let shown = readers_shown(names, &c, &c.e5);
    assert!(
        (names.epoch, names.join) < (2, 1) && shown == vec![c.ghost.m],
        "a writer's names floor moves only when a fold showed its user the names up to it \
         (§5.7); no device of this account folded the Join at epoch 2, join 1, that seated \
         {:?}, yet the desktop's names floor is now at epoch {}, join {}, and the fold before \
         its next post shows these new readers: {shown:?}",
        c.ghost.m,
        names.epoch,
        names.join,
    );
}
