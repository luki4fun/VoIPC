//! Dive 1 (hostile relay), finding F1: the times of an account's pins and the highest
//! seat-key counters it has seen live only in the relay-stored vault pages `gkc.N`, named by
//! the index `item.gk_floors`. A relay that leaves the index out of the sign-in frame makes
//! the device time every pin "now" (`GkFloors::pins_held`) and forget every counter. From
//! then on a writer's fold of a gated group's names (`fold_names`, §4.4 rules 4, 6 and 8)
//! refuses neither an identity key that is not the pinned one, nor an old seat-key counter,
//! in any header made up to 10 minutes after that sign-in: which is every header there is.
//!
//! The device here is a real `AccountSync` (the book the desktop app and the browser hand
//! `GroupKeying` as `GkCtx::pins` for a signed-in account), fed by a relay that is this test.
//! The fold is C1's `fold_names`, called as `group_state/names.rs` `fold` calls it: `pins`
//! from `GkPins::pin_then`, `counters` from `GkPins::seen`.
//!
//! The last tests run the desktop app's `GroupKeying` itself, with that book and what the app
//! keeps between runs (`LocalGk`, as `gk_local.bin` holds it): the counters it met are kept
//! there too, so a withheld index does not take them from a device with a local file. The
//! browser keeps the same counters in IndexedDB past a reload: crates/voipc-web gk.rs
//! `reload_tests` runs that through the page's own code.
//!
//! Run: cargo test -p voipc-crypto --test d1_pin_times

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use voipc_crypto::account::{SignedIn, Vault};
use voipc_crypto::group_key::commit::Pair;
use voipc_crypto::group_key::{
    fold_names, names_hash, names_step, tag, Added, AddedSeat, Endorsement, Fold, GroupKind,
    HeaderV1, Held, Keyholder, Kind, Known, MemberId, NamesFloor, NamesFrom, NamesList, Origin,
    PinThen, Removed, SeatKeys, SeatPair, Seen, SignedHeader,
};
use voipc_crypto::group_state::{
    GkCtx, GkPins, GkStart, GkTrack, GroupKeying, LocalGk, Platform, VaultFloor,
};
use voipc_crypto::sync::{AccountSync, Event, GkIndex, LogMemory, ITEM_GK_FLOORS};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{HeaderIn, InPiece};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage, ServerMessage};
use voipc_protocol::types::VaultBlob;

const RELAY: [u8; 16] = [9; 16];
const ME: [u8; 16] = [1; 16];
/// The account the writer pinned long ago.
const ALICE: [u8; 16] = [0xa1; 16];
const DAY: u64 = 24 * 60 * 60;

/// `sync::gk_floors::CounterRow` and `Counter`, field for field (postcard is positional): the
/// module is private, and a page is `Vec<CounterRow>` sealed as the vault item `gkc.N`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CounterRow {
    account: [u8; 16],
    counter: Option<Counter>,
    pin: Option<(u64, [u8; 8])>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Counter {
    n: u32,
    made: u64,
    rotation: bool,
}

fn now() -> u64 {
    voipc_crypto::time::now_millis() / 1000
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// The relay's vault for one account, and what it does with it.
#[derive(Default)]
struct Relay {
    items: HashMap<String, VaultBlob>,
    /// Hostile: the group key's index is left out of the sign-in frame, and its pages are
    /// answered as not there.
    withholds_gk: bool,
}

impl Relay {
    fn hidden(&self, k: &str) -> bool {
        self.withholds_gk && (k == ITEM_GK_FLOORS || k.starts_with("gkf.") || k.starts_with("gkc."))
    }

    /// The items of the sign-in frame: everything but the pages.
    fn sign_in(&self) -> Vec<VaultBlob> {
        self.items
            .values()
            .filter(|b| b.k.starts_with("item.") && !self.hidden(&b.k))
            .cloned()
            .collect()
    }

    fn put(&mut self, k: &str, v: Vec<u8>, expect: i64) -> AccountReply {
        let held = self.items.get(k).map_or(0, |b| b.version);
        if held != expect {
            return AccountReply::VaultConflict {
                k: k.to_string(),
                blob: self.items.get(k).cloned(),
            };
        }
        let version = held + 1;
        self.items.insert(
            k.to_string(),
            VaultBlob {
                k: k.to_string(),
                v,
                version,
            },
        );
        AccountReply::VaultStored {
            k: k.to_string(),
            version,
        }
    }

    /// Answers what `out` asks of the vault until nothing more comes: the events told.
    fn serve(&mut self, s: &mut AccountSync, out: Vec<ClientMessage>) -> Vec<Event> {
        let mut events = Vec::new();
        let mut queue: VecDeque<ClientMessage> = out.into();
        while let Some(m) = queue.pop_front() {
            let reply = match m {
                ClientMessage::Account(AccountRequest::VaultPut { k, v, expect }) => {
                    if self.hidden(&k) {
                        // What it would not hand over it does not take either; the device
                        // saves nothing over a missing item anyway
                        continue;
                    }
                    self.put(&k, v, expect)
                }
                ClientMessage::Account(AccountRequest::VaultPage { k }) => {
                    let blob = self.items.get(&k).filter(|_| !self.hidden(&k)).cloned();
                    AccountReply::VaultPageFound { k, blob }
                }
                _ => continue,
            };
            if let Some((more, told)) = s.on_reply(&reply) {
                queue.extend(more);
                events.extend(told);
            }
        }
        events
    }
}

/// One sign-in of the writer's account on a device that remembers `memory`: the pins in,
/// the group key on, every page read.
fn sign_in(
    relay: &mut Relay,
    dek: [u8; 32],
    identity: IdentityKeyPair,
    memory: LogMemory,
) -> (AccountSync, Vec<Event>) {
    let signed = SignedIn {
        relay_id: RELAY,
        name: "writer".into(),
        vault: Vault::from_dek(RELAY, "writer", dek),
        identity,
        recovery: None,
        blobs: relay.sign_in(),
        binding: None,
        keyed: false,
        login_key: None,
    };
    let (mut s, out) = AccountSync::start(&signed, ME, memory, false);
    let mut events = relay.serve(&mut s, out);
    let out = s.gk_begin(true, now(), false);
    events.extend(relay.serve(&mut s, out));
    for _ in 0..4 {
        let (out, told) = s.tick();
        events.extend(told);
        events.extend(relay.serve(&mut s, out));
    }
    assert!(s.ready(), "the pins and the group key's pages are in");
    (s, events)
}

/// What the device kept before the attack: Alice pinned 30 days ago, her seat-key counter 5
/// seen then. The relay's vault holds it as an honest relay would.
struct Before {
    relay: Relay,
    dek: [u8; 32],
    identity: IdentityKeyPair,
    alice: IdentityKeyPair,
    /// What the device itself remembers (`LogMemory::vault_gens`).
    memory: LogMemory,
    pinned: u64,
}

fn before() -> Before {
    let vault = Vault::create(RELAY, "writer");
    let dek = vault.dek();
    let identity = voipc_crypto::generate_identity_key_pair();
    let alice = voipc_crypto::generate_identity_key_pair();
    let pinned = now() - 30 * DAY;
    let mut relay = Relay::default();
    // The page and the index as the device saved them 30 days ago, when it met Alice
    let rows = vec![CounterRow {
        account: ALICE,
        counter: Some(Counter {
            n: 5,
            made: pinned,
            rotation: true,
        }),
        pin: Some((pinned, tag(&raw(&alice)))),
    }];
    let page = vault.seal_item("gkc.0", 1, &postcard::to_allocvec(&rows).unwrap());
    relay
        .items
        .insert("gkc.0".into(), VaultBlob { version: 1, ..page });
    let index = GkIndex {
        format: 1,
        floor_pages: vec![],
        counter_pages: vec![1],
    };
    relay.items.insert(
        ITEM_GK_FLOORS.into(),
        VaultBlob {
            version: 1,
            ..vault.seal_item(ITEM_GK_FLOORS, 1, &index.to_bytes())
        },
    );
    // The pin itself, through the device: its earlier sign-ins
    let (mut s, _) = sign_in(&mut relay, dek, identity, LogMemory::default());
    let key = alice.identity_key().serialize();
    let (_, out) = s.check_peer(&ALICE, "alice", &key);
    relay.serve(&mut s, out);
    for _ in 0..8 {
        let (out, _) = s.tick();
        relay.serve(&mut s, out);
        let out = s.gk_flush();
        relay.serve(&mut s, out);
    }
    assert_eq!(s.pin(&ALICE), Some(raw(&alice)), "Alice is pinned");
    let memory = s.memory();
    assert!(
        memory.vault_gens.contains_key(ITEM_GK_FLOORS),
        "the device saw the group key's index"
    );
    Before {
        relay,
        dek,
        identity,
        alice,
        memory,
        pinned,
    }
}

/// A gated group's names from the writer's names floor to the head: one Join, made a minute
/// ago, that seats `seat`. The fold of it, with `s` as the writer's book.
fn fold(s: &AccountSync, seat: AddedSeat) -> Fold {
    let t = now();
    let gen = [7; 16];
    let floor = NamesFloor {
        gen,
        epoch: 3,
        join: 0,
        names_hash: [0x33; 32],
        time: t - 3600,
    };
    let list = NamesList {
        time: t - 60,
        epoch: 3,
        join: 1,
        added: vec![seat],
        removed: vec![],
    };
    let head = HeaderV1 {
        group_kind: GroupKind::Text,
        group: "c:lounge-4".into(),
        gen,
        epoch: 3,
        join: 1,
        kind: Kind::Join,
        time: t - 60,
        parent: [9; 32],
        epoch_parent: [8; 32],
        kh_parent: [8; 32],
        signer: MemberId::Account([0xcc; 16]),
        keyholders: vec![],
        gated: true,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 2,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [0; 32],
        keyring_hash: [0; 32],
        names_hash: names_step(&floor.names_hash, &list),
        added: Added::List(vec![seat]),
        removed: Removed::List(vec![]),
        confirm: [0; 32],
    };
    let pin_then = |a: &[u8; 16], time: u64| s.pin_then(a, time);
    let counters = |a: &[u8; 16]| s.seen(a);
    let known = Known {
        pins: &pin_then,
        counters: &counters,
        own: Some(ME),
        now: t,
    };
    fold_names(&NamesFrom::Floor(floor), &[list], &head, &known).expect("the list folds")
}

/// Alice's account id with an identity key the relay made: what a relay seats to read a
/// gated channel as her.
fn impostor(made: u64) -> AddedSeat {
    AddedSeat {
        m: MemberId::Account(ALICE),
        ik: raw(&voipc_crypto::generate_identity_key_pair()),
        tag_sk: [1; 8],
        tag_sx: [2; 8],
        n: 5,
        made,
    }
}

/// Alice's own identity key with seat keys of counter 3: her old seat keys (a stolen
/// device's), which the writer's device saw replaced by counter 5 a month ago.
fn old_seat(alice: &IdentityKeyPair, made: u64) -> AddedSeat {
    AddedSeat {
        m: MemberId::Account(ALICE),
        ik: raw(alice),
        tag_sk: [3; 8],
        tag_sx: [4; 8],
        n: 3,
        made,
    }
}

fn gk_problems(events: &[Event]) -> Vec<&'static str> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::VaultProblem { item, problem } if *item == ITEM_GK_FLOORS => Some(*problem),
            _ => None,
        })
        .collect()
}

/// The control: under a relay that hands the vault over, the fold holds for both seats. It
/// passes today, and shows the harness reaches the rule.
#[test]
fn control_with_the_vault_handed_over_a_swapped_identity_and_an_old_counter_hold_the_fold() {
    let mut b = before();
    let (s, events) = sign_in(&mut b.relay, b.dek, b.identity, b.memory.clone());
    assert!(gk_problems(&events).is_empty());
    assert_eq!(
        s.pin_then(&ALICE, now() - 60),
        PinThen::Pin(raw(&b.alice)),
        "the pin as it stood a minute ago is known: it is a month old"
    );
    assert_eq!(
        s.seen(&ALICE),
        Some(Seen {
            n: 5,
            made: b.pinned
        })
    );
    assert!(matches!(
        fold(&s, impostor(b.pinned)),
        Fold::Hold {
            why: Held::Pin(_),
            ..
        }
    ));
    assert!(matches!(
        fold(&s, old_seat(&b.alice, b.pinned - 30 * DAY)),
        Fold::Hold {
            why: Held::Counter {
                n: 3,
                highest: 5,
                ..
            },
            ..
        }
    ));
}

/// F1, a device that saw the index before (a desktop app, which keeps `LogMemory`): the
/// relay leaves `item.gk_floors` out. The device says once that an item is missing, and from
/// then on names a relay-made identity key under Alice's pinned account as a new reader
/// instead of holding its posts (§4.4 rule 6: "every `IK` the device has a pin for matches
/// that pin"; THREAT-MODEL, hostile relay, Cannot: "Replace a pinned key unnoticed, unless it
/// removes the pins first"). The pins were not removed: `pin` still answers Alice's real key.
#[test]
fn f1_a_withheld_gk_index_does_not_let_a_swapped_identity_past_a_writers_fold() {
    let mut b = before();
    b.relay.withholds_gk = true;
    let (s, events) = sign_in(&mut b.relay, b.dek, b.identity, b.memory.clone());
    assert_eq!(
        gk_problems(&events),
        ["missing"],
        "what the device says: one item is missing"
    );
    assert_eq!(s.pin(&ALICE), Some(raw(&b.alice)), "the pin is still held");
    let folded = fold(&s, impostor(b.pinned));
    assert!(
        matches!(
            folded,
            Fold::Hold {
                why: Held::Pin(_),
                ..
            }
        ),
        "a seat under Alice's account with another identity key than the one pinned must \
         hold the fold; pin_then says {:?} of a header a minute old, and the fold says {folded:?}",
        s.pin_then(&ALICE, now() - 60),
    );
}

/// F1 on a device with no memory (a new browser page, a new install): the same, and not a
/// word is said, though the pins came from the vault and are held.
#[test]
fn f1_on_a_fresh_device_a_withheld_gk_index_does_not_let_a_swapped_identity_past_the_fold() {
    let mut b = before();
    b.relay.withholds_gk = true;
    let (s, events) = sign_in(&mut b.relay, b.dek, b.identity, LogMemory::default());
    assert!(gk_problems(&events).is_empty(), "nothing is said");
    assert_eq!(s.pin(&ALICE), Some(raw(&b.alice)), "the pin is held");
    let folded = fold(&s, impostor(b.pinned));
    assert!(
        matches!(
            folded,
            Fold::Hold {
                why: Held::Pin(_),
                ..
            }
        ),
        "a seat under Alice's account with another identity key than the one pinned must \
         hold the fold; pin_then says {:?} of a header a minute old, and the fold says {folded:?}",
        s.pin_then(&ALICE, now() - 60),
    );
}

/// F1, rule 8: the same withheld index takes the counters with it. A device that saw Alice's
/// counter 5 a month ago no longer flags her seat keys of counter 3 (§6 hostile relay,
/// Cannot: "Seat an account's old seat keys again once a keyholder has seen its newer
/// counter, or past a writer that has seen it: that writer's fold fails").
///
/// The book here is the vault's alone: a device that kept nothing of its own. A device that
/// did keeps the counters it met in `LocalGk::mirror`, which `GroupKeying` checks against too
/// and this test cannot reach: see
/// `f1_on_a_device_with_a_local_file_a_withheld_gk_index_does_not_let_an_old_counter_past_its_checks`
/// here, and voipc-web gk.rs `reload_tests` for the browser.
#[ignore = "the accepted limit (THREAT-MODEL): a device that kept nothing of its own (a new install, a new browser profile, cleared site data, a browser with storage off) has only the vault's counters, so withheld gk pages take them; the mirror of a device that kept one is tested through GroupKeying below and in voipc-web gk.rs reload_tests"]
#[test]
fn f1_a_withheld_gk_index_does_not_let_an_old_seat_key_counter_past_a_writers_fold() {
    let mut b = before();
    b.relay.withholds_gk = true;
    let (s, events) = sign_in(&mut b.relay, b.dek, b.identity, b.memory.clone());
    assert_eq!(gk_problems(&events), ["missing"]);
    let folded = fold(&s, old_seat(&b.alice, b.pinned - 30 * DAY));
    assert!(
        matches!(
            folded,
            Fold::Hold {
                why: Held::Counter { .. },
                ..
            }
        ),
        "Alice's seat keys of counter 3, seated a minute ago, must hold the fold of a device \
         that saw her counter 5 a month ago; it holds counter {:?} now, and the fold says \
         {folded:?}",
        s.seen(&ALICE),
    );
}

// ── Through the desktop app's `GroupKeying`, with its local file ─────────────────────────

/// The channel the writer follows, and its stored group.
const CHANNEL: u32 = 1;
const GROUP: &str = "c:lounge-4";
/// A keyholder of the group, an account the writer meets there.
const K1: [u8; 16] = [0x11; 16];

/// A desktop keyholder entry (origin 0x03) of `account` under its `ik`, at counter `n`.
fn keyholder(account: [u8; 16], ik: &IdentityKeyPair, n: u32, made: u64) -> Keyholder {
    let pair = SeatPair::generate();
    let m = MemberId::Account(account);
    let endorsement = Endorsement::sign(ik, Origin::Desktop, m, n, made, &pair.public()).unwrap();
    Pair {
        keys: pair.public(),
        endorsement,
    }
    .entry(GroupKind::Text, m, raw(ik))
    .expect("a desktop keyholder entry")
}

/// A Genesis of generation `gen` of the group, signed by K1 (`k1`), naming `keyholders`.
fn genesis(
    gen: [u8; 16],
    time: u64,
    k1: &IdentityKeyPair,
    keyholders: Vec<Keyholder>,
) -> SignedHeader {
    let mut hd = HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen,
        epoch: 1,
        join: 0,
        kind: Kind::Genesis,
        time,
        parent: [0; 32],
        epoch_parent: [0; 32],
        kh_parent: [0; 32],
        signer: MemberId::Account(K1),
        keyholders,
        gated: true,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 2,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [1; 32],
        keyring_hash: [1; 32],
        names_hash: [0; 32],
        added: Added::List(vec![]),
        removed: Removed::List(vec![]),
        confirm: [1; 32],
    };
    hd.names_hash = names_hash(None, &hd);
    SignedHeader::sign(hd, k1).expect("a header of a valid shape")
}

/// One run of the writer's desktop app on this relay: `GroupKeying` as the app runs it, the
/// account's book handed in at each call. What the app keeps for this relay and account
/// (`LocalGk`) goes from one run to the next as `gk_local.bin` holds it: postcard bytes.
struct App {
    keying: GroupKeying,
    st: SignalStores,
}

impl App {
    /// A run that starts from `file` (`None`: no file, as a new browser page starts).
    fn run(identity: IdentityKeyPair, file: Option<&[u8]>) -> App {
        let local: Option<LocalGk> =
            file.map(|b| postcard::from_bytes(b).expect("the local file reads"));
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: true,
            run: [0x22; 16],
            relay_clock: now(),
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: 20,
            identity,
            account: Some(ME),
            seat_keys: Some(SeatKeys::generate(1, now())),
            local,
            visible: true,
        });
        let _ = keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: GROUP.into(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: true,
            },
            VaultFloor::None,
        );
        App {
            keying,
            st: SignalStores::new(&identity, 20),
        }
    }

    /// The relay pushes `h`; the app checks it against `book`.
    fn push(&mut self, book: &mut AccountSync, h: &SignedHeader) {
        let msg = ServerMessage::EpochIn {
            group: GROUP.into(),
            part: 0,
            last: true,
            piece: Box::new(InPiece {
                chain: vec![HeaderIn {
                    body: h.body().to_vec(),
                    sig: h.sig().to_vec(),
                }],
                ..InPiece::default()
            }),
        };
        let c = GkCtx {
            pins: book,
            now: voipc_crypto::time::now_millis(),
        };
        let _ = self.keying.frame(&mut self.st, &msg, c);
    }

    /// The header the app holds the group's floor at.
    fn floor(&self) -> Option<[u8; 32]> {
        self.keying
            .local()
            .and_then(|l| l.floors.get(GROUP))
            .map(|f| f.floor.d)
    }

    /// The run ends: what it keeps, as the file holds it.
    fn end(mut self) -> Vec<u8> {
        let _ = self.keying.end();
        postcard::to_allocvec(self.keying.local().expect("kept")).unwrap()
    }
}

/// The app's first run, under an honest relay: K1 starts the group with Alice's desktop pair
/// under her counter 5 among its keyholders. The app checks that entry against the account's
/// book, which holds Alice's counter 5 (`before`), and takes it. What the run kept, and K1's
/// key and Genesis.
fn first_run(b: &mut Before) -> (Vec<u8>, IdentityKeyPair, SignedHeader) {
    let (mut s, _) = sign_in(&mut b.relay, b.dek, b.identity, b.memory.clone());
    let t = now();
    let k1 = voipc_crypto::generate_identity_key_pair();
    let g = genesis(
        [7; 16],
        t - 3000,
        &k1,
        vec![
            keyholder(K1, &k1, 1, t - 4000),
            keyholder(ALICE, &b.alice, 5, t - 4000),
        ],
    );
    let mut app = App::run(b.identity, None);
    app.push(&mut s, &g);
    assert_eq!(app.floor(), Some(g.d()), "the app took K1's Genesis");
    (app.end(), k1, g)
}

/// K1 starts the group anew a minute ago, with Alice's desktop pair of counter `n` (made
/// `made`) among its keyholders: a relay with a keyholder whose own checks passed it.
fn anew(
    gen: [u8; 16],
    k1: &IdentityKeyPair,
    alice: &IdentityKeyPair,
    n: u32,
    made: u64,
) -> SignedHeader {
    let t = now();
    genesis(
        gen,
        t - 60,
        k1,
        vec![
            keyholder(K1, k1, 1, t - 120),
            keyholder(ALICE, alice, n, made),
        ],
    )
}

/// The control: on the app's next run under an honest relay, the account's book still holds
/// Alice's counter 5, and a new start naming her old pair (counter 3) is refused (§4.4 rule 8
/// on a keyholder entry): the floor stays. It passes today, and shows the run reaches the rule.
#[test]
fn control_on_the_next_run_with_the_vault_handed_over_an_old_counter_is_refused() {
    let mut b = before();
    let (file, k1, g) = first_run(&mut b);
    let (mut s, events) = sign_in(&mut b.relay, b.dek, b.identity, b.memory.clone());
    assert!(gk_problems(&events).is_empty());
    let mut app = App::run(b.identity, Some(&file));
    assert_eq!(
        app.floor(),
        Some(g.d()),
        "the floor came back from the file"
    );
    app.push(
        &mut s,
        &anew([8; 16], &k1, &b.alice, 3, b.pinned - 30 * DAY),
    );
    assert_eq!(app.floor(), Some(g.d()), "refused: the floor stays");
}

/// F1, rule 8, on a device that keeps a local file (the desktop app, Android): the relay
/// leaves `item.gk_floors` out of the next sign-in, and the account's book holds no counter
/// for Alice. The counter 5 this device met in its first run is kept in its own file too, so
/// Alice's old pair (counter 3) is still refused (§6 hostile relay, Cannot: "Seat an
/// account's old seat keys again once a keyholder has seen its newer counter, or past a
/// writer that has seen it"). Her current pair (counter 5) is taken: the refusal is the
/// counter's.
#[test]
fn f1_on_a_device_with_a_local_file_a_withheld_gk_index_does_not_let_an_old_counter_past_its_checks(
) {
    let mut b = before();
    let (file, k1, g) = first_run(&mut b);
    b.relay.withholds_gk = true;
    let (mut s, events) = sign_in(&mut b.relay, b.dek, b.identity, b.memory.clone());
    assert_eq!(gk_problems(&events), ["missing"]);
    assert_eq!(
        s.seen(&ALICE),
        None,
        "the book holds no counter for Alice now"
    );
    let mut app = App::run(b.identity, Some(&file));
    assert_eq!(
        app.floor(),
        Some(g.d()),
        "the floor came back from the file"
    );
    let old = anew([8; 16], &k1, &b.alice, 3, b.pinned - 30 * DAY);
    app.push(&mut s, &old);
    assert_eq!(
        app.floor(),
        Some(g.d()),
        "a new start naming Alice's pair of counter 3 must be refused by a device that met \
         her counter 5 in its last run; it took it"
    );
    let current = anew([9; 16], &k1, &b.alice, 5, now() - 120);
    app.push(&mut s, &current);
    assert_eq!(
        app.floor(),
        Some(current.d()),
        "her pair of counter 5 is taken"
    );
}

/// A device that kept nothing of its own (THREAT-MODEL, accepted: a new install, a new
/// browser profile, cleared site data, a browser with storage off) has only the vault's pages
/// for Alice's counter, and with them withheld it takes her old pair. This is the limit the
/// docs state, kept here so a change to it is seen. A browser that kept its counters hands
/// them in at the next page (voipc-web gk.rs `reload_tests`).
#[test]
fn a_device_that_kept_nothing_has_only_the_vaults_counters_and_a_withheld_index_takes_them() {
    let mut b = before();
    let (_file, k1, _) = first_run(&mut b);
    b.relay.withholds_gk = true;
    let (mut s, _) = sign_in(&mut b.relay, b.dek, b.identity, LogMemory::default());
    let mut app = App::run(b.identity, None);
    let old = anew([8; 16], &k1, &b.alice, 3, b.pinned - 30 * DAY);
    app.push(&mut s, &old);
    assert_eq!(
        app.floor(),
        Some(old.d()),
        "taken: the device knows no counter of Alice's"
    );
}
