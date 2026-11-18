//! What the group key's C1 primitives cost (docs/GROUP-KEY.md §8), measured
//! instead of estimated: each operation's median and p95 time on one core,
//! its bytes, and the totals the §8 rows add up to at 100,000 seats.
//!
//! ```text
//! cargo run --release --locked -p voipc-crypto --example group_cost
//! ```
//!
//! Every value is made and opened through the crate's public API, so it pays
//! what the clients will: context strings, OS randomness, the low-order and
//! all-zero checks. A sample is one call, or the mean of a few back to back
//! where one call is under about 2 µs (the `n×k` column), so a p95 there is
//! of those means. Pin it to one core (`taskset -c 2 …`) for steady numbers.

use std::collections::HashMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use libsignal_protocol::{kem, IdentityKeyPair, KeyPair};
use voipc_crypto::group_key::*;
use zeroize::Zeroizing;

const GEN: [u8; 16] = [0x11; 16];
const T0: u64 = 1_800_000_000;
const GROUP_ID: &str = "c:0123456789abcdef0123456789abcdef";
/// 100,000 seats, 62 to a bucket version (§5.3).
const SEATS: u32 = 100_000;
const BUCKETS: usize = 1613;
/// A full re-seat: 391 Join commits of at most 256 (§8 "Re-seat time").
const JOINS: usize = 391;

// ── Timing ────────────────────────────────────────────────────────────────

struct Stat {
    name: String,
    median_ns: f64,
    p95_ns: f64,
    bytes: Option<usize>,
    samples: usize,
    batch: usize,
}

#[derive(Default)]
struct Bench {
    rows: Vec<Stat>,
}

impl Bench {
    /// Times `f`: a warm-up of at least 50 ms, then samples for about 0.4 s
    /// (15 at least). Returns the median in nanoseconds.
    fn run<T>(&mut self, name: &str, bytes: Option<usize>, mut f: impl FnMut() -> T) -> f64 {
        let start = Instant::now();
        let mut warm = 0u32;
        while start.elapsed() < Duration::from_millis(50) || warm < 3 {
            black_box(f());
            warm += 1;
        }
        let est = start.elapsed().as_nanos() as f64 / f64::from(warm);
        let batch = ((2_000.0 / est).ceil() as usize).max(1);
        let samples = ((400e6 / (est * batch as f64)) as usize).clamp(15, 3000);
        let mut times = Vec::with_capacity(samples);
        for _ in 0..samples {
            let t = Instant::now();
            for _ in 0..batch {
                black_box(f());
            }
            times.push(t.elapsed().as_nanos() as f64 / batch as f64);
        }
        times.sort_by(f64::total_cmp);
        let median = times[times.len() / 2];
        let p95 = times[((times.len() as f64 * 0.95) as usize).min(times.len() - 1)];
        self.rows.push(Stat {
            name: name.to_string(),
            median_ns: median,
            p95_ns: p95,
            bytes,
            samples,
            batch,
        });
        median
    }

    fn print(&self) {
        println!("| Operation | Median | p95 | Bytes | n×k |");
        println!("|---|---:|---:|---:|---:|");
        for r in &self.rows {
            println!(
                "| {} | {} | {} | {} | {}×{} |",
                r.name,
                time(r.median_ns),
                time(r.p95_ns),
                r.bytes.map(size).unwrap_or_default(),
                r.samples,
                r.batch
            );
        }
    }
}

fn time(ns: f64) -> String {
    if ns < 1e3 {
        format!("{ns:.0} ns")
    } else if ns < 1e6 {
        format!("{:.2} µs", ns / 1e3)
    } else if ns < 1e9 {
        format!("{:.2} ms", ns / 1e6)
    } else {
        format!("{:.2} s", ns / 1e9)
    }
}

fn size(b: usize) -> String {
    if b < 10_000 {
        format!("{b} B")
    } else if b < 10_000_000 {
        format!("{:.1} KB", b as f64 / 1e3)
    } else {
        format!("{:.1} MB", b as f64 / 1e6)
    }
}

// ── Parties ───────────────────────────────────────────────────────────────

/// A keyholder or a member: its id, its seat (or keyholder) pair, its identity.
struct Party {
    m: MemberId,
    pair: SeatPair,
    public: SeatPublic,
    ik: IdentityKeyPair,
}

impl Party {
    fn new(m: MemberId) -> Party {
        let pair = SeatPair::generate();
        Party {
            m,
            public: pair.public(),
            pair,
            ik: IdentityKeyPair::generate(&mut rand::rng()),
        }
    }

    fn me(&self) -> Me<'_> {
        Me {
            m: self.m,
            keys: &self.pair,
        }
    }

    fn them(&self) -> Them<'_> {
        Them {
            m: self.m,
            keys: &self.public,
        }
    }

    fn holder(&self) -> Holder {
        Holder::new(self.m, &self.public.dh_bytes()).expect("a holder")
    }

    fn seat(&self) -> SeatRef {
        self.public.seat(self.m)
    }

    fn ik_raw(&self) -> [u8; 32] {
        ik_raw(&self.ik)
    }

    fn entry(&self) -> Keyholder {
        Keyholder {
            m: self.m,
            u: None,
            origin: 0x03,
            n: 1,
            ik: self.ik_raw(),
            kx: self.public.dh_bytes()[1..].try_into().expect("32 bytes"),
            tag_kk: self.public.tag_kem(),
        }
    }
}

fn ik_raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key()
        .public_key_bytes()
        .try_into()
        .expect("32 bytes")
}

fn account(n: u64) -> MemberId {
    let mut a = [0xa0u8; 16];
    a[8..].copy_from_slice(&n.to_be_bytes());
    MemberId::Account(a)
}

fn random32() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(rand::random())
}

// ── Headers ───────────────────────────────────────────────────────────────

fn genesis(k: &Party, gated: bool) -> HeaderV1 {
    HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP_ID.to_string(),
        gen: GEN,
        epoch: 1,
        join: 0,
        kind: Kind::Genesis,
        time: T0,
        parent: [0; 32],
        epoch_parent: [0; 32],
        kh_parent: [0; 32],
        signer: k.m,
        keyholders: vec![k.entry()],
        gated,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 1,
        buckets: 1,
        conn_seats: 0,
        bucket_root: rand::random(),
        keyring_hash: rand::random(),
        names_hash: [0; 32],
        added: if gated {
            Added::List(vec![])
        } else {
            Added::Count(1)
        },
        removed: if gated {
            Removed::List(vec![])
        } else {
            Removed::Count(0)
        },
        confirm: rand::random(),
    }
}

/// One `added` entry: an account with a real identity key (a header refuses
/// one of low order) and the time of its endorsement.
fn added(m: MemberId, ik: [u8; 32]) -> AddedSeat {
    AddedSeat {
        m,
        ik,
        tag_sk: rand::random(),
        tag_sx: rand::random(),
        n: 3,
        made: T0 - 86_400,
    }
}

fn sorted(mut l: Vec<AddedSeat>) -> Vec<AddedSeat> {
    l.sort_by_key(|a| postcard::to_allocvec(a).expect("encodes"));
    l
}

/// Times a header's encode, digest, sign (with its sort and form check),
/// decode (rule 1) and signature check.
fn header_ops(b: &mut Bench, what: &str, h: &HeaderV1, by: &Party) -> SignedHeader {
    let signed = SignedHeader::sign(h.clone(), &by.ik).expect("a header in form");
    let body = signed.body().to_vec();
    let sig = signed.sig();
    let n = body.len() + 64;
    b.run(&format!("Header {what}: encode"), Some(body.len()), || {
        h.encode()
    });
    b.run(&format!("Header {what}: digest D"), None, || digest(&body));
    b.run(&format!("Header {what}: sign"), Some(n), || {
        SignedHeader::sign(h.clone(), &by.ik).expect("signs")
    });
    b.run(&format!("Header {what}: decode (rule 1)"), None, || {
        SignedHeader::decode(&body, &sig, GroupKind::Text, GROUP_ID).expect("decodes")
    });
    let ik = by.ik_raw();
    b.run(&format!("Header {what}: verify"), None, || {
        assert!(signed.verify(&ik))
    });
    signed
}

fn main() {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    println!("# group_cost: {cpu}, one core, release build\n");

    let mut b = Bench::default();
    let g = Group::new(GroupKind::Text, GROUP_ID, GEN).expect("a group");
    let kh = Party::new(account(1));
    let member = Party::new(account(2));
    let seed = random32();
    let (s, e) = (1u32, 2u32);
    let at = Version {
        b: rand::random(),
        v: rand::random(),
    };
    let bk = random32();
    let ck = random32();
    let krk = random32();
    let ks: [u8; 32] = rand::random();

    // ── Raw primitives (libsignal) ──
    let mut rng = voipc_crypto::rng();
    let kem_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let t_kem_gen = b.run("Kyber1024 key pair", None, || {
        kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng)
    });
    let (_, ct) = kem_pair.public_key.encapsulate(&mut rng).expect("encaps");
    let t_encaps = b.run("Kyber1024 encapsulate", Some(ct.len()), || {
        kem_pair.public_key.encapsulate(&mut rng).expect("encaps")
    });
    let t_decaps = b.run("Kyber1024 decapsulate", None, || {
        kem_pair.secret_key.decapsulate(&ct).expect("decaps")
    });
    let x_a = KeyPair::generate(&mut rng);
    let x_b = KeyPair::generate(&mut rng);
    b.run("X25519 key pair", None, || KeyPair::generate(&mut rng));
    let t_x25519 = b.run("X25519 agreement", None, || {
        x_a.private_key
            .calculate_agreement(&x_b.public_key)
            .expect("agrees")
    });
    let t_seat_pair = b.run("Seat pair (Kyber1024 + X25519, tags)", None, || {
        SeatPair::generate().public()
    });

    // ── Member secret, row base, row, seal, confirm, ratchet ──
    let seat = member.seat();
    let t_member_secret = b.run("member_secret s_m", None, || {
        member_secret(&g, s, &seed, &seat)
    });
    let s_m = member_secret(&g, s, &seed, &seat);
    let t_rb_k = b.run("RB, keyholder side (X25519 + HKDF)", None, || {
        RowBase::keyholder_side(&g, s, &kh.me(), &member.them(), &s_m).expect("RB")
    });
    let holder = kh.holder();
    let t_rb_m = b.run("RB, member side (X25519 + HKDF)", None, || {
        RowBase::member_side(&g, s, &member.me(), &holder, &s_m).expect("RB")
    });
    let rb_k = RowBase::keyholder_side(&g, s, &kh.me(), &member.them(), &s_m).expect("RB");
    let rb_m = RowBase::member_side(&g, s, &member.me(), &holder, &s_m).expect("RB");
    assert_eq!(rb_k.secret(), rb_m.secret(), "both ends agree on RB");
    let row = rb_k.row(at, &bk);
    let t_row = b.run("Row (kept RB: HKDF + AES-GCM)", Some(row.len()), || {
        rb_k.row(at, &bk)
    });
    let t_open_row = b.run("Row open", None, || rb_m.open_row(at, &row).expect("opens"));
    let ep_any = Epoch {
        e,
        d_e: rand::random(),
    };
    let sealed = seal(&g, &ep_any, at, &bk, &ck);
    let t_seal = b.run("Seal of CK_e", Some(sealed.len()), || {
        seal(&g, &ep_any, at, &bk, &ck)
    });
    b.run("Seal open", None, || {
        open_seal(&g, &ep_any, at, &bk, &sealed).expect("opens")
    });
    let named = confirm(&g, e, 0, &ck);
    b.run("confirm, checked", None, || {
        assert!(confirm_ok(&g, e, 0, &ck, &named))
    });
    let t_ratchet = b.run("Ratchet BK (promotion)", None, || {
        ratchet(&g, e, at, 7, &bk)
    });

    // ── Welcomes ──
    let w = seat_welcome(&g, s, at, &kh.me(), &member.them(), &s_m, &bk).expect("welcome");
    let t_seat_w = b.run("Seat welcome: make", Some(w.len()), || {
        seat_welcome(&g, s, at, &kh.me(), &member.them(), &s_m, &bk).expect("welcome")
    });
    let t_seat_w_open = b.run("Seat welcome: open", None, || {
        open_seat_welcome(&g, s, at, &member.me(), &holder, &w).expect("opens")
    });
    let w = seed_welcome(&g, s, &kh.me(), &member.them(), &s_m).expect("welcome");
    let t_seed_w = b.run("Seed welcome: make", Some(w.len()), || {
        seed_welcome(&g, s, &kh.me(), &member.them(), &s_m).expect("welcome")
    });
    let t_seed_w_open = b.run("Seed welcome: open", None, || {
        open_seed_welcome(&g, s, &member.me(), &holder, &w).expect("opens")
    });
    let other_kh = Party::new(account(3));
    let w = keyring_welcome(&g, s, e, &ks, &kh.me(), &other_kh.them(), &krk).expect("welcome");
    let t_ring_w = b.run("Keyring welcome: make", Some(w.len()), || {
        keyring_welcome(&g, s, e, &ks, &kh.me(), &other_kh.them(), &krk).expect("welcome")
    });
    b.run("Keyring welcome: open", None, || {
        open_keyring_welcome(&g, s, e, &ks, &other_kh.me(), &holder, &w).expect("opens")
    });

    // ── Keyring at B = 1613, bucket root, inclusion path ──
    let mut ids: Vec<u64> = (0..BUCKETS).map(|_| rand::random()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), BUCKETS);
    let buckets: Vec<KeyringBucket> = ids
        .iter()
        .enumerate()
        .map(|(i, &id)| KeyringBucket {
            b: id,
            v: rand::random(),
            pool: Pool::Accounts,
            // 1612 full versions and one of 56: 100,000 seats.
            seats: if i + 1 == BUCKETS {
                (SEATS - 62 * (BUCKETS as u32 - 1)) as u16
            } else {
                BUCKET_SEATS
            },
            list: rand::random(),
            via: Via::Row,
            bk: random32(),
            made: T0 + i as u64,
        })
        .collect();
    let leaves: Vec<Leaf> = buckets.iter().map(KeyringBucket::leaf).collect();
    let root = bucket_root(&leaves).expect("ordered");
    let t_root = b.run("Bucket root over 1613 leaves", None, || {
        bucket_root(&leaves).expect("ordered")
    });
    let mine = 777;
    let path = inclusion_path(&leaves, mine).expect("a path");
    let path_bytes =
        leaves[mine].encode().len() + postcard::to_allocvec(&path).expect("encodes").len();
    b.run("Inclusion path, made (relay)", Some(path_bytes), || {
        inclusion_path(&leaves, mine).expect("a path")
    });
    b.run("Inclusion path, checked", None, || {
        assert!(path_ok(&root, BUCKETS as u32, &leaves[mine], &path))
    });

    let gen = SignedHeader::sign(genesis(&kh, false), &kh.ik).expect("a genesis");
    let ks_real = keyholder_set_digest(&gen.header().keyholders);
    let base = KeyringBase {
        gen: GEN,
        epoch: e,
        join: 0,
        seeds: vec![(1, seed.clone())],
        ck: ck.clone(),
        exits_upto: 123_456,
        buckets: buckets.clone(),
    };
    let base_plain = postcard::to_allocvec(&base).expect("encodes").len();
    let base_sealed = seal_base(&g, s, &ks_real, &krk, &base);
    let t_base_seal = b.run("Keyring base (1613): seal", Some(base_sealed.len()), || {
        seal_base(&g, s, &ks_real, &krk, &base)
    });
    b.run("Keyring base (1613): open", Some(base_plain), || {
        open_keyring_part(&g, e, s, &ks_real, &krk, KeyringPart::Base, &base_sealed).expect("opens")
    });
    let delta = KeyringDelta {
        join: 1,
        buckets: vec![buckets[5].clone()],
    };
    let t_delta = b.run(
        "Keyring delta, one new bucket: seal",
        Some(seal_delta(&g, e, s, &ks_real, &krk, &delta).len()),
        || seal_delta(&g, e, s, &ks_real, &krk, &delta),
    );
    b.run("Keyring hash, one step", None, || {
        keyring_hash_start(&base_sealed)
    });

    // ── Headers ──
    // An opening header at 100k in an open group, the one the keyring and
    // the reader below are checked against.
    let mut fresh = HeaderV1 {
        epoch: e,
        kind: Kind::Fresh,
        time: T0 + 3600,
        parent: gen.d(),
        kh_parent: gen.kh(),
        keyholders: vec![],
        exits_upto: 123_456,
        seats: SEATS,
        buckets: BUCKETS as u32,
        bucket_root: root,
        keyring_hash: keyring_hash_start(&base_sealed),
        added: Added::Count(0),
        removed: Removed::Count(37),
        confirm: confirm(&g, e, 0, &ck),
        ..gen.header().clone()
    };
    fresh.canonicalize();
    let head = header_ops(&mut b, "Fresh, open group", &fresh, &kh);
    let t_header_sign = b
        .rows
        .iter()
        .find(|r| r.name == "Header Fresh, open group: sign")
        .map(|r| r.median_ns)
        .unwrap_or_default();
    let t_take = b.run("Keyring base (1613): take under its head", None, || {
        take_keyring(&g, &head, &gen, &krk, &base_sealed, &[]).expect("taken")
    });

    let holders: Vec<Party> = (10..18).map(|i| Party::new(account(i))).collect();
    let add = HeaderV1 {
        epoch: e + 1,
        kind: Kind::KeyholdersAdd,
        parent: head.d(),
        keyholders: holders.iter().map(Party::entry).collect(),
        ..fresh.clone()
    };
    header_ops(&mut b, "KeyholdersAdd, 8 keyholders", &add, &kh);

    let iks: Vec<IdentityKeyPair> = (0..256)
        .map(|_| IdentityKeyPair::generate(&mut rand::rng()))
        .collect();
    let names: Vec<AddedSeat> = sorted(
        (0..256u64)
            .map(|i| added(account(1000 + i), ik_raw(&iks[i as usize])))
            .collect(),
    );
    let entry_bytes = postcard::to_allocvec(&names[0]).expect("encodes").len();
    let removed_bytes = postcard::to_allocvec(&names[0].seat())
        .expect("encodes")
        .len();
    let mut gated_gen = genesis(&kh, true);
    gated_gen.names_hash = names_hash(None, &gated_gen);
    let gated_gen = SignedHeader::sign(gated_gen, &kh.ik).expect("a genesis");
    let mut join = HeaderV1 {
        join: 1,
        kind: Kind::Join,
        time: T0 + 2,
        parent: gated_gen.d(),
        epoch_parent: gated_gen.d_e(),
        kh_parent: gated_gen.kh(),
        keyholders: vec![],
        seats: 257,
        buckets: 5,
        added: Added::List(names.clone()),
        ..gated_gen.header().clone()
    };
    join.names_hash = names_hash(Some(gated_gen.header()), &join);
    let join = header_ops(&mut b, "Join, gated, 256 added", &join, &kh);

    // ── Names fold (§4.4 rule 4): a writer's check before it posts ──
    let pins: HashMap<[u8; 16], [u8; 32]> = names
        .iter()
        .map(|a| (a.m.account().expect("an account"), a.ik))
        .collect();
    let pins_at = |a: &[u8; 16], _t: u64| match pins.get(a) {
        Some(ik) => PinThen::Pin(*ik),
        None => PinThen::None,
    };
    let no_counters = |_: &[u8; 16]| -> Option<Seen> { None };
    let known = Known {
        pins: &pins_at,
        counters: &no_counters,
        own: None,
        now: T0 + 60,
    };
    let floor = NamesFrom::Floor(NamesFloor::of(gated_gen.header()));
    let one = [NamesList::of(join.header())];
    b.run("Names fold, 1 list of 256", Some(256 * entry_bytes), || {
        let fold = fold_names(&floor, &one, &[], join.header(), &known).expect("folds");
        assert!(matches!(fold, Fold::Take { .. }));
    });
    b.run("names_list_digest, 256", None, || names_list_digest(&names));

    // Every name since the Genesis after a full re-seat: 391 lists, 100k names.
    let mut lists = Vec::with_capacity(JOINS);
    let mut acc = gated_gen.header().names_hash;
    let mut big_pins = HashMap::new();
    for j in 0..JOINS {
        let n = if j + 1 == JOINS {
            SEATS as usize - 256 * (JOINS - 1)
        } else {
            256
        };
        let l: Vec<AddedSeat> = (0..n)
            .map(|i| {
                let m = account(10_000 + (j * 256 + i) as u64);
                let ik = ik_raw(&iks[i]);
                big_pins.insert(m.account().expect("an account"), ik);
                added(m, ik)
            })
            .collect();
        let list = NamesList {
            time: T0 + 2 * (j as u64 + 1),
            epoch: 1,
            join: j as u32 + 1,
            added: sorted(l),
        };
        acc = names_step(&acc, &list);
        lists.push(list);
    }
    let big_head = HeaderV1 {
        join: JOINS as u32,
        time: T0 + 2 * JOINS as u64,
        names_hash: acc,
        ..join.header().clone()
    };
    let big_pins_at = |a: &[u8; 16], _t: u64| match big_pins.get(a) {
        Some(ik) => PinThen::Pin(*ik),
        None => PinThen::None,
    };
    let big_known = Known {
        pins: &big_pins_at,
        now: T0 + 2 * JOINS as u64 + 60,
        ..known
    };
    let t_fold_all = b.run(
        "Names fold, 391 lists, 100k names",
        Some(SEATS as usize * entry_bytes),
        || {
            let fold = fold_names(&floor, &lists, &[], &big_head, &big_known).expect("folds");
            assert!(matches!(fold, Fold::Take { .. }));
        },
    );

    // ── A reader's epoch: the header, its leaf and path, its seal ──
    let ep = Epoch { e, d_e: head.d_e() };
    let my = buckets[mine].clone();
    let my_seal = seal(&g, &ep, my.version(), &my.bk, &ck);
    let body = head.body().to_vec();
    let sig = head.sig();
    let kh_ik = kh.ik_raw();
    let read_bytes = body.len() + 64 + path_bytes + my_seal.len();
    let t_read_core = b.run("Reader epoch: seal open + confirm + path", None, || {
        assert!(path_ok(
            &head.header().bucket_root,
            BUCKETS as u32,
            &my.leaf(),
            &path
        ));
        let ck = open_seal(&g, &ep, my.version(), &my.bk, &my_seal).expect("opens");
        assert!(confirm_ok(&g, e, 0, &ck, &head.header().confirm));
    });
    let t_read = b.run(
        "Reader epoch: + header decode and verify",
        Some(read_bytes),
        || {
            let h = SignedHeader::decode(&body, &sig, GroupKind::Text, GROUP_ID).expect("decodes");
            assert!(h.verify(&kh_ik));
            let hd = h.header();
            assert!(path_ok(&hd.bucket_root, hd.buckets, &my.leaf(), &path));
            let ep = Epoch {
                e: hd.epoch,
                d_e: h.d_e(),
            };
            let ck = open_seal(&g, &ep, my.version(), &my.bk, &my_seal).expect("opens");
            assert!(confirm_ok(&g, hd.epoch, hd.join, &ck, &hd.confirm));
        },
    );

    b.print();

    // ── What the §8 rows add up to at 100k (one core, from the medians) ──
    let n = f64::from(SEATS);
    let header_bytes = head.body().len() + 64;
    let seals_epoch = BUCKETS as f64 * t_seal + t_base_seal + t_root + t_header_sign;
    let seals_bytes = BUCKETS * ROW_BYTES + base_sealed.len() + header_bytes;
    let totals: Vec<(String, f64, Option<usize>)> = vec![
        ("100k X25519 agreements".into(), n * t_x25519, None),
        ("100k RB, keyholder side".into(), n * t_rb_k, None),
        (
            "100k RB, member side (one each, 8 keyholders: ×8 per member)".into(),
            n * t_rb_m,
            None,
        ),
        ("100k Kyber1024 encapsulations".into(), n * t_encaps, None),
        (
            "100k Kyber1024 decapsulations (one per member)".into(),
            n * t_decaps,
            None,
        ),
        (
            "Seed roll: 100k seed welcomes, made".into(),
            n * (t_member_secret + t_seed_w),
            Some(SEATS as usize * SMALL_WELCOME_BYTES),
        ),
        (
            "Seed roll, voice room: 250 seed welcomes".into(),
            250.0 * (t_member_secret + t_seed_w),
            Some(250 * SMALL_WELCOME_BYTES),
        ),
        (
            "Opening commit without rows: 1613 seals + keyring base + root + header".into(),
            seals_epoch,
            Some(seals_bytes),
        ),
        (
            "Exit batch of 1 (61 rows, kept RB)".into(),
            seals_epoch + 61.0 * t_row,
            Some(seals_bytes + 61 * ROW_BYTES),
        ),
        (
            "Exit batch of 100 (6100 rows, kept RB)".into(),
            seals_epoch + 6100.0 * t_row,
            Some(seals_bytes + 6100 * ROW_BYTES),
        ),
        (
            "Refresh: seals + base + one twelfth re-keyed (8.4k rows)".into(),
            seals_epoch + 8400.0 * t_row,
            Some(seals_bytes + 8400 * ROW_BYTES),
        ),
        (
            "Full re-key by rows, RB kept: 100k rows + opening commit".into(),
            seals_epoch + n * t_row,
            Some(seals_bytes + SEATS as usize * ROW_BYTES),
        ),
        (
            "Full re-key by rows, RB cold (new keyholder): + 100k RB".into(),
            seals_epoch + n * (t_row + t_rb_k),
            Some(seals_bytes + SEATS as usize * ROW_BYTES),
        ),
        (
            "Promotion: 1613 ratchets + opening commit + 8 keyring welcomes".into(),
            BUCKETS as f64 * t_ratchet + seals_epoch + 8.0 * t_ring_w,
            Some(seals_bytes + 8 * SMALL_WELCOME_BYTES),
        ),
        (
            "Join commit of 256 (s_m + seat welcome each, delta, header)".into(),
            256.0 * (t_member_secret + t_seat_w) + 5.0 * t_delta + t_header_sign,
            Some(256 * SEAT_WELCOME_BYTES + header_bytes),
        ),
        (
            "100k re-seat: 391 Join commits of 256".into(),
            (JOINS as f64) * (256.0 * (t_member_secret + t_seat_w) + 5.0 * t_delta + t_header_sign),
            Some(SEATS as usize * SEAT_WELCOME_BYTES + JOINS * header_bytes),
        ),
        ("Keyholder takes the keyring at 100k".into(), t_take, None),
        (
            "Member: first seat (open seat welcome + RB per keyholder, 1 keyholder)".into(),
            t_seat_w_open + t_rb_m,
            None,
        ),
        (
            "Member: seed roll (open seed welcome + RB for 8 keyholders)".into(),
            t_seed_w_open + 8.0 * t_rb_m,
            None,
        ),
        (
            "Member: one epoch read (decode, verify, path, seal, confirm)".into(),
            t_read,
            Some(read_bytes),
        ),
        (
            "Member: one epoch read whose bucket was re-keyed (+ row open)".into(),
            t_read + t_open_row,
            Some(read_bytes + ROW_BYTES),
        ),
        (
            "Writer: names fold after a 100k re-seat".into(),
            t_fold_all,
            Some(SEATS as usize * entry_bytes),
        ),
        (
            "Account rotates its seat keys (one new seat pair)".into(),
            t_seat_pair,
            None,
        ),
        (
            "10k X25519 (the 10,000-seat browser limit), native".into(),
            1e4 * t_x25519,
            None,
        ),
    ];
    println!("\n## Totals at 100k (one core, medians)\n");
    println!("| Event | CPU | Bytes |");
    println!("|---|---:|---:|");
    for (what, ns, bytes) in &totals {
        println!(
            "| {what} | {} | {} |",
            time(*ns),
            bytes.map(size).unwrap_or_default()
        );
    }
    println!(
        "\nSizes: added entry {entry_bytes} B, removed entry {removed_bytes} B, leaf + path {path_bytes} B, \
         keyring base {} B sealed ({:.1} B per version), delta {} B, Fresh header {header_bytes} B \
         with its signature, Kyber1024 key pair {} ms, reader core {}.",
        base_sealed.len(),
        base_plain as f64 / BUCKETS as f64,
        seal_delta(&g, e, s, &ks_real, &krk, &delta).len(),
        t_kem_gen / 1e6,
        time(t_read_core),
    );
}
