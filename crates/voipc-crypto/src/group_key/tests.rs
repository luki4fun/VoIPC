//! The §10 "Unit" list of docs/GROUP-KEY.md: each item has at least one test
//! here (the known answers are in `kat`). Fixtures are drawn fresh; what
//! matters is which keys open what, never their values.

use libsignal_protocol::{IdentityKeyPair, KeyPair, SenderKeyDistributionMessage};
use sha2::Digest as _;
use zeroize::Zeroizing;

use super::ctx::*;
use super::header::digest;
use super::keys::{s_canonical, sign};
use super::rules::Clock;
use super::*;

const GEN: [u8; 16] = [0x11; 16];
const T0: u64 = 1_800_000_000;

fn text() -> Group {
    Group::new(GroupKind::Text, "c:lounge-1", GEN).unwrap()
}

fn voice() -> Group {
    Group::new(
        GroupKind::Voice,
        "r:00112233445566778899aabbccddeeff:7",
        GEN,
    )
    .unwrap()
}

fn key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crate::aead::random())
}

fn acct(b: u8) -> MemberId {
    MemberId::Account([b; 16])
}

/// A member, or a keyholder: its id, its seat (or keyholder) pair, its identity.
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
            ik: IdentityKeyPair::generate(&mut crate::rng()),
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
        Holder::new(self.m, &self.public.dh_bytes()).unwrap()
    }

    fn seat(&self) -> SeatRef {
        self.public.seat(self.m)
    }

    fn ik_raw(&self) -> [u8; 32] {
        self.ik.public_key().public_key_bytes().try_into().unwrap()
    }

    fn entry(&self) -> Keyholder {
        Keyholder {
            m: self.m,
            u: None,
            origin: if self.m.is_conn() { 0x02 } else { 0x03 },
            n: 0,
            ik: self.ik_raw(),
            kx: self.public.dh_bytes()[1..].try_into().unwrap(),
            tag_kk: self.public.tag_kem(),
        }
    }

    fn added(&self, n: u32) -> AddedSeat {
        AddedSeat {
            m: self.m,
            ik: self.ik_raw(),
            tag_sk: self.public.tag_kem(),
            tag_sx: self.public.tag_dh(),
            n,
            made: T0,
        }
    }
}

/// The same account and identity with a new pair: what a desktop keyholder
/// holds after its account's seat-key rotation (§5.11).
fn rotated(p: &Party) -> Party {
    Party {
        ik: IdentityKeyPair::new(*p.ik.identity_key(), *p.ik.private_key()),
        ..Party::new(p.m)
    }
}

const NO_PINS: &dyn Fn(&[u8; 16]) -> Option<[u8; 32]> = &|_| None;

fn clock(now: u64) -> Clock {
    Clock { now, taken: None }
}

const V1: Version = Version { b: 1, v: 10 };
const V2: Version = Version { b: 2, v: 20 };

// ── Headers to test the rules on ──────────────────────────────────────────

fn genesis_of(k: &Party, group: &Group, time: u64, gated: bool) -> HeaderV1 {
    HeaderV1 {
        group_kind: group.kind(),
        group: group.id().to_string(),
        gen: group.gen(),
        epoch: 1,
        join: 0,
        kind: Kind::Genesis,
        time,
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
        bucket_root: [1; 32],
        keyring_hash: [2; 32],
        names_hash: [0; 32],
        added: if gated {
            Added::List(vec![k.added(0)])
        } else {
            Added::Count(1)
        },
        removed: if gated {
            Removed::List(vec![])
        } else {
            Removed::Count(0)
        },
        confirm: [3; 32],
    }
}

/// The next header after `p` of `kind`, every chain field following from it.
fn next(p: &SignedHeader, kind: Kind, time: u64) -> HeaderV1 {
    let ph = p.header();
    let opening = kind.opens_epoch();
    HeaderV1 {
        epoch: if opening { ph.epoch + 1 } else { ph.epoch },
        join: if opening { 0 } else { ph.join + 1 },
        kind,
        time,
        parent: p.d(),
        epoch_parent: if opening { [0; 32] } else { p.d_e() },
        kh_parent: p.kh(),
        keyholders: vec![],
        seed: match kind {
            Kind::Regenesis | Kind::KeyholdersRemove => ph.seed + 1,
            _ => ph.seed,
        },
        seed_floor: match kind {
            Kind::Regenesis => ph.seed + 1,
            _ => ph.seed_floor,
        },
        added: if ph.gated {
            Added::List(vec![])
        } else {
            Added::Count(0)
        },
        removed: if ph.gated {
            Removed::List(vec![])
        } else {
            Removed::Count(0)
        },
        ..ph.clone()
    }
}

/// Signs `h` after setting its `names_hash` from `parent`.
fn signed(parent: Option<&SignedHeader>, mut h: HeaderV1, by: &Party) -> SignedHeader {
    h.canonicalize();
    h.names_hash = names_hash(parent.map(|p| p.header()), &h);
    SignedHeader::sign(h, &by.ik).unwrap()
}

/// A body and signature made by hand, past `SignedHeader::sign`'s checks.
fn raw_signed(h: &HeaderV1, by: &Party) -> (Vec<u8>, [u8; 64]) {
    let body = h.encode();
    let d = digest(&body);
    let msg = [&b"voipc-gk/v1/header-sig|"[..], &d].concat();
    (body, sign(by.ik.private_key(), &msg))
}

fn decode(body: &[u8], sig: &[u8]) -> Result<SignedHeader, Refusal> {
    SignedHeader::decode(body, sig, GroupKind::Text, "c:lounge-1")
}

// ── Every value opens only in its own context ─────────────────────────────

#[test]
fn a_seat_welcome_opens_for_its_recipient_and_its_context_only() {
    let (g, k, m, other) = (
        text(),
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let (s_m, bk) = (key(), key());
    let w = seat_welcome(&g, 1, V1, &k.me(), &m.them(), &s_m, &bk).unwrap();
    assert_eq!(w.len(), SEAT_WELCOME_BYTES);
    assert_eq!(w.len(), 1694);
    let (got_s, got_bk) = open_seat_welcome(&g, 1, V1, &m.me(), &k.holder(), &w).unwrap();
    assert_eq!((*got_s, *got_bk), (*s_m, *bk));
    let refused = |r: Result<_, GkError>, why: &str| assert!(r.is_err(), "{why}");
    refused(
        open_seat_welcome(&g, 1, V1, &other.me(), &k.holder(), &w),
        "another seat",
    );
    refused(
        open_seat_welcome(&g, 1, V2, &m.me(), &k.holder(), &w),
        "another version",
    );
    refused(
        open_seat_welcome(&g, 1, Version { b: 1, v: 11 }, &m.me(), &k.holder(), &w),
        "another version id",
    );
    refused(
        open_seat_welcome(&g, 2, V1, &m.me(), &k.holder(), &w),
        "another seed",
    );
    refused(
        open_seat_welcome(&voice_named_alike(), 1, V1, &m.me(), &k.holder(), &w),
        "a voice group",
    );
    refused(
        open_seat_welcome(
            &Group::new(GroupKind::Text, "c:lounge-1", [0x12; 16]).unwrap(),
            1,
            V1,
            &m.me(),
            &k.holder(),
            &w,
        ),
        "another generation",
    );
    refused(
        open_seat_welcome(
            &Group::new(GroupKind::Text, "c:lounge-2", GEN).unwrap(),
            1,
            V1,
            &m.me(),
            &k.holder(),
            &w,
        ),
        "another group",
    );
    let same_keys_other_name = Holder::new(acct(9), &k.public.dh_bytes()).unwrap();
    refused(
        open_seat_welcome(&g, 1, V1, &m.me(), &same_keys_other_name, &w),
        "from another keyholder id",
    );
    let m_as_other = Me {
        m: acct(4),
        keys: &m.pair,
    };
    refused(
        open_seat_welcome(&g, 1, V1, &m_as_other, &k.holder(), &w),
        "to another member id",
    );
}

/// A text group and a voice group under one id never share a key (§2).
fn voice_named_alike() -> Group {
    Group::new(GroupKind::Voice, "c:lounge-1", GEN).unwrap()
}

#[test]
fn a_seed_welcome_opens_for_its_recipient_and_its_context_only() {
    let (g, k, m, other) = (
        text(),
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let s_m = key();
    let w = seed_welcome(&g, 2, &k.me(), &m.them(), &s_m).unwrap();
    assert_eq!(w.len(), SMALL_WELCOME_BYTES);
    assert_eq!(w.len(), 1662);
    assert_eq!(
        *open_seed_welcome(&g, 2, &m.me(), &k.holder(), &w).unwrap(),
        *s_m
    );
    assert!(open_seed_welcome(&g, 2, &other.me(), &k.holder(), &w).is_err());
    assert!(open_seed_welcome(&g, 3, &m.me(), &k.holder(), &w).is_err());
    assert!(open_seed_welcome(&voice_named_alike(), 2, &m.me(), &k.holder(), &w).is_err());
}

#[test]
fn a_keyring_welcome_opens_for_its_keyholder_and_its_context_only() {
    let (g, k, k2) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let (krk, ks) = (key(), [5u8; 32]);
    let w = keyring_welcome(&g, 1, 4, &ks, &k.me(), &k2.them(), &krk).unwrap();
    assert_eq!(w.len(), 1662);
    assert_eq!(
        *open_keyring_welcome(&g, 1, 4, &ks, &k2.me(), &k.holder(), &w).unwrap(),
        *krk
    );
    assert!(
        open_keyring_welcome(&g, 1, 5, &ks, &k2.me(), &k.holder(), &w).is_err(),
        "epoch"
    );
    assert!(
        open_keyring_welcome(&g, 2, 4, &ks, &k2.me(), &k.holder(), &w).is_err(),
        "seed"
    );
    assert!(
        open_keyring_welcome(&g, 1, 4, &[6; 32], &k2.me(), &k.holder(), &w).is_err(),
        "another keyholder set"
    );
    assert!(open_keyring_welcome(&g, 1, 4, &ks, &k.me(), &k.holder(), &w).is_err());
}

#[test]
fn a_row_opens_for_its_seat_from_its_keyholder_and_its_context_only() {
    let (g, k, m) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let s_m = member_secret(&g, 1, &[7; 32], &m.seat());
    let at_k = RowBase::keyholder_side(&g, 1, &k.me(), &m.them(), &s_m).unwrap();
    let at_m = RowBase::member_side(&g, 1, &m.me(), &k.holder(), &s_m).unwrap();
    assert_eq!(
        at_k.secret(),
        at_m.secret(),
        "both ends make the same row base"
    );
    let bk = key();
    let row = at_k.row(V1, &bk);
    assert_eq!(row.len(), ROW_BYTES);
    assert_eq!(*at_m.open_row(V1, &row).unwrap(), *bk);
    assert!(at_m.open_row(V2, &row).is_err(), "another version");
    // Another keyholder holding the same seed, and so the same s_m: no DH, no row.
    let k2 = Party::new(acct(3));
    let from_k2 = RowBase::member_side(&g, 1, &m.me(), &k2.holder(), &s_m).unwrap();
    assert!(
        from_k2.open_row(V1, &row).is_err(),
        "made by another keyholder"
    );
    let k2_side = RowBase::keyholder_side(&g, 1, &k2.me(), &m.them(), &s_m).unwrap();
    assert!(k2_side.open_row(V1, &row).is_err());
    // Another seat of one account: another s_m and another SX.
    let m2 = Party::new(acct(2));
    let s_m2 = member_secret(&g, 1, &[7; 32], &m2.seat());
    assert_ne!(*s_m, *s_m2, "s_m names the seat's tags");
    let at_m2 = RowBase::member_side(&g, 1, &m2.me(), &k.holder(), &s_m2).unwrap();
    assert!(at_m2.open_row(V1, &row).is_err());
    let voice_base =
        RowBase::member_side(&voice_named_alike(), 1, &m.me(), &k.holder(), &s_m).unwrap();
    assert!(voice_base.open_row(V1, &row).is_err(), "a voice group");
    let kept = RowBase::from_secret(&g, 1, m.m, k.holder().id(), at_m.secret());
    assert!(
        kept.open_row(V1, &row).is_ok(),
        "the row base a history row keeps"
    );
    assert_eq!(kept.key(), at_m.key(), "kept under the same key");
    let elsewhere = HolderId {
        m: acct(9),
        ..k.holder().id()
    };
    assert!(
        RowBase::from_secret(&g, 1, m.m, elsewhere, at_m.secret())
            .open_row(V1, &row)
            .is_err(),
        "names its keyholder"
    );
}

#[test]
fn a_seal_opens_with_its_bucket_key_and_its_header_only() {
    let g = text();
    let (bk, ck) = (key(), key());
    let ep = Epoch { e: 3, d_e: [4; 32] };
    let s = seal(&g, &ep, V1, &bk, &ck);
    assert_eq!(s.len(), 60);
    assert_eq!(*open_seal(&g, &ep, V1, &bk, &s).unwrap(), *ck);
    assert!(
        open_seal(&g, &Epoch { e: 4, ..ep }, V1, &bk, &s).is_err(),
        "epoch"
    );
    assert!(
        open_seal(&g, &Epoch { d_e: [5; 32], ..ep }, V1, &bk, &s).is_err(),
        "another opening header of the same epoch"
    );
    assert!(open_seal(&g, &ep, V2, &bk, &s).is_err(), "version");
    assert!(open_seal(&g, &ep, V1, &key(), &s).is_err(), "bucket key");
    assert!(open_seal(&voice_named_alike(), &ep, V1, &bk, &s).is_err());
    let zero = seal(&g, &ep, V1, &bk, &[0; 32]);
    assert_eq!(
        open_seal(&g, &ep, V1, &bk, &zero).err(),
        Some(GkError::WeakKey)
    );
}

#[test]
fn a_chain_seal_opens_in_its_context_only() {
    let (g, ck, state) = (text(), key(), key());
    let ep = Epoch { e: 2, d_e: [9; 32] };
    let owner = acct(1);
    let s = chain_seal(&g, &ep, &owner, 5, 1, &ck, &state).unwrap();
    assert_eq!(
        *open_chain_seal(&g, &ep, &owner, 5, 1, &ck, &s).unwrap(),
        *state
    );
    for (e, o, c, i) in [
        (3, owner, 5, 1),
        (2, acct(2), 5, 1),
        (2, owner, 6, 1),
        (2, owner, 5, 0),
    ] {
        assert!(
            open_chain_seal(&g, &Epoch { e, ..ep }, &o, c, i, &ck, &s).is_err(),
            "{e} {o:?} {c} {i}"
        );
    }
    assert!(open_chain_seal(&g, &Epoch { d_e: [8; 32], ..ep }, &owner, 5, 1, &ck, &s).is_err());
    assert_eq!(
        chain_seal(&voice(), &ep, &owner, 5, 1, &ck, &state).err(),
        Some(GkError::Malformed),
        "kept history is text only"
    );
}

#[test]
fn a_self_row_opens_for_the_accounts_devices_and_its_context_only() {
    let g = text();
    let keys = SeatKeys::generate(1, T0);
    let seat = keys.pair.public().seat(acct(1));
    let s_m = key();
    let row = self_row(&g, 1, &seat, keys.self_key(), &s_m);
    let other_device = SeatKeys::from_bytes(&keys.to_bytes()).unwrap();
    assert_eq!(
        *open_self_row(&g, 1, &seat, other_device.self_key(), &row).unwrap(),
        *s_m
    );
    assert!(
        open_self_row(&g, 2, &seat, keys.self_key(), &row).is_err(),
        "seed"
    );
    let rotated = SeatKeys::generate(1, T0).rotate(T0).unwrap();
    assert!(
        open_self_row(&g, 1, &seat, rotated.self_key(), &row).is_err(),
        "self key"
    );
    let new_seat = rotated.pair.public().seat(acct(1));
    assert!(
        open_self_row(&g, 1, &new_seat, keys.self_key(), &row).is_err(),
        "seat"
    );
    let hist = history_row(&g, 1, &seat, keys.self_key(), &[]);
    assert!(
        open_self_row(&g, 1, &seat, keys.self_key(), &hist).is_err(),
        "a history row is no self-row"
    );
}

#[test]
fn a_history_row_keeps_the_row_bases_sorted_and_opens_in_its_context_only() {
    let g = text();
    let keys = SeatKeys::generate(1, T0);
    let seat = keys.pair.public().seat(acct(1));
    let entry = |m: MemberId, t: u8, rb: u8| HistoryEntry {
        k: HolderId { m, tag_kx: [t; 8] },
        rb: Zeroizing::new([rb; 32]),
    };
    let (a, b) = (entry(acct(3), 1, 7), entry(MemberId::Conn(2), 1, 8));
    let row = history_row(
        &g,
        1,
        &seat,
        keys.self_key(),
        &[b.clone(), a.clone(), a.clone()],
    );
    let back = open_history_row(&g, 1, &seat, keys.self_key(), &row).unwrap();
    assert_eq!(back, [a, b], "sorted by encoding, each once");
    assert!(open_history_row(&g, 2, &seat, keys.self_key(), &row).is_err());
    let s_row = self_row(&g, 1, &seat, keys.self_key(), &key());
    assert!(open_history_row(&g, 1, &seat, keys.self_key(), &s_row).is_err());
}

#[test]
fn a_blob_opens_for_its_writer_and_its_epoch_only() {
    let g = text();
    let ck = key();
    let ep = Epoch { e: 2, d_e: [6; 32] };
    let w = Writer { m: acct(1), u: 42 };
    let ik = IdentityKeyPair::generate(&mut crate::rng());
    let skdm = skdm_for(&g, &ep);
    let blob = writer_blob(&g, &ep, &w, &ck, &ik, &skdm).unwrap();
    let opened = open_writer_blob(&g, &ep, &w, &ck, &blob).unwrap();
    assert_eq!(&opened.skdm[..], &skdm[..]);
    assert_eq!(opened.ik, *ik.identity_key());
    let other_device = Writer { m: acct(1), u: 43 };
    assert!(
        open_writer_blob(&g, &ep, &other_device, &ck, &blob).is_err(),
        "another sender"
    );
    assert!(open_writer_blob(&g, &Epoch { e: 3, ..ep }, &w, &ck, &blob).is_err());
    assert!(open_writer_blob(&g, &Epoch { d_e: [7; 32], ..ep }, &w, &ck, &blob).is_err());
    assert!(open_writer_blob(&g, &ep, &w, &key(), &blob).is_err());
    assert_eq!(
        writer_blob(&g, &Epoch { e: 3, ..ep }, &w, &ck, &ik, &skdm).err(),
        Some(GkError::Malformed),
        "an SKDM filed under another epoch"
    );
}

fn skdm_for(g: &Group, ep: &Epoch) -> Vec<u8> {
    let signing = KeyPair::generate(&mut crate::rng()).public_key;
    SenderKeyDistributionMessage::new(3, dist(g, ep), 7, 0, vec![9; 32], signing)
        .unwrap()
        .serialized()
        .to_vec()
}

#[test]
fn media_keys_differ_by_sender_seat_stream_epoch_and_header() {
    let g = voice();
    let ck = key();
    let ep = Epoch { e: 4, d_e: [1; 32] };
    let a = Party::new(acct(1));
    let k = |g: &Group, ep: &Epoch, m: &MemberId, t: &[u8; 8], s: u32, ck: &[u8; 32]| {
        *media_key(g, ep, m, t, s, ck).unwrap()
    };
    let base = k(&g, &ep, &a.m, &a.public.tag_dh(), 7, &ck);
    assert_ne!(base, k(&g, &ep, &a.m, &a.public.tag_dh(), 8, &ck), "stream");
    assert_ne!(
        base,
        k(&g, &Epoch { e: 5, ..ep }, &a.m, &a.public.tag_dh(), 7, &ck)
    );
    assert_ne!(
        base,
        k(
            &g,
            &Epoch { d_e: [2; 32], ..ep },
            &a.m,
            &a.public.tag_dh(),
            7,
            &ck
        )
    );
    assert_ne!(
        base,
        k(&g, &ep, &a.m, &[0; 8], 7, &ck),
        "another connection pair"
    );
    assert_ne!(base, k(&g, &ep, &a.m, &a.public.tag_dh(), 7, &key()));
    assert_eq!(
        media_key(&text(), &ep, &a.m, &a.public.tag_dh(), 7, &ck).err(),
        Some(GkError::Malformed),
        "voice groups only"
    );
}

/// Two senders whose stream ids collide, under one relay session id, never
/// share a (key, nonce): the key names the sender's seat.
#[test]
fn two_senders_with_equal_stream_and_session_ids_get_different_media_keys() {
    let g = voice();
    let ck = key();
    let ep = Epoch { e: 1, d_e: [3; 32] };
    let (a, b) = (Party::new(MemberId::Conn(5)), Party::new(MemberId::Conn(6)));
    let stream = 0x1234_5678;
    let ka = media_key(&g, &ep, &a.m, &a.public.tag_dh(), stream, &ck).unwrap();
    let kb = media_key(&g, &ep, &b.m, &b.public.tag_dh(), stream, &ck).unwrap();
    assert_ne!(*ka, *kb);
    // The same member id on two connection pairs (an account on two devices).
    let a2 = Party::new(MemberId::Conn(5));
    let ka2 = media_key(&g, &ep, &a2.m, &a2.public.tag_dh(), stream, &ck).unwrap();
    assert_ne!(*ka, *ka2);
    // The session id stays in the AAD only; the packet AAD is the same for both.
    let sid = 9;
    assert_eq!(build_aad_for(sid), build_aad_for(sid));
    let ma = crate::MediaKey::new(7, 1, 0, *ka);
    let mb = crate::MediaKey::new(7, 1, 0, *kb);
    let aad = build_aad_for(sid);
    let pa = crate::media_encrypt(&ma, stream, 1, 0, &aad, b"hello").unwrap();
    assert!(crate::media_decrypt(&ma, stream, 1, 0, &aad, &pa).is_ok());
    assert!(crate::media_decrypt(&mb, stream, 1, 0, &aad, &pa).is_err());
}

fn build_aad_for(sid: u32) -> [u8; 9] {
    crate::build_aad(7, 1, sid)
}

// ── Welcomes ──────────────────────────────────────────────────────────────

/// Each of the three secrets is needed: the Kyber1024 one, the ephemeral
/// X25519 one, and the one with the keyholder's static `KX`. Each case
/// changes that one secret and nothing public, so the salt and the context
/// are the genuine ones and only the missing secret can make it fail: with
/// any one of them left out of the KEK, this test fails.
#[test]
fn a_welcome_fails_when_kyber_eph_or_ks_dh_is_wrong() {
    let (g, k, m) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let c = welcome_ctx(
        &g,
        1,
        WelcomeKind::Seed { to: &m.seat() },
        &k.me().holder_id(),
    );
    let s_m = key();
    let made = |forge: Option<usize>| {
        let mut d = welcome::draw(&k.me(), &m.them(), &mut crate::rng()).unwrap();
        if let Some(i) = forge {
            d.ss[i] = Zeroizing::new(key().to_vec());
        }
        d.welcome(&d.kek(&k.me(), &m.them(), &c), &c, &*s_m)
    };
    assert_eq!(
        *open_seed_welcome(&g, 1, &m.me(), &k.holder(), &made(None)).unwrap(),
        *s_m,
        "the control"
    );
    // The maker used another secret than the one the welcome's public bytes give.
    for (i, which) in ["the Kyber1024 secret", "eph's DH", "K's DH"]
        .iter()
        .enumerate()
    {
        assert_eq!(
            open_seed_welcome(&g, 1, &m.me(), &k.holder(), &made(Some(i))).err(),
            Some(GkError::Sealed),
            "{which}"
        );
    }
    // The recipient's side: a Kyber1024 secret key that is not its public
    // key's decapsulates to another secret (implicit rejection), with every
    // public value, the salt's ser(SK.pub) among them, still the genuine one.
    let other = Party::new(acct(3));
    let mismatched = SeatPair {
        kem: libsignal_protocol::kem::KeyPair::from_public_and_private(
            &m.public.kem_bytes(),
            &other.pair.kem.secret_key.serialize(),
        )
        .unwrap(),
        dh: m.pair.dh,
    };
    let m_mismatched = Me {
        m: m.m,
        keys: &mismatched,
    };
    assert_eq!(
        open_seed_welcome(&g, 1, &m_mismatched, &k.holder(), &made(None)).err(),
        Some(GkError::Sealed)
    );

    // Public bytes changed on the wire: each is in the salt, so these fail
    // whatever the secrets; they show the opener reads them where they are.
    let w = made(None);
    let mut kyber = w.clone();
    kyber[100] ^= 1;
    assert_eq!(
        open_seed_welcome(&g, 1, &m.me(), &k.holder(), &kyber).err(),
        Some(GkError::Sealed)
    );
    let to_other = seed_welcome(&g, 1, &k.me(), &Party::new(acct(2)).them(), &key()).unwrap();
    let swapped = [&to_other[..1569], &w[1569..]].concat();
    assert!(open_seed_welcome(&g, 1, &m.me(), &k.holder(), &swapped).is_err());
    let eph = KeyPair::generate(&mut crate::rng()).public_key.serialize();
    let other_eph = [&w[..1569], &eph[..], &w[1602..]].concat();
    assert_eq!(
        open_seed_welcome(&g, 1, &m.me(), &k.holder(), &other_eph).err(),
        Some(GkError::Sealed)
    );
    let k2 = Party::new(acct(1));
    assert!(open_seed_welcome(&g, 1, &m.me(), &k2.holder(), &w).is_err());
    // A low-order ephemeral key is refused before anything opens.
    let mut low = w.clone();
    low[1569..1602].copy_from_slice(&[&[5u8][..], &[0; 32]].concat());
    assert_eq!(
        open_seed_welcome(&g, 1, &m.me(), &k.holder(), &low).err(),
        Some(GkError::WeakKey)
    );
    assert_eq!(
        open_seed_welcome(&g, 1, &m.me(), &k.holder(), &w[1..]).err(),
        Some(GkError::Malformed)
    );
}

/// Keyholder `K`'s name with a private key that is not `KX_K`'s: what a
/// relay can make, holding `K`'s public keys but not its private one.
fn in_ks_name(k: &Party, relay: &Party) -> SeatPair {
    SeatPair {
        kem: relay.pair.kem.clone(),
        dh: KeyPair::new(k.pair.dh.public_key, relay.pair.dh.private_key),
    }
}

/// What a relay can make: a welcome to the member's public keys in keyholder
/// `K`'s name, with `K`'s public `KX` wherever it is named, so the salt and
/// the context are the genuine ones, but a private key of its own, since it
/// holds no `KX_K`. Only `ss_k` is wrong, and it does not open: the relay
/// cannot hand a member an `s_m` or `BK`, or a keyholder a `KRK`, of its
/// choosing.
#[test]
fn a_welcome_made_without_ks_kx_does_not_open() {
    let (g, k, m) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let relay = Party::new(acct(9));
    let pair = in_ks_name(&k, &relay);
    let forger = Me {
        m: k.m,
        keys: &pair,
    };
    assert_eq!(forger.holder_id(), k.holder().id(), "it names K exactly");
    let genuine = seat_welcome(&g, 1, V1, &k.me(), &m.them(), &key(), &key()).unwrap();
    assert!(
        open_seat_welcome(&g, 1, V1, &m.me(), &k.holder(), &genuine).is_ok(),
        "the control"
    );
    let forged = seat_welcome(&g, 1, V1, &forger, &m.them(), &key(), &key()).unwrap();
    assert_eq!(
        open_seat_welcome(&g, 1, V1, &m.me(), &k.holder(), &forged).err(),
        Some(GkError::Sealed)
    );
    let forged = seed_welcome(&g, 2, &forger, &m.them(), &key()).unwrap();
    assert_eq!(
        open_seed_welcome(&g, 2, &m.me(), &k.holder(), &forged).err(),
        Some(GkError::Sealed)
    );
    let k2 = Party::new(acct(3));
    let forged = keyring_welcome(&g, 1, 1, &[1; 32], &forger, &k2.them(), &key()).unwrap();
    assert_eq!(
        open_keyring_welcome(&g, 1, 1, &[1; 32], &k2.me(), &k.holder(), &forged).err(),
        Some(GkError::Sealed)
    );
}

#[test]
fn no_welcome_kind_opens_as_another() {
    let (g, k, m) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let krk = key();
    let seed = seed_welcome(&g, 1, &k.me(), &m.them(), &krk).unwrap();
    let ring = keyring_welcome(&g, 1, 1, &[0; 32], &k.me(), &m.them(), &krk).unwrap();
    assert_eq!(
        seed.len(),
        ring.len(),
        "the same size, so only the context tells them apart"
    );
    assert!(open_keyring_welcome(&g, 1, 1, &[0; 32], &m.me(), &k.holder(), &seed).is_err());
    assert!(open_seed_welcome(&g, 1, &m.me(), &k.holder(), &ring).is_err());
    let seat = seat_welcome(&g, 1, V1, &k.me(), &m.them(), &krk, &krk).unwrap();
    assert!(open_seed_welcome(&g, 1, &m.me(), &k.holder(), &seat).is_err());
    let padded = [&seed[..], &[0; 32]].concat();
    assert!(open_seat_welcome(&g, 1, V1, &m.me(), &k.holder(), &padded).is_err());
}

/// A keyholder's keyring arrives through its own keyholder pair, never its
/// account's seat keys, so its account's other devices open none of it.
#[test]
fn a_keyring_welcome_to_a_keyholder_pair_does_not_open_with_its_accounts_seat_keys() {
    let g = text();
    let k = Party::new(acct(1));
    let desktop = Party::new(acct(2));
    let account_seat = SeatKeys::generate(1, T0);
    let krk = key();
    let w = keyring_welcome(&g, 1, 2, &[1; 32], &k.me(), &desktop.them(), &krk).unwrap();
    assert!(open_keyring_welcome(&g, 1, 2, &[1; 32], &desktop.me(), &k.holder(), &w).is_ok());
    let seat_me = Me {
        m: acct(2),
        keys: &account_seat.pair,
    };
    assert!(open_keyring_welcome(&g, 1, 2, &[1; 32], &seat_me, &k.holder(), &w).is_err());
}

#[test]
fn a_row_or_welcome_under_another_seed_does_not_open() {
    let (g, k, m) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    let s1 = member_secret(&g, 1, &seed1, &m.seat());
    let s2 = member_secret(&g, 2, &seed2, &m.seat());
    let row = RowBase::keyholder_side(&g, 1, &k.me(), &m.them(), &s1)
        .unwrap()
        .row(V1, &key());
    // The member holds s_m under seed 2 too; a row names its seed number.
    let as2 = RowBase::member_side(&g, 2, &m.me(), &k.holder(), &s2).unwrap();
    assert!(as2.open_row(V1, &row).is_err());
    let as2_number_only = RowBase::member_side(&g, 2, &m.me(), &k.holder(), &s1).unwrap();
    assert!(
        as2_number_only.open_row(V1, &row).is_err(),
        "the number alone"
    );
    assert_ne!(
        *s1,
        *member_secret(&g, 2, &seed1, &m.seat()),
        "s_m names the seed number"
    );
    let w = seat_welcome(&g, 1, V1, &k.me(), &m.them(), &s1, &key()).unwrap();
    assert!(open_seat_welcome(&g, 2, V1, &m.me(), &k.holder(), &w).is_err());
    let w = seed_welcome(&g, 2, &k.me(), &m.them(), &s2).unwrap();
    assert!(open_seed_welcome(&g, 1, &m.me(), &k.holder(), &w).is_err());
}

// ── Leavers, newcomers, promotions ────────────────────────────────────────

/// Bucket 1 holds Ann and Lee. Lee leaves: the next opening commit gives
/// bucket 1 a new version by a row to Ann only, and seats Nia, who came
/// later, in a bucket of her own. Lee opens nothing of the new epoch; Nia
/// nothing of the old one.
#[test]
fn a_leaver_opens_no_later_epoch_and_a_newcomer_no_earlier_one() {
    let g = text();
    let k = Party::new(acct(9));
    let (ann, lee, nia) = (
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let seed = [4u8; 32];
    let rb = |p: &Party| {
        let s_m = member_secret(&g, 1, &seed, &p.seat());
        (
            RowBase::keyholder_side(&g, 1, &k.me(), &p.them(), &s_m).unwrap(),
            RowBase::member_side(&g, 1, &p.me(), &k.holder(), &s_m).unwrap(),
        )
    };
    let ((k_ann, ann_rb), (k_lee, lee_rb), (_, nia_rb)) = (rb(&ann), rb(&lee), rb(&nia));
    let e1 = Epoch { e: 1, d_e: [1; 32] };
    let (bk1, ck1) = (key(), key());
    let old = Version { b: 1, v: 100 };
    let rows1 = [k_ann.row(old, &bk1), k_lee.row(old, &bk1)];
    let seal1 = seal(&g, &e1, old, &bk1, &ck1);
    // Epoch 2: bucket 1 at a new version for Ann, Nia in bucket 2.
    let e2 = Epoch { e: 2, d_e: [2; 32] };
    let (bk2, bk3, ck2) = (key(), key(), key());
    let new = Version { b: 1, v: 101 };
    let nias = Version { b: 2, v: 200 };
    let row_ann = k_ann.row(new, &bk2);
    let s_nia = member_secret(&g, 1, &seed, &nia.seat());
    let w_nia = seat_welcome(&g, 1, nias, &k.me(), &nia.them(), &s_nia, &bk3).unwrap();
    let seals2 = [
        seal(&g, &e2, new, &bk2, &ck2),
        seal(&g, &e2, nias, &bk3, &ck2),
    ];

    // Ann reads both.
    let a1 = ann_rb.open_row(old, &rows1[0]).unwrap();
    assert_eq!(*open_seal(&g, &e1, old, &a1, &seal1).unwrap(), *ck1);
    let a2 = ann_rb.open_row(new, &row_ann).unwrap();
    assert_eq!(*open_seal(&g, &e2, new, &a2, &seals2[0]).unwrap(), *ck2);

    // Lee: every key it ever held, against every value of epoch 2.
    let lee_bk = lee_rb.open_row(old, &rows1[1]).unwrap();
    assert_eq!(*open_seal(&g, &e1, old, &lee_bk, &seal1).unwrap(), *ck1);
    assert!(lee_rb.open_row(new, &row_ann).is_err(), "Ann's row");
    assert!(open_seat_welcome(&g, 1, nias, &lee.me(), &k.holder(), &w_nia).is_err());
    for (at, s) in [(new, &seals2[0]), (nias, &seals2[1])] {
        for key in [&*lee_bk, &*ck1] {
            assert!(
                open_seal(&g, &e2, at, key, s).is_err(),
                "Lee opens no seal of epoch 2"
            );
        }
    }

    // Nia: her welcome, and with it epoch 2 only.
    let (_, n_bk) = open_seat_welcome(&g, 1, nias, &nia.me(), &k.holder(), &w_nia).unwrap();
    assert_eq!(*open_seal(&g, &e2, nias, &n_bk, &seals2[1]).unwrap(), *ck2);
    for row in &rows1 {
        assert!(
            nia_rb.open_row(old, row).is_err(),
            "no row of the old version"
        );
    }
    for key in [&*n_bk, &*ck2] {
        assert!(
            open_seal(&g, &e1, old, key, &seal1).is_err(),
            "Nia opens no seal of epoch 1"
        );
    }
}

/// A promotion ratchets every bucket in place (§3.5): the new keyholder,
/// handed the ratcheted keys, opens no seal of an earlier version, and the
/// ratchet version keeps its source's `made`.
#[test]
fn after_a_ratchet_the_new_keyholders_key_opens_no_earlier_seal_and_keeps_made() {
    let g = text();
    let src = KeyringBucket {
        b: 7,
        v: 70,
        pool: Pool::Accounts,
        seats: 3,
        list: [1; 32],
        via: Via::Row,
        bk: Zeroizing::new([9; 32]),
        made: T0 - 3000,
    };
    let e_old = Epoch { e: 4, d_e: [4; 32] };
    let ck_old = key();
    let old_seal = seal(&g, &e_old, src.version(), &src.bk, &ck_old);
    let ratcheted = src.ratcheted(&g, 5, 71, [2; 32]);
    assert_eq!(ratcheted.made, src.made, "keeps its source's made");
    assert_eq!(ratcheted.via, Via::Ratchet { from: 70 });
    assert_eq!((ratcheted.b, ratcheted.v), (7, 71));
    assert_ne!(ratcheted.bk, src.bk);
    assert_eq!(
        *ratcheted.bk,
        *ratchet(&g, 5, src.version(), 71, &src.bk),
        "the old key leads forward"
    );
    for k in [
        &*ratcheted.bk,
        &*ratchet(&g, 5, ratcheted.version(), 70, &ratcheted.bk),
    ] {
        assert!(open_seal(&g, &e_old, src.version(), k, &old_seal).is_err());
    }
    assert_ne!(
        *ratchet(&g, 6, src.version(), 71, &src.bk),
        *ratcheted.bk,
        "a rebase under another epoch ratchets to another key"
    );
    let e_new = Epoch { e: 5, d_e: [5; 32] };
    let ck_new = key();
    let new_seal = seal(&g, &e_new, ratcheted.version(), &ratcheted.bk, &ck_new);
    assert_eq!(
        *open_seal(&g, &e_new, ratcheted.version(), &ratcheted.bk, &new_seal).unwrap(),
        *ck_new
    );
}

// ── Confirm ───────────────────────────────────────────────────────────────

#[test]
fn a_mixed_ck_fails_confirm_in_a_join_header_too() {
    let g = text();
    let (ck_a, ck_b) = (key(), key());
    let opening = confirm(&g, 3, 0, &ck_a);
    assert!(confirm_ok(&g, 3, 0, &ck_a, &opening));
    assert!(
        !confirm_ok(&g, 3, 0, &ck_b, &opening),
        "the other commit's key"
    );
    let join = confirm(&g, 3, 2, &ck_a);
    assert_ne!(
        join, opening,
        "each join has its own confirm of the same key"
    );
    assert!(confirm_ok(&g, 3, 2, &ck_a, &join));
    assert!(!confirm_ok(&g, 3, 2, &ck_b, &join));
    assert!(!confirm_ok(&g, 3, 1, &ck_a, &join), "another join");
    assert!(!confirm_ok(&g, 4, 2, &ck_a, &join), "another epoch");
    assert!(!confirm_ok(&voice_named_alike(), 3, 2, &ck_a, &join));
}

/// A fresh device is given a genuine, signed Join header, and a welcome and
/// seal the relay made. Without `KX_K` the welcome does not open. With it (a
/// quantum attacker that broke X25519), the seal opens to a key that fails
/// the header's `confirm`, and the device takes nothing.
#[test]
fn a_fresh_device_given_a_genuine_join_header_with_a_forged_welcome_and_seal_refuses_it() {
    let g = text();
    let (k, m) = (Party::new(acct(1)), Party::new(acct(2)));
    let ck = key();
    let genesis = signed(None, genesis_of(&k, &g, T0, false), &k);
    let mut join = next(&genesis, Kind::Join, T0 + 2);
    join.confirm = confirm(&g, 1, 1, &ck);
    let join = signed(Some(&genesis), join, &k);
    assert!(
        check_signer(&join, Some(&genesis), NO_PINS).is_ok(),
        "the header is genuine"
    );
    let ep = Epoch {
        e: 1,
        d_e: join.d_e(),
    };
    let (bk_x, ck_x) = (key(), key());
    let relay = Party::new(acct(9));
    let pair = in_ks_name(&k, &relay);
    let forger = Me {
        m: k.m,
        keys: &pair,
    };
    let forged = seat_welcome(&g, 1, V1, &forger, &m.them(), &key(), &bk_x).unwrap();
    assert!(open_seat_welcome(&g, 1, V1, &m.me(), &k.holder(), &forged).is_err());
    // As if X25519 were broken: the attacker holds K's KX.
    let quantum = seat_welcome(&g, 1, V1, &k.me(), &m.them(), &key(), &bk_x).unwrap();
    let (_, bk) = open_seat_welcome(&g, 1, V1, &m.me(), &k.holder(), &quantum).unwrap();
    let opened = open_seal(&g, &ep, V1, &bk, &seal(&g, &ep, V1, &bk_x, &ck_x)).unwrap();
    assert!(!confirm_ok(&g, 1, 1, &opened, &join.header().confirm));
    assert!(
        confirm_ok(&g, 1, 1, &ck, &join.header().confirm),
        "the control"
    );
}

// ── Headers: form and signature ───────────────────────────────────────────

/// S + ℓ, little-endian, keeping libsignal's sign bit; `None` past 2^253.
fn plus_ell(sig: &[u8; 64]) -> Option<[u8; 64]> {
    const ELL: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let sign_bit = sig[63] & 0x80;
    let mut out = *sig;
    out[63] &= 0x7f;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(out[32 + i]) + u16::from(ELL[i]) + carry;
        out[32 + i] = v as u8;
        carry = v >> 8;
    }
    (out[63] & 0xe0 == 0).then(|| {
        out[63] |= sign_bit;
        out
    })
}

pub(super) fn malleated(h: &SignedHeader) -> Option<[u8; 64]> {
    plus_ell(&h.sig())
}

/// libsignal takes `(R, S + ℓ)`; the digest leaves the signature out, so it
/// is the same header; our wrapper refuses the second signature.
#[test]
fn a_header_re_signed_with_s_plus_ell_keeps_its_digest_and_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let (h, sig2) = loop {
        let h = signed(None, genesis_of(&k, &g, T0, false), &k);
        if let Some(s) = malleated(&h) {
            break (h, s);
        }
    };
    let pk = k.ik.public_key();
    let msg = [&b"voipc-gk/v1/header-sig|"[..], &h.d()].concat();
    assert!(pk.verify_signature(&msg, &h.sig()));
    assert!(pk.verify_signature(&msg, &sig2), "libsignal takes S + ℓ");
    assert!(!s_canonical(&sig2));
    assert_eq!(decode(h.body(), &sig2).err(), Some(Refusal::Signature));
    let same = h.with_sig(sig2);
    assert_eq!(same.d(), h.d(), "the digest is over the body only");
    assert!(!same.verify(&k.ik_raw()), "and our wrapper refuses it");
    assert!(h.verify(&k.ik_raw()));
    assert_eq!(decode(h.body(), &h.sig()).unwrap(), h);
}

#[test]
fn a_header_with_unsorted_or_duplicate_lists_or_other_bytes_is_refused() {
    let (g, k, k2) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let mut h = genesis_of(&k, &g, T0, true);
    h.keyholders = vec![k.entry(), k2.entry()];
    h.canonicalize();
    h.names_hash = names_hash(None, &h);
    let (body, sig) = raw_signed(&h, &k);
    assert!(decode(&body, &sig).is_ok(), "the control");
    let unsorted = HeaderV1 {
        keyholders: h.keyholders.iter().rev().copied().collect(),
        ..h.clone()
    };
    let (b, s) = raw_signed(&unsorted, &k);
    assert!(matches!(decode(&b, &s), Err(Refusal::Form(_))));
    let twice = HeaderV1 {
        keyholders: vec![h.keyholders[0], h.keyholders[0]],
        ..h.clone()
    };
    let (b, s) = raw_signed(&twice, &k);
    assert!(matches!(decode(&b, &s), Err(Refusal::Form(_))));
    let names_twice = HeaderV1 {
        added: Added::List(vec![k.added(1), k.added(1)]),
        ..h.clone()
    };
    let (b, s) = raw_signed(&names_twice, &k);
    assert!(matches!(decode(&b, &s), Err(Refusal::Form(_))));
    let removed_unsorted = {
        let mut seats = vec![k.seat(), k2.seat()];
        seats.sort_by_key(|x| postcard::to_allocvec(x).unwrap());
        seats.reverse();
        HeaderV1 {
            removed: Removed::List(seats),
            ..h.clone()
        }
    };
    let (b, s) = raw_signed(&removed_unsorted, &k);
    assert!(matches!(decode(&b, &s), Err(Refusal::Form(_))));
    // Trailing bytes, and an overlong varint for `join` (0 as 0x80 0x00).
    let trailing = [&body[..], &[0]].concat();
    assert!(matches!(decode(&trailing, &sig), Err(Refusal::Form(_))));
    let at = 1 + 1 + 1 + "c:lounge-1".len() + 16 + 1;
    assert_eq!(body[at], 0, "join sits here");
    let overlong = [&body[..at], &[0x80, 0x00], &body[at + 1..]].concat();
    assert!(matches!(decode(&overlong, &sig), Err(Refusal::Form(_))));
    let mut too_big = h.clone();
    too_big.group = "c:".to_string() + &"x".repeat(64);
    let (b, s) = raw_signed(&too_big, &k);
    assert_eq!(decode(&b, &s).err(), Some(Refusal::WrongGroup));
    assert_eq!(
        SignedHeader::decode(&b, &s, GroupKind::Voice, &too_big.group).err(),
        Some(Refusal::WrongGroup)
    );
    assert!(decode(&vec![0; HEADER_MAX_BYTES + 1], &sig).is_err());
}

#[test]
fn a_header_that_breaks_its_kinds_form_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let bad = |h: HeaderV1, why: &str| {
        let (b, s) = raw_signed(&h, &k);
        assert!(decode(&b, &s).is_err(), "{why}");
    };
    bad(
        HeaderV1 {
            epoch: 2,
            ..gen.header().clone()
        },
        "a Genesis at epoch 2",
    );
    bad(
        HeaderV1 {
            parent: [1; 32],
            ..gen.header().clone()
        },
        "a Genesis with a parent",
    );
    bad(
        HeaderV1 {
            keyholders: vec![],
            ..gen.header().clone()
        },
        "nobody holds keys",
    );
    bad(
        HeaderV1 {
            names_hash: [1; 32],
            ..gen.header().clone()
        },
        "names in an open group",
    );
    bad(
        HeaderV1 {
            added: Added::List(vec![]),
            ..gen.header().clone()
        },
        "a list in an open group",
    );
    let join = next(&gen, Kind::Join, T0 + 2);
    bad(
        HeaderV1 {
            join: 0,
            ..join.clone()
        },
        "a Join at join 0",
    );
    bad(
        HeaderV1 {
            epoch_parent: [0; 32],
            ..join.clone()
        },
        "a Join with no epoch",
    );
    bad(
        HeaderV1 {
            keyholders: vec![k.entry()],
            ..join.clone()
        },
        "a Join sets no keyholders",
    );
    bad(
        HeaderV1 {
            seed_floor: 2,
            ..join.clone()
        },
        "a floor above the seed",
    );
    let mut voice_entry = k.entry();
    voice_entry.u = Some(4);
    bad(
        HeaderV1 {
            keyholders: vec![voice_entry],
            ..gen.header().clone()
        },
        "a user id on a text keyholder",
    );
    let mut low = k.entry();
    low.kx = [0; 32];
    bad(
        HeaderV1 {
            keyholders: vec![low],
            ..gen.header().clone()
        },
        "a KX of low order",
    );
    let guest_desktop = Keyholder {
        m: MemberId::Conn(4),
        origin: 0x03,
        ..k.entry()
    };
    bad(
        HeaderV1 {
            keyholders: vec![guest_desktop],
            ..gen.header().clone()
        },
        "a desktop pair is an account's",
    );
    // Every voice keyholder is a connection keyholder (§2, §5.9): an
    // account's desktop pair has no place in a voice room.
    let vg = voice();
    let voice_form = |h: &HeaderV1| {
        let (b, s) = raw_signed(h, &k);
        SignedHeader::decode(&b, &s, GroupKind::Voice, vg.id()).map(|_| ())
    };
    let mut in_voice = genesis_of(&k, &vg, T0, false);
    in_voice.keyholders[0].u = Some(4);
    in_voice.keyholders[0].origin = 0x02;
    assert_eq!(
        voice_form(&in_voice),
        Ok(()),
        "the control: a connection pair"
    );
    in_voice.keyholders[0].origin = 0x03;
    assert_eq!(
        voice_form(&in_voice),
        Err(Refusal::Form(
            "a keyholder entry has no origin its member can have"
        ))
    );
    // An identity key of low order, in a keyholder entry or an added one.
    let mut low_ik = k.entry();
    low_ik.ik = [0; 32];
    let (b, s) = raw_signed(
        &HeaderV1 {
            keyholders: vec![low_ik],
            ..gen.header().clone()
        },
        &k,
    );
    assert_eq!(
        decode(&b, &s).err(),
        Some(Refusal::Form("a keyholder's IK is of low order"))
    );
    let mut gated = genesis_of(&k, &g, T0, true);
    if let Added::List(l) = &mut gated.added {
        l[0].ik = [0; 32];
        l[0].ik[0] = 1;
    }
    let (b, s) = raw_signed(&gated, &k);
    assert_eq!(
        decode(&b, &s).err(),
        Some(Refusal::Form("an added IK is of low order"))
    );
}

/// Under an identity key of low order, XEdDSA takes `R = [S]B` for about
/// half of all messages, so whatever such a key "signed", anyone could have.
/// No signature check here takes one: a header's, a blob's or an
/// endorsement's.
#[test]
fn an_identity_key_of_low_order_signs_nothing() {
    let (g, k) = (text(), Party::new(acct(1)));
    let h = signed(None, genesis_of(&k, &g, T0, false), &k);
    assert!(h.verify(&k.ik_raw()), "the control");
    let mut one = [0u8; 32];
    one[0] = 1;
    for low in [[0u8; 32], one] {
        assert!(!h.verify(&low));
        let ik = libsignal_protocol::IdentityKey::decode(&[&[5u8][..], &low].concat()).unwrap();
        let pair = SeatPair::generate().public();
        let e = Endorsement {
            origin: Origin::VaultSeat,
            m: acct(1),
            n: 1,
            made: T0,
            sig: [0; 64],
        };
        assert!(!e.verify(&ik, &pair));
    }
    // A blob that names an identity key of low order.
    let ep = Epoch { e: 1, d_e: [1; 32] };
    let (ck, w) = (key(), Writer { m: acct(1), u: 1 });
    let skdm = skdm_for(&g, &ep);
    let blob = writer_blob(&g, &ep, &w, &ck, &k.ik, &skdm).unwrap();
    let plain = super::open_derived(&ck, &writer_ctx(&g, &ep, &w), &blob).unwrap();
    let at = 2 + skdm.len();
    let mut low = plain.to_vec();
    low[at + 1..at + 33].copy_from_slice(&[0; 32]);
    let resealed = super::seal_derived(&ck, &writer_ctx(&g, &ep, &w), &low);
    assert_eq!(
        open_writer_blob(&g, &ep, &w, &ck, &resealed).err(),
        Some(GkError::WeakKey)
    );
}

#[test]
fn a_forged_header_is_refused() {
    let (g, k, mallory) = (text(), Party::new(acct(1)), Party::new(acct(2)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = next(&gen, Kind::Fresh, T0 + 60);
    assert!(check_signer(&signed(Some(&gen), fresh.clone(), &k), Some(&gen), NO_PINS).is_ok());
    // Signed by someone holding no keys, in its own name and in K's.
    let as_mallory = signed(
        Some(&gen),
        HeaderV1 {
            signer: mallory.m,
            ..fresh.clone()
        },
        &mallory,
    );
    assert_eq!(
        check_signer(&as_mallory, Some(&gen), NO_PINS).err(),
        Some(Refusal::NotKeyholder)
    );
    let in_ks_name = signed(Some(&gen), fresh.clone(), &mallory);
    assert_eq!(
        check_signer(&in_ks_name, Some(&gen), NO_PINS).err(),
        Some(Refusal::Signature)
    );
    // The body changed after K signed it.
    let genuine = signed(Some(&gen), fresh.clone(), &k);
    let mut changed = genuine.header().clone();
    changed.exits_upto = 99;
    let body = changed.encode();
    let moved = decode(&body, &genuine.sig()).unwrap();
    assert_eq!(
        check_signer(&moved, Some(&gen), NO_PINS).err(),
        Some(Refusal::Signature)
    );
    // A Genesis whose signer is pinned to another key.
    let pin = mallory.ik_raw();
    let pins = move |_: &[u8; 16]| Some(pin);
    assert_eq!(
        check_signer(&gen, None, &pins).err(),
        Some(Refusal::Pin(k.m))
    );
    assert_eq!(
        check_signer(&gen, None, NO_PINS).unwrap(),
        k.ik_raw(),
        "TOFU"
    );
    // Checked against a set that is not the one kh_parent names.
    let other_gen = signed(None, genesis_of(&k, &g, T0 + 1, false), &k);
    assert!(matches!(
        check_signer(&genuine, Some(&other_gen), NO_PINS),
        Err(Refusal::Chain(_))
    ));
}

#[test]
fn a_keyholder_change_follows_its_kind() {
    let g = text();
    let (k1, k2, k3) = (
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let gen = signed(None, genesis_of(&k1, &g, T0, false), &k1);
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 60);
    add.keyholders = vec![k1.entry(), k2.entry()];
    let add_ok = signed(Some(&gen), add.clone(), &k1);
    assert!(check_signer(&add_ok, Some(&gen), NO_PINS).is_ok());
    let by_newcomer = signed(
        Some(&gen),
        HeaderV1 {
            signer: k2.m,
            ..add.clone()
        },
        &k2,
    );
    assert_eq!(
        check_signer(&by_newcomer, Some(&gen), NO_PINS).err(),
        Some(Refusal::NotKeyholder),
        "signed by the set before it"
    );
    let drops = signed(
        Some(&gen),
        HeaderV1 {
            keyholders: vec![k2.entry()],
            ..add.clone()
        },
        &k1,
    );
    assert!(matches!(
        check_signer(&drops, Some(&gen), NO_PINS),
        Err(Refusal::KeyholderChange(_))
    ));
    let mut remove = next(&add_ok, Kind::KeyholdersRemove, T0 + 120);
    remove.keyholders = vec![k2.entry()];
    remove.signer = k2.m;
    assert!(check_signer(
        &signed(Some(&add_ok), remove.clone(), &k2),
        Some(&add_ok),
        NO_PINS
    )
    .is_ok());
    let own_removal = signed(
        Some(&add_ok),
        HeaderV1 {
            signer: k1.m,
            ..remove.clone()
        },
        &k1,
    );
    assert!(matches!(
        check_signer(&own_removal, Some(&add_ok), NO_PINS),
        Err(Refusal::KeyholderChange(_))
    ));
    // A keyholder replacing its own pair no longer does it in a
    // KeyholdersRemove: that kind only removes. It signs a KeyholdersReplace.
    let k1_new = rotated(&k1);
    let mut new_entry = k1_new.entry();
    new_entry.n = 1;
    let in_a_remove = HeaderV1 {
        keyholders: vec![new_entry, k2.entry()],
        signer: k1.m,
        ..remove.clone()
    };
    assert_eq!(
        check_signer(
            &signed(Some(&add_ok), in_a_remove.clone(), &k1),
            Some(&add_ok),
            NO_PINS
        ),
        Err(Refusal::KeyholderChange("a KeyholdersRemove only removes"))
    );
    let replace = HeaderV1 {
        kind: Kind::KeyholdersReplace,
        seed: 1,
        seed_floor: 1,
        ..in_a_remove
    };
    assert!(check_signer(&signed(Some(&add_ok), replace, &k1), Some(&add_ok), NO_PINS).is_ok());
    let sneaks_in = HeaderV1 {
        keyholders: vec![k2.entry(), k3.entry()],
        signer: k2.m,
        ..remove.clone()
    };
    assert!(matches!(
        check_signer(
            &signed(Some(&add_ok), sneaks_in, &k2),
            Some(&add_ok),
            NO_PINS
        ),
        Err(Refusal::KeyholderChange(_))
    ));
}

/// §5.6: a roll start sets `seed = s + 1` and `seed_floor = s`, also while
/// an earlier roll still runs, so the seeds every earlier removed keyholder
/// holds leave the keyring at the latest there. In a text group a
/// KeyholdersRemove may also leave the seed alone (its slot is closed), or
/// finish a roll; when it is due is the keyholders' and the validator's
/// (`SeedRolls`), not the members'.
#[test]
fn a_roll_start_sets_the_seed_floor_to_the_old_seed_also_while_one_runs() {
    let g = text();
    let (k1, k2, k3) = (
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let gen = signed(None, genesis_of(&k1, &g, T0, false), &k1);
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 60);
    add.keyholders = vec![k1.entry(), k2.entry(), k3.entry()];
    let add = signed(Some(&gen), add, &k1);
    let mut r1 = next(&add, Kind::KeyholdersRemove, T0 + 120);
    r1.keyholders = vec![k1.entry(), k2.entry()];
    assert_eq!((r1.seed, r1.seed_floor), (2, 1));
    let r1 = signed(Some(&add), r1, &k1);
    assert!(check_link(&add, &r1).is_ok());
    // The second removal comes before every seat holds seed 2.
    let mut r2 = next(&r1, Kind::KeyholdersRemove, T0 + 180);
    r2.keyholders = vec![k1.entry()];
    let at = |seed: u32, floor: u32| {
        signed(
            Some(&r1),
            HeaderV1 {
                seed,
                seed_floor: floor,
                ..r2.clone()
            },
            &k1,
        )
    };
    assert!(check_link(&r1, &at(3, 2)).is_ok(), "a start drops seed 1");
    assert_eq!(
        check_link(&r1, &at(3, 1)).err(),
        Some(Refusal::Chain("the seed does not follow")),
        "keeping seed 1, which k3 holds"
    );
    assert!(
        check_link(&r1, &at(3, 3)).is_err(),
        "finishing a roll it began"
    );
    assert!(
        check_link(&r1, &at(2, 1)).is_ok(),
        "no start: the slot is shut"
    );
    assert!(
        check_link(&r1, &at(2, 2)).is_ok(),
        "the running roll finishes"
    );
    assert!(check_link(&r1, &at(4, 3)).is_err(), "two seeds on");
}

// ── Headers: the chain ────────────────────────────────────────────────────

#[test]
fn an_opening_header_not_at_its_parents_epoch_plus_one_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = next(&gen, Kind::Fresh, T0 + 60);
    assert!(check_link(&gen, &signed(Some(&gen), fresh.clone(), &k)).is_ok());
    for epoch in [1, 3, u32::MAX] {
        let h = signed(
            Some(&gen),
            HeaderV1 {
                epoch,
                ..fresh.clone()
            },
            &k,
        );
        assert!(
            matches!(check_link(&gen, &h), Err(Refusal::Chain(_))),
            "epoch {epoch}"
        );
    }
    let join = next(&gen, Kind::Join, T0 + 2);
    let j1 = signed(Some(&gen), join.clone(), &k);
    assert!(check_link(&gen, &j1).is_ok());
    let skip = signed(
        Some(&gen),
        HeaderV1 {
            join: 2,
            ..join.clone()
        },
        &k,
    );
    assert!(check_link(&gen, &skip).is_err());
    let other_epoch = signed(
        Some(&gen),
        HeaderV1 {
            epoch: 2,
            ..join.clone()
        },
        &k,
    );
    assert!(check_link(&gen, &other_epoch).is_err());
    let wrong_ep = signed(
        Some(&gen),
        HeaderV1 {
            epoch_parent: [7; 32],
            ..join.clone()
        },
        &k,
    );
    assert!(check_link(&gen, &wrong_ep).is_err());
    let wrong_kh = signed(
        Some(&gen),
        HeaderV1 {
            kh_parent: [7; 32],
            ..fresh.clone()
        },
        &k,
    );
    assert!(check_link(&gen, &wrong_kh).is_err());
    let no_roll = signed(
        Some(&gen),
        HeaderV1 {
            seed: 2,
            seed_floor: 1,
            ..join.clone()
        },
        &k,
    );
    assert!(
        check_link(&gen, &no_roll).is_err(),
        "a Join never rolls the seed"
    );
    let back = signed(
        Some(&j1),
        HeaderV1 {
            exits_upto: 0,
            ..next(&j1, Kind::Fresh, T0 + 9)
        },
        &k,
    );
    assert!(check_link(&j1, &back).is_ok());
    // On the floor alone, the same.
    let floor = Floor::after(None, &gen, T0);
    assert!(check_on_floor(&floor, &signed(Some(&gen), fresh.clone(), &k)).is_ok());
    let h = signed(Some(&gen), HeaderV1 { epoch: 3, ..fresh }, &k);
    assert!(check_on_floor(&floor, &h).is_err());
}

#[test]
fn a_header_below_the_floor_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let j1 = signed(Some(&fresh), next(&fresh, Kind::Join, T0 + 62), &k);
    let floor = Floor::after(Some(&Floor::after(None, &gen, T0)), &j1, T0);
    for h in [&gen, &fresh, &j1] {
        assert_eq!(check_above(&floor, h.header()), Err(Refusal::BelowFloor));
    }
    let j2 = signed(Some(&j1), next(&j1, Kind::Join, T0 + 64), &k);
    assert!(check_above(&floor, j2.header()).is_ok());
    // And a walk to the floor refuses it the same way.
    let to = WalkTo::Floor {
        floor: &floor,
        kh: &gen,
    };
    let head = WalkLink {
        header: &fresh,
        parent: None,
    };
    assert_eq!(
        check_walk(to, &[], head, clock(T0 + 70), NO_PINS).err(),
        Some(Refusal::BelowFloor)
    );
}

/// The member's floor is the Genesis. The relay shows it a head far ahead
/// whose parent it does not hold: the walk follows the keyholder chain, and
/// the epoch may be at most one per 2 s of elapsed time (plus the clock
/// slack) above the floor's.
#[test]
fn a_walked_header_past_the_epoch_bound_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let floor = Floor::after(None, &gen, T0);
    let at = |epoch: u32, time: u64| {
        let h = HeaderV1 {
            epoch,
            parent: [8; 32],
            ..next(&gen, Kind::Fresh, time)
        };
        signed(None, h, &k)
    };
    let to = WalkTo::Floor {
        floor: &floor,
        kh: &gen,
    };
    let walk = |h: &SignedHeader, now| {
        check_walk(
            to,
            &[],
            WalkLink {
                header: h,
                parent: None,
            },
            clock(now),
            NO_PINS,
        )
    };
    // 100 s later: (100 + 600) / 2 = 350 epochs more at most.
    assert!(walk(&at(351, T0 + 100), T0 + 100).is_ok());
    assert_eq!(
        walk(&at(352, T0 + 100), T0 + 100).err(),
        Some(Refusal::EpochBound)
    );
    assert_eq!(
        walk(&at(u32::MAX, T0 + 100), T0 + 100).err(),
        Some(Refusal::EpochBound)
    );
    // An odd second rounds up.
    assert!(walk(&at(352, T0 + 101), T0 + 101).is_ok());
    // A header claiming a time well before the floor gets no new epoch at all.
    assert!(!epoch_bound_ok(1, T0, at(2, T0 - 700).header()));
    assert!(epoch_bound_ok(1, T0, at(1, T0 - 700).header()));
}

#[test]
fn a_walk_follows_the_keyholder_chain_back_to_the_floor() {
    let g = text();
    let (k1, k2, k3) = (
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let gen = signed(None, genesis_of(&k1, &g, T0, false), &k1);
    let floor = Floor::after(None, &gen, T0);
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 60);
    add.keyholders = vec![k1.entry(), k2.entry()];
    let add = signed(Some(&gen), add, &k1);
    let mut remove = next(&add, Kind::KeyholdersRemove, T0 + 120);
    remove.keyholders = vec![k2.entry()];
    remove.signer = k2.m;
    let remove = signed(Some(&add), remove, &k2);
    let fresh = next(&remove, Kind::Fresh, T0 + 180);
    let head = signed(
        Some(&remove),
        HeaderV1 {
            signer: k2.m,
            ..fresh.clone()
        },
        &k2,
    );
    let to = WalkTo::Floor {
        floor: &floor,
        kh: &gen,
    };
    let links = [
        WalkLink {
            header: &remove,
            parent: None,
        },
        WalkLink {
            header: &add,
            parent: None,
        },
    ];
    let now = clock(T0 + 200);
    let hl = WalkLink {
        header: &head,
        parent: None,
    };
    assert!(check_walk(to, &links, hl, now, NO_PINS).is_ok());
    // k1, removed, signs a head on the set it was removed from: the chain the
    // relay shows must then skip the removal, and the header names the set.
    let by_k1 = signed(
        Some(&remove),
        HeaderV1 {
            signer: k1.m,
            ..fresh.clone()
        },
        &k1,
    );
    assert_eq!(
        check_walk(
            to,
            &links,
            WalkLink {
                header: &by_k1,
                parent: None
            },
            now,
            NO_PINS
        )
        .err(),
        Some(Refusal::NotKeyholder)
    );
    // A link out of order, a link left out, a link signed by someone outside the set.
    let swapped = [links[1], links[0]];
    assert!(check_walk(to, &swapped, hl, now, NO_PINS).is_err());
    assert!(check_walk(to, &links[..1], hl, now, NO_PINS).is_err());
    let mut rogue = next(&add, Kind::KeyholdersRemove, T0 + 120);
    rogue.keyholders = vec![k2.entry(), k3.entry()];
    rogue.signer = k3.m;
    let rogue = signed(Some(&add), rogue, &k3);
    let rogue_head = signed(
        Some(&rogue),
        HeaderV1 {
            signer: k3.m,
            ..next(&rogue, Kind::Fresh, T0 + 180)
        },
        &k3,
    );
    let rogue_links = [
        WalkLink {
            header: &rogue,
            parent: None,
        },
        links[1],
    ];
    assert!(check_walk(
        to,
        &rogue_links,
        WalkLink {
            header: &rogue_head,
            parent: None
        },
        now,
        NO_PINS
    )
    .is_err());
    let too_long = vec![links[0]; MAX_WALK + 1];
    assert_eq!(
        check_walk(to, &too_long, hl, now, NO_PINS).err(),
        Some(Refusal::Walk("more than 4096 links"))
    );
}

#[test]
fn a_device_with_no_floor_walks_back_to_the_generations_start() {
    let g = text();
    let k = Party::new(acct(1));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let head = signed(Some(&fresh), next(&fresh, Kind::Join, T0 + 62), &k);
    let walked = check_walk(
        WalkTo::Start { floor: None },
        &[WalkLink {
            header: &gen,
            parent: None,
        }],
        WalkLink {
            header: &head,
            parent: None,
        },
        clock(T0 + 70),
        NO_PINS,
    )
    .unwrap();
    assert_eq!(walked.signers, [(k.m, k.ik_raw())], "pinned on trust");
    assert_eq!(walked.start.as_ref(), Some(&gen));
    // A Regenesis start needs its parent, an hour older.
    let mut regen = next(&fresh, Kind::Regenesis, T0 + 60 + 3600);
    regen.keyholders = vec![k.entry()];
    let regen = signed(Some(&fresh), regen, &k);
    let after = signed(Some(&regen), next(&regen, Kind::Join, T0 + 3700), &k);
    let start = |parent| {
        check_walk(
            WalkTo::Start { floor: None },
            &[WalkLink {
                header: &regen,
                parent,
            }],
            WalkLink {
                header: &after,
                parent: None,
            },
            clock(T0 + 3700),
            NO_PINS,
        )
    };
    assert!(start(Some(&fresh)).is_ok());
    assert!(start(None).is_err());
}

/// The hour a Regenesis waits is measured from its parent's `time`, so on a
/// walk to the floor its parent must be genuine and at or above the floor
/// (§5.7). The member took a header five minutes ago; the relay shows it a
/// Regenesis an hour after a parent from below the floor, or after one
/// nobody in the set signed, and neither is taken, as head or as link.
#[test]
fn a_regenesis_over_a_forged_or_below_floor_parent_is_refused_on_a_walk() {
    let g = text();
    let (k, vol, mallory) = (
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let j1 = signed(Some(&fresh), next(&fresh, Kind::Join, T0 + 62), &k);
    let j2 = signed(Some(&j1), next(&j1, Kind::Join, T0 + 3500), &k);
    let floor = Floor::after(Some(&Floor::after(None, &gen, T0)), &j2, T0);
    let regen_over = |parent: &SignedHeader, time: u64| {
        let mut h = next(parent, Kind::Regenesis, time);
        h.keyholders = vec![vol.entry()];
        h.signer = vol.m;
        signed(Some(parent), h, &vol)
    };
    let to = WalkTo::Floor {
        floor: &floor,
        kh: &gen,
    };
    let walk = |r: &SignedHeader, parent: &SignedHeader, now: u64| {
        check_walk(
            to,
            &[],
            WalkLink {
                header: r,
                parent: Some(parent),
            },
            clock(now),
            NO_PINS,
        )
    };
    let now = T0 + 3800;

    // A genuine header from below the floor, more than an hour old.
    let below = regen_over(&j1, j1.header().time + REGENESIS_WAIT);
    assert!(
        check_regenesis(Some(&floor), clock(now), &below, &j1).is_ok(),
        "the hour alone passes"
    );
    assert_eq!(walk(&below, &j1, now).err(), Some(Refusal::BelowFloor));
    // And the same Regenesis as a link before the head.
    let after = signed(Some(&below), next(&below, Kind::Join, now), &vol);
    assert_eq!(
        check_walk(
            to,
            &[WalkLink {
                header: &below,
                parent: Some(&j1),
            }],
            WalkLink {
                header: &after,
                parent: None,
            },
            clock(now),
            NO_PINS,
        )
        .err(),
        Some(Refusal::BelowFloor)
    );

    // Above the floor, dated two hours back, but signed by nobody in the
    // set: in its own name, and in K's. The Regenesis is dated now, within
    // the epoch bound.
    let mut fake = next(&j2, Kind::Join, now - 7200);
    let in_k_name = signed(Some(&j2), fake.clone(), &mallory);
    fake.signer = mallory.m;
    let own_name = signed(Some(&j2), fake, &mallory);
    for (parent, why) in [
        (&own_name, Refusal::NotKeyholder),
        (&in_k_name, Refusal::Signature),
    ] {
        let r = regen_over(parent, now);
        assert!(check_regenesis(Some(&floor), clock(now), &r, parent).is_ok());
        assert_eq!(walk(&r, parent, now).err(), Some(why));
    }

    // The controls: over the floor itself, and over a genuine header above
    // it, each an hour on.
    let over_floor = regen_over(&j2, T0 + 3500 + REGENESIS_WAIT);
    assert!(walk(&over_floor, &j2, T0 + 3500 + REGENESIS_WAIT).is_ok());
    let j3 = signed(Some(&j2), next(&j2, Kind::Join, T0 + 3600), &k);
    let over_j3 = regen_over(&j3, T0 + 3600 + REGENESIS_WAIT);
    assert!(walk(&over_j3, &j3, T0 + 3600 + REGENESIS_WAIT).is_ok());
}

// ── Generations (§5.7) ────────────────────────────────────────────────────

#[test]
fn a_generation_among_the_last_eight_or_begun_before_the_floor_is_refused() {
    let k = Party::new(acct(1));
    let gen_n = |n: u8| Group::new(GroupKind::Text, "c:lounge-1", [n; 16]).unwrap();
    let mut floor: Option<Floor> = None;
    let mut t = T0;
    for n in 1..=9u8 {
        let h = signed(None, genesis_of(&k, &gen_n(n), t, false), &k);
        assert!(
            check_new_generation(floor.as_ref(), clock(t), h.header()).is_ok(),
            "gen {n}"
        );
        floor = Some(Floor::after(floor.as_ref(), &h, t));
        t += 86_400;
    }
    let floor = floor.unwrap();
    assert_eq!(floor.gens.len(), 8);
    let now = clock(t);
    for n in 2..=9u8 {
        let replay = genesis_of(&k, &gen_n(n), t, false);
        assert_eq!(
            check_new_generation(Some(&floor), now, &replay).err(),
            Some(Refusal::Generation("a generation this device took already")),
            "gen {n}"
        );
    }
    assert!(
        check_new_generation(Some(&floor), now, &genesis_of(&k, &gen_n(1), t, false)).is_ok(),
        "the ninth back is forgotten; its time still has to pass"
    );
    // Begun before the floor's time (less the slack): refused, whatever its age.
    let fresh_gen = gen_n(20);
    let before = genesis_of(&k, &fresh_gen, floor.time - CLOCK_SLACK, false);
    assert!(check_new_generation(Some(&floor), now, &before).is_err());
    let just_after = genesis_of(&k, &fresh_gen, floor.time - CLOCK_SLACK + 1, false);
    assert!(check_new_generation(Some(&floor), now, &just_after).is_ok());
    // A device that took a header 5 minutes ago refuses a Genesis 20 minutes old.
    let live = Clock {
        now: t,
        taken: Some(t - 300),
    };
    let twenty = genesis_of(&k, &fresh_gen, t - 1200, false);
    assert!(check_new_generation(Some(&floor), clock(t), &twenty).is_ok());
    assert!(check_new_generation(Some(&floor), live, &twenty).is_err());
    let five = genesis_of(&k, &fresh_gen, t - 300, false);
    assert!(check_new_generation(Some(&floor), live, &five).is_ok());
    // A fresh device takes a generation begun 3 days ago.
    let old = genesis_of(&k, &fresh_gen, t - 3 * 86_400, false);
    assert!(check_new_generation(None, clock(t), &old).is_ok());
}

#[test]
fn a_regenesis_before_an_hour_after_its_parent_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let parent = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let regen_at = |time| {
        let mut h = next(&parent, Kind::Regenesis, time);
        h.keyholders = vec![k.entry()];
        signed(Some(&parent), h, &k)
    };
    let early = regen_at(T0 + 60 + 3599);
    let on_time = regen_at(T0 + 60 + 3600);
    let now = clock(T0 + 4000);
    assert!(check_regenesis(None, now, &early, &parent).is_err());
    assert!(check_regenesis(None, now, &on_time, &parent).is_ok());
    assert!(check_link(&parent, &early).is_err());
    assert!(check_link(&parent, &on_time).is_ok());
    let floor = Floor::after(None, &parent, T0);
    assert!(check_on_floor(&floor, &early).is_err());
    assert!(check_on_floor(&floor, &on_time).is_ok());
    // A device following the group live takes it only as it happens.
    let live = Clock {
        now: T0 + 60 + 3600 + 1200,
        taken: Some(T0 + 60 + 3600 + 1000),
    };
    assert!(check_regenesis(Some(&floor), live, &on_time, &parent).is_err());
}

// ── "Fast new start" (owner, 2026-11-19) ──────────────────────────────────
//
// A keyholder set of connection entries alone (0x02: a browser's or a guest's pair, gone with
// its connection) lets a Regenesis come 2 minutes after its parent instead of the hour. The
// tests write the 2 minutes out (`FAST`), so the old rule (an hour whatever the set) fails them.

/// The fast wait, written out.
const FAST: u64 = 2 * 60;

/// A Regenesis by volunteer `vol` over `parent`, dated `time`.
fn regen_by(vol: &Party, parent: &SignedHeader, time: u64) -> SignedHeader {
    let mut h = next(parent, Kind::Regenesis, time);
    h.keyholders = vec![vol.entry()];
    h.signer = vol.m;
    signed(Some(parent), h, vol)
}

/// A text group whose only keyholder is browser `b`'s connection pair: its Genesis at `T0`
/// and a Fresh a minute on. `vol` is another connection that volunteers.
struct ConnHeld {
    b: Party,
    vol: Party,
    gen: SignedHeader,
    fresh: SignedHeader,
}

fn conn_held() -> ConnHeld {
    let b = Party::new(MemberId::Conn(7));
    let gen = signed(None, genesis_of(&b, &text(), T0, false), &b);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &b);
    ConnHeld {
        b,
        vol: Party::new(MemberId::Conn(9)),
        gen,
        fresh,
    }
}

fn link_of<'a>(header: &'a SignedHeader, parent: Option<&'a SignedHeader>) -> WalkLink<'a> {
    WalkLink { header, parent }
}

/// Every way a member takes a Regenesis over a set of connection entries alone: as a
/// newcomer walking from the Genesis, walking to its floor, as the start of its walk on
/// trust, and holding the parent or only its floor with the set beside it. Each takes it 2
/// minutes after its parent, and none a second sooner.
#[test]
fn a_regenesis_over_connection_entries_alone_is_taken_two_minutes_after_its_parent() {
    let ConnHeld {
        vol, gen, fresh, ..
    } = conn_held();
    assert_eq!(gen.header().keyholders[0].origin, Origin::Connection as u8);
    let p_time = fresh.header().time;
    let early = regen_by(&vol, &fresh, p_time + FAST - 1);
    let on_time = regen_by(&vol, &fresh, p_time + FAST);
    let now = clock(p_time + FAST + 5);
    let soon = Refusal::Generation("a Regenesis comes two minutes after its parent");
    let floor_gen = Floor::after(None, &gen, T0);
    let floor = Floor::after(Some(&floor_gen), &fresh, T0);

    // A newcomer: no floor, walked from the Genesis
    let newcomer = |r: &SignedHeader| {
        check_walk(
            WalkTo::Start { floor: None },
            &[link_of(&gen, None)],
            link_of(r, Some(&fresh)),
            now,
            NO_PINS,
        )
    };
    assert!(newcomer(&on_time).is_ok());
    assert_eq!(newcomer(&early).err(), Some(soon.clone()));

    // A member whose floor is the Genesis, walking to the Regenesis over the Fresh
    let walker = |r: &SignedHeader| {
        check_walk(
            WalkTo::Floor {
                floor: &floor_gen,
                kh: &gen,
            },
            &[],
            link_of(r, Some(&fresh)),
            now,
            NO_PINS,
        )
    };
    assert!(walker(&on_time).is_ok());
    assert_eq!(walker(&early).err(), Some(soon.clone()));

    // A newcomer whose walk starts at the Regenesis (the relay walks a device with no floor
    // back to its newest Regenesis): it takes it on trust, after the shortest wait still
    let after = signed(
        Some(&on_time),
        next(&on_time, Kind::Join, p_time + FAST + 3),
        &vol,
    );
    let early_after = signed(
        Some(&early),
        next(&early, Kind::Join, p_time + FAST + 3),
        &vol,
    );
    let started = |r: &SignedHeader, head: &SignedHeader| {
        check_walk(
            WalkTo::Start { floor: None },
            &[link_of(r, Some(&fresh))],
            link_of(head, None),
            now,
            NO_PINS,
        )
    };
    assert!(started(&on_time, &after).is_ok());
    assert_eq!(started(&early, &early_after).err(), Some(soon.clone()));

    // Holding the parent, or only the floor, with the set beside it
    assert_eq!(check_link_under(&fresh, &on_time, &gen), Ok(vec![]));
    assert_eq!(
        check_link_under(&fresh, &early, &gen).err(),
        Some(soon.clone())
    );
    assert_eq!(check_on_floor_under(&floor, &on_time, &gen), Ok(vec![]));
    assert_eq!(
        check_on_floor_under(&floor, &early, &gen).err(),
        Some(soon.clone())
    );
    assert!(check_regenesis_under(Some(&floor), now, &on_time, &fresh, &gen).is_ok());
    assert!(check_regenesis_under(None, now, &on_time, &fresh, &gen).is_ok());
    assert_eq!(
        check_regenesis_under(Some(&floor), now, &early, &fresh, &gen).err(),
        Some(soon)
    );

    // A parent that sets keyholders is the set itself: seen without being handed over
    let over_gen = regen_by(&vol, &gen, T0 + FAST);
    assert_eq!(check_link(&gen, &over_gen), Ok(vec![]));
    assert!(check_regenesis(Some(&floor_gen), now, &over_gen, &gen).is_ok());
    assert!(check_link(&gen, &regen_by(&vol, &gen, T0 + FAST - 1)).is_err());
}

/// One entry that is not a connection's (here a desktop's pair, 0x03) keeps the hour for the
/// whole set, whoever shows the set and however the member reaches the Regenesis. Only a
/// device with no floor whose walk starts at the Regenesis takes it sooner: the set before is
/// never shown to it, and it takes a Genesis of any age on trust the same way (§5.7).
#[test]
fn a_regenesis_over_a_set_with_a_desktop_entry_waits_the_hour() {
    let ConnHeld { b, vol, gen, .. } = conn_held();
    let d = Party::new(acct(3));
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 30);
    add.keyholders = vec![b.entry(), d.entry()];
    let add = signed(Some(&gen), add, &b);
    assert!(!connection_only(&add.header().keyholders));
    let fresh = signed(Some(&add), next(&add, Kind::Fresh, T0 + 60), &b);
    let p_time = fresh.header().time;
    let fast = regen_by(&vol, &fresh, p_time + FAST);
    let late = regen_by(&vol, &fresh, p_time + REGENESIS_WAIT - 1);
    let hour = regen_by(&vol, &fresh, p_time + REGENESIS_WAIT);
    let now = clock(p_time + REGENESIS_WAIT + 5);
    let refused = Some(Refusal::Generation(
        "a Regenesis comes an hour after its parent",
    ));
    let floor_add = Floor::after(Some(&Floor::after(None, &gen, T0)), &add, T0);
    let floor = Floor::after(Some(&floor_add), &fresh, T0);
    for r in [&fast, &late] {
        let newcomer = check_walk(
            WalkTo::Start { floor: None },
            &[link_of(&add, None), link_of(&gen, None)],
            link_of(r, Some(&fresh)),
            now,
            NO_PINS,
        );
        assert_eq!(newcomer.err(), refused.clone());
        let walker = check_walk(
            WalkTo::Floor {
                floor: &floor_add,
                kh: &add,
            },
            &[],
            link_of(r, Some(&fresh)),
            now,
            NO_PINS,
        );
        assert_eq!(walker.err(), refused.clone());
        assert_eq!(check_link(&fresh, r).err(), refused.clone());
        assert_eq!(check_link_under(&fresh, r, &add).err(), refused.clone());
        assert_eq!(check_on_floor(&floor, r).err(), refused.clone());
        assert_eq!(check_on_floor_under(&floor, r, &add).err(), refused.clone());
        assert!(check_regenesis(Some(&floor), now, r, &fresh).is_err());
        assert!(check_regenesis(None, now, r, &fresh).is_err());
        assert!(check_regenesis_under(Some(&floor), now, r, &fresh, &add).is_err());
        assert!(check_regenesis_under(None, now, r, &fresh, &add).is_err());
    }
    assert_eq!(check_link_under(&fresh, &hour, &add), Ok(vec![]));
    assert_eq!(check_on_floor_under(&floor, &hour, &add), Ok(vec![]));
    assert!(check_regenesis_under(Some(&floor), now, &hour, &fresh, &add).is_ok());

    // A set of desktops alone, and one connection beside them: the hour either way
    assert_eq!(regenesis_wait(add.header(), p_time), REGENESIS_WAIT);
    assert_eq!(regenesis_wait(gen.header(), p_time), FAST);
    let desktop = signed(None, genesis_of(&d, &text(), T0, false), &d);
    assert_eq!(regenesis_wait(desktop.header(), p_time), REGENESIS_WAIT);

    // The trust start: with no floor and the Regenesis where its walk begins
    let after = signed(
        Some(&fast),
        next(&fast, Kind::Join, p_time + FAST + 3),
        &vol,
    );
    let started = check_walk(
        WalkTo::Start { floor: None },
        &[link_of(&fast, Some(&fresh))],
        link_of(&after, None),
        clock(p_time + FAST + 5),
        NO_PINS,
    );
    assert!(started.is_ok(), "on trust, as a Genesis of any age");
}

/// A member that holds only its floor (a restarted app, or one whose last header was pushed)
/// holds the keyholder header the floor names beside it (§5.7, `LocalFloor.kh`). With it, it
/// takes the fast Regenesis; without it, it waits the hour. No other header passes for the
/// set: one the floor or the Regenesis does not name is refused, so a relay cannot shorten the
/// hour of a set with a desktop entry by showing a set of connections in its place.
#[test]
fn a_member_holding_only_its_floor_takes_a_fast_regenesis_under_the_set_it_holds() {
    let ConnHeld { b, vol, gen, fresh } = conn_held();
    let p_time = fresh.header().time;
    let r = regen_by(&vol, &fresh, p_time + FAST);
    let now = clock(p_time + FAST + 5);
    let floor = Floor::after(Some(&Floor::after(None, &gen, T0)), &fresh, T0);
    let hour = Some(Refusal::Generation(
        "a Regenesis comes an hour after its parent",
    ));
    let not_the_set = Some(Refusal::Chain("kh_parent is not the set in force"));

    // Without the set: the hour (what a member that does not hand it over checks)
    assert_eq!(check_on_floor(&floor, &r).err(), hour.clone());
    assert_eq!(check_regenesis(Some(&floor), now, &r, &fresh).err(), hour);
    // With it: 2 minutes
    assert_eq!(check_on_floor_under(&floor, &r, &gen), Ok(vec![]));
    assert!(check_regenesis_under(Some(&floor), now, &r, &fresh, &gen).is_ok());

    // Another group of connections alone, its Genesis shown as the set: refused
    let other = signed(None, genesis_of(&b, &text(), T0 + 1, false), &b);
    assert_eq!(
        check_on_floor_under(&floor, &r, &other).err(),
        not_the_set.clone()
    );
    assert_eq!(
        check_link_under(&fresh, &r, &other).err(),
        not_the_set.clone()
    );
    assert_eq!(
        check_regenesis_under(Some(&floor), now, &r, &fresh, &other).err(),
        not_the_set.clone()
    );
    // The parent, which sets no keyholders, shown as the set: refused
    assert_eq!(
        check_regenesis_under(Some(&floor), now, &r, &fresh, &fresh).err(),
        not_the_set.clone()
    );

    // A set with a desktop entry, and a set of connections shown in its place
    let d = Party::new(acct(3));
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 30);
    add.keyholders = vec![b.entry(), d.entry()];
    let add = signed(Some(&gen), add, &b);
    let fresh2 = signed(Some(&add), next(&add, Kind::Fresh, T0 + 60), &b);
    let floor2 = Floor::after(Some(&Floor::after(None, &add, T0)), &fresh2, T0);
    let r2 = regen_by(&vol, &fresh2, p_time + FAST);
    for shown in [&gen, &other] {
        assert_eq!(
            check_on_floor_under(&floor2, &r2, shown).err(),
            not_the_set.clone()
        );
        assert_eq!(
            check_link_under(&fresh2, &r2, shown).err(),
            not_the_set.clone()
        );
        assert_eq!(
            check_regenesis_under(Some(&floor2), now, &r2, &fresh2, shown).err(),
            not_the_set.clone()
        );
    }
}

/// The churn bound: a set of connections that a Regenesis itself started keeps the hour for
/// an hour after that Regenesis, so connections that drop again and again (or a relay that
/// drops them) start anew at most once an hour. An hour on, the set goes fast again, 2
/// minutes after its parent.
#[test]
fn a_set_a_regenesis_started_keeps_the_hour_for_an_hour() {
    let ConnHeld { vol, fresh, .. } = conn_held();
    let vol2 = Party::new(MemberId::Conn(11));
    let r1 = regen_by(&vol, &fresh, fresh.header().time + FAST);
    let t1 = r1.header().time;
    assert_eq!(regenesis_wait(r1.header(), t1 + 3599), REGENESIS_WAIT);
    assert_eq!(regenesis_wait(r1.header(), t1 + 3600), FAST);
    let f2 = signed(Some(&r1), next(&r1, Kind::Fresh, t1 + 120), &vol);
    let hour = Some(Refusal::Generation(
        "a Regenesis comes an hour after its parent",
    ));

    // Again 2 minutes after its parent, within the hour of r1: refused everywhere
    let r2 = regen_by(&vol2, &f2, t1 + 240);
    let now = clock(t1 + 300);
    let floor_r1 = Floor::after(None, &r1, t1);
    let floor_f2 = Floor::after(Some(&floor_r1), &f2, t1);
    assert_eq!(check_link_under(&f2, &r2, &r1).err(), hour.clone());
    assert_eq!(
        check_on_floor_under(&floor_f2, &r2, &r1).err(),
        hour.clone()
    );
    assert_eq!(
        check_regenesis_under(Some(&floor_f2), now, &r2, &f2, &r1).err(),
        hour.clone()
    );
    let walker = check_walk(
        WalkTo::Floor {
            floor: &floor_r1,
            kh: &r1,
        },
        &[],
        link_of(&r2, Some(&f2)),
        now,
        NO_PINS,
    );
    assert_eq!(walker.err(), hour.clone());
    // A newcomer whose walk starts at r1, on trust, still sees r1 as r2's set
    let started = check_walk(
        WalkTo::Start { floor: None },
        &[link_of(&r1, Some(&fresh))],
        link_of(&r2, Some(&f2)),
        now,
        NO_PINS,
    );
    assert_eq!(started.err(), hour);

    // An hour after r1, 2 minutes after its parent: taken, and not a second sooner
    let f3 = signed(Some(&r1), next(&r1, Kind::Fresh, t1 + 3500), &vol);
    let r3 = regen_by(&vol2, &f3, t1 + 3500 + FAST);
    let r3_early = regen_by(&vol2, &f3, t1 + 3500 + FAST - 1);
    let now = clock(t1 + 3500 + FAST + 5);
    let floor_f3 = Floor::after(Some(&floor_r1), &f3, t1);
    assert_eq!(check_link_under(&f3, &r3, &r1), Ok(vec![]));
    assert_eq!(check_on_floor_under(&floor_f3, &r3, &r1), Ok(vec![]));
    assert!(check_regenesis_under(Some(&floor_f3), now, &r3, &f3, &r1).is_ok());
    assert!(check_link_under(&f3, &r3_early, &r1).is_err());
    let walker = check_walk(
        WalkTo::Floor {
            floor: &floor_r1,
            kh: &r1,
        },
        &[],
        link_of(&r3, Some(&f3)),
        now,
        NO_PINS,
    );
    assert!(walker.is_ok(), "{walker:?}");
}

#[test]
fn a_header_ten_minutes_ahead_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let h = genesis_of(&k, &g, T0 + CLOCK_SLACK, false);
    assert!(check_time(&h, T0).is_ok());
    let ahead = HeaderV1 {
        time: T0 + CLOCK_SLACK + 1,
        ..h
    };
    assert_eq!(check_time(&ahead, T0), Err(Refusal::Ahead));
    assert_eq!(
        check_new_generation(None, clock(T0), &ahead).err(),
        Some(Refusal::Ahead)
    );
}

#[test]
fn two_floors_merge_to_the_later_generation_and_keep_the_newest_eight() {
    let k = Party::new(acct(1));
    let at = |n: u8, t: u64| {
        let g = Group::new(GroupKind::Text, "c:lounge-1", [n; 16]).unwrap();
        signed(None, genesis_of(&k, &g, t, false), &k)
    };
    let mut a = Floor::after(None, &at(1, T0), T0);
    for n in 2..=6 {
        a = Floor::after(Some(&a), &at(n, T0 + u64::from(n)), T0 + u64::from(n));
    }
    let mut b = Floor::after(None, &at(10, T0 + 10), T0 + 10);
    for n in 11..=14 {
        b = Floor::after(Some(&b), &at(n, T0 + u64::from(n)), T0 + u64::from(n));
    }
    let m = Floor::merge(&a, &b);
    assert_eq!(m.gen, [14; 16], "the later gen_time wins");
    assert_eq!(m, Floor::merge(&b, &a), "either way round");
    let kept: Vec<u8> = m.gens.iter().map(|(g, _)| g[0]).collect();
    assert_eq!(kept, [4, 5, 6, 10, 11, 12, 13, 14]);
    // Within one generation, the higher (epoch, join).
    let g = Group::new(GroupKind::Text, "c:lounge-1", [30; 16]).unwrap();
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let low = Floor::after(None, &gen, T0);
    let high = Floor::after(Some(&low), &fresh, T0);
    assert_eq!(Floor::merge(&low, &high).epoch, 2);
    assert_eq!(Floor::merge(&high, &low).epoch, 2);
    assert!(high.above(&low) && !low.above(&high));
}

// ── Gated groups ──────────────────────────────────────────────────────────

const NO_PINS_AT: &dyn Fn(&[u8; 16], u64) -> PinThen = &|_, _| PinThen::None;
const NO_COUNTERS: &dyn Fn(&[u8; 16]) -> Option<Seen> = &|_| None;

/// What a writer knows: no pins and no counters unless a test says so.
fn knows(now: u64) -> Known<'static> {
    Known {
        pins: NO_PINS_AT,
        counters: NO_COUNTERS,
        own: None,
        now,
    }
}

/// Every member checks the signed `conn_seats` and that no keyholder is a
/// guest; a guest among the `added` names is a keyholder's to refuse and a
/// writer's to hold for, not a reader's (§4.4 rule 6).
#[test]
fn a_guest_in_a_gated_header_or_connection_seats_are_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let guest = Party::new(MemberId::Conn(77));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    assert!(check_gated(gen.header(), None).is_ok());
    let mut join = next(&gen, Kind::Join, T0 + 2);
    join.added = Added::List(vec![guest.added(0)]);
    let with_guest = signed(Some(&gen), join, &k);
    assert_eq!(
        check_gated(with_guest.header(), Some(true)),
        Ok(vec![]),
        "a reader checks no names"
    );
    assert_eq!(
        check_added(with_guest.header(), NO_PINS, NO_COUNTERS, None),
        Err(Refusal::GuestSeat(Some(guest.seat()))),
        "a keyholder does"
    );
    let fold = fold_names(
        &NamesFrom::Floor(NamesFloor::of(gen.header())),
        &[NamesList::of(with_guest.header())],
        &[],
        with_guest.header(),
        &knows(T0 + 3),
    );
    assert!(
        matches!(fold, Ok(Fold::Hold { why: Held::Guest(s), .. }) if s == guest.seat()),
        "and a writer holds: {fold:?}"
    );
    // conn_seats above 0: refused at the form already, as the member decodes it.
    let mut h = next(&gen, Kind::Join, T0 + 2);
    h.conn_seats = 1;
    h.seats = 2;
    h.names_hash = names_hash(Some(gen.header()), &h);
    let (b, s) = raw_signed(&h, &k);
    assert_eq!(decode(&b, &s).err(), Some(Refusal::GuestSeat(None)));
    assert_eq!(
        check_gated(&h, Some(true)).err(),
        Some(Refusal::GuestSeat(None))
    );
    // A guest keyholder.
    let mut guest_kh = genesis_of(&k, &g, T0, true);
    guest_kh.keyholders.push(guest.entry());
    assert_eq!(
        check_gated(&guest_kh, None).err(),
        Some(Refusal::GuestKeyholder)
    );
    // An added IK against its pin, as a keyholder checks it.
    let newcomer = Party::new(acct(5));
    let mut join = next(&gen, Kind::Join, T0 + 2);
    join.added = Added::List(vec![newcomer.added(0)]);
    let pin = k.ik_raw();
    let pins = move |a: &[u8; 16]| (*a == [5; 16]).then_some(pin);
    assert_eq!(
        check_added(&join, &pins, NO_COUNTERS, None).err(),
        Some(Refusal::Pin(newcomer.m))
    );
    assert_eq!(check_gated(&join, Some(true)), Ok(vec![]));
    // gated changes only at an opening header, and a change to open is told.
    let mut open_join = next(&gen, Kind::Join, T0 + 2);
    open_join.gated = false;
    open_join.added = Added::Count(0);
    open_join.removed = Removed::Count(0);
    assert_eq!(
        check_gated(&open_join, Some(true)).err(),
        Some(Refusal::GatedChanged)
    );
    let mut opened = next(&gen, Kind::Fresh, T0 + 60);
    opened.gated = false;
    opened.added = Added::Count(0);
    opened.removed = Removed::Count(0);
    assert_eq!(
        check_gated(&opened, Some(true)).unwrap(),
        [Warning::GatedTurnedOff]
    );
    let opened = signed(Some(&gen), opened, &k);
    assert_eq!(
        check_link(&gen, &opened).unwrap(),
        [Warning::GatedTurnedOff]
    );
}

/// Two names per list, sorted as a header carries them.
fn people(from: u8, lists: usize) -> Vec<Vec<AddedSeat>> {
    (0..lists as u8)
        .map(|i| {
            let mut l: Vec<AddedSeat> = (0..2)
                .map(|j| Party::new(acct(from + i * 2 + j)).added(1))
                .collect();
            l.sort_by_key(|a| postcard::to_allocvec(a).unwrap());
            l
        })
        .collect()
}

/// A Join header after `parent` seating `names`, at `time`.
fn join_of(parent: &SignedHeader, names: &[AddedSeat], time: u64, k: &Party) -> SignedHeader {
    let mut j = next(parent, Kind::Join, time);
    j.added = Added::List(names.to_vec());
    signed(Some(parent), j, k)
}

/// One Join per list after `gen`, 2 s apart, each checked as a link.
fn joins(gen: &SignedHeader, lists: &[Vec<AddedSeat>], k: &Party) -> Vec<SignedHeader> {
    let mut parent = gen.clone();
    let mut heads = vec![];
    for (i, l) in lists.iter().enumerate() {
        let h = join_of(&parent, l, gen.header().time + 2 * (i as u64 + 1), k);
        assert!(check_link(&parent, &h).is_ok());
        heads.push(h.clone());
        parent = h;
    }
    heads
}

fn lists_of(heads: &[SignedHeader]) -> Vec<NamesList> {
    heads.iter().map(|h| NamesList::of(h.header())).collect()
}

/// §4.4 rule 4: a gated writer's post waits until every `added` list since
/// its names floor folds to the head's `names_hash`; a list left out,
/// changed or reordered, or a name dropped, fails the fold.
#[test]
fn a_writer_holds_until_every_list_since_its_names_floor_folds_to_the_head() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let floor = NamesFloor::of(gen.header());
    let people = people(10, 3);
    let heads = joins(&gen, &people, &k);
    // A Join with no names keeps the hash.
    let quiet = signed(Some(&heads[0]), next(&heads[0], Kind::Join, T0 + 3), &k);
    assert_eq!(quiet.header().names_hash, heads[0].header().names_hash);
    let head = heads[2].header();
    let lists = lists_of(&heads);
    let fold =
        |from: &NamesFrom, lists: &[NamesList]| fold_names(from, lists, &[], head, &knows(T0 + 10));
    let from = NamesFrom::Floor(floor);
    let Ok(Fold::Take {
        floor: moved,
        shown:
            Shown {
                named,
                unchecked,
                gone,
                older_unnamed,
            },
        warnings,
    }) = fold(&from, &lists)
    else {
        panic!("the control folds")
    };
    assert_eq!(
        moved,
        NamesFloor::of(head),
        "the names floor moves to the head"
    );
    assert_eq!(named, people.concat(), "every new reader, in order");
    assert!(unchecked.is_empty() && gone.is_empty() && !older_unnamed && warnings.is_empty());
    assert_eq!(fold(&from, &lists[..2]), Err(Refusal::Names), "one to come");
    assert_eq!(
        fold(&from, &[lists[0].clone(), lists[2].clone()]),
        Err(Refusal::Names),
        "a list left out"
    );
    let mut changed = lists.clone();
    changed[1].added[0].n += 1;
    assert_eq!(fold(&from, &changed), Err(Refusal::Names), "a list changed");
    let reordered = [lists[1].clone(), lists[0].clone(), lists[2].clone()];
    assert_eq!(
        fold(&from, &reordered),
        Err(Refusal::Names),
        "lists reordered"
    );
    let mut within = lists.clone();
    within[0].added.reverse();
    assert!(
        matches!(fold(&from, &within), Ok(Fold::Take { .. })),
        "a list is folded sorted, as the header carries it"
    );
    let mut cut = lists.clone();
    cut[1].added.pop();
    assert_eq!(fold(&from, &cut), Err(Refusal::Names), "a name dropped");
    // A list past the head, or one from before the floor, is out of place.
    let mut past = lists.clone();
    past.push(NamesList {
        join: 9,
        ..lists[2].clone()
    });
    assert_eq!(fold(&from, &past), Err(Refusal::Names));
    let mut early = vec![NamesList::of(gen.header())];
    early.extend(lists.iter().cloned());
    assert_eq!(fold(&from, &early), Err(Refusal::Names));
    // So is an empty list, though it steps no hash: one past the head, or
    // one that goes back between two lists in order.
    let empty_at = |join| NamesList {
        join,
        added: vec![],
        ..lists[2].clone()
    };
    let mut past_empty = lists.clone();
    past_empty.push(empty_at(9));
    assert_eq!(fold(&from, &past_empty), Err(Refusal::Names), "past");
    let mut back = lists.clone();
    back.insert(2, empty_at(1));
    assert_eq!(fold(&from, &back), Err(Refusal::Names), "back");
    let mut between = lists.clone();
    between.insert(2, empty_at(lists[1].join));
    assert_eq!(
        fold(&from, &between),
        Err(Refusal::Names),
        "at the same place"
    );
    // A writer whose names floor is in an older generation folds every list
    // since the Genesis, from zero; and only from the real start.
    assert!(matches!(
        fold(&NamesFrom::Start, &early),
        Ok(Fold::Take { .. })
    ));
    assert_eq!(fold(&NamesFrom::Start, &lists), Err(Refusal::Names));
    // A names floor with no chain to the head, from another generation or
    // from while the group was open (0³²), folds from the start itself: the
    // caller's choice of start cannot make an honest relay's lists fail.
    let older = NamesFloor {
        gen: [0x22; 16],
        ..floor
    };
    let zero = NamesFloor {
        names_hash: [0; 32],
        ..floor
    };
    for f in [older, zero] {
        let from_f = NamesFrom::Floor(f);
        assert_eq!(fold(&from_f, &early), fold(&NamesFrom::Start, &early));
        assert_eq!(fold(&from_f, &lists), Err(Refusal::Names), "{f:?}");
    }
    // An open head names nobody: nothing to fold.
    let open = signed(None, genesis_of(&k, &g, T0, false), &k);
    assert!(matches!(
        fold_names(&NamesFrom::Start, &[], &[], open.header(), &knows(T0)),
        Ok(Fold::Take { shown, .. }) if shown == Shown::default()
    ));
}

/// D6: each step of `names_hash` binds its header's `time`, `epoch` and
/// `join`, so a list given another header's place does not fold, and a list
/// moved to another header does not either.
#[test]
fn a_list_given_another_headers_time_epoch_or_join_does_not_fold() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let heads = joins(&gen, &people(10, 2), &k);
    let lists = lists_of(&heads);
    let from = NamesFrom::Floor(NamesFloor::of(gen.header()));
    let head = heads[1].header();
    let fold = |lists: &[NamesList]| fold_names(&from, lists, &[], head, &knows(T0 + 10));
    assert!(matches!(fold(&lists), Ok(Fold::Take { .. })), "the control");
    let p = gen.header().names_hash;
    let first = &lists[0];
    for moved in [
        NamesList {
            time: first.time + 1,
            ..first.clone()
        },
        NamesList {
            time: first.time - 1,
            ..first.clone()
        },
        NamesList {
            join: first.join + 1,
            ..first.clone()
        },
        NamesList {
            epoch: first.epoch + 1,
            ..first.clone()
        },
    ] {
        assert_ne!(names_step(&p, &moved), names_step(&p, first), "{moved:?}");
        assert_eq!(
            fold(&[moved.clone(), lists[1].clone()]),
            Err(Refusal::Names),
            "{moved:?}"
        );
    }
    // The second list's names at the first's place, and the first's at the
    // second's: the same names, the same order, other places.
    let swapped = [
        NamesList {
            added: lists[1].added.clone(),
            ..lists[0].clone()
        },
        NamesList {
            added: lists[0].added.clone(),
            ..lists[1].clone()
        },
    ];
    assert_eq!(fold(&swapped), Err(Refusal::Names));
    // The step is the 98 bytes §11.3 names.
    let step = first.step_from(&p);
    let by_hand: [u8; 32] = sha2::Sha256::new()
        .chain_update(b"voipc-gk/v1/names|")
        .chain_update(p)
        .chain_update(first.time.to_be_bytes())
        .chain_update(first.epoch.to_be_bytes())
        .chain_update(first.join.to_be_bytes())
        .chain_update(names_list_digest(&first.added))
        .finalize()
        .into();
    assert_eq!(step.hash(), by_hand);
    assert_eq!(heads[0].header().names_hash, by_hand);
}

/// Members take headers without the names (owner, 2026-11-17): a reader
/// takes a Join on its floor, whatever its list holds, and checks no entry;
/// a keyholder checks every entry of each header it takes.
#[test]
fn a_gated_reader_takes_headers_without_the_lists() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let floor = Floor::after(None, &gen, T0);
    let impostor = Party::new(acct(5));
    let pin = k.ik_raw();
    let pins = move |a: &[u8; 16]| (*a == [5; 16]).then_some(pin);
    let seen = |a: &[u8; 16]| {
        (*a == [5; 16]).then_some(Seen {
            n: 9,
            made: T0 - 86_400,
        })
    };
    let join = join_of(&gen, &[impostor.added(1)], T0 + 2, &k);
    assert_eq!(check_on_floor(&floor, &join), Ok(vec![]));
    assert_eq!(check_gated(join.header(), Some(floor.gated)), Ok(vec![]));
    assert_eq!(check_link(&gen, &join), Ok(vec![]));
    assert_eq!(
        check_added(join.header(), &pins, &seen, None),
        Err(Refusal::Pin(impostor.m)),
        "the keyholder's check"
    );
    assert!(matches!(
        check_added(join.header(), NO_PINS, &seen, None),
        Err(Refusal::OldCounter {
            n: 1,
            highest: 9,
            own: false,
            ..
        })
    ));
    // And the reader takes the opening header after it on its new floor.
    let floor = Floor::after(Some(&floor), &join, T0);
    let fresh = signed(Some(&join), next(&join, Kind::Fresh, T0 + 60), &k);
    assert_eq!(check_on_floor(&floor, &fresh), Ok(vec![]));
}

/// The exception (§4.4 rule 4, §10 Names): a reader skips other Join
/// headers, but takes the one that seated it, list and all. The list is in
/// the signed body, so the newcomer finds its own entry as writers are shown
/// it, and the app's on-demand check passes it; a list the relay changed
/// does not verify.
#[test]
fn a_newcomer_takes_the_join_header_that_seated_it_with_its_list() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let floor = Floor::after(None, &gen, T0);
    let (me, other) = (Party::new(acct(7)), Party::new(acct(8)));
    let mut names = vec![me.added(1), other.added(1)];
    names.sort_by_key(|a| postcard::to_allocvec(a).unwrap());
    let join = join_of(&gen, &names, T0 + 2, &k);
    assert_eq!(check_on_floor(&floor, &join), Ok(vec![]));
    assert_eq!(check_link(&gen, &join), Ok(vec![]));
    assert_eq!(check_gated(join.header(), Some(floor.gated)), Ok(vec![]));
    let list = NamesList::of(join.header());
    assert!(list.added.contains(&me.added(1)), "its own entry");
    let pin = me.ik_raw();
    let pins = move |a: &[u8; 16]| (*a == [7; 16]).then_some(pin);
    let seen = |a: &[u8; 16]| (*a == [7; 16]).then_some(Seen { n: 1, made: T0 });
    assert_eq!(
        check_added(join.header(), &pins, &seen, Some([7; 16])),
        Ok(())
    );
    // Its entry with another seat key, under the same signature.
    let mut forged = join.header().clone();
    forged.added = Added::List(
        names
            .iter()
            .map(|a| match a.m {
                m if m == me.m => AddedSeat {
                    tag_sk: [0xee; 8],
                    ..*a
                },
                _ => *a,
            })
            .collect(),
    );
    let forged = decode(&forged.encode(), &join.sig()).unwrap();
    assert_eq!(
        check_signer(&forged, Some(&gen), NO_PINS).err(),
        Some(Refusal::Signature)
    );
    assert!(
        check_signer(&join, Some(&gen), NO_PINS).is_ok(),
        "the control"
    );
}

/// A failed fold keeps its names floor at a place the head's `names_hash`
/// binds. An empty list steps nothing, so its `time`, `epoch` and `join` are
/// in no hash: one the relay made up just before the failing list, dated at
/// either end of time, does not become the floor `names_may_be_gone` reads.
#[test]
fn a_failed_fold_keeps_its_names_floor_at_a_signed_place_past_empty_lists() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let a = Party::new(acct(20));
    let guest = Party::new(MemberId::Conn(77));
    let j1 = join_of(&gen, &[a.added(1)], T0 + 2, &k);
    let fresh = signed(Some(&j1), next(&j1, Kind::Fresh, T0 + 60), &k);
    let j2 = join_of(&fresh, &[guest.added(0)], T0 + 62, &k);
    let held = |from: NamesFloor, lists: &[NamesList]| match fold_names(
        &NamesFrom::Floor(from),
        lists,
        &[],
        j2.header(),
        &knows(T0 + 70),
    ) {
        Ok(Fold::Hold { floor, .. }) => floor,
        other => panic!("{other:?}"),
    };
    let (at_gen, at_j1) = (NamesFloor::of(gen.header()), NamesFloor::of(j1.header()));
    let real = lists_of(&[j1.clone(), fresh.clone(), j2.clone()]);
    assert_eq!(
        held(at_gen, &real),
        Some(at_j1),
        "past the opening header's empty list"
    );
    for time in [0, u64::MAX] {
        let made_up = NamesList {
            time,
            epoch: 1,
            join: 9,
            added: vec![],
        };
        let lists = [real[0].clone(), made_up.clone(), real[2].clone()];
        assert_eq!(held(at_gen, &lists), Some(at_j1), "time {time}");
        // With no list stepped before the failing one, it stays put.
        let lists = [made_up, real[2].clone()];
        assert_eq!(held(at_j1, &lists), Some(at_j1), "time {time}");
    }
}

/// §4.4 rule 4 (D7): a writer whose fold meets a guest seat, a pin mismatch
/// or a flagged counter holds its posts and says why, keeps its names floor
/// before that list, and folds on once an opening header after that list
/// names the seat in `removed`.
#[test]
fn a_failed_fold_holds_the_posts_and_keeps_the_names_floor_before_that_list() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let floor = NamesFloor::of(gen.header());
    let guest = Party::new(MemberId::Conn(77));
    let (a, c) = (Party::new(acct(20)), Party::new(acct(21)));
    let lists = vec![vec![a.added(1)], vec![guest.added(0)], vec![c.added(1)]];
    let heads = joins(&gen, &lists, &k);
    let names = lists_of(&heads);
    let from = NamesFrom::Floor(floor);
    let held = fold_names(&from, &names, &[], heads[2].header(), &knows(T0 + 10)).unwrap();
    assert_eq!(
        held,
        Fold::Hold {
            why: Held::Guest(guest.seat()),
            floor: Some(NamesFloor::of(heads[0].header())),
            shown: Shown {
                named: vec![a.added(1)],
                ..Shown::default()
            },
            warnings: vec![],
        },
        "past the list that passed, whose reader is shown, before the one that failed"
    );
    // A name before the failed one in the same list is not shown yet: the
    // names floor does not pass that list.
    let x = Party::new(acct(22));
    let mixed = join_of(&gen, &[x.added(1), guest.added(0)], T0 + 2, &k);
    assert_eq!(
        fold_names(
            &from,
            &[NamesList::of(mixed.header())],
            &[],
            mixed.header(),
            &knows(T0 + 3)
        ),
        Ok(Fold::Hold {
            why: Held::Guest(guest.seat()),
            floor: Some(floor),
            shown: Shown::default(),
            warnings: vec![],
        })
    );
    // Failing in the first list it folds keeps the floor where it was.
    let from_a = NamesFrom::Floor(NamesFloor::of(heads[0].header()));
    assert!(matches!(
        fold_names(&from_a, &names[1..], &[], heads[2].header(), &knows(T0 + 10)),
        Ok(Fold::Hold { floor: Some(f), .. }) if f == NamesFloor::of(heads[0].header())
    ));
    // An opening header after the list names the guest's seat in `removed`.
    let mut out = next(&heads[2], Kind::Fresh, T0 + 60);
    out.removed = Removed::List(vec![guest.seat()]);
    let out = signed(Some(&heads[2]), out, &k);
    assert_eq!(check_link(&heads[2], &out), Ok(vec![]));
    let taken = fold_names(
        &from_a,
        &names[1..],
        std::slice::from_ref(&out),
        out.header(),
        &knows(T0 + 61),
    );
    assert!(
        matches!(&taken, Ok(Fold::Take { shown, floor, .. })
            if shown.named == vec![c.added(1)] && shown.gone == vec![guest.seat()]
                && *floor == NamesFloor::of(out.header())),
        "named and gone: {taken:?}"
    );
    // The removal counts only after the list, at or before the head, in the
    // head's generation.
    assert!(matches!(
        fold_names(
            &from_a,
            &names[1..],
            std::slice::from_ref(&out),
            heads[2].header(),
            &knows(T0 + 61)
        ),
        Ok(Fold::Hold { .. })
    ));
    let elsewhere = Group::new(GroupKind::Text, "c:lounge-1", [0x22; 16]).unwrap();
    let other_gen = signed(None, genesis_of(&k, &elsewhere, T0, true), &k);
    let mut stray = next(&other_gen, Kind::Fresh, T0 + 60);
    stray.removed = Removed::List(vec![guest.seat()]);
    let stray = signed(Some(&other_gen), stray, &k);
    let quiet_out = signed(Some(&heads[2]), next(&heads[2], Kind::Fresh, T0 + 60), &k);
    assert!(matches!(
        fold_names(
            &from_a,
            &names[1..],
            &[stray],
            quiet_out.header(),
            &knows(T0 + 61)
        ),
        Ok(Fold::Hold { .. })
    ));
    // An opening header that named the seat before the list seated it
    // removes nothing the list put there.
    let mut early = next(&gen, Kind::Fresh, T0 + 60);
    early.removed = Removed::List(vec![guest.seat()]);
    let early = signed(Some(&gen), early, &k);
    let late_join = join_of(&early, &[guest.added(0)], T0 + 62, &k);
    assert!(matches!(
        fold_names(
            &NamesFrom::Floor(NamesFloor::of(early.header())),
            &[NamesList::of(late_join.header())],
            std::slice::from_ref(&early),
            late_join.header(),
            &knows(T0 + 63)
        ),
        Ok(Fold::Hold {
            why: Held::Guest(_),
            ..
        })
    ));

    // A pin mismatch at the list's time, and a pin the device no longer knows.
    let newcomer = [vec![a.added(1)]];
    let one = joins(&gen, &newcomer, &k);
    let one_list = lists_of(&one);
    let other_ik = c.ik_raw();
    let a_ik = a.ik_raw();
    // a's pin changed at T0 + 1000: the old one was a's IK, the new one c's.
    let history = move |acct: &[u8; 16], t: u64| match (*acct == [20; 16], t < T0 + 1000) {
        (false, _) => PinThen::None,
        (true, true) => PinThen::Pin(a_ik),
        (true, false) => PinThen::Pin(other_ik),
    };
    let fold_with = |pins: PinsAt| {
        let known = Known {
            pins,
            ..knows(T0 + 2000)
        };
        fold_names(&from, &one_list, &[], one[0].header(), &known)
    };
    assert!(
        matches!(fold_with(&history), Ok(Fold::Take { .. })),
        "checked against the pin as it stood then"
    );
    let now_only = move |acct: &[u8; 16], _: u64| {
        if *acct == [20; 16] {
            PinThen::Pin(other_ik)
        } else {
            PinThen::None
        }
    };
    assert!(matches!(
        fold_with(&now_only),
        Ok(Fold::Hold { why: Held::Pin(s), .. }) if s == a.seat()
    ));
    let forgotten = |_: &[u8; 16], _: u64| PinThen::Unknown;
    assert!(
        matches!(fold_with(&forgotten), Ok(Fold::Take { shown, .. })
            if shown.unchecked == [a.added(1)] && shown.named == [a.added(1)]),
        "shown, not refused"
    );
    // A flagged counter.
    let counters = |acct: &[u8; 16]| {
        (*acct == [20; 16]).then_some(Seen {
            n: 3,
            made: T0 - 86_400,
        })
    };
    let known = Known {
        counters: &counters,
        ..knows(T0 + 10)
    };
    assert_eq!(
        fold_names(&from, &one_list, &[], one[0].header(), &known),
        Ok(Fold::Hold {
            why: Held::Counter {
                seat: a.seat(),
                n: 1,
                highest: 3
            },
            floor: Some(floor),
            shown: Shown::default(),
            warnings: vec![],
        })
    );
}

/// Rule 8 at a fold (D6): a writer that folds its own account's old seat
/// from a header made before its rotation does not flag it; from a header
/// made after the new endorsement's `made` plus `CLOCK_SLACK`, it holds its
/// posts and warns.
#[test]
fn a_writers_own_old_seat_from_before_its_rotation_is_not_flagged_and_after_it_is() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let me = Party::new(acct(5));
    let rotation = T0 + 3600;
    let counters = move |a: &[u8; 16]| {
        (*a == [5; 16]).then_some(Seen {
            n: 2,
            made: rotation,
        })
    };
    let fold_at = |time: u64, own: Option<[u8; 16]>| {
        let head = join_of(&gen, &[me.added(1)], time, &k);
        let known = Known {
            counters: &counters,
            own,
            ..knows(time + 10)
        };
        fold_names(
            &NamesFrom::Floor(NamesFloor::of(gen.header())),
            &[NamesList::of(head.header())],
            &[],
            head.header(),
            &known,
        )
        .unwrap()
    };
    let own = Some([5; 16]);
    for before in [rotation - 3600, rotation, rotation + CLOCK_SLACK] {
        assert!(
            matches!(fold_at(before, own), Fold::Take { ref warnings, .. } if warnings.is_empty()),
            "at {before}"
        );
    }
    let after = rotation + CLOCK_SLACK + 1;
    let Fold::Hold { why, warnings, .. } = fold_at(after, own) else {
        panic!("held after the rotation")
    };
    assert_eq!(
        why,
        Held::Counter {
            seat: me.seat(),
            n: 1,
            highest: 2
        }
    );
    assert_eq!(warnings, [Warning::OldOwnSeat { n: 1, own: 2 }]);
    let Fold::Hold { warnings, .. } = fold_at(after, None) else {
        panic!("held for another's account too")
    };
    assert!(warnings.is_empty(), "only its own account warns");
}

/// The tail proof (D6): a writer away more than 90 days takes "gone" only
/// with a step before the tail that is more than 90 days old and folds, with
/// the tail, to the head's `names_hash`; it checks and shows the tail's
/// names and says that older ones went unnamed. A step younger than that, a
/// step or tail that does not fold, or a names floor 89 days old, is refused.
#[test]
fn a_gone_answer_is_taken_only_with_a_step_ninety_days_old_that_folds_to_the_head() {
    let (g, k) = (text(), Party::new(acct(1)));
    let day = 86_400;
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let floor = NamesFloor::of(gen.header());
    let people = people(30, 3);
    let old = join_of(&gen, &people[0], T0 + 60, &k);
    let recent = join_of(&old, &people[1], T0 + 95 * day, &k);
    let newest = join_of(&recent, &people[2], T0 + 95 * day + 2, &k);
    let now = T0 + 96 * day;
    let step = NamesList::of(old.header()).step_from(&gen.header().names_hash);
    let tail = lists_of(&[recent.clone(), newest.clone()]);
    let gone = |floor: NamesFloor, step: NamesStep, tail: &[NamesList], now: u64| {
        fold_names(
            &NamesFrom::Gone { floor, step },
            tail,
            &[],
            newest.header(),
            &knows(now),
        )
    };
    let Ok(Fold::Take {
        shown: Shown {
            named,
            older_unnamed,
            ..
        },
        floor: moved,
        ..
    }) = gone(floor, step, &tail, now)
    else {
        panic!("the control takes it")
    };
    assert!(
        older_unnamed,
        "people joined more than 90 days ago went unnamed"
    );
    assert_eq!(named, [people[1].clone(), people[2].clone()].concat());
    assert_eq!(moved, NamesFloor::of(newest.header()));
    // A step younger than 90 days: the relay holds what comes after it.
    let young = NamesList::of(recent.header()).step_from(&old.header().names_hash);
    assert_eq!(
        gone(floor, young, &tail[1..], now),
        Err(Refusal::NamesNotGone)
    );
    // A step whose time the relay moved back, or a tail with a list left out.
    let backdated = NamesStep {
        time: T0 - day,
        ..young
    };
    assert_eq!(gone(floor, backdated, &tail[1..], now), Err(Refusal::Names));
    assert_eq!(gone(floor, step, &tail[1..], now), Err(Refusal::Names));
    let mut wrong = step;
    wrong.list[0] ^= 1;
    assert_eq!(gone(floor, wrong, &tail, now), Err(Refusal::Names));
    // A writer away 89 days takes no "gone".
    assert_eq!(
        gone(floor, step, &tail, T0 + 89 * day),
        Err(Refusal::NamesNotGone)
    );
    // At the edge, a second past 90 days away: a step 90 days less the
    // slack old, and one second more, is old enough; a second less is not.
    let at_edge = |age: u64| {
        let now = T0 + NAMES_KEPT + 1;
        let before_tail = join_of(&gen, &people[0], now - age, &k);
        let head = join_of(&before_tail, &people[1], now - 1, &k);
        let step = NamesList::of(before_tail.header()).step_from(&gen.header().names_hash);
        fold_names(
            &NamesFrom::Gone { floor, step },
            &[NamesList::of(head.header())],
            &[],
            head.header(),
            &knows(now),
        )
    };
    assert!(matches!(
        at_edge(NAMES_KEPT - CLOCK_SLACK + 1),
        Ok(Fold::Take { .. })
    ));
    assert_eq!(
        at_edge(NAMES_KEPT - CLOCK_SLACK),
        Err(Refusal::NamesNotGone)
    );
    // A tail whose entry fails holds, its names floor at the step.
    let guest = Party::new(MemberId::Conn(5));
    let bad = join_of(&old, &[guest.added(0)], T0 + 95 * day, &k);
    let held = fold_names(
        &NamesFrom::Gone { floor, step },
        &[NamesList::of(bad.header())],
        &[],
        bad.header(),
        &knows(now),
    );
    assert!(matches!(
        held,
        Ok(Fold::Hold { floor: Some(f), shown, .. })
            if f.names_hash == old.header().names_hash && f.time == old.header().time
                && shown.older_unnamed
    ));
}

// ── Counters ──────────────────────────────────────────────────────────────

/// Rule 8 with D6's time rule: a counter below the highest seen is flagged
/// only in a header made after that endorsement's `made` plus `CLOCK_SLACK`.
/// A keyholder refuses such an `added` entry; every member refuses such a
/// new keyholder entry; one of its own account says so.
#[test]
fn an_added_entry_or_new_keyholder_with_a_counter_below_the_highest_seen_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let p = Party::new(acct(5));
    let made = T0 - 86_400;
    let highest = move |a: &[u8; 16]| (*a == [5; 16]).then_some(Seen { n: 5, made });
    let with = |n| {
        let mut j = next(&gen, Kind::Join, T0 + 2);
        j.added = Added::List(vec![p.added(n)]);
        j
    };
    assert!(check_added(&with(5), NO_PINS, &highest, None).is_ok());
    assert_eq!(
        check_added(&with(4), NO_PINS, &highest, None).err(),
        Some(Refusal::OldCounter {
            account: [5; 16],
            n: 4,
            highest: 5,
            own: false,
        })
    );
    assert_eq!(
        check_added(&with(4), NO_PINS, &highest, Some([5; 16])).err(),
        Some(Refusal::OldCounter {
            account: [5; 16],
            n: 4,
            highest: 5,
            own: true,
        }),
        "its own account: refused, and the app warns"
    );
    // A header made before the newer endorsement, or within the slack after
    // it, does not flag the older counter.
    for at in [made - 1, made, made + CLOCK_SLACK] {
        let mut h = with(4);
        h.time = at;
        assert!(check_added(&h, NO_PINS, &highest, None).is_ok(), "at {at}");
        assert_eq!(counter_flagged(4, at, highest(&[5; 16])), None);
    }
    assert_eq!(
        counter_flagged(4, made + CLOCK_SLACK + 1, highest(&[5; 16])),
        Some(5)
    );
    assert_eq!(counter_flagged(4, u64::MAX, None), None, "nothing seen");
    // A new keyholder entry, and one the parent's set already held.
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 60);
    let mut entry = p.entry();
    entry.n = 4;
    add.keyholders = vec![k.entry(), entry];
    for own in [None, Some([1; 16]), Some([5; 16])] {
        assert_eq!(
            check_counters(&add, &gen.header().keyholders, &highest, own),
            Err(Refusal::OldCounter {
                account: [5; 16],
                n: 4,
                highest: 5,
                own: own == Some([5; 16]),
            }),
            "{own:?}: only its own account says so"
        );
    }
    assert!(check_counters(&add, &add.keyholders, &highest, None).is_ok());
    let mut early = add.clone();
    early.time = made;
    assert!(
        check_counters(&early, &gen.header().keyholders, &highest, None).is_ok(),
        "made before the newer endorsement"
    );
    // A guest has no account and no counter to compare.
    let guest = Party::new(MemberId::Conn(3));
    let mut j = next(&gen, Kind::Join, T0 + 2);
    j.added = Added::List(vec![guest.added(0)]);
    let any = |_: &[u8; 16]| Some(Seen { n: 9, made: 0 });
    assert_eq!(
        check_added(&j, NO_PINS, &any, None),
        Err(Refusal::GuestSeat(Some(guest.seat()))),
        "refused as a guest, not by a counter"
    );
}

#[test]
fn a_voice_keyholder_must_be_among_the_four_lowest_user_ids() {
    let g = voice();
    let k = Party::new(MemberId::Conn(30));
    let mut h = genesis_of(&k, &g, T0, false);
    h.keyholders[0].u = Some(30);
    h.keyholders[0].origin = 0x02;
    assert!(check_voice_keyholders(&h, &[], &[50, 10, 20, 30, 40]).is_ok());
    assert_eq!(
        check_voice_keyholders(&h, &[], &[50, 10, 20, 25, 40]).err(),
        Some(Refusal::VoiceKeyholder(30))
    );
}

// ── Posts, blobs, lists ───────────────────────────────────────────────────

#[test]
fn a_post_with_another_prefix_is_refused_and_a_moved_blob_does_not_open() {
    let g = text();
    let ep = Epoch { e: 4, d_e: [4; 32] };
    let plain = post_plaintext(&GEN, &ep, b"hello");
    assert_eq!(plain.len(), 16 + 4 + 32 + 5);
    assert_eq!(open_post(&GEN, &ep, &plain).unwrap(), b"hello");
    assert!(
        open_post(&[0x12; 16], &ep, &plain).is_err(),
        "another generation"
    );
    assert!(
        open_post(&GEN, &Epoch { e: 5, ..ep }, &plain).is_err(),
        "another epoch"
    );
    assert!(
        open_post(&GEN, &Epoch { d_e: [5; 32], ..ep }, &plain).is_err(),
        "the fork"
    );
    assert!(open_post(&GEN, &ep, &plain[..51]).is_err());
    // A blob moved to another header of the same epoch number (a fork), or
    // to another writer, does not open there.
    let ck = key();
    let ik = IdentityKeyPair::generate(&mut crate::rng());
    let w = Writer { m: acct(1), u: 1 };
    let blob = writer_blob(&g, &ep, &w, &ck, &ik, &skdm_for(&g, &ep)).unwrap();
    let fork = Epoch { d_e: [5; 32], ..ep };
    assert_eq!(
        open_writer_blob(&g, &fork, &w, &ck, &blob).err(),
        Some(GkError::Sealed)
    );
    assert_ne!(
        dist(&g, &ep),
        dist(&g, &fork),
        "and each half files its own sender key"
    );
}

/// A member who holds `CK_e` writes as Alice: the blob opens, and its
/// signature is by the key inside, not Alice's pin; one whose signature
/// does not cover its bytes is refused outright.
#[test]
fn a_forged_blob_is_refused() {
    let g = text();
    let ep = Epoch { e: 1, d_e: [1; 32] };
    let ck = key();
    let (alice, mallory) = (
        IdentityKeyPair::generate(&mut crate::rng()),
        IdentityKeyPair::generate(&mut crate::rng()),
    );
    let w = Writer { m: acct(1), u: 1 };
    let skdm = skdm_for(&g, &ep);
    let as_alice = writer_blob(&g, &ep, &w, &ck, &mallory, &skdm).unwrap();
    let opened = open_writer_blob(&g, &ep, &w, &ck, &as_alice).unwrap();
    assert_ne!(
        opened.ik,
        *alice.identity_key(),
        "the reader's pin check refuses it"
    );
    // Alice's signature with Mallory's sender key in the blob.
    let real = writer_blob(&g, &ep, &w, &ck, &alice, &skdm).unwrap();
    let plain = super::open_derived(&ck, &writer_ctx(&g, &ep, &w), &real).unwrap();
    let other_skdm = skdm_for(&g, &ep);
    assert_eq!(other_skdm.len(), skdm.len());
    let swapped = [&plain[..2], &other_skdm[..], &plain[2 + skdm.len()..]].concat();
    let resealed = super::seal_derived(&ck, &writer_ctx(&g, &ep, &w), &swapped);
    assert_eq!(
        open_writer_blob(&g, &ep, &w, &ck, &resealed).err(),
        Some(GkError::Forged)
    );
    // A signature S + ℓ.
    let sig: [u8; 64] = plain[plain.len() - 64..].try_into().unwrap();
    if let Some(sig2) = plus_ell(&sig) {
        let malleated = [&plain[..plain.len() - 64], &sig2[..]].concat();
        let resealed = super::seal_derived(&ck, &writer_ctx(&g, &ep, &w), &malleated);
        assert_eq!(
            open_writer_blob(&g, &ep, &w, &ck, &resealed).err(),
            Some(GkError::Forged)
        );
    }
}

#[test]
fn a_reversion_with_an_extra_seat_is_refused_by_the_list_digest() {
    let g = text();
    let (a, b, c) = (
        Party::new(acct(1)),
        Party::new(acct(2)),
        Party::new(acct(3)),
    );
    let old = Version { b: 4, v: 40 };
    let list = [a.seat(), b.seat()];
    let digest = list_digest(&g, old, &list);
    assert_eq!(
        digest,
        list_digest(&g, old, &[b.seat(), a.seat(), a.seat()])
    );
    assert!(
        check_reversion(&g, old, &digest, &list, &[a.seat()]).is_ok(),
        "a leaver gone"
    );
    assert_eq!(
        check_reversion(&g, old, &digest, &list, &[a.seat(), c.seat()]).err(),
        Some(GkError::Forged),
        "a seat that was not in the old version"
    );
    // The relay's list with the extra seat slipped into the old version.
    let padded = [a.seat(), b.seat(), c.seat()];
    assert_eq!(
        check_reversion(&g, old, &digest, &padded, &padded).err(),
        Some(GkError::Sealed)
    );
    assert_ne!(
        digest,
        list_digest(&g, Version { b: 4, v: 41 }, &list),
        "names its version"
    );
    assert_ne!(digest, list_digest(&voice_named_alike(), old, &list));
    let new_key_same_account = Party::new(acct(2));
    assert_ne!(
        digest,
        list_digest(&g, old, &[a.seat(), new_key_same_account.seat()]),
        "new seat keys are a new seat"
    );
}

// ── The keyring ───────────────────────────────────────────────────────────

struct Case {
    base: KeyringBase,
    deltas: Vec<KeyringDelta>,
    /// What the context says: `s`, `e`, `KS`, each delta's `j`.
    s: u32,
    e: u32,
    ks: Option<[u8; 32]>,
    js: Vec<u32>,
    krk: [u8; 32],
}

fn bucket(b: u64, pool: Pool, seats: u16) -> KeyringBucket {
    KeyringBucket {
        b,
        v: b * 10,
        pool,
        seats,
        list: [b as u8; 32],
        via: Via::Row,
        bk: Zeroizing::new([b as u8 + 1; 32]),
        made: T0,
    }
}

fn case() -> Case {
    Case {
        base: KeyringBase {
            gen: GEN,
            epoch: 3,
            join: 0,
            seeds: vec![(2, Zeroizing::new([2; 32])), (3, Zeroizing::new([3; 32]))],
            ck: Zeroizing::new([7; 32]),
            exits_upto: 5,
            buckets: vec![bucket(1, Pool::Accounts, 62), bucket(5, Pool::Conns, 4)],
        },
        deltas: vec![
            KeyringDelta {
                join: 1,
                buckets: vec![bucket(3, Pool::Accounts, 2)],
            },
            KeyringDelta {
                join: 2,
                buckets: vec![bucket(9, Pool::Conns, 1)],
            },
        ],
        s: 3,
        e: 3,
        ks: None,
        js: vec![1, 2],
        krk: [0x42; 32],
    }
}

/// Seals the case and takes it under a head that matches what `case()`
/// holds, after `edit` changes the head.
fn take_case(c: Case, edit: impl FnOnce(&mut HeaderV1)) -> Result<Keyring, GkError> {
    take_case_by(c, |_, _, h| {
        edit(h);
        (text(), None)
    })
}

/// `take_case`, with `edit` also seeing the keyholder and the Genesis, and
/// saying which group the keyring is taken in and which keyholder header is
/// passed as the head's set (`None`: the Genesis, the one the head names).
fn take_case_by(
    c: Case,
    edit: impl FnOnce(&Party, &SignedHeader, &mut HeaderV1) -> (Group, Option<SignedHeader>),
) -> Result<Keyring, GkError> {
    let g = text();
    let k = Party::new(acct(1));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let ks =
        c.ks.unwrap_or_else(|| keyholder_set_digest(&gen.header().keyholders));
    let mut plain_base = c.base.clone();
    plain_base.epoch = c.e;
    let base = seal_base(&g, c.s, &ks, &c.krk, &plain_base);
    let deltas: Vec<Vec<u8>> = c
        .deltas
        .iter()
        .zip(&c.js)
        .map(|(d, j)| {
            seal_delta(
                &g,
                c.e,
                c.s,
                &ks,
                &c.krk,
                &KeyringDelta {
                    join: *j,
                    ..d.clone()
                },
            )
        })
        .collect();
    let mut hash = keyring_hash_start(&base);
    for d in &deltas {
        hash = keyring_hash_next(&hash, d);
    }
    let mut all: Vec<KeyringBucket> = c.base.buckets.clone();
    for d in &c.deltas {
        all.extend(d.buckets.iter().cloned());
    }
    all.sort_by_key(|b| b.b);
    let leaves: Vec<Leaf> = all.iter().map(KeyringBucket::leaf).collect();
    let mut head = HeaderV1 {
        epoch: 3,
        join: 2,
        kind: Kind::Join,
        parent: [1; 32],
        epoch_parent: [2; 32],
        kh_parent: gen.d(),
        keyholders: vec![],
        seed: 3,
        seed_floor: 2,
        seats: all.iter().map(|b| u32::from(b.seats)).sum(),
        buckets: all.len() as u32,
        conn_seats: all
            .iter()
            .filter(|b| b.pool == Pool::Conns)
            .map(|b| u32::from(b.seats))
            .sum(),
        bucket_root: bucket_root(&leaves).unwrap_or([0; 32]),
        keyring_hash: hash,
        confirm: confirm(&g, 3, 2, &c.base.ck),
        ..gen.header().clone()
    };
    let (taken_in, kh) = edit(&k, &gen, &mut head);
    let head = signed(None, head, &k);
    take_keyring(
        &taken_in,
        &head,
        kh.as_ref().unwrap_or(&gen),
        &c.krk,
        &base,
        &deltas,
    )
}

#[test]
fn a_keyring_that_matches_its_head_is_taken() {
    let ring = take_case(case(), |_| {}).unwrap();
    assert_eq!(
        ring.buckets.iter().map(|b| b.b).collect::<Vec<_>>(),
        [1, 3, 5, 9]
    );
    assert_eq!(ring.ck(), &[7; 32]);
    assert_eq!(ring.seed(3), Some(&[3; 32]));
}

#[test]
fn a_keyring_whose_hash_root_seats_position_seeds_or_confirm_do_not_match_its_head_is_refused() {
    let refused = |c: Case, edit: fn(&mut HeaderV1), why: &str| {
        assert!(take_case(c, edit).is_err(), "{why}");
    };
    refused(case(), |h| h.keyring_hash[0] ^= 1, "the hash");
    refused(case(), |h| h.bucket_root[0] ^= 1, "the root");
    refused(case(), |h| h.conn_seats = 4, "conn_seats");
    refused(case(), |h| h.seats += 1, "seats");
    refused(case(), |h| h.buckets = 3, "buckets");
    refused(case(), |h| h.confirm[0] ^= 1, "confirm");
    refused(case(), |h| h.gen = [0x12; 16], "the generation");
    refused(case(), |h| h.seed = 4, "the seed number");
    refused(
        case(),
        |h| h.seed_floor = 3,
        "the seed list against the floor",
    );
    refused(case(), |h| h.join = 1, "a delta more than the head names");
    refused(
        Case { s: 2, ..case() },
        |_| {},
        "sealed under another seed number",
    );
    refused(Case { e: 4, ..case() }, |_| {}, "sealed in another epoch");
    refused(
        Case {
            ks: Some([9; 32]),
            ..case()
        },
        |_| {},
        "another keyholder set",
    );
    refused(
        Case {
            js: vec![2, 1],
            ..case()
        },
        |_| {},
        "deltas out of position",
    );
    let mut c = case();
    c.base.seeds.remove(0);
    refused(c, |_| {}, "a seed missing");
    let mut c = case();
    c.base.join = 1;
    refused(c, |_| {}, "a base at join 1");
    let mut c = case();
    c.base.gen = [0x12; 16];
    refused(c, |_| {}, "a base of another generation");
    let mut c = case();
    c.deltas[0].buckets[0].via = Via::Ratchet { from: 1 };
    refused(c, |_| {}, "a Join makes no ratchet");
    let mut c = case();
    c.deltas[0].buckets[0].seats = 63;
    refused(c, |_| {}, "a bucket of 63");
    let mut c = case();
    c.deltas[1].buckets[0].b = 1;
    refused(c, |_| {}, "a Join makes no new version of an old bucket");
}

#[test]
fn a_keyring_part_opens_under_its_krk_and_its_context_only() {
    let g = text();
    let (krk, ks) = (key(), [3u8; 32]);
    let c = case();
    let base = seal_base(&g, 3, &ks, &krk, &c.base);
    let delta = seal_delta(&g, 3, 3, &ks, &krk, &c.deltas[0]);
    let open = |e, s, ks: &[u8; 32], krk: &[u8; 32], part, sealed: &[u8]| {
        open_keyring_part(&g, e, s, ks, krk, part, sealed)
    };
    assert!(open(3, 3, &ks, &krk, KeyringPart::Base, &base).is_ok());
    assert!(open(3, 3, &ks, &krk, KeyringPart::Delta(1), &delta).is_ok());
    assert!(
        open(3, 3, &ks, &krk, KeyringPart::Delta(0), &base).is_err(),
        "a base as a delta"
    );
    assert!(
        open(3, 3, &ks, &krk, KeyringPart::Base, &delta).is_err(),
        "a delta as a base"
    );
    assert!(
        open(3, 3, &ks, &krk, KeyringPart::Delta(2), &delta).is_err(),
        "another position"
    );
    assert!(
        open(4, 3, &ks, &krk, KeyringPart::Base, &base).is_err(),
        "another epoch"
    );
    assert!(
        open(3, 2, &ks, &krk, KeyringPart::Base, &base).is_err(),
        "another seed"
    );
    assert!(
        open(3, 3, &[4; 32], &krk, KeyringPart::Base, &base).is_err(),
        "another set"
    );
    assert!(
        open(3, 3, &ks, &key(), KeyringPart::Base, &base).is_err(),
        "another KRK"
    );
    assert!(open_keyring_part(
        &voice_named_alike(),
        3,
        3,
        &ks,
        &krk,
        KeyringPart::Base,
        &base
    )
    .is_err());
}

#[test]
fn a_keyring_with_an_all_zero_key_is_refused() {
    let mut c = case();
    c.base.ck = Zeroizing::new([0; 32]);
    assert_eq!(take_case(c, |_| {}).err(), Some(GkError::WeakKey));
    let mut c = case();
    c.base.seeds[1].1 = Zeroizing::new([0; 32]);
    assert_eq!(take_case(c, |_| {}).err(), Some(GkError::WeakKey));
    let mut c = case();
    c.krk = [0; 32];
    assert_eq!(take_case(c, |_| {}).err(), Some(GkError::WeakKey));
    // A bucket key of zero: the head committing to it does not help.
    let mut c = case();
    c.base.buckets[0].bk = Zeroizing::new([0; 32]);
    assert_eq!(take_case(c, |_| {}).err(), Some(GkError::WeakKey));
}

// ── Contexts ──────────────────────────────────────────────────────────────

/// One of each context, every field at a distinct value, with the kind of
/// each field after the label: `k` the group kind, `g` a group id, `G` 32 hex
/// digits, `X` 64, `t` 16, `d` a decimal, `m` a member id, `w` a writer, `W`
/// a fixed word.
fn every_context(g: &Group) -> Vec<(String, &'static str)> {
    let seat = SeatRef {
        m: acct(1),
        tag_sk: [2; 8],
        tag_sx: [3; 8],
    };
    let k = HolderId {
        m: MemberId::Conn(4),
        tag_kx: [5; 8],
    };
    let ep = Epoch { e: 6, d_e: [7; 32] };
    let at = Version { b: 8, v: 9 };
    let w = Writer { m: acct(1), u: 10 };
    vec![
        (member_ctx(g, 11, &seat), "kgGdmtt"),
        (
            welcome_ctx(g, 11, WelcomeKind::Seat { at, to: &seat }, &k),
            "kgGdWWddmttmt",
        ),
        (
            welcome_ctx(g, 11, WelcomeKind::Seed { to: &seat }, &k),
            "kgGdWWmttmt",
        ),
        (
            welcome_ctx(
                g,
                11,
                WelcomeKind::Keyring {
                    e: 6,
                    ks: &[12; 32],
                    to: &k,
                    tag_kk: &[13; 8],
                },
                &k,
            ),
            "kgGdWWdXmttmt",
        ),
        (rowbase_ctx(g, 11, &seat.m, &seat.tag_sx, &k), "kgGdmtmt"),
        (row_ctx(g, 11, at, &seat.m, &k.m), "kgGdddmm"),
        (seal_ctx(g, &ep, at), "kgGdXdd"),
        (ratchet_ctx(g, 6, at, 14), "kgGdddd"),
        (confirm_ctx(g, 6, 15), "kgGdd"),
        (list_ctx(g, at), "kgGdd"),
        (
            keyring_ctx(g, 6, 15, 11, &[12; 32], KeyringWord::Base),
            "kgGdddXW",
        ),
        (
            keyring_ctx(g, 6, 15, 11, &[12; 32], KeyringWord::Delta),
            "kgGdddXW",
        ),
        (writer_ctx(g, &ep, &w), "kgGdXw"),
        (writer_sig_ctx(g, &ep, &w), "kgGdXw"),
        (dist_ctx(g, &ep), "kgGdX"),
        (chain_ctx(g, &ep, &seat.m, 16, 1), "kgGdXmdd"),
        (media_ctx(g, &ep, &seat.m, &seat.tag_sx, 17), "kgGdXmtd"),
        (self_ctx(g, 11, &seat), "kgGdmtt"),
        (self_history_ctx(g, 11, &seat), "kgGdmtt"),
    ]
}

fn is_hex(f: &str, len: usize) -> bool {
    f.len() == len && f.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_decimal(f: &str) -> bool {
    !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) && (f == "0" || !f.starts_with('0'))
}

fn is_member(f: &str) -> bool {
    f.strip_prefix("a:").is_some_and(|h| is_hex(h, 32))
        || f.strip_prefix("g:").is_some_and(is_decimal)
}

/// Whether `f` has the one format a field of `kind` can have.
fn field_ok(kind: char, f: &str) -> bool {
    match kind {
        'k' => f == "t" || f == "v",
        'g' => valid_group_id(f),
        'G' => is_hex(f, 32),
        'X' => is_hex(f, 64),
        't' => is_hex(f, 16),
        'd' => is_decimal(f),
        'm' => is_member(f),
        'w' => f
            .rsplit_once('/')
            .is_some_and(|(m, u)| is_member(m) && is_decimal(u)),
        'W' => ["kyber1024", "seat", "seed", "keyring", "base", "delta"].contains(&f),
        _ => false,
    }
}

/// Every label is unique among contexts and among the binary labels, none is
/// a prefix of another followed by `|`, and every context carries
/// `|k|group|gen|` right after its label.
#[test]
fn the_labels_never_collide() {
    let g = Group::new(GroupKind::Text, "c:x", [0xab; 16]).unwrap();
    let contexts = every_context(&g);
    let mut labels: Vec<&str> = contexts
        .iter()
        .map(|(c, _)| c.split('|').next().unwrap())
        .collect();
    labels.sort();
    labels.dedup();
    // Three welcomes share a label and two keyring parts share one: their
    // words tell them apart.
    assert_eq!(labels.len(), contexts.len() - 3);
    let binary = [
        TAG_LABEL,
        DIGEST_LABEL,
        HEADER_SIG_LABEL,
        SEAT_LABEL,
        LEAF_LABEL,
        NODE_LABEL,
        KEYRING_HASH_LABEL,
        KEYHOLDERS_LABEL,
        NAMES_LABEL,
    ];
    let mut all: Vec<String> = labels.iter().map(|l| format!("{l}|")).collect();
    all.extend(
        binary
            .iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap()),
    );
    for (i, a) in all.iter().enumerate() {
        assert!(a.starts_with("voipc-gk/v1/") && a.ends_with('|'), "{a}");
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert!(!b.starts_with(a.as_str()), "{a} is a prefix of {b}");
            }
        }
    }
    for old in [
        "voipc-seat/v1|",
        "voipc-chain/v1/",
        "voipc-wrap/v1|",
        "voipc-wrap/v2|",
        "voipc-list/v1|",
        "voipc-seal/v1|",
        "voipc-vlink/v1|",
        "voipc-log/v1|",
        "voipc-log/v2|",
        "voipc-logkey/v1|",
    ] {
        assert!(all
            .iter()
            .all(|l| !l.starts_with(old) && !old.starts_with(l.as_str())));
    }
    let start = format!("|t|c:x|{}|", "ab".repeat(16));
    for (c, _) in &contexts {
        let after_label = &c[c.find('|').unwrap()..];
        assert!(after_label.starts_with(&start), "{c}");
    }
}

/// A context splits back into exactly its fields, each in the one format
/// its position allows, and no format can hold a `|`: so a string has one
/// reading, and two field tuples never give one string.
#[test]
fn every_context_splits_back_into_its_fields() {
    for g in [
        Group::new(GroupKind::Text, "c:Lounge_1-x", [0; 16]).unwrap(),
        Group::new(
            GroupKind::Voice,
            "r:00112233445566778899aabbccddeeff:0",
            [0xff; 16],
        )
        .unwrap(),
    ] {
        for (c, kinds) in every_context(&g) {
            let parts: Vec<&str> = c.split('|').collect();
            assert_eq!(parts.len(), 1 + kinds.len(), "{c}");
            for (kind, f) in kinds.chars().zip(&parts[1..]) {
                assert!(field_ok(kind, f), "{kind} {f} in {c}");
            }
        }
    }
    // Field values that would run together are kept apart by the separator.
    let g = text();
    let one = row_ctx(&g, 1, Version { b: 12, v: 3 }, &acct(1), &acct(2));
    let two = row_ctx(&g, 1, Version { b: 1, v: 23 }, &acct(1), &acct(2));
    assert_ne!(one, two);
    let w1 = Writer {
        m: MemberId::Conn(1),
        u: 23,
    };
    let w2 = Writer {
        m: MemberId::Conn(12),
        u: 3,
    };
    assert_ne!(w1.ctx(), w2.ctx());
    // Each field changed alone changes the string.
    let seat = SeatRef {
        m: acct(1),
        tag_sk: [2; 8],
        tag_sx: [3; 8],
    };
    let variants = [
        member_ctx(&g, 1, &seat),
        member_ctx(&g, 2, &seat),
        member_ctx(&g, 1, &SeatRef { m: acct(9), ..seat }),
        member_ctx(
            &g,
            1,
            &SeatRef {
                m: MemberId::Conn(1),
                ..seat
            },
        ),
        member_ctx(
            &g,
            1,
            &SeatRef {
                tag_sk: [9; 8],
                ..seat
            },
        ),
        member_ctx(
            &g,
            1,
            &SeatRef {
                tag_sx: [9; 8],
                ..seat
            },
        ),
        member_ctx(
            &Group::new(GroupKind::Voice, "c:lounge-1", GEN).unwrap(),
            1,
            &seat,
        ),
        member_ctx(
            &Group::new(GroupKind::Text, "c:lounge-2", GEN).unwrap(),
            1,
            &seat,
        ),
        member_ctx(
            &Group::new(GroupKind::Text, "c:lounge-1", [0; 16]).unwrap(),
            1,
            &seat,
        ),
    ];
    let distinct: std::collections::HashSet<_> = variants.iter().collect();
    assert_eq!(distinct.len(), variants.len());
}

#[test]
fn a_group_id_of_any_other_shape_is_refused() {
    for ok in [
        "c:kat",
        "c:0123456789abcdef0123456789abcdef",
        &format!("c:{}", "a".repeat(64)),
        "r:00112233445566778899aabbccddeeff:4294967295",
        "r:00112233445566778899aabbccddeeff:0",
    ] {
        assert!(valid_group_id(ok), "{ok}");
    }
    for bad in [
        "",
        "c:",
        "c:a|b",
        "c:é",
        &format!("c:{}", "a".repeat(65)),
        "d:abc",
        "r:00112233445566778899aabbccddeeff",
        "r:00112233445566778899AABBCCDDEEFF:1",
        "r:00112233445566778899aabbccddeeff:01",
        "r:00112233445566778899aabbccddeeff:4294967296",
        "r:00112233445566778899aabbccddee:1",
        "r:00112233445566778899aabbccddeeff:1:2",
    ] {
        assert!(!valid_group_id(bad), "{bad}");
        assert_eq!(
            Group::new(GroupKind::Text, bad, GEN).err(),
            Some(GkError::Malformed)
        );
    }
}

// ── Edges: refusals, the shortest seal, the fuzz target's seals ───────────

/// What an app shows its user when an opener refuses: one sentence per
/// refusal, each its own, so a log tells them apart.
#[test]
fn every_refusal_of_an_opener_reads_as_its_own_sentence() {
    let said: Vec<String> = [
        GkError::Sealed,
        GkError::Forged,
        GkError::Malformed,
        GkError::WeakKey,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    for s in &said {
        assert!(s.starts_with("a group key value "), "{s}");
    }
    let distinct: std::collections::HashSet<_> = said.iter().collect();
    assert_eq!(distinct.len(), said.len());
}

/// The shortest sealed value is an IV and a tag around no plaintext: it
/// opens (a keyring part of no bytes is then refused by its decoder, not by
/// the AEAD), and one byte less is malformed before any AEAD runs.
#[test]
fn a_sealed_value_of_just_an_iv_and_a_tag_opens_and_one_byte_less_is_malformed() {
    let (g, krk, ks) = (text(), key(), [5u8; 32]);
    let c = keyring::part_ctx(&g, 3, 1, &ks, KeyringPart::Base);
    let empty = seal_derived(&krk, &c, &[]);
    assert_eq!(empty.len(), 12 + 16);
    let open = |sealed: &[u8]| open_keyring_part(&g, 3, 1, &ks, &krk, KeyringPart::Base, sealed);
    assert_eq!(open(&empty).unwrap().len(), 0);
    assert_eq!(open(&empty[..27]).err(), Some(GkError::Malformed));
}

/// The fuzz target seals its input under fixed keys so that it gets past
/// each AEAD to the parser behind it. Each of its seals must open under the
/// genuine opener of that value, or the fuzzer would only ever see `Sealed`.
#[test]
fn what_the_fuzz_target_seals_opens_under_the_genuine_openers() {
    let g = text();
    let ck = key();
    let ep = Epoch { e: 2, d_e: [6; 32] };
    let w = Writer { m: acct(1), u: 42 };
    let ik = IdentityKeyPair::generate(&mut crate::rng());
    let skdm = skdm_for(&g, &ep);
    let blob = writer_blob(&g, &ep, &w, &ck, &ik, &skdm).unwrap();
    let plain = open_derived(&ck, &writer_ctx(&g, &ep, &w), &blob).unwrap();
    let resealed = fuzz_seal::writer(&g, &ep, &w, &ck, &plain);
    assert_eq!(
        &open_writer_blob(&g, &ep, &w, &ck, &resealed).unwrap().skdm[..],
        &skdm[..]
    );

    let (krk, ks) = (key(), [5u8; 32]);
    for part in [KeyringPart::Base, KeyringPart::Delta(2)] {
        let sealed = fuzz_seal::keyring(&g, 3, 1, &ks, &krk, part, b"plain");
        assert_eq!(
            &open_keyring_part(&g, 3, 1, &ks, &krk, part, &sealed).unwrap()[..],
            b"plain",
            "{part:?}"
        );
    }

    let keys = SeatKeys::generate(1, T0);
    let seat = keys.pair.public().seat(acct(1));
    let entries = [HistoryEntry {
        k: HolderId {
            m: acct(3),
            tag_kx: [1; 8],
        },
        rb: Zeroizing::new([7; 32]),
    }];
    let row = history_row(&g, 1, &seat, keys.self_key(), &entries);
    let plain = open_derived(keys.self_key(), &self_history_ctx(&g, 1, &seat), &row).unwrap();
    let resealed = fuzz_seal::history(&g, 1, &seat, keys.self_key(), &plain);
    assert_eq!(
        open_history_row(&g, 1, &seat, keys.self_key(), &resealed).unwrap(),
        entries
    );
}

// ── The form, clause by clause ────────────────────────────────────────────

/// Each clause of `check_shape` on its own: a header that breaks exactly one
/// is refused for that one, so no clause leans on a later one to catch it.
#[test]
fn a_header_that_breaks_one_clause_of_its_form_is_refused_for_that_clause() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let genesis = gen.header().clone();
    let fresh = next(&gen, Kind::Fresh, T0 + 60);
    let join = next(&gen, Kind::Join, T0 + 2);
    let form = |h: &HeaderV1| {
        let (b, s) = raw_signed(h, &k);
        decode(&b, &s).map(|_| ())
    };
    for h in [&genesis, &fresh, &join] {
        assert_eq!(form(h), Ok(()), "the control: {:?}", h.kind);
    }
    let cases: Vec<(HeaderV1, &str)> = vec![
        (
            HeaderV1 {
                join: 1,
                ..fresh.clone()
            },
            "an opening header has join 0 and no epoch parent",
        ),
        (
            HeaderV1 {
                epoch_parent: [1; 32],
                ..fresh.clone()
            },
            "an opening header has join 0 and no epoch parent",
        ),
        (
            HeaderV1 {
                join: 0,
                ..join.clone()
            },
            "a Join header has join 1 or more and an epoch parent",
        ),
        (
            HeaderV1 {
                epoch_parent: [0; 32],
                ..join.clone()
            },
            "a Join header has join 1 or more and an epoch parent",
        ),
        (
            HeaderV1 {
                epoch: 2,
                ..genesis.clone()
            },
            "a Genesis is epoch 1 under seed 1",
        ),
        (
            HeaderV1 {
                seed: 2,
                ..genesis.clone()
            },
            "a Genesis is epoch 1 under seed 1",
        ),
        (
            HeaderV1 {
                seed_floor: 0,
                ..genesis.clone()
            },
            "a Genesis is epoch 1 under seed 1",
        ),
        (
            HeaderV1 {
                parent: [1; 32],
                ..genesis.clone()
            },
            "a Genesis has no parent",
        ),
        (
            HeaderV1 {
                kh_parent: [1; 32],
                ..genesis.clone()
            },
            "a Genesis has no parent",
        ),
        (
            HeaderV1 {
                parent: [0; 32],
                ..fresh.clone()
            },
            "only a Genesis has no parent",
        ),
        (
            HeaderV1 {
                kh_parent: [0; 32],
                ..fresh.clone()
            },
            "only a Genesis has no parent",
        ),
        (
            HeaderV1 {
                epoch: 0,
                ..fresh.clone()
            },
            "epochs count from 1",
        ),
        (
            HeaderV1 {
                keyholders: vec![],
                ..genesis.clone()
            },
            "a header that sets keyholders names 1 to 8",
        ),
        (
            HeaderV1 {
                keyholders: vec![k.entry()],
                ..join.clone()
            },
            "only a header that sets keyholders names them",
        ),
        (
            HeaderV1 {
                seed_floor: 0,
                ..fresh.clone()
            },
            "seed_floor is between 1 and seed",
        ),
        (
            HeaderV1 {
                seed_floor: 2,
                ..fresh.clone()
            },
            "seed_floor is between 1 and seed",
        ),
        (
            HeaderV1 {
                names_hash: [1; 32],
                ..fresh.clone()
            },
            "an open group carries no names",
        ),
        (
            HeaderV1 {
                added: Added::List(vec![]),
                removed: Removed::List(vec![]),
                ..fresh.clone()
            },
            "lists in gated groups, counts in open ones",
        ),
        (
            HeaderV1 {
                gated: true,
                ..fresh.clone()
            },
            "lists in gated groups, counts in open ones",
        ),
        (
            HeaderV1 {
                seats: 1,
                conn_seats: 2,
                ..fresh.clone()
            },
            "more connection seats than seats",
        ),
    ];
    for (h, why) in cases {
        assert_eq!(form(&h), Err(Refusal::Form(why)), "{h:?}");
    }
    let all_guests = HeaderV1 {
        seats: 2,
        conn_seats: 2,
        ..fresh.clone()
    };
    assert_eq!(form(&all_guests), Ok(()), "every seat a connection's");
    let bad_id = HeaderV1 {
        group: "c:a|b".to_string(),
        ..genesis.clone()
    };
    let (b, s) = raw_signed(&bad_id, &k);
    assert_eq!(
        SignedHeader::decode(&b, &s, GroupKind::Text, "c:a|b").err(),
        Some(Refusal::Form("the group id has no valid shape"))
    );
}

/// An account id numbered `i`, apart from every `acct(_)`.
fn numbered(i: usize) -> MemberId {
    let mut a = [0xee; 16];
    a[..2].copy_from_slice(&u16::try_from(i).unwrap().to_be_bytes());
    MemberId::Account(a)
}

/// Eight keyholders, 256 added and 768 removed names are each the most a
/// header carries, and are taken; one more of any is refused. A header at
/// one cap is well over a kilobyte and within its 32 KiB; one at both caps
/// is over them, and neither signed nor taken.
#[test]
fn a_header_at_each_list_cap_is_taken_and_one_past_it_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let form = |mut h: HeaderV1| {
        h.canonicalize();
        let (b, s) = raw_signed(&h, &k);
        (b.len(), decode(&b, &s).map(|_| ()))
    };
    let open = genesis_of(&k, &g, T0, false);
    let with_holders = |n: usize| HeaderV1 {
        keyholders: (0..n)
            .map(|i| Keyholder {
                m: numbered(i),
                ..k.entry()
            })
            .collect(),
        ..open.clone()
    };
    assert_eq!(form(with_holders(MAX_KEYHOLDERS)).1, Ok(()));
    assert_eq!(
        form(with_holders(MAX_KEYHOLDERS + 1)).1,
        Err(Refusal::Form("a header that sets keyholders names 1 to 8"))
    );

    let gated = genesis_of(&k, &g, T0, true);
    let lists = |a: usize, r: usize| HeaderV1 {
        added: Added::List(
            (0..a)
                .map(|i| AddedSeat {
                    m: numbered(i),
                    ..k.added(1)
                })
                .collect(),
        ),
        removed: Removed::List(
            (0..r)
                .map(|i| SeatRef {
                    m: numbered(i),
                    ..k.seat()
                })
                .collect(),
        ),
        ..gated.clone()
    };
    for (a, r) in [(MAX_ADDED, 0), (0, MAX_REMOVED)] {
        let (len, taken) = form(lists(a, r));
        assert_eq!(taken, Ok(()), "{a} added, {r} removed");
        assert!((2 * 1024..=HEADER_MAX_BYTES).contains(&len), "{len} bytes");
    }
    for (a, r) in [(MAX_ADDED + 1, 0), (0, MAX_REMOVED + 1)] {
        assert_eq!(
            form(lists(a, r)).1,
            Err(Refusal::Form("too many names")),
            "{a} added, {r} removed"
        );
    }
    let over = Refusal::Form("the header is over 32 KiB");
    let (len, taken) = form(lists(MAX_ADDED, MAX_REMOVED));
    assert!(len > HEADER_MAX_BYTES, "{len} bytes");
    assert_eq!(taken, Err(over.clone()));
    assert_eq!(
        SignedHeader::sign(lists(MAX_ADDED, MAX_REMOVED), &k.ik).err(),
        Some(over)
    );
}

/// A body of exactly 32 KiB is the largest taken: signed and decoded. The
/// names fill it to within one seat record, and the varints of a few `made`
/// times take up the rest.
#[test]
fn a_header_of_exactly_32_kib_is_signed_and_taken() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gated = genesis_of(&k, &g, T0, true);
    let lists = |r: usize| HeaderV1 {
        added: Added::List(
            (0..MAX_ADDED)
                .map(|i| AddedSeat {
                    m: numbered(i),
                    ..k.added(1)
                })
                .collect(),
        ),
        removed: Removed::List(
            (0..r)
                .map(|i| SeatRef {
                    m: numbered(i),
                    ..k.seat()
                })
                .collect(),
        ),
        ..gated.clone()
    };
    let mut r = (HEADER_MAX_BYTES - lists(0).encode().len()) / 33;
    while lists(r).encode().len() > HEADER_MAX_BYTES {
        r -= 1;
    }
    let mut h = lists(r);
    let short = HEADER_MAX_BYTES - h.encode().len();
    // `made` is T0 (a 5-byte varint): u64::MAX adds 5 bytes, 2^(7·(4+n)) adds n.
    if let Added::List(l) = &mut h.added {
        for a in &mut l[..short / 5] {
            a.made = u64::MAX;
        }
        if !short.is_multiple_of(5) {
            l[short / 5].made = 1 << (7 * (4 + short % 5));
        }
    }
    assert_eq!(h.encode().len(), HEADER_MAX_BYTES);
    let signed = SignedHeader::sign(h, &k.ik).unwrap();
    assert_eq!(signed.body().len(), HEADER_MAX_BYTES);
    assert!(decode(signed.body(), &signed.sig()).is_ok());
}

// ── The keyring's head and set, one field at a time ──────────────────────

/// A head of another group, generation or kind is refused before anything
/// opens, each of the three on its own; so is a keyholder header other than
/// the one the head names, or one that names it but sets no keyholders. The
/// other Genesis holds the very same keyholders, so the keyring would open
/// under its set: only the check of `D` refuses it.
#[test]
fn a_keyring_under_another_group_or_keyholder_header_is_malformed() {
    assert!(take_case(case(), |_| {}).is_ok(), "the control");
    assert_eq!(
        take_case(case(), |h| h.gen = [0x12; 16]).err(),
        Some(GkError::Malformed),
        "another generation"
    );
    for (in_group, why) in [
        (
            Group::new(GroupKind::Text, "c:lounge-2", GEN).unwrap(),
            "another group",
        ),
        (voice_named_alike(), "another kind"),
    ] {
        assert_eq!(
            take_case_by(case(), |_, _, _| (in_group, None)).err(),
            Some(GkError::Malformed),
            "{why}"
        );
    }
    assert_eq!(
        take_case_by(case(), |k, _, _| {
            let twin = signed(None, genesis_of(k, &text(), T0 + 1, false), k);
            (text(), Some(twin))
        })
        .err(),
        Some(GkError::Malformed),
        "another Genesis with the same keyholders"
    );
    assert_eq!(
        take_case_by(case(), |k, gen, h| {
            let fresh = signed(Some(gen), next(gen, Kind::Fresh, T0 + 60), k);
            h.kh_parent = fresh.d();
            (text(), Some(fresh))
        })
        .err(),
        Some(GkError::Malformed),
        "named, but it sets no keyholders"
    );
}

/// The keyring's versions sit in one vector sized once, so no growing
/// vector leaves a copy of a bucket key behind: its capacity is its length,
/// also when the deltas hold more versions than the base.
#[test]
fn a_taken_keyrings_versions_fill_a_vector_sized_once() {
    for (base, deltas) in [(2, 1), (1, 2), (3, 0)] {
        let mut c = case();
        c.base.buckets = (0..base)
            .map(|i| bucket(10 + i, Pool::Accounts, 3))
            .collect();
        c.deltas = vec![KeyringDelta {
            join: 1,
            buckets: (0..deltas)
                .map(|i| bucket(20 + i, Pool::Conns, 2))
                .collect(),
        }];
        c.js = vec![1];
        let ck = *c.base.ck;
        let ring = take_case(c, |h| {
            h.join = 1;
            h.confirm = confirm(&text(), 3, 1, &ck);
        })
        .unwrap();
        assert_eq!(ring.buckets.len(), (base + deltas) as usize);
        assert_eq!(
            ring.buckets.capacity(),
            ring.buckets.len(),
            "{base} in the base, {deltas} in the delta"
        );
    }
}

// ── names_hash at the edges ───────────────────────────────────────────────

/// An open group that turns gated at an opening header starts the fold from
/// zero even with no names yet, so its `names_hash` is never the zero of an
/// open group; and a Genesis folds from zero whatever header came before.
#[test]
fn turning_gated_on_or_a_genesis_starts_the_names_fold_afresh() {
    let (g, k) = (text(), Party::new(acct(1)));
    let open = signed(None, genesis_of(&k, &g, T0, false), &k);
    let mut on = next(&open, Kind::Fresh, T0 + 60);
    on.gated = true;
    on.added = Added::List(vec![]);
    on.removed = Removed::List(vec![]);
    assert_eq!(
        names_hash(Some(open.header()), &on),
        names_start(&NamesList::of(&on))
    );
    assert_ne!(names_hash(Some(open.header()), &on), [0; 32]);
    let on = signed(Some(&open), on, &k);
    assert_eq!(check_link(&open, &on), Ok(vec![]));
    let floor = Floor::after(None, &open, T0);
    assert_eq!(check_on_floor(&floor, &on), Ok(vec![]));

    let gated = signed(None, genesis_of(&k, &g, T0, true), &k);
    let anew = genesis_of(&k, &g, T0 + 1, true);
    assert_eq!(
        names_hash(Some(gated.header()), &anew),
        names_hash(None, &anew)
    );
    assert_eq!(
        names_hash(None, &anew),
        names_start(&NamesList::of(&anew)),
        "folded from zero"
    );
    // A writer folds from the start across the turn: the first step is the
    // empty list of the header that turned gated on.
    let floor = NamesFloor::of(open.header());
    assert_eq!(floor.names_hash, [0; 32]);
    // A names floor from while it was open folds from the start as well,
    // without the caller choosing `Start`.
    for from in [NamesFrom::Floor(floor), NamesFrom::Start] {
        assert!(matches!(
            fold_names(
                &from,
                &[NamesList::of(on.header())],
                &[],
                on.header(),
                &knows(T0 + 60)
            ),
            Ok(Fold::Take { .. })
        ));
    }
}

/// An origin byte reads back as the origin it was written from, and no
/// other byte reads as one. The vault's own seat keys (0x01) are an origin
/// too, but never a keyholder's.
#[test]
fn an_origin_byte_reads_back_as_its_origin_and_a_vault_seat_holds_no_keys() {
    for o in [Origin::VaultSeat, Origin::Connection, Origin::Desktop] {
        assert_eq!(Origin::from_byte(o as u8), Some(o));
    }
    for b in [0x00, 0x04, 0xff] {
        assert_eq!(Origin::from_byte(b), None, "{b:#x}");
    }
    let (g, k) = (text(), Party::new(acct(1)));
    let mut vault = genesis_of(&k, &g, T0, false);
    vault.keyholders[0].origin = Origin::VaultSeat as u8;
    let (b, s) = raw_signed(&vault, &k);
    assert_eq!(
        decode(&b, &s).err(),
        Some(Refusal::Form(
            "a keyholder entry has no origin its member can have"
        ))
    );
}

/// During a rotation the old seat keeps the self key its self-rows were
/// sealed under, so those rows still open until the re-seat is done.
#[test]
fn a_rotation_keeps_the_old_self_key_and_its_self_rows_still_open() {
    let g = text();
    let keys = SeatKeys::generate(1, T0);
    let seat = keys.pair.public().seat(acct(1));
    let before = *keys.self_key();
    let s_m = key();
    let row = self_row(&g, 1, &seat, keys.self_key(), &s_m);
    let rotated = keys.rotate(T0 + 60).unwrap();
    let old = rotated.old.as_ref().unwrap();
    assert_eq!(old.self_key(), &before);
    assert_eq!(
        *open_self_row(&g, 1, &seat, old.self_key(), &row).unwrap(),
        *s_m
    );
    let back = SeatKeys::from_bytes(&rotated.to_bytes()).unwrap();
    assert_eq!(
        back.old.unwrap().self_key(),
        &before,
        "through the vault too"
    );
}

/// A floor keeps its generation's start time within the generation, whatever
/// the caller passes, and takes the passed one at a new generation.
#[test]
fn a_floor_keeps_its_generations_start_time_until_the_generation_changes() {
    let k = Party::new(acct(1));
    let g1 = text();
    let gen = signed(None, genesis_of(&k, &g1, T0, false), &k);
    let start = Floor::after(None, &gen, T0);
    assert_eq!(start.gen_time, T0);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let within = Floor::after(Some(&start), &fresh, T0 + 999);
    assert_eq!(within.gen_time, T0, "kept within the generation");
    assert_eq!(within.gens, [(GEN, T0)]);
    let g2 = Group::new(GroupKind::Text, "c:lounge-1", [0x22; 16]).unwrap();
    let anew = signed(None, genesis_of(&k, &g2, T0 + 5000, false), &k);
    let next_gen = Floor::after(Some(&within), &anew, T0 + 5000);
    assert_eq!(next_gen.gen_time, T0 + 5000, "a new generation's own");
    assert_eq!(next_gen.gens, [(GEN, T0), ([0x22; 16], T0 + 5000)]);
    // `above` is strict: a floor at the very same place is not above it.
    for f in [&start, &within, &next_gen] {
        assert!(!f.above(f), "{}", f.epoch);
    }
    assert!(within.above(&start) && !start.above(&within));
    assert!(next_gen.above(&within) && !within.above(&next_gen));
}

// ── Rules, clause by clause ───────────────────────────────────────────────

/// A KeyholdersAdd that keeps every entry and adds one is taken up to 8; one
/// that adds nothing, or adds while it drops another, is refused, and so is
/// any set of 9. Each on its own.
#[test]
fn a_keyholders_add_keeps_every_entry_adds_one_and_stops_at_eight() {
    let (g, k) = (text(), Party::new(acct(1)));
    let entries: Vec<Keyholder> = (0..=MAX_KEYHOLDERS)
        .map(|i| Keyholder {
            m: numbered(i),
            ..k.entry()
        })
        .collect();
    let add = |new: &[Keyholder]| HeaderV1 {
        kind: Kind::KeyholdersAdd,
        keyholders: new.to_vec(),
        ..genesis_of(&k, &g, T0, false)
    };
    let only_adds = Err(Refusal::KeyholderChange("a KeyholdersAdd only adds"));
    assert_eq!(
        check_keyholder_change(&entries[..7], &add(&entries[..8])),
        Ok(())
    );
    assert_eq!(
        check_keyholder_change(&entries[..8], &add(&entries[..9])),
        Err(Refusal::KeyholderChange("more than 8 keyholders"))
    );
    assert_eq!(
        check_keyholder_change(&entries[..2], &add(&entries[..2])),
        only_adds,
        "adds nothing"
    );
    assert_eq!(
        check_keyholder_change(&entries[..2], &add(&entries[1..4])),
        only_adds,
        "adds two, drops one"
    );
}

/// §5.9 checks only the new keyholders of a voice Genesis or KeyholdersAdd:
/// a text group's header, or a voice header of another kind, passes whatever
/// the roster says.
#[test]
fn only_a_voice_genesis_or_keyholders_add_is_checked_against_the_roster() {
    let k = Party::new(MemberId::Conn(99));
    let mut entry = k.entry();
    entry.u = Some(99);
    let roster = [1, 2, 3, 4];
    let header = |g: &Group, kind: Kind| HeaderV1 {
        kind,
        keyholders: vec![entry],
        ..genesis_of(&k, g, T0, false)
    };
    assert_eq!(
        check_voice_keyholders(&header(&voice(), Kind::KeyholdersAdd), &[], &roster),
        Err(Refusal::VoiceKeyholder(99)),
        "the control"
    );
    assert_eq!(
        check_voice_keyholders(&header(&voice(), Kind::Genesis), &[], &roster),
        Err(Refusal::VoiceKeyholder(99))
    );
    assert_eq!(
        check_voice_keyholders(&header(&text(), Kind::Genesis), &[], &roster),
        Ok(())
    );
    for kind in [Kind::KeyholdersRemove, Kind::Regenesis, Kind::Fresh] {
        assert_eq!(
            check_voice_keyholders(&header(&voice(), kind), &[], &roster),
            Ok(()),
            "{kind:?}"
        );
    }
}

/// A signer whose `IK` is its pin is taken; only another `IK` is refused.
#[test]
fn a_signer_or_added_name_that_matches_its_pin_is_taken() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, true), &k);
    let ik = k.ik_raw();
    let pins = move |a: &[u8; 16]| (*a == [1; 16]).then_some(ik);
    assert_eq!(check_signer(&gen, None, &pins), Ok(ik));
    assert_eq!(check_added(gen.header(), &pins, NO_COUNTERS, None), Ok(()));
    let other = Party::new(acct(2)).ik_raw();
    let wrong = move |a: &[u8; 16]| (*a == [1; 16]).then_some(other);
    assert_eq!(
        check_signer(&gen, None, &wrong).err(),
        Some(Refusal::Pin(k.m))
    );
}

/// `check_link`: a header of another generation, group or group kind is
/// refused, each on its own; `exits_upto` may rise but never go back; and the
/// seeds of a Regenesis and of a Join follow their parent's exactly.
#[test]
fn a_link_is_refused_for_each_of_its_clauses_on_its_own() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let fresh = next(&gen, Kind::Fresh, T0 + 60);
    let link = |h: HeaderV1| check_link(&gen, &signed(Some(&gen), h, &k));
    assert_eq!(link(fresh.clone()), Ok(vec![]), "the control");
    let new_gen = Refusal::Chain("a generation changes only at a Genesis");
    for h in [
        HeaderV1 {
            gen: [0x22; 16],
            ..fresh.clone()
        },
        HeaderV1 {
            group: "c:lounge-2".to_string(),
            ..fresh.clone()
        },
        HeaderV1 {
            group_kind: GroupKind::Voice,
            ..fresh.clone()
        },
    ] {
        assert_eq!(link(h.clone()), Err(new_gen.clone()), "{h:?}");
    }
    let raised = signed(
        Some(&gen),
        HeaderV1 {
            exits_upto: 5,
            ..fresh.clone()
        },
        &k,
    );
    assert_eq!(check_link(&gen, &raised), Ok(vec![]), "exits_upto rises");
    let back = HeaderV1 {
        exits_upto: 4,
        ..next(&raised, Kind::Join, T0 + 62)
    };
    assert_eq!(
        check_link(&raised, &signed(Some(&raised), back, &k)),
        Err(Refusal::Chain("exits_upto went back"))
    );

    let seeds = Refusal::Chain("the seed does not follow");
    let regen = |seed: u32, seed_floor: u32| HeaderV1 {
        keyholders: vec![k.entry()],
        seed,
        seed_floor,
        ..next(&gen, Kind::Regenesis, T0 + REGENESIS_WAIT)
    };
    assert_eq!(link(regen(2, 2)), Ok(vec![]), "the control: a Regenesis");
    assert_eq!(link(regen(2, 1)), Err(seeds.clone()), "the floor stays");
    assert_eq!(link(regen(3, 3)), Err(seeds.clone()), "two seeds on");
    // After a removal the seed is 2 and its floor 1: a Join keeps both.
    let removal = signed(
        Some(&gen),
        HeaderV1 {
            keyholders: vec![k.entry()],
            ..next(&gen, Kind::KeyholdersRemove, T0 + 60)
        },
        &k,
    );
    assert_eq!((removal.header().seed, removal.header().seed_floor), (2, 1));
    let join = next(&removal, Kind::Join, T0 + 62);
    let join_link = |h: HeaderV1| check_link(&removal, &signed(Some(&removal), h, &k));
    assert_eq!(join_link(join.clone()), Ok(vec![]), "the control: a Join");
    assert_eq!(
        join_link(HeaderV1 {
            seed_floor: 2,
            ..join.clone()
        }),
        Err(seeds)
    );
}

/// `check_on_floor`, each clause on its own: the parent and the generation;
/// and a Join at the floor's epoch, its next join and its `D_e`. A gated
/// Join on the floor is taken without its names: the floor keeps none.
#[test]
fn a_header_on_the_floor_is_refused_for_each_of_its_clauses_on_its_own() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let floor = Floor::after(None, &gen, T0);
    let on = |h: HeaderV1| check_on_floor(&floor, &signed(Some(&gen), h, &k));
    let fresh = next(&gen, Kind::Fresh, T0 + 60);
    let join = next(&gen, Kind::Join, T0 + 2);
    assert_eq!(on(fresh.clone()), Ok(vec![]), "the control: Fresh");
    assert_eq!(on(join.clone()), Ok(vec![]), "the control: Join");
    let not_floor = Refusal::Chain("parent is not the floor");
    assert_eq!(
        on(HeaderV1 {
            parent: [9; 32],
            ..fresh.clone()
        }),
        Err(not_floor.clone())
    );
    assert_eq!(
        on(HeaderV1 {
            gen: [0x22; 16],
            ..fresh.clone()
        }),
        Err(not_floor)
    );
    let in_epoch = Refusal::Chain("a Join header follows in its parent's epoch");
    for h in [
        HeaderV1 {
            epoch: 2,
            ..join.clone()
        },
        HeaderV1 {
            join: 2,
            ..join.clone()
        },
        HeaderV1 {
            epoch_parent: [9; 32],
            ..join.clone()
        },
    ] {
        assert_eq!(on(h.clone()), Err(in_epoch.clone()), "{h:?}");
    }

    // A gated floor: a Join is taken whatever its names_hash; the writer's
    // fold, and a member that holds the parent, check it.
    let gated = signed(None, genesis_of(&k, &g, T0, true), &k);
    let gated_floor = Floor::after(None, &gated, T0);
    let mut named = next(&gated, Kind::Join, T0 + 2);
    named.added = Added::List(vec![Party::new(acct(5)).added(1)]);
    let mut wrong = named.clone();
    let named = signed(Some(&gated), named, &k);
    assert_eq!(
        named.header().names_hash,
        names_step(&gated.header().names_hash, &NamesList::of(named.header()))
    );
    assert_eq!(check_on_floor(&gated_floor, &named), Ok(vec![]));
    wrong.names_hash = [9; 32];
    let wrong = SignedHeader::sign(wrong, &k.ik).unwrap();
    assert_eq!(check_on_floor(&gated_floor, &wrong), Ok(vec![]));
    assert_eq!(check_link(&gated, &wrong), Err(Refusal::Names));
}

/// A device follows the group live for 10 minutes after it last took a
/// header, and not a second longer; a `taken` ahead of its clock (the clock
/// went back) is not live. Only a live device refuses a Genesis 20 minutes
/// old.
#[test]
fn a_device_is_live_for_ten_minutes_after_it_took_a_header_and_no_longer() {
    let k = Party::new(acct(1));
    let old = Group::new(GroupKind::Text, "c:lounge-1", [1; 16]).unwrap();
    let first = signed(None, genesis_of(&k, &old, T0, false), &k);
    let floor = Floor::after(None, &first, T0);
    let now = T0 + 86_400;
    let fresh_gen = Group::new(GroupKind::Text, "c:lounge-1", [2; 16]).unwrap();
    let twenty = genesis_of(&k, &fresh_gen, now - 1200, false);
    let taken = |t| Clock {
        now,
        taken: Some(t),
    };
    assert!(check_new_generation(Some(&floor), taken(now - LIVE_WINDOW), &twenty).is_err());
    assert_eq!(
        check_new_generation(Some(&floor), taken(now - LIVE_WINDOW - 1), &twenty),
        Ok(())
    );
    assert_eq!(
        check_new_generation(Some(&floor), taken(now + 5), &twenty),
        Ok(()),
        "taken ahead of the clock"
    );
    // A live device takes a Genesis 10 minutes old, either way, and no older.
    let live = taken(now - 1);
    for t in [now - LIVE_WINDOW, now + LIVE_WINDOW] {
        let at = genesis_of(&k, &fresh_gen, t, false);
        assert_eq!(check_new_generation(Some(&floor), live, &at), Ok(()), "{t}");
    }
    let past = genesis_of(&k, &fresh_gen, now - LIVE_WINDOW - 1, false);
    assert!(check_new_generation(Some(&floor), live, &past).is_err());
}

/// Two floors in different generations begun at the same time: neither is
/// above the other.
#[test]
fn floors_of_two_generations_begun_at_once_are_neither_above_the_other() {
    let k = Party::new(acct(1));
    let at = |n: u8| {
        let g = Group::new(GroupKind::Text, "c:lounge-1", [n; 16]).unwrap();
        Floor::after(None, &signed(None, genesis_of(&k, &g, T0, false), &k), T0)
    };
    let (a, b) = (at(1), at(2));
    assert!(!a.above(&b) && !b.above(&a));
    let later = Floor {
        gen_time: T0 + 1,
        ..b.clone()
    };
    assert!(later.above(&a) && !a.above(&later));
}

/// `check_walk`, each clause on its own: the floor's keyholder header (its
/// `D`, its kind, its generation), each link (a keyholder header, of this
/// generation, naming the one before it, at a later epoch), and the cap of
/// 4096 links, which 4096 links do not reach.
#[test]
fn a_walk_is_refused_for_each_of_its_clauses_on_its_own() {
    let g = text();
    let (k, k2) = (Party::new(acct(1)), Party::new(acct(2)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let floor = Floor::after(None, &gen, T0);
    let add_h = HeaderV1 {
        keyholders: vec![k.entry(), k2.entry()],
        ..next(&gen, Kind::KeyholdersAdd, T0 + 60)
    };
    let add = signed(Some(&gen), add_h.clone(), &k);
    let head = signed(Some(&add), next(&add, Kind::Fresh, T0 + 120), &k);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let now = clock(T0 + 200);
    let link = |h| WalkLink {
        header: h,
        parent: None,
    };
    let walk = |floor: &Floor, kh: &SignedHeader, links: &[WalkLink]| {
        check_walk(
            WalkTo::Floor { floor, kh },
            links,
            link(&head),
            now,
            NO_PINS,
        )
    };
    assert!(walk(&floor, &gen, &[link(&add)]).is_ok(), "the control");

    let another = Err(Refusal::Walk("the floor's keyholder header is another"));
    let twin = signed(None, genesis_of(&k, &g, T0 + 1, false), &k);
    assert_eq!(walk(&floor, &twin, &[link(&add)]), another, "another D");
    let names_fresh = Floor {
        kh: fresh.d(),
        ..floor.clone()
    };
    assert_eq!(
        walk(&names_fresh, &fresh, &[link(&add)]),
        another,
        "no keyholder header"
    );
    let other_gen = Floor {
        gen: [0x22; 16],
        ..floor.clone()
    };
    assert_eq!(
        walk(&other_gen, &gen, &[link(&add)]),
        another,
        "of another generation"
    );

    let no_kh = Err(Refusal::Walk(
        "a link is no keyholder header of this generation",
    ));
    assert_eq!(walk(&floor, &gen, &[link(&fresh)]), no_kh, "a Fresh link");
    let elsewhere = signed(
        None,
        HeaderV1 {
            gen: [0x22; 16],
            ..add_h.clone()
        },
        &k,
    );
    assert_eq!(
        walk(&floor, &gen, &[link(&elsewhere)]),
        no_kh,
        "a link of another generation"
    );
    let not_following = Err(Refusal::Walk("a link does not follow the one before it"));
    let off_chain = signed(
        None,
        HeaderV1 {
            kh_parent: [9; 32],
            ..add_h.clone()
        },
        &k,
    );
    assert_eq!(
        walk(&floor, &gen, &[link(&off_chain)]),
        not_following,
        "names another set"
    );
    let same_epoch = signed(
        None,
        HeaderV1 {
            epoch: 1,
            ..add_h.clone()
        },
        &k,
    );
    assert_eq!(
        walk(&floor, &gen, &[link(&same_epoch)]),
        not_following,
        "at the floor's epoch"
    );

    let full = vec![link(&fresh); MAX_WALK];
    assert_eq!(walk(&floor, &gen, &full), no_kh, "4096 links are walked");
    let over = vec![link(&fresh); MAX_WALK + 1];
    assert_eq!(
        walk(&floor, &gen, &over),
        Err(Refusal::Walk("more than 4096 links"))
    );
}

/// The head of a walk, each clause on its own: its generation, the set it
/// names, an opening header past the last link's epoch; and a Join in the
/// floor's own epoch is taken when it names the floor's `D_e`.
#[test]
fn a_walks_head_is_refused_for_each_of_its_clauses_on_its_own() {
    let g = text();
    let (k, k2) = (Party::new(acct(1)), Party::new(acct(2)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let floor = Floor::after(None, &gen, T0);
    let add = signed(
        Some(&gen),
        HeaderV1 {
            keyholders: vec![k.entry(), k2.entry()],
            ..next(&gen, Kind::KeyholdersAdd, T0 + 60)
        },
        &k,
    );
    let to = WalkTo::Floor {
        floor: &floor,
        kh: &gen,
    };
    let walk = |links: &[WalkLink], h: HeaderV1| {
        let head = signed(None, h, &k);
        check_walk(
            to,
            links,
            WalkLink {
                header: &head,
                parent: None,
            },
            clock(T0 + 200),
            NO_PINS,
        )
        .map(|_| ())
    };
    let links = [WalkLink {
        header: &add,
        parent: None,
    }];
    let fresh = next(&add, Kind::Fresh, T0 + 120);
    assert_eq!(walk(&links, fresh.clone()), Ok(()), "the control");
    let off = Err(Refusal::Walk("the header does not follow the chain"));
    for h in [
        HeaderV1 {
            gen: [0x22; 16],
            ..fresh.clone()
        },
        HeaderV1 {
            kh_parent: [9; 32],
            ..fresh.clone()
        },
        HeaderV1 {
            epoch: add.header().epoch,
            ..fresh.clone()
        },
    ] {
        assert_eq!(walk(&links, h.clone()), off, "{h:?}");
    }
    // A Join of the floor's epoch, its parent not held: taken with the
    // floor's D_e, refused with another.
    let join = HeaderV1 {
        join: 2,
        parent: [8; 32],
        ..next(&gen, Kind::Join, T0 + 4)
    };
    assert_eq!(join.epoch_parent, floor.d_e);
    assert_eq!(walk(&[], join.clone()), Ok(()));
    assert_eq!(
        walk(
            &[],
            HeaderV1 {
                epoch_parent: [7; 32],
                ..join
            }
        ),
        Err(Refusal::Chain("a Join of the floor's epoch names its D_e"))
    );
}

/// A Regenesis whose parent is the keyholder header in force itself (here
/// the floor's own Genesis, an hour old) is taken on a walk.
#[test]
fn a_regenesis_over_the_keyholder_header_in_force_is_taken_on_a_walk() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let floor = Floor::after(None, &gen, T0);
    let regen = signed(
        Some(&gen),
        HeaderV1 {
            keyholders: vec![k.entry()],
            ..next(&gen, Kind::Regenesis, T0 + REGENESIS_WAIT)
        },
        &k,
    );
    let walked = check_walk(
        WalkTo::Floor {
            floor: &floor,
            kh: &gen,
        },
        &[],
        WalkLink {
            header: &regen,
            parent: Some(&gen),
        },
        clock(T0 + REGENESIS_WAIT + 100),
        NO_PINS,
    )
    .unwrap();
    assert_eq!(walked.signers, [(k.m, k.ik_raw())]);
}

/// A Regenesis on a walk over a parent the member does not hold, in a
/// later epoch than the floor: signed by the set in force and above the
/// floor, so taken. Its `D_e` is its own, not the floor's, and needs not be.
#[test]
fn a_regenesis_over_a_parent_past_the_floors_epoch_is_taken_on_a_walk() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let floor = Floor::after(None, &gen, T0);
    let fresh = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let regen = signed(
        Some(&fresh),
        HeaderV1 {
            keyholders: vec![k.entry()],
            ..next(&fresh, Kind::Regenesis, T0 + 60 + REGENESIS_WAIT)
        },
        &k,
    );
    assert!(check_walk(
        WalkTo::Floor {
            floor: &floor,
            kh: &gen,
        },
        &[],
        WalkLink {
            header: &regen,
            parent: Some(&fresh),
        },
        clock(T0 + 60 + REGENESIS_WAIT + 100),
        NO_PINS,
    )
    .is_ok());
}

/// `check_regenesis`: a Regenesis follows its parent in every one of the
/// fields it names, each refused on its own.
#[test]
fn a_regenesis_that_does_not_follow_its_parent_in_one_field_is_refused() {
    let (g, k) = (text(), Party::new(acct(1)));
    let gen = signed(None, genesis_of(&k, &g, T0, false), &k);
    let parent = signed(Some(&gen), next(&gen, Kind::Fresh, T0 + 60), &k);
    let regen = HeaderV1 {
        keyholders: vec![k.entry()],
        ..next(&parent, Kind::Regenesis, T0 + 60 + REGENESIS_WAIT)
    };
    let now = clock(T0 + 60 + REGENESIS_WAIT + 100);
    let check = |h: HeaderV1| check_regenesis(None, now, &signed(Some(&parent), h, &k), &parent);
    assert_eq!(check(regen.clone()), Ok(()), "the control");
    let not_following = Err(Refusal::Chain("a Regenesis follows its parent"));
    for h in [
        HeaderV1 {
            parent: [9; 32],
            ..regen.clone()
        },
        HeaderV1 {
            gen: [0x22; 16],
            ..regen.clone()
        },
        HeaderV1 {
            epoch: 4,
            ..regen.clone()
        },
        HeaderV1 {
            kh_parent: [9; 32],
            ..regen.clone()
        },
        HeaderV1 {
            seed: 3,
            seed_floor: 3,
            ..regen.clone()
        },
    ] {
        assert_eq!(check(h.clone()), not_following, "{h:?}");
    }
}

/// The relay may say the names since a floor are gone only once the floor
/// is more than 90 days old: at 90 days to the second, they are still kept.
#[test]
fn names_are_kept_ninety_days_to_the_second() {
    let (g, k) = (text(), Party::new(acct(1)));
    let floor = NamesFloor::of(signed(None, genesis_of(&k, &g, T0, true), &k).header());
    assert!(!names_may_be_gone(&floor, T0 + NAMES_KEPT));
    assert!(names_may_be_gone(&floor, T0 + NAMES_KEPT + 1));
}

/// A post with an empty body is its prefix alone, and opens to nothing;
/// one byte short of the prefix is malformed.
#[test]
fn a_post_of_no_body_opens_and_a_shorter_prefix_is_malformed() {
    let ep = Epoch { e: 4, d_e: [4; 32] };
    let plain = post_plaintext(&GEN, &ep, b"");
    assert_eq!(plain.len(), 16 + 4 + 32);
    assert_eq!(open_post(&GEN, &ep, &plain), Ok(&b""[..]));
    assert_eq!(
        open_post(&GEN, &ep, &plain[..51]).err(),
        Some(GkError::Malformed)
    );
}

// ── KeyholdersReplace (§4.3, §5.11) ───────────────────────────────────────

/// Keyholders `k1` (a desktop, counter 0) and `k2` after a KeyholdersAdd,
/// `k1` after its account's rotation, and the KeyholdersReplace in which
/// `k1` swaps its entry for the new pair with counter 1.
fn replace_case() -> (Party, Party, Party, SignedHeader, HeaderV1) {
    let g = text();
    let (k1, k2) = (Party::new(acct(1)), Party::new(acct(2)));
    let gen = signed(None, genesis_of(&k1, &g, T0, false), &k1);
    let mut add = next(&gen, Kind::KeyholdersAdd, T0 + 60);
    add.keyholders = vec![k1.entry(), k2.entry()];
    let add = signed(Some(&gen), add, &k1);
    let k1_new = rotated(&k1);
    let mut entry = k1_new.entry();
    entry.n = 1;
    let mut h = next(&add, Kind::KeyholdersReplace, T0 + 120);
    h.keyholders = vec![entry, k2.entry()];
    h.signer = k1.m;
    (k1, k2, k1_new, add, h)
}

/// The form of a KeyholdersReplace: kind 6 on the wire, a header that sets
/// keyholders, an opening header that keeps the seed.
#[test]
fn a_keyholders_replace_is_kind_six_and_an_opening_header_that_sets_keyholders() {
    assert_eq!(
        postcard::to_allocvec(&Kind::KeyholdersReplace).unwrap(),
        [6]
    );
    assert_eq!(postcard::to_allocvec(&Kind::KeyholdersRemove).unwrap(), [5]);
    let kind = Kind::KeyholdersReplace;
    assert!(kind.opens_epoch() && kind.sets_keyholders() && !kind.starts_anew());
    let (k1, _, _, add, h) = replace_case();
    let replace = signed(Some(&add), h.clone(), &k1);
    assert_eq!(replace.kh(), replace.d(), "it names its own set");
    let (b, s) = raw_signed(
        &HeaderV1 {
            keyholders: vec![],
            ..replace.header().clone()
        },
        &k1,
    );
    assert_eq!(
        decode(&b, &s).err(),
        Some(Refusal::Form("a header that sets keyholders names 1 to 8"))
    );
}

/// §4.3: a KeyholdersReplace swaps exactly one entry, its signer's own, for
/// one with the same member id, user id, origin and `IK`, a higher counter
/// and a new pair. Each clause refused on its own.
#[test]
fn a_keyholders_replace_swaps_exactly_its_signers_entry_for_a_newer_pair() {
    let (k1, k2, k1_new, add, h) = replace_case();
    let old = add.header().keyholders.clone();
    let new = h.keyholders.iter().find(|k| k.m == k1.m).copied().unwrap();
    assert_eq!(
        replaced_entry(&old, &h),
        Ok(Swap {
            old: k1.entry(),
            new
        }),
        "the control"
    );
    assert_eq!(check_keyholder_change(&old, &h), Ok(()));
    let refused = |why| Err(Refusal::KeyholderChange(why));
    let with = |entries: Vec<Keyholder>| HeaderV1 {
        keyholders: entries,
        ..h.clone()
    };
    let one = refused("a KeyholdersReplace swaps exactly one entry");
    let k2_new = {
        let mut e = rotated(&k2).entry();
        e.n = 1;
        e
    };
    let k3 = Party::new(acct(3)).entry();
    assert_eq!(replaced_entry(&old, &with(vec![new, k2_new])), one, "two");
    assert_eq!(
        replaced_entry(&old, &with(vec![new, k2.entry(), k3])),
        one,
        "and adds"
    );
    assert_eq!(replaced_entry(&old, &with(vec![new])), one, "and drops");
    assert_eq!(replaced_entry(&old, &with(old.clone())), one, "none");
    assert_eq!(
        replaced_entry(&old, &with(vec![k1.entry(), k2_new])),
        refused("a KeyholdersReplace swaps its signer's own entry"),
        "k1 swapping k2's pair"
    );
    let keeps = refused("a swapped entry keeps its member id, user id, origin and IK");
    for changed in [
        Keyholder { m: acct(9), ..new },
        Keyholder { u: Some(5), ..new },
        Keyholder {
            origin: 0x02,
            ..new
        },
        Keyholder {
            ik: k2.ik_raw(),
            ..new
        },
    ] {
        assert_eq!(
            replaced_entry(&old, &with(vec![changed, k2.entry()])),
            keeps,
            "{changed:?}"
        );
    }
    let counter = refused("a swapped entry has a higher counter");
    for n in [0, 0] {
        let mut e = new;
        e.n = n;
        assert_eq!(replaced_entry(&old, &with(vec![e, k2.entry()])), counter);
    }
    let higher_before: Vec<Keyholder> = vec![Keyholder { n: 3, ..k1.entry() }, k2.entry()];
    assert_eq!(
        replaced_entry(
            &higher_before,
            &with(vec![Keyholder { n: 2, ..new }, k2.entry()])
        ),
        counter,
        "a lower counter"
    );
    let pair = refused("a swapped entry has a new pair");
    let same_kx = Keyholder {
        kx: k1.entry().kx,
        ..new
    };
    let same_kk = Keyholder {
        tag_kk: k1.entry().tag_kk,
        ..new
    };
    for e in [same_kx, same_kk] {
        assert_eq!(replaced_entry(&old, &with(vec![e, k2.entry()])), pair);
    }
    // A connection keyholder does not rotate.
    let conn_before = vec![
        Keyholder {
            origin: 0x02,
            ..k1.entry()
        },
        k2.entry(),
    ];
    let conn_after = Keyholder {
        origin: 0x02,
        ..new
    };
    assert_eq!(
        replaced_entry(&conn_before, &with(vec![conn_after, k2.entry()])),
        refused("only a desktop keyholder pair is replaced")
    );
    assert_eq!(
        replaced_entry(
            &old,
            &HeaderV1 {
                kind: Kind::KeyholdersRemove,
                ..h.clone()
            }
        ),
        refused("not a KeyholdersReplace")
    );
    // As a member checks it: signed by the swapped entry's IK, from the set
    // the header names; k2 may not swap k1's pair.
    let replace = signed(Some(&add), h.clone(), &k1);
    assert_eq!(check_signer(&replace, Some(&add), NO_PINS), Ok(k1.ik_raw()));
    assert_eq!(check_link(&add, &replace), Ok(vec![]));
    let by_k2 = signed(
        Some(&add),
        HeaderV1 {
            signer: k2.m,
            ..h.clone()
        },
        &k2,
    );
    assert_eq!(
        check_signer(&by_k2, Some(&add), NO_PINS),
        Err(Refusal::KeyholderChange(
            "a KeyholdersReplace swaps its signer's own entry"
        ))
    );
    // Its new entry's counter is checked as any new keyholder entry's.
    let seen = |a: &[u8; 16]| (*a == [1; 16]).then_some(Seen { n: 1, made: T0 });
    assert_eq!(check_counters(&h, &old, &seen, Some([1; 16])), Ok(()));
    let _ = k1_new;
}

/// §4.3: a KeyholdersReplace never starts or finishes a roll; and it makes
/// the rows a Fresh makes, never a ratchet.
#[test]
fn a_keyholders_replace_keeps_the_seed_and_makes_rows_only_as_a_fresh_would() {
    let (k1, _, _, add, h) = replace_case();
    let link = |seed, seed_floor| {
        let h = HeaderV1 {
            seed,
            seed_floor,
            ..h.clone()
        };
        check_link(&add, &signed(Some(&add), h, &k1))
    };
    assert_eq!(link(1, 1), Ok(vec![]), "the control");
    assert_eq!(
        link(2, 1),
        Err(Refusal::Chain("the seed does not follow")),
        "starts a roll"
    );
    // Over a roll that runs: neither finished nor started anew.
    let (k1, k2) = (k1, Party::new(acct(2)));
    let g = text();
    let gen = signed(None, genesis_of(&k1, &g, T0, false), &k1);
    let mut started = next(&gen, Kind::Fresh, T0 + 60);
    started.seed = 2;
    let started = signed(Some(&gen), started, &k1);
    assert_eq!((started.header().seed, started.header().seed_floor), (2, 1));
    let mut entry = rotated(&k1).entry();
    entry.n = 1;
    let replace_at = |seed, seed_floor| HeaderV1 {
        keyholders: vec![entry],
        seed,
        seed_floor,
        ..next(&started, Kind::KeyholdersReplace, T0 + 120)
    };
    let _ = k2;
    assert!(check_link(&started, &signed(Some(&started), replace_at(2, 1), &k1)).is_ok());
    for (s, f) in [(2, 2), (3, 2)] {
        assert_eq!(
            check_link(&started, &signed(Some(&started), replace_at(s, f), &k1)),
            Err(Refusal::Chain("the seed does not follow")),
            "({s}, {f})"
        );
    }
    // The versions: as a Fresh, by rows only.
    let before = [leaf_at(1, 10, Via::Row), leaf_at(2, 20, Via::Row)];
    let kind = Kind::KeyholdersReplace;
    assert_eq!(check_versions(kind, &before, &before), Ok(()));
    assert_eq!(
        check_versions(kind, &before, &[leaf_at(1, 11, Via::Row), before[1]]),
        Ok(()),
        "a re-key by rows"
    );
    assert_eq!(
        check_versions(
            kind,
            &before,
            &[leaf_at(1, 11, Via::Ratchet { from: 10 }), before[1]]
        ),
        Err(Refusal::Versions("only a KeyholdersAdd ratchets"))
    );
    // §10's "rows other than a Fresh would make them", as far as the leaves
    // show it: a Replace is taken or refused on exactly a Fresh's terms. Which
    // versions are due (leavers, the refresh slice, merges, 1 h old) needs
    // the exits and the keyring's `made` times, the keyholder's duty (§5.5)
    // and the relay's `exits_upto` check (§9); a Fresh that leaves a due
    // version is no more refused than a Replace.
    let other = |b, v| Leaf {
        seats: 9,
        ..leaf_at(b, v, Via::Row)
    };
    let afters: [&[Leaf]; 8] = [
        &before,
        &[leaf_at(1, 11, Via::Row), before[1]],
        &[leaf_at(1, 11, Via::Row), leaf_at(2, 21, Via::Row)],
        &[before[0]],
        &[before[0], before[1], leaf_at(3, 30, Via::Row)],
        &[leaf_at(1, 11, Via::Ratchet { from: 10 }), before[1]],
        &[other(1, 10), before[1]],
        &[],
    ];
    for after in afters {
        assert_eq!(
            check_versions(kind, &before, after),
            check_versions(Kind::Fresh, &before, after),
            "{after:?}"
        );
    }
}

/// D5: a KeyholdersReplace signed with the account's `IK` by a device that
/// lacks the old pair passes a member's checks, as §6 says; the other
/// keyholders refuse it, since its keyring welcomes do not open as from the
/// old pair. Nor does one from any entry but the one it swaps. A keyring
/// whose carried-over seeds or kept bucket keys differ from a keyholder's
/// own copy is refused. After a swap, a member's kept row base of the old
/// pair opens no row of the new one.
#[test]
fn a_swap_from_a_device_without_the_old_pair_is_refused_by_the_other_keyholders() {
    let g = text();
    let (k1, k2, k1_new, add, h) = replace_case();
    let replace = signed(Some(&add), h, &k1);
    assert!(check_signer(&replace, Some(&add), NO_PINS).is_ok());
    let swap = replaced_entry(&add.header().keyholders, replace.header()).unwrap();
    let maker = swap.maker().unwrap();
    assert_eq!(maker.id(), k1.holder().id(), "named by its old tag(KX)");
    let (e, s) = (replace.header().epoch, replace.header().seed);
    let ks = keyholder_set_digest(&replace.header().keyholders);
    let krk = key();
    let to_k2 = |from: &Party| keyring_welcome(&g, s, e, &ks, &from.me(), &k2.them(), &krk);
    let open = |w: &[u8]| open_keyring_welcome(&g, s, e, &ks, &k2.me(), &maker, w);
    assert_eq!(
        *open(&to_k2(&k1).unwrap()).unwrap(),
        *krk,
        "from the old pair"
    );
    assert!(
        open(&to_k2(&k1_new).unwrap()).is_err(),
        "from the new pair only"
    );
    let k3 = Party::new(acct(3));
    assert!(open(&to_k2(&k3).unwrap()).is_err(), "from another entry");

    // The device whose entry was swapped, and that did not make the swap,
    // sees its own pair go.
    assert!(swap.swaps(&k1.entry().kx));
    assert!(!swap.swaps(&k2.entry().kx));

    // The keyring the Replace brings: carried-over seeds and kept versions
    // must be the keyholder's own copy.
    let own = Keyring {
        base: KeyringBase {
            gen: GEN,
            epoch: 2,
            join: 0,
            seeds: vec![(1, Zeroizing::new([1; 32]))],
            ck: Zeroizing::new([7; 32]),
            exits_upto: 0,
            buckets: vec![],
        },
        buckets: vec![bucket(1, Pool::Accounts, 3), bucket(2, Pool::Accounts, 4)],
    };
    let again = |edit: &dyn Fn(&mut Keyring)| {
        let mut k = Keyring {
            base: KeyringBase {
                epoch: 3,
                ck: Zeroizing::new([8; 32]),
                ..own.base.clone()
            },
            buckets: own.buckets.clone(),
        };
        edit(&mut k);
        check_carried(&own, &k)
    };
    assert_eq!(again(&|_| {}), Ok(()), "the control");
    assert_eq!(
        again(&|k| {
            k.base.seeds.push((2, Zeroizing::new([2; 32])));
            k.buckets[0] = KeyringBucket {
                v: 11,
                bk: Zeroizing::new([0x55; 32]),
                ..bucket(1, Pool::Accounts, 3)
            };
        }),
        Ok(()),
        "a new seed and a re-versioned bucket are the commit's own"
    );
    assert_eq!(
        again(&|k| k.base.seeds[0].1 = Zeroizing::new([9; 32])),
        Err(GkError::Forged),
        "a seed of its own choosing"
    );
    assert_eq!(
        again(&|k| k.buckets[1].bk = Zeroizing::new([9; 32])),
        Err(GkError::Forged),
        "a kept version's key of its own choosing"
    );
    assert_eq!(
        again(&|k| k.buckets[1].made += 1),
        Err(GkError::Forged),
        "a kept version made anew"
    );
    assert_eq!(
        again(&|k| k.buckets[1].seats -= 1),
        Err(GkError::Forged),
        "a kept version with other seats"
    );

    // A member's kept row base of the old pair, keyed by (K, tag(KX), s).
    let m = Party::new(acct(7));
    let s_m = member_secret(&g, 1, &[7; 32], &m.seat());
    let kept = RowBase::member_side(&g, 1, &m.me(), &k1.holder(), &s_m).unwrap();
    let new_side = RowBase::keyholder_side(&g, 1, &k1_new.me(), &m.them(), &s_m).unwrap();
    let bk = key();
    let row = new_side.row(V1, &bk);
    assert!(kept.open_row(V1, &row).is_err(), "the old pair's row base");
    assert_eq!(
        kept.key().0.m,
        new_side.key().0.m,
        "one member id, one seed"
    );
    assert_eq!(kept.key().1, new_side.key().1);
    assert_ne!(kept.key(), new_side.key(), "kept apart by tag(KX)");
    let fresh = RowBase::member_side(&g, 1, &m.me(), &k1_new.holder(), &s_m).unwrap();
    assert_eq!(fresh.key(), new_side.key());
    assert_eq!(*fresh.open_row(V1, &row).unwrap(), *bk);
}

// ── Seed rolls by kind (§4.3, §5.6) ───────────────────────────────────────

/// A Genesis in `g` by `k`: in a voice group its keyholder is a connection
/// keyholder with a user id.
fn genesis_in(g: &Group, k: &Party) -> SignedHeader {
    let mut h = genesis_of(k, g, T0, false);
    if g.kind() == GroupKind::Voice {
        h.keyholders[0].u = Some(1);
        h.keyholders[0].origin = 0x02;
    }
    signed(None, h, k)
}

/// A header of `kind` after `p` carrying `seed` and `seed_floor`, an hour
/// on so that a Regenesis may come; it keeps `p`'s keyholder set where its
/// kind sets one, which the seed rule does not look at.
fn seeded(p: &SignedHeader, kind: Kind, seed: u32, seed_floor: u32, k: &Party) -> SignedHeader {
    let set = if kind.sets_keyholders() {
        p.header().keyholders.clone()
    } else {
        vec![]
    };
    let set = if set.is_empty() && kind.sets_keyholders() {
        vec![k.entry()]
    } else {
        set
    };
    let h = HeaderV1 {
        keyholders: set,
        seed,
        seed_floor,
        ..next(p, kind, p.header().time + REGENESIS_WAIT)
    };
    signed(Some(p), h, k)
}

/// §4.3 "Seed rolls by kind": over a parent whose roll runs (seed 2, floor
/// 1), what each kind may carry, in a text group and in a voice group. A
/// start is (3, 2), a finish (2, 2), neither (2, 1).
#[test]
fn a_roll_starts_and_finishes_only_at_the_kinds_that_may_in_text_and_in_voice() {
    let k = Party::new(acct(1));
    for g in [text(), voice()] {
        let voice = g.kind() == GroupKind::Voice;
        let gen = genesis_in(&g, &k);
        let start_kind = if voice {
            Kind::KeyholdersRemove
        } else {
            Kind::Fresh
        };
        let p = seeded(&gen, start_kind, 2, 1, &k);
        assert!(check_link(&gen, &p).is_ok(), "{g:?}");
        let ok = |kind, s, f| check_link(&p, &seeded(&p, kind, s, f, &k)).is_ok();
        use Kind::*;
        for (kind, start, finish, neither) in [
            (Fresh, !voice, true, true),
            (KeyholdersAdd, !voice, true, true),
            (KeyholdersRemove, true, !voice, !voice),
            (Join, false, false, true),
            (KeyholdersReplace, false, false, true),
        ] {
            assert_eq!(ok(kind, 3, 2), start, "{kind:?} starts in {g:?}");
            assert_eq!(ok(kind, 2, 2), finish, "{kind:?} finishes in {g:?}");
            assert_eq!(ok(kind, 2, 1), neither, "{kind:?} neither in {g:?}");
            assert!(
                !ok(kind, 3, 3),
                "{kind:?}: a start finishes nothing of its own"
            );
            assert!(!ok(kind, 3, 1), "{kind:?}: a start drops the older seed");
        }
        if voice {
            // A voice room has no Regenesis: it makes a new Genesis (§5.9).
            let h = HeaderV1 {
                keyholders: p.header().keyholders.clone(),
                seed: 3,
                seed_floor: 3,
                ..next(&p, Regenesis, p.header().time + REGENESIS_WAIT)
            };
            assert_eq!(
                SignedHeader::sign(h, &k.ik).err(),
                Some(Refusal::Form(
                    "a voice room makes a new Genesis, never a Regenesis"
                ))
            );
            continue;
        }
        // A Regenesis always starts anew, with its floor at its own seed.
        assert!(ok(Regenesis, 3, 3), "{g:?}");
        assert!(!ok(Regenesis, 2, 2) && !ok(Regenesis, 3, 2) && !ok(Regenesis, 4, 4));
    }
    let voice_start = SeedRolls::at_start(genesis_in(&voice(), &k).header());
    assert!(!voice_start.starts(GroupKind::Voice, Kind::Regenesis, T0 + 86_400 * 365));
}

/// §5.6, a text group: a removal makes a roll due, two removals while it is
/// due share it, and it starts at the first opening commit that may start
/// one once 24 h have passed since the last start, the removal itself when
/// that was long enough ago. A removal while a roll runs makes the next one
/// due. And a seed 30 days old is due as well.
#[test]
fn a_text_roll_starts_once_a_day_when_due_and_a_seed_is_due_after_thirty_days() {
    use Kind::*;
    let (day, text_g) = (86_400, GroupKind::Text);
    let k = Party::new(acct(1));
    let gen = genesis_in(&text(), &k);
    let at = |h: &SignedHeader, kind: Kind, seed: u32, floor: u32, time: u64| HeaderV1 {
        keyholders: if kind.sets_keyholders() {
            vec![k.entry()]
        } else {
            vec![]
        },
        seed,
        seed_floor: floor,
        ..next(h, kind, time)
    };
    let r0 = SeedRolls::at_start(gen.header());
    assert_eq!(
        r0,
        SeedRolls {
            raised: T0,
            removal: false
        }
    );
    for kind in [Fresh, KeyholdersAdd, Join, KeyholdersReplace] {
        assert!(!r0.starts(text_g, kind, T0 + 2 * day), "{kind:?}: none due");
    }
    // A removal starts its own roll once the slot is open, counted from the
    // Genesis for the first seed.
    assert!(!r0.starts(text_g, KeyholdersRemove, T0 + day - 1));
    assert!(r0.starts(text_g, KeyholdersRemove, T0 + day));
    // A removal in the first hour: due, and the slot is shut.
    let removal = at(&gen, KeyholdersRemove, 1, 1, T0 + 3600);
    let r1 = r0.after(gen.header(), &removal);
    assert!(r1.removal && r1.due(text_g, T0 + 3600));
    assert!(!r1.starts(text_g, Fresh, T0 + day - 1));
    for kind in [Fresh, KeyholdersAdd, KeyholdersRemove] {
        assert!(r1.starts(text_g, kind, T0 + day), "{kind:?} starts it");
    }
    for kind in [Join, KeyholdersReplace] {
        assert!(!r1.starts(text_g, kind, T0 + day), "{kind:?} never does");
    }
    // A second removal while it is due adds nothing.
    let again = at(&gen, KeyholdersRemove, 1, 1, T0 + 7200);
    assert_eq!(r1.after(gen.header(), &again), r1);
    // The start clears it; a removal while that roll runs makes the next due.
    let start = at(&gen, Fresh, 2, 1, T0 + day);
    let r2 = r1.after(gen.header(), &start);
    assert_eq!(
        r2,
        SeedRolls {
            raised: T0 + day,
            removal: false
        }
    );
    assert!(!r2.due(text_g, T0 + day + 1));
    let during = at(&gen, KeyholdersRemove, 2, 1, T0 + day + 60);
    let r3 = r2.after(&start, &during);
    assert!(r3.due(text_g, T0 + day + 60));
    assert!(!r3.starts(text_g, Fresh, T0 + 2 * day - 1));
    assert!(r3.starts(text_g, Fresh, T0 + 2 * day));
    // A KeyholdersRemove 25 h after the last roll starts the next itself.
    assert!(r2.starts(text_g, KeyholdersRemove, T0 + day + 25 * 3600));
    // Monthly: a seed whose roll started 30 days ago is due, and the next
    // opening commit that may start one does. For seed 1, from the Genesis.
    assert!(!r2.due(text_g, T0 + day + SEED_MAX_AGE - 1));
    assert!(r2.due(text_g, T0 + day + SEED_MAX_AGE));
    assert!(r2.starts(text_g, Fresh, T0 + day + SEED_MAX_AGE));
    assert!(!r2.starts(text_g, Join, T0 + day + SEED_MAX_AGE));
    assert!(r0.starts(text_g, KeyholdersAdd, T0 + SEED_MAX_AGE));
    assert!(!r0.starts(text_g, KeyholdersAdd, T0 + SEED_MAX_AGE - 1));
}

/// §5.6 (D3): a Regenesis is a roll start, exempt from the 24 h rule, that
/// clears a due roll; the validator takes it within 24 h of the last.
#[test]
fn a_regenesis_within_a_day_of_a_roll_is_taken_and_clears_a_due_one() {
    let k = Party::new(acct(1));
    let gen = genesis_in(&text(), &k);
    let p = gen.header();
    let removal = HeaderV1 {
        keyholders: vec![k.entry()],
        ..next(&gen, Kind::KeyholdersRemove, T0 + 60)
    };
    let removal = HeaderV1 { seed: 1, ..removal };
    let due = SeedRolls::at_start(p).after(p, &removal);
    assert!(due.removal);
    let regen = HeaderV1 {
        keyholders: vec![k.entry()],
        ..next(&gen, Kind::Regenesis, T0 + REGENESIS_WAIT)
    };
    assert_eq!((regen.seed, regen.seed_floor), (2, 2));
    assert!(due.starts(GroupKind::Text, Kind::Regenesis, regen.time));
    assert_eq!(check_roll(due, p, &regen), Ok(()));
    let after = due.after(p, &regen);
    assert_eq!(
        after,
        SeedRolls {
            raised: regen.time,
            removal: false
        },
        "the due roll is cleared"
    );
}

/// §5.6 (D2): in a voice group a KeyholdersRemove rolls the seed at once,
/// within 24 h of the last roll too; nothing else starts one, and the 30-day
/// age does not apply.
#[test]
fn a_voice_keyholders_remove_rolls_at_once_and_nothing_else_does() {
    use Kind::*;
    let voice_g = GroupKind::Voice;
    let k = Party::new(acct(1));
    let gen = genesis_in(&voice(), &k);
    let r0 = SeedRolls::at_start(gen.header());
    assert!(r0.starts(voice_g, KeyholdersRemove, T0 + 1));
    let first = seeded(&gen, KeyholdersRemove, 2, 1, &k);
    let r1 = r0.after(gen.header(), first.header());
    assert!(r1.starts(voice_g, KeyholdersRemove, first.header().time + 1));
    assert_eq!(
        check_roll(
            r1,
            first.header(),
            &HeaderV1 {
                seed: 3,
                seed_floor: 2,
                time: first.header().time + 2,
                ..first.header().clone()
            }
        ),
        Ok(()),
        "a second removal 2 s later rolls again"
    );
    for kind in [Fresh, KeyholdersAdd, Join, KeyholdersReplace] {
        assert!(!r1.starts(voice_g, kind, T0 + 40 * 86_400), "{kind:?}");
    }
    assert!(!r0.due(voice_g, T0 + 40 * 86_400), "no seed age in voice");
}

/// The relay's validator (§9): a commit that raises `seed` when no roll is
/// due, or within 24 h of the last raise in a text group, is refused; a
/// commit that leaves a due roll for later is not.
#[test]
fn the_validator_refuses_a_raise_with_no_roll_due_or_within_a_day_of_the_last() {
    let k = Party::new(acct(1));
    let gen = genesis_in(&text(), &k);
    let p = gen.header();
    let r0 = SeedRolls::at_start(p);
    let at = |kind: Kind, seed: u32, time: u64| HeaderV1 {
        keyholders: if kind.sets_keyholders() {
            vec![k.entry()]
        } else {
            vec![]
        },
        seed,
        seed_floor: 1,
        ..next(&gen, kind, time)
    };
    let not_due = Err(Refusal::Roll(
        "the seed rises with no roll due, or within 24 h of the last",
    ));
    let day = 86_400;
    assert_eq!(
        check_roll(r0, p, &at(Kind::Fresh, 2, T0 + 2 * day)),
        not_due
    );
    assert_eq!(
        check_roll(r0, p, &at(Kind::KeyholdersRemove, 2, T0 + day - 1)),
        not_due,
        "within 24 h"
    );
    assert_eq!(
        check_roll(r0, p, &at(Kind::KeyholdersRemove, 2, T0 + day)),
        Ok(())
    );
    let due = SeedRolls {
        removal: true,
        ..r0
    };
    assert_eq!(check_roll(due, p, &at(Kind::Fresh, 2, T0 + day)), Ok(()));
    assert_eq!(
        check_roll(due, p, &at(Kind::Fresh, 1, T0 + day)),
        Ok(()),
        "left for later"
    );
    assert_eq!(check_roll(due, p, &at(Kind::Fresh, 2, T0 + 60)), not_due);
    // A commit that keeps the seed raises nothing: none is refused where no
    // roll could start, with none due or within the day.
    assert_eq!(check_roll(r0, p, &at(Kind::Fresh, 1, T0 + 60)), Ok(()));
    assert_eq!(check_roll(due, p, &at(Kind::Fresh, 1, T0 + 60)), Ok(()));
    assert_eq!(check_roll(due, p, &at(Kind::Join, 1, T0 + day)), Ok(()));
}

/// §5.6: a row uses the newest seed its seat was given a welcome under; a
/// seat still on a seed the new floor dropped gets its seed welcome first.
/// At the commit that starts a roll every seat still holds the old seed.
#[test]
fn a_seat_on_a_dropped_seed_gets_its_seed_welcome_before_any_row() {
    let k = Party::new(acct(1));
    let gen = genesis_in(&text(), &k);
    let start = seeded(&gen, Kind::Fresh, 2, 1, &k);
    assert_eq!(
        row_seed(1, start.header()),
        RowSeed::Row(1),
        "its own rows use s"
    );
    let again = seeded(&start, Kind::Fresh, 3, 2, &k);
    assert_eq!(row_seed(2, again.header()), RowSeed::Row(2));
    assert_eq!(row_seed(3, again.header()), RowSeed::Row(3));
    assert_eq!(
        row_seed(1, again.header()),
        RowSeed::WelcomeFirst(3),
        "seed 1 left the keyring"
    );
}

// ── The versions each kind makes (§4.3) ───────────────────────────────────

fn leaf_at(b: u64, v: u64, via: Via) -> Leaf {
    Leaf {
        b,
        v,
        pool: Pool::Accounts,
        seats: 5,
        list: [v as u8; 32],
        via,
    }
}

/// §4.3 "Buckets": a Join keeps every version and adds new buckets; a
/// KeyholdersAdd ratchets every bucket in place or re-versions it by rows;
/// a KeyholdersRemove and a Regenesis keep none; a Fresh keeps or
/// re-versions by rows. A version id never stands for another version.
#[test]
fn each_kind_makes_only_the_versions_its_kind_may() {
    use Kind::*;
    let (one, two) = (leaf_at(1, 10, Via::Row), leaf_at(2, 20, Via::Row));
    let before = [one, two];
    let rekeyed = leaf_at(1, 11, Via::Row);
    let merged = leaf_at(3, 30, Via::Row);
    let ratchet = |b, from| leaf_at(b, from + 1, Via::Ratchet { from });
    let bad = |why| Err(Refusal::Versions(why));
    for kind in [Fresh, KeyholdersReplace] {
        assert_eq!(check_versions(kind, &before, &before), Ok(()));
        assert_eq!(check_versions(kind, &before, &[rekeyed, two]), Ok(()));
        assert_eq!(check_versions(kind, &before, &[merged]), Ok(()), "a merge");
        assert_eq!(
            check_versions(kind, &before, &[ratchet(1, 10), two]),
            bad("only a KeyholdersAdd ratchets")
        );
    }
    assert_eq!(check_versions(Join, &before, &[one, two, merged]), Ok(()));
    assert_eq!(
        check_versions(Join, &before, &[rekeyed, two, merged]),
        bad("a Join makes new buckets only")
    );
    assert_eq!(
        check_versions(Join, &before, &[one, merged]),
        bad("a Join keeps every version")
    );
    assert_eq!(
        check_versions(KeyholdersAdd, &before, &[ratchet(1, 10), ratchet(2, 20)]),
        Ok(())
    );
    assert_eq!(
        check_versions(
            KeyholdersAdd,
            &before,
            &[ratchet(1, 10), leaf_at(2, 21, Via::Row)]
        ),
        Ok(()),
        "re-versioned by rows for an exit"
    );
    assert_eq!(
        check_versions(KeyholdersAdd, &before, &[ratchet(1, 10), two]),
        bad("this kind keeps no version")
    );
    let other_seats = Leaf {
        seats: 6,
        ..ratchet(1, 10)
    };
    for wrong in [ratchet(1, 99), ratchet(3, 10), other_seats] {
        assert_eq!(
            check_versions(KeyholdersAdd, &before, &[wrong]),
            bad("a ratchet is of its own bucket's version, seats and all"),
            "{wrong:?}"
        );
    }
    for kind in [KeyholdersRemove, Regenesis] {
        assert_eq!(
            check_versions(kind, &before, &[rekeyed, leaf_at(2, 21, Via::Row)]),
            Ok(())
        );
        assert_eq!(
            check_versions(kind, &before, &[rekeyed, two]),
            bad("this kind keeps no version"),
            "{kind:?}"
        );
        assert_eq!(
            check_versions(kind, &before, &[ratchet(1, 10)]),
            bad("only a KeyholdersAdd ratchets")
        );
    }
    let changed = Leaf { seats: 4, ..one };
    assert_eq!(
        check_versions(Fresh, &before, &[changed, two]),
        bad("a version id stands for another version")
    );
    assert_eq!(check_versions(Genesis, &[], &[one]), Ok(()));
}
