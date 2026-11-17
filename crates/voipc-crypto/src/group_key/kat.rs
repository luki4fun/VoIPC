//! Known answers (§11.9), in two sets with fixed inputs of their own.
//!
//! **Python's vectors** (`python_known_answers`): every row of §11.9 that
//! names Python (`tag`, `D`, `KS`, the list digest, `names_hash`, the keyring
//! hash chain, the Merkle root and paths; `s_m`, `RB`, the row, seal, blob,
//! chain, media, keyring and self-row keys, the ratchet and `confirm`; the
//! rows, seals, blobs, chain seals, self-rows, history rows and keyring parts
//! this code must open), the cross-checks of the endorsement and header
//! signed bytes, and every context string.
//!
//! They were computed from the text of docs/GROUP-KEY.md alone, by an author
//! who did not read this code, with the script
//! `target/gk-c1/kat/gen_kats.py` (2026-11-17; `target/` is not committed, so
//! the script is not in the tree). It writes HKDF-SHA256 out over Python's
//! `hmac`, X25519 as the RFC 7748 ladder, XEdDSA from Ed25519 arithmetic in
//! libsignal's variant (no negation, the sign bit in `sig[63]`), postcard and
//! the libsignal SKDM protobuf by hand, and seals with `cryptography`'s
//! AESGCM at the fixed nonce `0c0d…17`; it checks each primitive against
//! published vectors (RFC 5869, 7748, 8032, the GCM spec, and Python-made
//! answers `log.rs` keeps) before it prints anything. Its values are `PY`
//! below, under the names it printed them with. Each check here rebuilds the
//! script's exact inputs (`Py`) and asserts this code's output is Python's
//! value; every value in `PY` is checked.
//!
//! D6 (2026-11-17) made each `names_hash` step bind its header's `time`,
//! `epoch` and `join`; the script's second run (same day) gave the gated
//! headers H2 and H3 on that rule, a three-list names fold, and a
//! KeyholdersReplace H5 with its keys, contexts, row and endorsements.
//!
//! The script's inputs: group `c:kat`, kind `t` (`v` for the media key and
//! one context), generation `run(0x01)[..16]` = `0102…10`; `s` = 2, `e` = 7,
//! `j` = 3; `(b, v)` = `(0x0123456789abcdef, 3)`, `v'` = `0xfedcba9876543210`;
//! chain 5, index 1, stream `0xdeadbeef`; `m` = `Account([1; 16])`, `K` =
//! `Account([2; 16])` (a desktop keyholder pair, origin 0x03), `K'` =
//! `Conn(9)` (a guest's connection pair, origin 0x02), `w = (m, 42)`, owner
//! `m`. Keys: `seed_s` = `run(0x00)`, `D_e` = `run(0x20)`, `CK_e` =
//! `run(0x40)`, `KRK` = `run(0x60)`, `BK(b,v)` = `run(0x80)`, self key =
//! `run(0xa0)`; X25519 privates `KX_K` `run(0xc0)`, `SX_m` `run(0xe0)`,
//! `KX_K'` `run(0x30)`; identity privates `IK_A` (= `IK_w`, `m`'s)
//! `run(0x90)`, `IK_B` (`K`'s) `run(0xb0)`, `IK_g9` (`K'`'s) `run(0x10)`; the
//! SKDM's chain key `run(0x70)`, its signing private `run(0xd0)`, chain id
//! `0x1234`, iteration 0; chain state `run(0x50)`; XEdDSA's 64 random bytes
//! `Z` = `run(0x10)` for 64 bytes; `ser(SK_m)` = `08 ‖ run(0x00)` for 1568
//! bytes, `ser(KK_K)` = `08 ‖ run(0x40)`, `ser(KK_K')` = `08 ‖ run(0x80)`.
//! For the Replace: `KX_K_new` `run(0xf0)` with `ser(KK_K_new)` = `08 ‖
//! run(0xc0)`; `m`'s desktop keyholder pair `KX_A` `run(0x08)` with
//! `ser(KK_A)` = `08 ‖ run(0x20)`; `m`'s connection pair on `u` = 42, X25519
//! `run(0x28)` with `08 ‖ run(0x60)`.
//! `run(x)` is the bytes `x, x+1, …` mod 256, 32 of them unless said.
//!
//! **This code's own answers**, where §11.9 says "libsignal" or "this code":
//! the three whole welcomes (Kyber1024 from a seeded RNG, which Python does
//! not do), whose KEK is still rebuilt from its parts outside `welcome.rs`;
//! an endorsement per origin; and a header with its signature. They pin what
//! this code does today, on inputs of their own: group `c:kat`, generation
//! `run(0x00)[..16]`, `m` = `Account(run(0x10)[..16])`, `K` =
//! `Account(run(0x20)[..16])`, `IK` the identity of `run(200)`.

use hkdf::Hkdf;
use libsignal_protocol::{IdentityKeyPair, KeyPair, PrivateKey, PublicKey};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;
use zeroize::Zeroizing;

use super::ctx::*;
use super::keys::Me;
use super::*;

/// `from, from + 1, …`, mod 256.
fn run(from: u8) -> [u8; 32] {
    std::array::from_fn(|i| from.wrapping_add(i as u8))
}

fn run16(from: u8) -> [u8; 16] {
    std::array::from_fn(|i| from.wrapping_add(i as u8))
}

fn run_n(from: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| from.wrapping_add(i as u8)).collect()
}

const GROUP: &str = "c:kat";

fn kat_group(kind: GroupKind) -> Group {
    Group::new(kind, GROUP, run16(0)).unwrap()
}

fn m() -> MemberId {
    MemberId::Account(run16(0x10))
}

fn k() -> MemberId {
    MemberId::Account(run16(0x20))
}

/// `ser` of a Kyber1024 public key in shape: `08`, then 1568 bytes, byte `i`
/// = `(i mod 256) xor xor`. What tags and endorsements hash; no KEM
/// operation runs on it.
fn kem_pub(xor: u8) -> Vec<u8> {
    std::iter::once(0x08)
        .chain((0..1568).map(|i| (i as u8) ^ xor))
        .collect()
}

fn x25519(private: [u8; 32]) -> KeyPair {
    let private = PrivateKey::deserialize(&private).unwrap();
    KeyPair::new(private.public_key().unwrap(), private)
}

fn identity(private: [u8; 32]) -> IdentityKeyPair {
    IdentityKeyPair::try_from(PrivateKey::deserialize(&private).unwrap()).unwrap()
}

fn seat_m() -> SeatPublic {
    SeatPublic::from_bytes(&kem_pub(0), &x25519(run(128)).public_key.serialize()).unwrap()
}

fn iv() -> [u8; 12] {
    run(12)[..12].try_into().unwrap()
}

fn bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// An RNG that hands out exactly the bytes it was given: XEdDSA's 64
/// random bytes, fixed, so a signature is a known answer.
struct Fixed {
    bytes: Vec<u8>,
    at: usize,
}

impl Fixed {
    fn new(bytes: Vec<u8>) -> Fixed {
        Fixed { bytes, at: 0 }
    }
}

impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let end = self.at + dst.len();
        dst.copy_from_slice(
            self.bytes
                .get(self.at..end)
                .expect("asked for more than given"),
        );
        self.at = end;
    }
}

impl CryptoRng for Fixed {}

/// A deterministic RNG for the vectors §11.9 draws from a seeded one: block
/// `i` of the stream is `SHA-256("voipc-kat-rng|" ‖ seed ‖ i as u64 BE)`,
/// read in order, `next_u32`/`next_u64` little-endian from it. libsignal and
/// rand draw what they draw from it; the stream itself is portable.
pub(super) struct KatRng {
    seed: [u8; 32],
    block: u64,
    buf: [u8; 32],
    used: usize,
}

impl KatRng {
    pub(super) fn new(seed: [u8; 32]) -> KatRng {
        KatRng {
            seed,
            block: 0,
            buf: [0; 32],
            used: 32,
        }
    }
}

impl RngCore for KatRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for d in dst {
            if self.used == 32 {
                self.buf = Sha256::new()
                    .chain_update(b"voipc-kat-rng|")
                    .chain_update(self.seed)
                    .chain_update(self.block.to_be_bytes())
                    .finalize()
                    .into();
                self.block += 1;
                self.used = 0;
            }
            *d = self.buf[self.used];
            self.used += 1;
        }
    }
}

impl CryptoRng for KatRng {}

#[test]
fn the_kat_rng_is_the_stream_it_says() {
    let mut r = KatRng::new(run(0));
    let mut first = [0u8; 40];
    r.fill_bytes(&mut first);
    let b0: [u8; 32] = Sha256::new()
        .chain_update(b"voipc-kat-rng|")
        .chain_update(run(0))
        .chain_update(0u64.to_be_bytes())
        .finalize()
        .into();
    let b1: [u8; 32] = Sha256::new()
        .chain_update(b"voipc-kat-rng|")
        .chain_update(run(0))
        .chain_update(1u64.to_be_bytes())
        .finalize()
        .into();
    assert_eq!(first[..32], b0);
    assert_eq!(first[32..], b1[..8]);
}

// ── Contexts: string equality, written out from §11.1 ─────────────────────

#[test]
fn context_known_answers() {
    let g = kat_group(GroupKind::Text);
    let gen = "000102030405060708090a0b0c0d0e0f";
    let a = "a:101112131415161718191a1b1c1d1e1f";
    let kk = "a:202122232425262728292a2b2c2d2e2f";
    let d_e = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    let seat = SeatRef {
        m: m(),
        tag_sk: [0xaa; 8],
        tag_sx: [0xbb; 8],
    };
    let holder = HolderId {
        m: k(),
        tag_kx: [0xcc; 8],
    };
    let ep = Epoch {
        e: 7,
        d_e: run(160),
    };
    let at = Version {
        b: 0x0123_4567_89ab_cdef,
        v: 3,
    };
    let w = Writer { m: m(), u: 42 };
    let ks = [0xdd; 32];
    let ks_hex = "dd".repeat(32);
    let tags = "aaaaaaaaaaaaaaaa|bbbbbbbbbbbbbbbb";
    let cases = [
        (
            member_ctx(&g, 1, &seat),
            format!("voipc-gk/v1/member|t|c:kat|{gen}|1|{a}|{tags}"),
        ),
        (
            welcome_ctx(&g, 1, WelcomeKind::Seat { at, to: &seat }, &holder),
            format!(
                "voipc-gk/v1/welcome|t|c:kat|{gen}|1|kyber1024|seat|81985529216486895|3|{a}|{tags}|{kk}|cccccccccccccccc"
            ),
        ),
        (
            welcome_ctx(&g, 1, WelcomeKind::Seed { to: &seat }, &holder),
            format!(
                "voipc-gk/v1/welcome|t|c:kat|{gen}|1|kyber1024|seed|{a}|{tags}|{kk}|cccccccccccccccc"
            ),
        ),
        (
            welcome_ctx(
                &g,
                1,
                WelcomeKind::Keyring {
                    e: 7,
                    ks: &ks,
                    to: &HolderId {
                        m: MemberId::Conn(9),
                        tag_kx: [0xee; 8],
                    },
                    tag_kk: &[0xff; 8],
                },
                &holder,
            ),
            format!(
                "voipc-gk/v1/welcome|t|c:kat|{gen}|1|kyber1024|keyring|7|{ks_hex}|g:9|ffffffffffffffff|eeeeeeeeeeeeeeee|{kk}|cccccccccccccccc"
            ),
        ),
        (
            rowbase_ctx(&g, 1, &m(), &[0xbb; 8], &holder),
            format!("voipc-gk/v1/rowbase|t|c:kat|{gen}|1|{a}|bbbbbbbbbbbbbbbb|{kk}|cccccccccccccccc"),
        ),
        (
            row_ctx(&g, 1, at, &m(), &k()),
            format!("voipc-gk/v1/row|t|c:kat|{gen}|1|81985529216486895|3|{a}|{kk}"),
        ),
        (
            seal_ctx(&g, &ep, at),
            format!("voipc-gk/v1/seal|t|c:kat|{gen}|7|{d_e}|81985529216486895|3"),
        ),
        (
            ratchet_ctx(&g, 7, at, 4),
            format!("voipc-gk/v1/ratchet|t|c:kat|{gen}|7|81985529216486895|3|4"),
        ),
        (
            confirm_ctx(&g, 7, 2),
            format!("voipc-gk/v1/confirm|t|c:kat|{gen}|7|2"),
        ),
        (
            list_ctx(&g, at),
            format!("voipc-gk/v1/list|t|c:kat|{gen}|81985529216486895|3"),
        ),
        (
            keyring_ctx(&g, 7, 0, 1, &ks, KeyringWord::Base),
            format!("voipc-gk/v1/keyring|t|c:kat|{gen}|7|0|1|{ks_hex}|base"),
        ),
        (
            keyring_ctx(&g, 7, 2, 1, &ks, KeyringWord::Delta),
            format!("voipc-gk/v1/keyring|t|c:kat|{gen}|7|2|1|{ks_hex}|delta"),
        ),
        (
            writer_ctx(&g, &ep, &w),
            format!("voipc-gk/v1/writer|t|c:kat|{gen}|7|{d_e}|{a}/42"),
        ),
        (
            writer_sig_ctx(&g, &ep, &w),
            format!("voipc-gk/v1/writer-sig|t|c:kat|{gen}|7|{d_e}|{a}/42"),
        ),
        (
            dist_ctx(&g, &ep),
            format!("voipc-gk/v1/dist|t|c:kat|{gen}|7|{d_e}"),
        ),
        (
            chain_ctx(&g, &ep, &m(), 5, 1),
            format!("voipc-gk/v1/chain|t|c:kat|{gen}|7|{d_e}|{a}|5|1"),
        ),
        (
            media_ctx(&kat_group(GroupKind::Voice), &ep, &MemberId::Conn(42), &[0xbb; 8], 0x0102_0304),
            format!("voipc-gk/v1/media|v|c:kat|{gen}|7|{d_e}|g:42|bbbbbbbbbbbbbbbb|16909060"),
        ),
        (
            self_ctx(&g, 1, &seat),
            format!("voipc-gk/v1/self|t|c:kat|{gen}|1|{a}|{tags}"),
        ),
        (
            self_history_ctx(&g, 1, &seat),
            format!("voipc-gk/v1/self-history|t|c:kat|{gen}|1|{a}|{tags}"),
        ),
    ];
    for (got, want) in &cases {
        assert_eq!(got, want);
    }
    // §11.1's own example.
    let lounge = Group::new(GroupKind::Text, "c:lounge-1", run16(0)).unwrap();
    assert_eq!(
        seal_ctx(&lounge, &ep, at),
        format!("voipc-gk/v1/seal|t|c:lounge-1|{gen}|7|{d_e}|81985529216486895|3")
    );
    assert_eq!(
        dist(&g, &ep),
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, cases[14].1.as_bytes())
    );
}

// ── This code's answers ───────────────────────────────────────────────────

/// The three welcomes, each whole, from one `KatRng` seeded with `run(0)`,
/// drawn in this order: `m`'s seat pair (`SeatPair::generate_with`: Kyber1024
/// then X25519), `K`'s keyholder pair, `K'`'s keyholder pair (`K'` =
/// `Account(303132…3f)`), then for the seat, seed and keyring welcomes in
/// turn the encapsulation and `eph` (`welcome::draw`). Nonce `0c0d…17`. Seed
/// `s` = 1; the seat welcome at `(b, v)` = `(0x0123456789abcdef, 3)`, the
/// keyring welcome at `e` = 7 with `KS` = `dd…dd`. `P`: `s_m` = `run(16)`,
/// `BK` = `run(192)`, `KRK` = `run(96)`.
///
/// Each welcome is also opened from its parts, outside `welcome.rs`: `ss_q`
/// by decapsulation, `ss_x = X25519(RX, eph)`, `ss_k = X25519(RX, KX_K)`,
/// the salt over the five public values of §3.2, and `KEK = HKDF(salt, ss_q
/// ‖ ss_x ‖ ss_k, c)`. The tail opens under that KEK to `P`, and under none
/// that leaves one of the three secrets out: so the welcome is §3.2's
/// formula, not just what this code made last time.
#[test]
fn welcome_known_answers() {
    let g = kat_group(GroupKind::Text);
    let mut rng = KatRng::new(run(0));
    let member = SeatPair::generate_with(&mut rng);
    let kh = SeatPair::generate_with(&mut rng);
    let other_kh = SeatPair::generate_with(&mut rng);
    let k_prime = MemberId::Account(run16(0x30));
    let at = Version {
        b: 0x0123_4567_89ab_cdef,
        v: 3,
    };
    let from = Me { m: k(), keys: &kh };
    let (m_pub, kprime_pub) = (member.public(), other_kh.public());
    let to_m = Them {
        m: m(),
        keys: &m_pub,
    };
    let to_k = Them {
        m: k_prime,
        keys: &kprime_pub,
    };
    let (s_m, bk, krk, ks) = (run(16), run(192), run(96), [0xdd; 32]);
    let seat_c = welcome_ctx(
        &g,
        1,
        WelcomeKind::Seat {
            at,
            to: &m_pub.seat(m()),
        },
        &from.holder_id(),
    );
    let seed_c = welcome_ctx(
        &g,
        1,
        WelcomeKind::Seed {
            to: &m_pub.seat(m()),
        },
        &from.holder_id(),
    );
    let ring_c = welcome_ctx(
        &g,
        1,
        WelcomeKind::Keyring {
            e: 7,
            ks: &ks,
            to: &HolderId {
                m: k_prime,
                tag_kx: kprime_pub.tag_dh(),
            },
            tag_kk: &kprime_pub.tag_kem(),
        },
        &from.holder_id(),
    );
    // As `welcome::Drawn::welcome` makes it, at the fixed nonce.
    let make = |to: &Them, c: &str, p: &[u8], rng: &mut KatRng| {
        let d = welcome::draw(&from, to, rng).unwrap();
        let kek = d.kek(&from, to, c);
        let sealed = crate::aead::seal_at(&kek, c, iv(), p);
        [&d.ct_q[..], &d.eph_pub, &iv(), &sealed].concat()
    };
    let p_seat = [&s_m[..], &bk[..]].concat();
    let seat_w = make(&to_m, &seat_c, &p_seat, &mut rng);
    let seed_w = make(&to_m, &seed_c, &s_m, &mut rng);
    let ring_w = make(&to_k, &ring_c, &krk, &mut rng);
    let holder = Holder::new(k(), &kh.public().dh_bytes()).unwrap();
    let me = Me {
        m: m(),
        keys: &member,
    };
    let (got_s, got_bk) = open_seat_welcome(&g, 1, at, &me, &holder, &seat_w).unwrap();
    assert_eq!((*got_s, *got_bk), (s_m, bk));
    assert_eq!(
        *open_seed_welcome(&g, 1, &me, &holder, &seed_w).unwrap(),
        s_m
    );
    let me_k = Me {
        m: k_prime,
        keys: &other_kh,
    };
    assert_eq!(
        *open_keyring_welcome(&g, 1, 7, &ks, &me_k, &holder, &ring_w).unwrap(),
        krk
    );

    assert_eq!(
        hex(&kh.dh.public_key.serialize()),
        WELCOME_KX_K,
        "K's KX public"
    );
    for (w, to, c, p, want) in [
        (&seat_w, &member, &seat_c, &p_seat[..], WELCOME_SEAT),
        (&seed_w, &member, &seed_c, &s_m[..], WELCOME_SEED),
        (&ring_w, &other_kh, &ring_c, &krk[..], WELCOME_KEYRING),
    ] {
        let (ct, eph, tail) = (&w[..1569], &w[1569..1602], &w[1602..]);
        let ss_q = to.kem.secret_key.decapsulate(&Box::from(ct)).unwrap();
        let ss_x = to
            .dh
            .private_key
            .calculate_agreement(&PublicKey::deserialize(eph).unwrap())
            .unwrap();
        let ss_k = to
            .dh
            .private_key
            .calculate_agreement(&kh.dh.public_key)
            .unwrap();
        let salt: [u8; 32] = Sha256::new()
            .chain_update(ct)
            .chain_update(eph)
            .chain_update(to.kem.public_key.serialize())
            .chain_update(to.dh.public_key.serialize())
            .chain_update(kh.dh.public_key.serialize())
            .finalize()
            .into();
        let opens = |ikm: &[u8]| {
            let mut kek = [0u8; 32];
            Hkdf::<Sha256>::new(Some(&salt), ikm)
                .expand(c.as_bytes(), &mut kek)
                .unwrap();
            crate::aead::open(&kek, c, &tail[..12], &tail[12..])
        };
        let (q, x, kk) = (&ss_q[..], &ss_x[..], &ss_k[..]);
        assert_eq!(opens(&[q, x, kk].concat()).as_deref(), Some(p));
        for (left_out, ikm) in [
            ("ss_q", [x, kk].concat()),
            ("ss_x", [q, kk].concat()),
            ("ss_k", [q, x].concat()),
        ] {
            assert!(opens(&ikm).is_none(), "a KEK without {left_out}");
        }
        assert_eq!(
            [
                hex(&Sha256::digest(w)),
                hex(&to.dh.private_key.serialize()),
                hex(eph),
                hex(&ss_q),
                hex(&salt),
                hex(tail),
            ],
            want
        );
    }
}

/// `K`'s `KX` public key from the seeded RNG.
const WELCOME_KX_K: &str = "05055412782157296fa5cadd8ff80c57a366030f3fef7ede4897b302c6cb08873e";
/// Per welcome: SHA-256 of the whole welcome, the recipient's X25519 private
/// key, `eph.pub`, `ss_q`, the salt, and the tail `iv ‖ ct ‖ tag`.
const WELCOME_SEAT: [&str; 6] = [
    "bc2d2d8366f073cedf875e4a347d4fb92abdbb54cd923371b5f0fa7caafa33e4",
    "20c7c5de845587f3e7dfddfeb5f038b1b7cb919b656a9517e6435f6496c03072",
    "052a136dfffb6a6891aac61e367cfe6f61acef36ca29eb10af8a4a24992aca3617",
    "5204097fa023cb81699564fb6c293257927d11c4c67cb064c7c374ff5ff97668",
    "05036d335eb4dd813126a3f227af4469311c5ba75ce9ccabe121a9881a848bde",
    "0c0d0e0f1011121314151617149dcd63e9cf71c83350365209fa2e20bc680752b482bd6fe3cd9f06ec2fba717d8fba4f58fcdfaac54adf028e8fe7e8ad0ad3e662a39390431fb84ae05c280a5454243fbd5b24d1436788d569222e1a",
];
const WELCOME_SEED: [&str; 6] = [
    "0c6e0a50cde53b281d8072916a92958d05076db13ef2569143b4d49c08830b02",
    "20c7c5de845587f3e7dfddfeb5f038b1b7cb919b656a9517e6435f6496c03072",
    "0582a6949e54ab39a7da94c7f37aa3890e1f1c8cafe1857429d171832b89d4db15",
    "cfd039c7782ec003cf342f2461f018b52d325c798bbc4944ef4de43cfd5a5475",
    "0dd29db857cc859b8a9b591b39f638e45c2a55fbae331df83fe2cafd3ac0277b",
    "0c0d0e0f1011121314151617cc0eeb68783fa2cf34edd8737bda1d07ef43ac51415eeb3c153a4a22484cd5b5566d997adce7fe1dd1291d388da05ec6",
];
const WELCOME_KEYRING: [&str; 6] = [
    "ccc3fbf6a5cd00a558f470917d5da749b3e638c55b6136cb1e235fdee4275d99",
    "6081d87a97e8355af86203746f9429a40eb6940ce91bd602faca10952210d562",
    "05b944b68e49a399b733be017316a5275f98f9ba4c28b49104ddf006878ad1fa79",
    "454d070c3bf8780de817f90da498c558e22ecb9fa15538f8608fa4865ec6baed",
    "cccf70aee9cc76224a0b24d9f19cef99ba4a3bf5711aac0024599138423cfef4",
    "0c0d0e0f10111213141516172d2e41d09d25a7b594b1bc6419fd58795a80de32f5c8d5092e91f223d6754142fcd601aeccd867f8c4b028434cde3c3e",
];

/// An endorsement for each origin (§11.8), signed by `IK` = the identity
/// whose private key is `run(200)`, with XEdDSA's 64 random bytes from a
/// `KatRng` seeded with `run(1)`, drawn in the order below. Keys: `SK_m`
/// public `kem_pub(0)`, `SX_m` from `run(128)`. `made` = 1 800 000 000.
#[test]
fn endorsement_known_answers() {
    let ik = IdentityKeyPair::try_from(PrivateKey::deserialize(&run(200)).unwrap()).unwrap();
    let keys = seat_m();
    let mut rng = KatRng::new(run(1));
    let cases = [
        (Origin::VaultSeat, m(), 7, ENDORSE_VAULT),
        (Origin::Connection, MemberId::Conn(42), 0, ENDORSE_CONN),
        (Origin::Desktop, m(), 7, ENDORSE_DESKTOP),
    ];
    assert_eq!(hex(&ik.public_key().serialize()), ENDORSE_IK);
    for (origin, who, n, want) in cases {
        let e =
            Endorsement::sign_with(&ik, origin, who, n, 1_800_000_000, &keys, &mut rng).unwrap();
        assert!(e.verify(ik.identity_key(), &keys));
        let msg = keys::endorsement_message(origin, &who, n, 1_800_000_000, &keys);
        assert_eq!(msg.len(), 17 + 1 + 17 + 4 + 8 + 1569 + 33);
        assert_eq!(
            [hex(&Sha256::digest(&msg)), hex(&e.sig)],
            want,
            "{origin:?}"
        );
    }
}

const ENDORSE_IK: &str = "054d5bab89b0733d9d8dcecf04f321c90b761b7765a6bdb2bddbfad3e7abdf1f66";
/// SHA-256 of the signed bytes, and the signature.
const ENDORSE_VAULT: [&str; 2] = [
    "4a1e22a700d005a6fc8128d6809ee383412b22cd5015e3c834ed6740cda01545",
    "0c35d0d212cdc7eee75a1ed0d6206f848ec08208b8026c5337b16b636b1d6cac3cc07a43fc1cf49ad7110da21d6079b7658b8f24a884dc47340bece21a26328d",
];
const ENDORSE_CONN: [&str; 2] = [
    "58a2d8c893768a4b94f679536677a4bf82031132b038b85a8bf9cd46e173ad90",
    "f32e0f041e83c46dc1131c42fbc602d31fd9acc4c8a2c65604964c6a7cee5c52592a0c88b03444dd9258b373d4c91b0ea292206a986394c90a794fea0cca3587",
];
const ENDORSE_DESKTOP: [&str; 2] = [
    "58c122b08df1dba1b60a8b85b223be1269bf3684c4ab9e4f6b19cdc2fc06ee3c",
    "069aa25d281a023d0ed66f78e99a260d5259f385b5ba1afeab290e688533f915cc44e7dfbbd68d14a871278088e6efc48bb1743579acd0ece44364442039b589",
];

/// A gated Join header with every list filled, signed by the identity of
/// `run(200)` with XEdDSA's random bytes from a `KatRng` seeded with
/// `run(2)`: its body, its `D`, and a signature that verifies. The same
/// signature with `S + ℓ` keeps `D` and is refused. Its `names_hash` steps
/// on from `run(8)` with its own `time`, `epoch` and `join` (§11.3); the
/// body, `D` and signature were made again on 2026-11-17 when D6 brought
/// that in, and differ from the ones before only there.
pub(super) fn kat_header() -> HeaderV1 {
    let ik = IdentityKeyPair::try_from(PrivateKey::deserialize(&run(200)).unwrap()).unwrap();
    let ik_raw: [u8; 32] = ik.public_key().public_key_bytes().try_into().unwrap();
    let mut h = HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen: run16(0),
        epoch: 7,
        join: 2,
        kind: Kind::Join,
        time: 1_800_000_000,
        parent: run(1),
        epoch_parent: run(160),
        kh_parent: run(3),
        signer: k(),
        keyholders: vec![],
        gated: true,
        seed: 2,
        seed_floor: 1,
        exits_upto: 300,
        seats: 130,
        buckets: 3,
        conn_seats: 0,
        bucket_root: run(4),
        keyring_hash: run(5),
        names_hash: [0; 32],
        added: Added::List(vec![
            AddedSeat {
                m: m(),
                ik: ik_raw,
                tag_sk: [0xaa; 8],
                tag_sx: [0xbb; 8],
                n: 7,
                made: 1_799_999_000,
            },
            AddedSeat {
                m: MemberId::Account(run16(0x40)),
                ik: run(6),
                tag_sk: [1; 8],
                tag_sx: [2; 8],
                n: 0,
                made: 1_700_000_000,
            },
        ]),
        removed: Removed::List(vec![]),
        confirm: run(7),
    };
    h.canonicalize();
    h.names_hash = names_step(&run(8), &NamesList::of(&h));
    h
}

#[test]
fn header_known_answers() {
    let ik = IdentityKeyPair::try_from(PrivateKey::deserialize(&run(200)).unwrap()).unwrap();
    let h = SignedHeader::sign_with(kat_header(), &ik, &mut KatRng::new(run(2))).unwrap();
    assert_eq!(hex(h.body()), HEADER_BODY);
    assert_eq!(hex(&h.d()), HEADER_D);
    assert_eq!(hex(&h.sig()), HEADER_SIG);
    let ik_raw: [u8; 32] = ik.public_key().public_key_bytes().try_into().unwrap();
    let back = SignedHeader::decode(
        &bytes(HEADER_BODY),
        &bytes(HEADER_SIG),
        GroupKind::Text,
        GROUP,
    )
    .unwrap();
    assert!(back.verify(&ik_raw));
    assert_eq!(back.header(), &kat_header());
    let s_plus_ell = super::tests::malleated(&back).expect("this S has room for ℓ");
    assert_eq!(
        SignedHeader::decode(back.body(), &s_plus_ell, GroupKind::Text, GROUP).err(),
        Some(Refusal::Signature)
    );
    let msg = [&b"voipc-gk/v1/header-sig|"[..], &back.d()].concat();
    assert!(
        ik.public_key().verify_signature(&msg, &s_plus_ell),
        "libsignal alone takes it, at the same D"
    );
}

const HEADER_BODY: &str = "000005633a6b6174000102030405060708090a0b0c0d0e0f07020380a4a7da060102030405060708090a0b0c0d0e0f10\
    1112131415161718191a1b1c1d1e1f20a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
    030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212200202122232425262728292a2b2c2d2e\
    2f00010201ac02820103000405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122230506070809\
    0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223241adcf0fff493166aa1555bddaba28e213bf5342f9b\
    6718b9914d67b656fc6f59010200101112131415161718191a1b1c1d1e1f4d5bab89b0733d9d8dcecf04f321c90b761b\
    7765a6bdb2bddbfad3e7abdf1f66aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb07989ca7da0600404142434445464748494a\
    4b4c4d4e4f060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324250101010101010101020202\
    02020202020080e2cfaa0601000708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526";
const HEADER_D: &str = "b42fe557a8e487c027fcb28ef3ae55fb33bd1d7454a0fd58903d6c3caf9c5ad3";
const HEADER_SIG: &str = "1969f101f1e059d58c74cff004b0609431d70a6b6342a849331fdafdb475b31233a4e8113b7f30af1935ebe80be1e438bd65acc18eb7fb554f34cca2bd91ef88";

// ── Python's answers ──────────────────────────────────────────────────────

const S: u32 = 2;
const E: u32 = 7;
const J: u32 = 3;
const B_ID: u64 = 0x0123_4567_89ab_cdef;
const V_RATCHET: u64 = 0xfedc_ba98_7654_3210;
const STREAM: u32 = 0xdead_beef;
const TIME: u64 = 1_700_000_000;

/// `ser` of a Kyber1024 public key as the script makes it: `08 ‖ run(from)`
/// for 1568 bytes.
fn kem_ser(from: u8) -> Vec<u8> {
    [&[0x08][..], &run_n(from, 1568)].concat()
}

/// The 32 raw bytes of the public key of `private` (an X25519 or identity
/// private key), as headers carry it.
fn raw(private: [u8; 32]) -> [u8; 32] {
    x25519(private)
        .public_key
        .public_key_bytes()
        .try_into()
        .unwrap()
}

/// A pair whose X25519 half is `private`. Rows take only that half; the
/// Kyber1024 half is drawn to fill the type.
fn pair_with_dh(private: [u8; 32]) -> SeatPair {
    let mut pair = SeatPair::generate_with(&mut KatRng::new(run(3)));
    pair.dh = x25519(private);
    pair
}

/// The script's inputs, as this code takes them.
struct In {
    t: Group,
    v: Group,
    m: MemberId,
    k: MemberId,
    k2: MemberId,
    at: Version,
    ep: Epoch,
    /// `m`'s seat keys `SK_m`, `SX_m`; `K`'s `KK_K`, `KX_K`; `K'`'s.
    seat: SeatPublic,
    kk: SeatPublic,
    kk2: SeatPublic,
    /// The keyholder entries of `K` and `K'`, in their encoded order.
    holders: [Keyholder; 2],
    ks: [u8; 32],
}

impl In {
    fn new() -> In {
        let gen = run16(0x01);
        let pair = |kem: u8, dh: u8| {
            SeatPublic::from_bytes(&kem_ser(kem), &x25519(run(dh)).public_key.serialize()).unwrap()
        };
        let (kk, kk2) = (pair(0x40, 0xc0), pair(0x80, 0x30));
        let holders = [
            Keyholder {
                m: MemberId::Account([2; 16]),
                u: None,
                origin: 0x03,
                n: 4,
                ik: raw(run(0xb0)),
                kx: raw(run(0xc0)),
                tag_kk: kk.tag_kem(),
            },
            Keyholder {
                m: MemberId::Conn(9),
                u: None,
                origin: 0x02,
                n: 0,
                ik: raw(run(0x10)),
                kx: raw(run(0x30)),
                tag_kk: kk2.tag_kem(),
            },
        ];
        In {
            t: Group::new(GroupKind::Text, GROUP, gen).unwrap(),
            v: Group::new(GroupKind::Voice, GROUP, gen).unwrap(),
            m: MemberId::Account([1; 16]),
            k: MemberId::Account([2; 16]),
            k2: MemberId::Conn(9),
            at: Version { b: B_ID, v: 3 },
            ep: Epoch {
                e: E,
                d_e: run(0x20),
            },
            seat: pair(0x00, 0xe0),
            kk,
            kk2,
            ks: keyholder_set_digest(&holders),
            holders,
        }
    }

    /// `m`'s seat: `(m, tag(SK_m), tag(SX_m))`.
    fn seat_ref(&self) -> SeatRef {
        self.seat.seat(self.m)
    }

    fn s_m(&self) -> Zeroizing<[u8; 32]> {
        member_secret(&self.t, S, &run(0x00), &self.seat_ref())
    }

    /// `RB` from keyholder `K` (`kx` its `KX` private key) to `m`.
    fn rb_from(&self, k: MemberId, kx: [u8; 32]) -> RowBase {
        let pair = pair_with_dh(kx);
        let me = Me { m: k, keys: &pair };
        let to = Them {
            m: self.m,
            keys: &self.seat,
        };
        RowBase::keyholder_side(&self.t, S, &me, &to, &self.s_m()).unwrap()
    }

    /// The same `RB` as `m` makes it, from `K`'s entry.
    fn rb_at_m(&self) -> RowBase {
        let pair = pair_with_dh(run(0xe0));
        let me = Me {
            m: self.m,
            keys: &pair,
        };
        let from = Holder::new(self.k, &x25519(run(0xc0)).public_key.serialize()).unwrap();
        RowBase::member_side(&self.t, S, &me, &from, &self.s_m()).unwrap()
    }

    /// The five leaves, sorted by `b` as a u64: `L0`..`L4`.
    fn leaves(&self) -> [Leaf; 5] {
        let list_kat = list_digest(
            &self.t,
            self.at,
            &[
                SeatRef {
                    m: self.k,
                    tag_sk: [0xb1; 8],
                    tag_sx: [0xb2; 8],
                },
                self.seat_ref(),
            ],
        );
        let list_conn = list_digest(&self.t, Version { b: 200, v: 17 }, &[g42()]);
        let leaf = |b, v, pool, seats, list, via| Leaf {
            b,
            v,
            pool,
            seats,
            list,
            via,
        };
        [
            leaf(1, 16, Pool::Accounts, 62, [0xa0; 32], Via::Row),
            leaf(200, 17, Pool::Conns, 1, list_conn, Via::Row),
            leaf(
                B_ID,
                3,
                Pool::Accounts,
                2,
                list_kat,
                Via::Ratchet { from: 2 },
            ),
            leaf(
                1 << 63,
                (1 << 63) + 1,
                Pool::Accounts,
                61,
                [0xa3; 32],
                Via::Row,
            ),
            leaf(
                u64::MAX,
                7,
                Pool::Conns,
                62,
                [0xa4; 32],
                Via::Ratchet { from: V_RATCHET },
            ),
        ]
    }
}

/// The connection seat `g:42` with tags `c1…` and `c2…`.
fn g42() -> SeatRef {
    SeatRef {
        m: MemberId::Conn(42),
        tag_sk: [0xc1; 8],
        tag_sx: [0xc2; 8],
    }
}

/// `AEAD(HKDF(key, c), c, plain)` at the script's nonce, as hex.
fn sealed_at(key: &[u8; 32], c: &str, plain: &[u8]) -> String {
    let kek = super::hkdf32(None, key, c.as_bytes());
    hex(&[&iv()[..], &crate::aead::seal_at(&kek, c, iv(), plain)].concat())
}

/// XEdDSA's 64 random bytes as the script fixes them: `run(0x10)`, 64 long.
fn z() -> Fixed {
    Fixed::new(run_n(0x10, 64))
}

/// What the checks took from the table of Python's values (`PY`), and what
/// did not match.
struct Py {
    table: &'static [(&'static str, &'static str)],
    used: std::collections::BTreeSet<&'static str>,
    wrong: Vec<String>,
}

impl Py {
    fn new(table: &'static [(&'static str, &'static str)]) -> Py {
        Py {
            table,
            used: Default::default(),
            wrong: vec![],
        }
    }

    fn value(&mut self, name: &'static str) -> &'static str {
        let (n, v) = self
            .table
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("no Python vector named {name}"));
        self.used.insert(n);
        v
    }

    fn bytes(&mut self, name: &'static str) -> Vec<u8> {
        bytes(self.value(name))
    }

    /// Notes a mismatch and goes on, so one run shows every one.
    fn check(&mut self, name: &'static str, got: impl AsRef<str>) {
        let want = self.value(name);
        if got.as_ref() != want {
            self.wrong.push(format!(
                "{name}\n  this code: {}\n  Python:    {want}",
                got.as_ref()
            ));
        }
    }
}

fn keys_and_tags(i: &In, py: &mut Py) {
    for (name, private) in [
        ("ser(KX_K.pub)", 0xc0),
        ("ser(SX_m.pub)", 0xe0),
        ("ser(KX_K'.pub)", 0x30),
        ("ser(IK_A.pub) = ser(IK_w)", 0x90),
        ("ser(IK_B.pub)", 0xb0),
        ("ser(IK_g9.pub)", 0x10),
        ("ser(SKDM signing pub)", 0xd0),
    ] {
        py.check(name, hex(&x25519(run(private)).public_key.serialize()));
    }
    py.check("tag(SK_m)", hex(&i.seat.tag_kem()));
    py.check("tag(SX_m)", hex(&i.seat.tag_dh()));
    py.check("tag(KX_K)", hex(&i.kk.tag_dh()));
    py.check("tag(KK_K)", hex(&i.kk.tag_kem()));
    py.check("tag(KK_K')", hex(&i.kk2.tag_kem()));
    py.check("tag(KX_K')", hex(&i.kk2.tag_dh()));
    assert_eq!(i.seat.tag_kem(), tag(&kem_ser(0x00)), "tag() is the same");
    py.check("seat record a:01…01", hex(&seat_record(&i.seat_ref())));
    py.check("seat record g:42", hex(&seat_record(&g42())));
}

fn contexts(i: &In, py: &mut Py) {
    let seat = i.seat_ref();
    let k = HolderId {
        m: i.k,
        tag_kx: i.kk.tag_dh(),
    };
    let k2 = HolderId {
        m: i.k2,
        tag_kx: i.kk2.tag_dh(),
    };
    let w = Writer { m: i.m, u: 42 };
    let ring = WelcomeKind::Keyring {
        e: E,
        ks: &i.ks,
        to: &k2,
        tag_kk: &i.kk2.tag_kem(),
    };
    let cases = [
        ("ctx member", member_ctx(&i.t, S, &seat)),
        (
            "ctx welcome-seat",
            welcome_ctx(
                &i.t,
                S,
                WelcomeKind::Seat {
                    at: i.at,
                    to: &seat,
                },
                &k,
            ),
        ),
        (
            "ctx welcome-seed",
            welcome_ctx(&i.t, S, WelcomeKind::Seed { to: &seat }, &k),
        ),
        ("ctx welcome-keyring", welcome_ctx(&i.t, S, ring, &k)),
        ("ctx rowbase", rowbase_ctx(&i.t, S, &i.m, &seat.tag_sx, &k)),
        (
            "ctx rowbase (K'=g:9)",
            rowbase_ctx(&i.t, S, &i.m, &seat.tag_sx, &k2),
        ),
        ("ctx row", row_ctx(&i.t, S, i.at, &i.m, &i.k)),
        ("ctx seal", seal_ctx(&i.t, &i.ep, i.at)),
        ("ctx ratchet", ratchet_ctx(&i.t, E, i.at, V_RATCHET)),
        ("ctx confirm", confirm_ctx(&i.t, E, J)),
        ("ctx list", list_ctx(&i.t, i.at)),
        (
            "ctx keyring-base",
            keyring_ctx(&i.t, E, 0, S, &i.ks, KeyringWord::Base),
        ),
        (
            "ctx keyring-delta-3",
            keyring_ctx(&i.t, E, J, S, &i.ks, KeyringWord::Delta),
        ),
        ("ctx writer", writer_ctx(&i.t, &i.ep, &w)),
        ("ctx writer-sig", writer_sig_ctx(&i.t, &i.ep, &w)),
        ("ctx dist", dist_ctx(&i.t, &i.ep)),
        ("ctx chain", chain_ctx(&i.t, &i.ep, &i.m, 5, 1)),
        (
            "ctx media",
            media_ctx(&i.v, &i.ep, &i.m, &seat.tag_sx, STREAM),
        ),
        ("ctx self", self_ctx(&i.t, S, &seat)),
        ("ctx self-history", self_history_ctx(&i.t, S, &seat)),
        (
            "ctx member (conn m, s=u32 max)",
            member_ctx(
                &i.v,
                u32::MAX,
                &SeatRef {
                    m: MemberId::Conn(0),
                    ..seat
                },
            ),
        ),
        (
            "ctx row (b=0, v=u64 max, conn K)",
            row_ctx(&i.t, 1, Version { b: 0, v: u64::MAX }, &i.m, &i.k2),
        ),
    ];
    for (name, c) in cases {
        py.check(name, c);
    }
}

fn lists_and_roots(i: &In, py: &mut Py) {
    let b_seat = SeatRef {
        m: i.k,
        tag_sk: [0xb1; 8],
        tag_sx: [0xb2; 8],
    };
    // Given as [B, A, B]: sorted and each once.
    let list = list_digest(&i.t, i.at, &[b_seat, i.seat_ref(), b_seat]);
    py.check("list(b,v)", hex(&list));
    py.check(
        "list(200,17) conns",
        hex(&list_digest(&i.t, Version { b: 200, v: 17 }, &[g42()])),
    );
    let leaves = i.leaves();
    for (leaf, name) in leaves.iter().zip([
        "leaf L0 postcard",
        "leaf L1 postcard",
        "leaf L2 postcard",
        "leaf L3 postcard",
        "leaf L4 postcard",
    ]) {
        py.check(name, hex(&leaf.encode()));
    }
    py.check("leaf_hash L2", hex(&leaf_hash(&leaves[2])));
    let root = bucket_root(&leaves).unwrap();
    py.check("bucket_root (5 leaves)", hex(&root));
    for (index, name) in [
        (2, "Merkle path for leaf 2 of 5"),
        (4, "Merkle path for leaf 4 of 5"),
    ] {
        let path = inclusion_path(&leaves, index).unwrap();
        assert!(path_ok(&root, 5, &leaves[index], &path));
        let siblings: Vec<String> = path.siblings.iter().map(|s| hex(s)).collect();
        py.check(name, siblings.join(","));
    }
    py.check("bucket_root (no leaves)", hex(&bucket_root(&[]).unwrap()));
    py.check(
        "bucket_root (1 leaf: L2)",
        hex(&bucket_root(&leaves[2..3]).unwrap()),
    );
    py.check(
        "bucket_root (3 leaves: L0..L2)",
        hex(&bucket_root(&leaves[..3]).unwrap()),
    );
    py.check(
        "postcard(keyholders) for KS",
        hex(&postcard::to_allocvec(&i.holders[..]).unwrap()),
    );
    // Given out of order: sorted before it is hashed.
    py.check(
        "KS",
        hex(&keyholder_set_digest(&[i.holders[1], i.holders[0]])),
    );
    py.check(
        "KS voice",
        hex(&keyholder_set_digest(&[
            voice_holder(300, 6),
            voice_holder(5, 5),
        ])),
    );
}

/// A voice keyholder `g:<u>` of the script: `IK` `b…`, `KX` `b+10…`,
/// `tag_kk` `b+20…`.
fn voice_holder(u: u32, b: u8) -> Keyholder {
    Keyholder {
        m: MemberId::Conn(u),
        u: Some(u),
        origin: 0x02,
        n: 0,
        ik: [b; 32],
        kx: [b + 0x10; 32],
        tag_kk: [b + 0x20; 8],
    }
}

fn derived_keys(i: &In, py: &mut Py) {
    let seat = i.seat_ref();
    let s_m = i.s_m();
    py.check("s_m", hex(&*s_m));
    let dh = keys::agree(
        &x25519(run(0xc0)).private_key,
        &x25519(run(0xe0)).public_key,
    )
    .unwrap();
    py.check("X25519(KX_K, SX_m)", hex(&dh));
    let rb = i.rb_from(i.k, run(0xc0));
    py.check("RB", hex(rb.secret()));
    assert_eq!(i.rb_at_m().secret(), rb.secret(), "m's side makes the same");
    py.check("RB' (K'=g:9)", hex(i.rb_from(i.k2, run(0x30)).secret()));
    let key = |k: &[u8; 32], c: String| hex(&*super::hkdf32(None, k, c.as_bytes()));
    let w = Writer { m: i.m, u: 42 };
    let (ck, krk, slf) = (run(0x40), run(0x60), run(0xa0));
    py.check(
        "row key",
        key(rb.secret(), row_ctx(&i.t, S, i.at, &i.m, &i.k)),
    );
    py.check("seal key", key(&run(0x80), seal_ctx(&i.t, &i.ep, i.at)));
    py.check(
        "BK(b,v') ratchet",
        hex(&*ratchet(&i.t, E, i.at, V_RATCHET, &run(0x80))),
    );
    py.check("confirm", hex(&confirm(&i.t, E, J, &ck)));
    let mk = media_key(&i.v, &i.ep, &i.m, &seat.tag_sx, STREAM, &ck).unwrap();
    py.check("media key MK", hex(&*mk));
    py.check("writer blob key", key(&ck, writer_ctx(&i.t, &i.ep, &w)));
    py.check(
        "chain seal key",
        key(&ck, chain_ctx(&i.t, &i.ep, &i.m, 5, 1)),
    );
    py.check(
        "keyring base key",
        key(&krk, keyring_ctx(&i.t, E, 0, S, &i.ks, KeyringWord::Base)),
    );
    py.check("self-row key", key(&slf, self_ctx(&i.t, S, &seat)));
    py.check(
        "history-row key",
        key(&slf, self_history_ctx(&i.t, S, &seat)),
    );
    py.check("dist(group, gen, e, D_e)", dist(&i.t, &i.ep).to_string());
}

/// Each sealed value made again at the script's nonce, and Python's own
/// bytes opened by this code's opener.
fn sealed_values(i: &In, py: &mut Py) {
    let seat = i.seat_ref();
    let (ck, bk, slf, state) = (run(0x40), run(0x80), run(0xa0), run(0x50));
    let rb = i.rb_from(i.k, run(0xc0));
    py.check(
        "row",
        sealed_at(rb.secret(), &row_ctx(&i.t, S, i.at, &i.m, &i.k), &bk),
    );
    let row = py.bytes("row");
    assert_eq!(*i.rb_at_m().open_row(i.at, &row).unwrap(), bk, "row");
    py.check("seal", sealed_at(&bk, &seal_ctx(&i.t, &i.ep, i.at), &ck));
    let seal = py.bytes("seal");
    assert_eq!(*open_seal(&i.t, &i.ep, i.at, &bk, &seal).unwrap(), ck);
    let chain_c = chain_ctx(&i.t, &i.ep, &i.m, 5, 1);
    py.check("chain_seal", sealed_at(&ck, &chain_c, &state));
    let chain = py.bytes("chain_seal");
    assert_eq!(
        *open_chain_seal(&i.t, &i.ep, &i.m, 5, 1, &ck, &chain).unwrap(),
        state
    );
    let s_m = i.s_m();
    py.check(
        "self_row",
        sealed_at(&slf, &self_ctx(&i.t, S, &seat), &*s_m),
    );
    let self_row = py.bytes("self_row");
    assert_eq!(
        *open_self_row(&i.t, S, &seat, &slf, &self_row).unwrap(),
        *s_m
    );

    let rb2 = i.rb_from(i.k2, run(0x30));
    let items = [
        (i.k, i.kk.tag_dh(), *rb.secret()),
        (i.k2, i.kk2.tag_dh(), *rb2.secret()),
    ];
    let plain = postcard::to_allocvec(&items[..]).unwrap();
    py.check("history_row plaintext", hex(&plain));
    py.check(
        "history_row",
        sealed_at(&slf, &self_history_ctx(&i.t, S, &seat), &plain),
    );
    let hist = py.bytes("history_row");
    let entries = open_history_row(&i.t, S, &seat, &slf, &hist).unwrap();
    let want: Vec<HistoryEntry> = items
        .iter()
        .map(|(m, tag_kx, rb)| HistoryEntry {
            k: HolderId {
                m: *m,
                tag_kx: *tag_kx,
            },
            rb: Zeroizing::new(*rb),
        })
        .collect();
    assert_eq!(entries, want, "history row");
}

fn writer_blob_vectors(i: &In, py: &mut Py) {
    let w = Writer { m: i.m, u: 42 };
    let ck = run(0x40);
    let skdm = libsignal_protocol::SenderKeyDistributionMessage::new(
        3,
        dist(&i.t, &i.ep),
        0x1234,
        0,
        run(0x70).to_vec(),
        x25519(run(0xd0)).public_key,
    )
    .unwrap();
    let skdm = skdm.serialized();
    py.check("SKDM", hex(skdm));
    let c = writer_sig_ctx(&i.t, &i.ep, &w);
    let msg = [c.as_bytes(), b"|", skdm].concat();
    py.check("writer-sig signed message", hex(&msg));
    let ik_w = identity(run(0x90));
    let sig = keys::sign_with(ik_w.private_key(), &msg, &mut z());
    py.check("writer sig", hex(&sig));
    let len = u16::try_from(skdm.len()).unwrap().to_be_bytes();
    let plain = [&len[..], skdm, &ik_w.identity_key().serialize(), &sig].concat();
    py.check("blob plaintext", hex(&plain));
    py.check("blob", sealed_at(&ck, &writer_ctx(&i.t, &i.ep, &w), &plain));
    let blob = py.bytes("blob");
    let opened = open_writer_blob(&i.t, &i.ep, &w, &ck, &blob).unwrap();
    assert_eq!(&opened.skdm[..], skdm);
    assert_eq!(opened.ik, *ik_w.identity_key());
}

fn keyring_vectors(i: &In, py: &mut Py) {
    let (krk, ck) = (run(0x60), run(0x40));
    let leaves = i.leaves();
    let bucket = |l: &Leaf, bk: [u8; 32], made: u64| KeyringBucket {
        b: l.b,
        v: l.v,
        pool: l.pool,
        seats: l.seats,
        list: l.list,
        via: l.via,
        bk: Zeroizing::new(bk),
        made,
    };
    let base = KeyringBase {
        gen: run16(0x01),
        epoch: E,
        join: 0,
        seeds: vec![
            (1, Zeroizing::new([0x5e; 32])),
            (2, Zeroizing::new(run(0x00))),
        ],
        ck: Zeroizing::new(ck),
        exits_upto: 12,
        buckets: vec![
            bucket(&leaves[0], [0x0b; 32], 1_699_990_000),
            bucket(&leaves[2], run(0x80), 1_699_996_400),
        ],
    };
    let plain = postcard::to_allocvec(&base).unwrap();
    py.check("keyring base plaintext", hex(&plain));
    let base_c = keyring_ctx(&i.t, E, 0, S, &i.ks, KeyringWord::Base);
    py.check("keyring base (sealed)", sealed_at(&krk, &base_c, &plain));
    let sealed_base = py.bytes("keyring base (sealed)");
    let opened = open_keyring_part(&i.t, E, S, &i.ks, &krk, KeyringPart::Base, &sealed_base);
    assert_eq!(opened.unwrap()[..], plain[..]);
    let mut chain = keyring_hash_start(&sealed_base);
    py.check("H_7,0", hex(&chain));
    let deltas = [
        (
            1,
            vec![bucket(&leaves[1], [0x0c; 32], TIME)],
            [
                "keyring delta 1 plaintext",
                "keyring delta 1 key",
                "keyring delta 1 (sealed)",
                "H_7,1",
            ],
        ),
        (
            2,
            vec![bucket(&leaves[4], [0x0d; 32], TIME + 36)],
            [
                "keyring delta 2 plaintext",
                "keyring delta 2 key",
                "keyring delta 2 (sealed)",
                "H_7,2",
            ],
        ),
        (
            3,
            vec![],
            [
                "keyring delta 3 plaintext",
                "keyring delta 3 key",
                "keyring delta 3 (sealed)",
                "H_7,3",
            ],
        ),
    ];
    let mut sealed = vec![];
    for (j, buckets, [plain_name, key_name, sealed_name, hash_name]) in deltas {
        let plain = postcard::to_allocvec(&KeyringDelta { join: j, buckets }).unwrap();
        py.check(plain_name, hex(&plain));
        let c = keyring_ctx(&i.t, E, j, S, &i.ks, KeyringWord::Delta);
        py.check(key_name, hex(&*super::hkdf32(None, &krk, c.as_bytes())));
        py.check(sealed_name, sealed_at(&krk, &c, &plain));
        let part = py.bytes(sealed_name);
        let opened = open_keyring_part(&i.t, E, S, &i.ks, &krk, KeyringPart::Delta(j), &part);
        assert_eq!(opened.unwrap()[..], plain[..], "delta {j}");
        chain = keyring_hash_next(&chain, &part);
        py.check(hash_name, hex(&chain));
        sealed.push(part);
    }

    // Taken whole, through delta 1, under a head that commits to Python's
    // `H_7,1` and three-leaf root. (Delta 2 holds a ratchet version, which a
    // Join never makes, §4.3: `take_keyring` would refuse it.)
    let ik_b = identity(run(0xb0));
    let kh = SignedHeader::sign(holders_genesis(i), &ik_b).unwrap();
    let head = HeaderV1 {
        epoch: E,
        join: 1,
        kind: Kind::Join,
        time: TIME,
        parent: [0x11; 32],
        epoch_parent: [0x22; 32],
        kh_parent: kh.d(),
        keyholders: vec![],
        seed: 2,
        seed_floor: 1,
        exits_upto: 12,
        seats: 62 + 1 + 2,
        buckets: 3,
        conn_seats: 1,
        bucket_root: py
            .bytes("bucket_root (3 leaves: L0..L2)")
            .try_into()
            .unwrap(),
        keyring_hash: py.bytes("H_7,1").try_into().unwrap(),
        confirm: confirm(&i.t, E, 1, &ck),
        ..kh.header().clone()
    };
    let head = SignedHeader::sign(head, &ik_b).unwrap();
    let ring = take_keyring(&i.t, &head, &kh, &krk, &sealed_base, &sealed[..1]).unwrap();
    assert_eq!(ring.ck(), &ck);
    assert_eq!(ring.seed(2), Some(&run(0x00)));
    let bs: Vec<u64> = ring.buckets.iter().map(|b| b.b).collect();
    assert_eq!(bs, [1, 200, B_ID]);
}

/// An open text Genesis that sets the script's keyholder set `[K, K']`.
fn holders_genesis(i: &In) -> HeaderV1 {
    HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen: run16(0x01),
        epoch: 1,
        join: 0,
        kind: Kind::Genesis,
        time: TIME - 3600,
        parent: [0; 32],
        epoch_parent: [0; 32],
        kh_parent: [0; 32],
        signer: i.k,
        keyholders: i.holders.to_vec(),
        gated: false,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 1,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [0x66; 32],
        keyring_hash: [0x77; 32],
        names_hash: [0; 32],
        added: Added::Count(1),
        removed: Removed::Count(0),
        confirm: [0x88; 32],
    }
}

fn headers(i: &In, py: &mut Py) {
    let ik_b = identity(run(0xb0));
    let h1 = HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen: run16(0x01),
        epoch: 7,
        join: 3,
        kind: Kind::Join,
        time: TIME,
        parent: [0x11; 32],
        epoch_parent: run(0x20),
        kh_parent: [0x22; 32],
        signer: i.k,
        keyholders: vec![],
        gated: false,
        seed: 2,
        seed_floor: 1,
        exits_upto: 12,
        seats: 300,
        buckets: 5,
        conn_seats: 1,
        bucket_root: [0x33; 32],
        keyring_hash: [0x44; 32],
        names_hash: [0; 32],
        added: Added::Count(1),
        removed: Removed::Count(0),
        confirm: [0x55; 32],
    };
    let s1 = SignedHeader::sign_with(h1, &ik_b, &mut z()).unwrap();
    py.check("header H1 body", hex(s1.body()));
    py.check("D(H1)", hex(&s1.d()));
    let msg = [HEADER_SIG_LABEL, &s1.d()].concat();
    py.check("header-sig message (H1)", hex(&msg));
    py.check("header sig (H1)", hex(&s1.sig()));
    assert!(s1.verify(&raw(run(0xb0))));
    // S + ℓ: libsignal takes Python's, at the same D; our wrapper does not.
    let malleated = super::tests::malleated(&s1).expect("this S has room for ℓ");
    py.check("header sig (H1) with S + l", hex(&malleated));
    let theirs = py.bytes("header sig (H1) with S + l");
    assert!(ik_b.public_key().verify_signature(&msg, &theirs));
    assert_eq!(
        SignedHeader::decode(s1.body(), &theirs, GroupKind::Text, GROUP).err(),
        Some(Refusal::Signature)
    );

    // The two gated lists of H2 and H3 below, as their headers encode them.
    // Their bytes are the same whatever `names_hash` binds them to.
    let (added2, added3) = names_lists(i);
    py.check(
        "postcard(added) H2",
        hex(&postcard::to_allocvec(&added2).unwrap()),
    );
    py.check(
        "postcard(added) H3",
        hex(&postcard::to_allocvec(&added3).unwrap()),
    );

    // An open voice KeyholdersRemove: connection keyholders with user ids,
    // and a u64 past the u32 range.
    let mut h4 = HeaderV1 {
        group_kind: GroupKind::Voice,
        epoch: 9,
        join: 0,
        kind: Kind::KeyholdersRemove,
        time: TIME + 60,
        parent: [0xd1; 32],
        epoch_parent: [0; 32],
        kh_parent: [0xd2; 32],
        signer: MemberId::Conn(5),
        keyholders: vec![voice_holder(300, 6), voice_holder(5, 5)],
        seed: 3,
        seed_floor: 2,
        exits_upto: (1 << 32) + 5,
        seats: 4,
        buckets: 1,
        conn_seats: 4,
        bucket_root: [0xd3; 32],
        keyring_hash: [0xd4; 32],
        confirm: [0xd5; 32],
        ..s1.header().clone()
    };
    h4.added = Added::Count(0);
    h4.removed = Removed::Count(2);
    h4.canonicalize();
    assert_eq!(h4.check_shape(), Ok(()));
    py.check("header H4 body", hex(&h4.encode()));
    py.check("D(H4)", hex(&digest(&h4.encode())));

    let mut removed = vec![
        SeatRef {
            m: MemberId::Account([3; 16]),
            tag_sk: [0xc3; 8],
            tag_sx: [0xc4; 8],
        },
        i.seat_ref(),
    ];
    removed.sort_by_key(|r| postcard::to_allocvec(r).unwrap());
    py.check(
        "postcard(removed) list",
        hex(&postcard::to_allocvec(&Removed::List(removed)).unwrap()),
    );
}

/// The `added` lists of H2 (one name, `K`'s) and H3 (two names, sorted),
/// as their headers carry them.
fn names_lists(i: &In) -> (Added, Added) {
    let seat_b = AddedSeat {
        m: i.k,
        ik: raw(run(0xb0)),
        tag_sk: [0xb1; 8],
        tag_sx: [0xb2; 8],
        n: 4,
        made: 1_699_999_000,
    };
    let seat_a = AddedSeat {
        m: i.m,
        ik: raw(run(0x90)),
        tag_sk: i.seat.tag_kem(),
        tag_sx: i.seat.tag_dh(),
        n: 1,
        made: TIME,
    };
    let seat_c = AddedSeat {
        m: MemberId::Account([3; 16]),
        ik: [0xcc; 32],
        tag_sk: [0xc3; 8],
        tag_sx: [0xc4; 8],
        n: 0,
        made: TIME + 1,
    };
    let mut three = HeaderV1 {
        added: Added::List(vec![seat_c, seat_a]),
        ..holders_genesis(i)
    };
    three.canonicalize();
    (Added::List(vec![seat_b]), three.added)
}

/// The 98 bytes a `names_hash` step hashes (§11.3), laid out here by hand
/// from the step's fields; `NamesStep::hash` must be their SHA-256.
fn names_preimage(step: &NamesStep) -> Vec<u8> {
    let bytes = [
        NAMES_LABEL,
        &step.before,
        &step.time.to_be_bytes(),
        &step.epoch.to_be_bytes(),
        &step.join.to_be_bytes(),
        &step.list,
    ]
    .concat();
    assert_eq!(bytes.len(), 98);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), step.hash());
    bytes
}

/// H2, a gated text Genesis whose `names_hash` is a first step from 0³²,
/// and H3, a gated Join after it whose `names_hash` steps on from H2's: each
/// step bound to its own header's `time`, `epoch` and `join` (§11.3, D6 of
/// 2026-11-17). Returns H3, the names floor the fold below starts from.
fn names_headers(i: &In, py: &mut Py) -> SignedHeader {
    let ik_b = identity(run(0xb0));
    let (added2, added3) = names_lists(i);
    let Added::List(list2) = &added2 else {
        unreachable!("a gated list")
    };
    let h2_place = NamesList {
        time: TIME - 3600,
        epoch: 1,
        join: 0,
        added: list2.clone(),
    };
    py.check(
        "names step preimage H2 (Genesis)",
        hex(&names_preimage(&h2_place.step_from(&[0; 32]))),
    );
    let names2 = names_start(&h2_place);
    py.check("names_hash H2 (Genesis)", hex(&names2));
    // §11.3's `postcard(added)` read as the bare list, without the
    // `Added::List` index: not what §11.3 says, nor what this code does.
    let bare = NamesStep {
        list: Sha256::digest(postcard::to_allocvec(list2).unwrap()).into(),
        ..h2_place.step_from(&[0; 32])
    }
    .hash();
    assert_ne!(bare, names2);
    let h2 = HeaderV1 {
        keyholders: vec![i.holders[0]],
        gated: true,
        names_hash: names2,
        added: added2,
        removed: Removed::List(vec![]),
        ..holders_genesis(i)
    };
    assert_eq!(names_hash(None, &h2), names2);
    let s2 = SignedHeader::sign(h2, &ik_b).unwrap();
    py.check("header H2 body", hex(s2.body()));
    py.check("D(H2)", hex(&s2.d()));

    let mut h3 = HeaderV1 {
        epoch: 1,
        join: 1,
        kind: Kind::Join,
        time: TIME,
        parent: s2.d(),
        epoch_parent: s2.d(),
        kh_parent: s2.d(),
        keyholders: vec![],
        seats: 3,
        buckets: 2,
        bucket_root: [0x99; 32],
        keyring_hash: [0xaa; 32],
        added: added3,
        confirm: [0xbb; 32],
        ..s2.header().clone()
    };
    h3.names_hash = names_hash(Some(s2.header()), &h3);
    assert_eq!(h3.names_hash, names_step(&names2, &NamesList::of(&h3)));
    py.check("names_hash H3 (Join after H2)", hex(&h3.names_hash));
    let s3 = SignedHeader::sign(h3, &ik_b).unwrap();
    py.check("header H3 body", hex(s3.body()));
    py.check("D(H3)", hex(&s3.d()));
    assert_eq!(check_link(&s2, &s3), Ok(vec![]));

    // The first step is taken even for an empty list, at the opening header
    // that turns `gated` on (§11.3): `01 00` is what it digests.
    py.check(
        "postcard(added) empty list",
        hex(&postcard::to_allocvec(&Added::List(vec![])).unwrap()),
    );
    let open = holders_genesis(i);
    let on = HeaderV1 {
        epoch: 12,
        kind: Kind::Fresh,
        time: 1_700_007_200,
        parent: [0x12; 32],
        kh_parent: [0x13; 32],
        keyholders: vec![],
        gated: true,
        added: Added::List(vec![]),
        removed: Removed::List(vec![]),
        ..open.clone()
    };
    let gate_on = names_hash(Some(&open), &on);
    assert_eq!(gate_on, names_start(&NamesList::of(&on)));
    py.check("names_hash gate-on step (empty list)", hex(&gate_on));
    s3
}

/// One fill-byte `added` entry of the fold below: account `a`, `IK` `ik`,
/// tags `t…` and `t+1…`.
fn fill_seat(a: u8, ik: u8, t: u8, n: u32, made: u64) -> AddedSeat {
    AddedSeat {
        m: MemberId::Account([a; 16]),
        ik: [ik; 32],
        tag_sk: [t; 8],
        tag_sx: [t + 1; 8],
        n,
        made,
    }
}

/// §4.4 rule 4: a writer whose names floor is H3 folds three later lists
/// (F1, F2 given unsorted, F3), skipping the empty lists of the opening
/// headers between, to the head's `names_hash`: here H5's, the Replace
/// below. A list given another's place, or two lists swapped, step to
/// other values, and the fold refuses them. Returns the fold's head value.
fn names_fold(py: &mut Py, h3: &SignedHeader) -> [u8; 32] {
    let f1 = NamesList {
        time: TIME + 30,
        epoch: 1,
        join: 2,
        added: vec![fill_seat(4, 0x44, 0x41, 3, TIME + 20)],
    };
    let unsorted = vec![
        fill_seat(7, 0x77, 0x71, 1, TIME + 350),
        fill_seat(5, 0x55, 0x51, 0, TIME + 300),
    ];
    let mut sorted = unsorted.clone();
    sorted.sort_by_key(|a| postcard::to_allocvec(a).unwrap());
    assert_eq!(names_list_digest(&unsorted), names_list_digest(&sorted));
    let f2 = NamesList {
        time: TIME + 400,
        epoch: 2,
        join: 1,
        added: unsorted,
    };
    let f3 = NamesList {
        time: TIME + 3600,
        epoch: 4,
        join: 1,
        added: vec![fill_seat(6, 0x66, 0x61, 7, TIME + 3500)],
    };
    let floor = NamesFloor::of(h3.header());
    let mut acc = floor.names_hash;
    for (n, (l, digest, enc)) in [
        (&f1, "list digest F1", "postcard(added) F1"),
        (&f2, "list digest F2", "postcard(added) F2"),
        (&f3, "list digest F3", "postcard(added) F3"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut list = l.added.clone();
        list.sort_by_key(|a| postcard::to_allocvec(a).unwrap());
        py.check(
            enc,
            hex(&postcard::to_allocvec(&Added::List(list)).unwrap()),
        );
        py.check(digest, hex(&names_list_digest(&l.added)));
        if n == 0 {
            py.check(
                "names step preimage F1",
                hex(&names_preimage(&l.step_from(&acc))),
            );
        }
        acc = names_step(&acc, l);
        let name = [
            "names fold after F1",
            "names fold after F2",
            "names fold after F3",
        ][n];
        py.check(name, hex(&acc));
    }
    py.check("names fold head (H3 → F1, F2, F3)", hex(&acc));
    let after_f1 = names_step(&floor.names_hash, &f1);
    let at = |l: &NamesList, p: &NamesList| NamesList {
        time: p.time,
        epoch: p.epoch,
        join: p.join,
        added: l.added.clone(),
    };
    let moved = names_step(&after_f1, &at(&f2, &f3));
    py.check(
        "names step F2 moved to F3's position (must not match)",
        hex(&moved),
    );
    let (f3_at_f2, f2_at_f3) = (at(&f3, &f2), at(&f2, &f3));
    let swapped = names_step(&names_step(&after_f1, &f3_at_f2), &f2_at_f3);
    py.check(
        "names fold with F2's and F3's lists swapped (must not match)",
        hex(&swapped),
    );
    assert!(acc != moved && acc != swapped);

    // The fold itself, to a head at (5, 0) carrying `acc`, past the empty
    // lists of the opening headers between, which step nothing.
    let head = HeaderV1 {
        epoch: 5,
        join: 0,
        kind: Kind::Fresh,
        time: TIME + 3700,
        names_hash: acc,
        added: Added::List(vec![]),
        ..h3.header().clone()
    };
    let gap = |epoch, time| NamesList {
        time,
        epoch,
        join: 0,
        added: vec![],
    };
    let lists = [
        f1.clone(),
        gap(2, TIME + 300),
        f2.clone(),
        gap(3, TIME + 1800),
        gap(4, TIME + 3000),
        f3.clone(),
        NamesList::of(&head),
    ];
    let known = Known {
        pins: &|_, _| PinThen::None,
        counters: &|_| None,
        own: None,
        now: TIME + 3700,
    };
    let fold =
        |lists: &[NamesList]| fold_names(&NamesFrom::Floor(floor), lists, &[], &head, &known);
    match fold(&lists) {
        Ok(Fold::Take { floor, shown, .. }) => {
            assert_eq!(floor, NamesFloor::of(&head));
            assert_eq!(shown.named.len(), 4);
        }
        other => panic!("the fold to H5: {other:?}"),
    }
    assert_eq!(fold(&[f1.clone(), f3_at_f2, f2_at_f3]), Err(Refusal::Names));
    assert_eq!(fold(&[f1, at(&f2, &f3)]), Err(Refusal::Names));
    acc
}

/// The pair `08 ‖ run(kem)` (1568 bytes) with the X25519 private `run(dh)`.
fn kat_pair(kem: u8, dh: u8) -> SeatPublic {
    SeatPublic::from_bytes(&kem_ser(kem), &x25519(run(dh)).public_key.serialize()).unwrap()
}

/// H5, a gated text KeyholdersReplace (§4.3, §5.11): `K` swaps its desktop
/// keyholder pair for `KK_K_new` / `KX_K_new` (counter 4 to 5), beside `m`'s
/// desktop keyholder entry. Its keyring welcomes come from the old pair,
/// named by `tag(KX_K)`; the rows after it from the new one, which the old
/// pair's row base does not open.
fn keyholders_replace(i: &In, py: &mut Py, names_head: [u8; 32]) {
    let (kk_new, kk_a) = (kat_pair(0xc0, 0xf0), kat_pair(0x20, 0x08));
    for (name, private) in [
        ("ser(KX_K_new.pub)", 0xf0),
        ("ser(KX_A.pub)", 0x08),
        ("ser(conn pair X.pub) of a:01…01 u=42", 0x28),
    ] {
        py.check(name, hex(&x25519(run(private)).public_key.serialize()));
    }
    py.check("tag(KX_K_new)", hex(&kk_new.tag_dh()));
    py.check("tag(KK_K_new)", hex(&kk_new.tag_kem()));
    py.check("tag(KX_A)", hex(&kk_a.tag_dh()));
    py.check("tag(KK_A)", hex(&kk_a.tag_kem()));

    let desktop_a = Keyholder {
        m: i.m,
        u: None,
        origin: 0x03,
        n: 1,
        ik: raw(run(0x90)),
        kx: raw(run(0x08)),
        tag_kk: kk_a.tag_kem(),
    };
    let k_new = Keyholder {
        n: 5,
        kx: raw(run(0xf0)),
        tag_kk: kk_new.tag_kem(),
        ..i.holders[0]
    };
    let mut h5 = HeaderV1 {
        group_kind: GroupKind::Text,
        group: GROUP.into(),
        gen: run16(0x01),
        epoch: 5,
        join: 0,
        kind: Kind::KeyholdersReplace,
        time: TIME + 3700,
        parent: [0xe1; 32],
        epoch_parent: [0; 32],
        kh_parent: [0xe2; 32],
        signer: i.k,
        keyholders: vec![k_new, desktop_a],
        gated: true,
        seed: 2,
        seed_floor: 1,
        exits_upto: 40,
        seats: 120,
        buckets: 3,
        conn_seats: 0,
        bucket_root: [0xe3; 32],
        keyring_hash: [0xe4; 32],
        names_hash: names_head,
        added: Added::List(vec![]),
        removed: Removed::List(vec![
            SeatRef {
                m: MemberId::Account([5; 16]),
                tag_sk: [0x51; 8],
                tag_sx: [0x52; 8],
            },
            SeatRef {
                m: MemberId::Account([3; 16]),
                tag_sk: [0xc3; 8],
                tag_sx: [0xc4; 8],
            },
        ]),
        confirm: [0xe5; 32],
    };
    h5.canonicalize();
    py.check(
        "postcard(keyholders) H5",
        hex(&postcard::to_allocvec(&h5.keyholders).unwrap()),
    );
    let ks = keyholder_set_digest(&h5.keyholders);
    py.check("KS H5", hex(&ks));
    py.check(
        "postcard(removed) H5",
        hex(&postcard::to_allocvec(&h5.removed).unwrap()),
    );
    // The set before it: `K`'s old entry beside `m`'s desktop one. The swap
    // is read off the two sets, no header field names it (§11.3).
    let before = [i.holders[0], desktop_a];
    assert_eq!(check_keyholder_change(&before, &h5), Ok(()));
    let swap = replaced_entry(&before, &h5).unwrap();
    assert_eq!((swap.old, swap.new), (i.holders[0], k_new));
    let maker = swap.maker().unwrap().id();
    assert_eq!(maker.tag_kx, i.kk.tag_dh(), "named by its old tag(KX)");

    let ik_b = identity(run(0xb0));
    let s5 = SignedHeader::sign_with(h5, &ik_b, &mut z()).unwrap();
    py.check("header H5 body (KeyholdersReplace)", hex(s5.body()));
    py.check("D(H5)", hex(&s5.d()));
    py.check("header sig (H5)", hex(&s5.sig()));
    assert!(s5.verify(&raw(run(0xb0))));

    let seat = i.seat_ref();
    let to_a = HolderId {
        m: i.m,
        tag_kx: kk_a.tag_dh(),
    };
    let to_k = HolderId {
        m: i.k,
        tag_kx: kk_new.tag_dh(),
    };
    for (name, to, tag_kk) in [
        ("ctx welcome-keyring H5 to a:01…01", &to_a, kk_a.tag_kem()),
        (
            "ctx welcome-keyring H5 to K's new pair",
            &to_k,
            kk_new.tag_kem(),
        ),
    ] {
        let ring = WelcomeKind::Keyring {
            e: 5,
            ks: &ks,
            to,
            tag_kk: &tag_kk,
        };
        py.check(name, welcome_ctx(&i.t, S, ring, &maker));
    }
    py.check(
        "ctx keyring-base H5",
        keyring_ctx(&i.t, 5, 0, S, &ks, KeyringWord::Base),
    );
    py.check(
        "ctx rowbase (K's new pair)",
        rowbase_ctx(&i.t, S, &i.m, &seat.tag_sx, &to_k),
    );

    let dh = keys::agree(
        &x25519(run(0xf0)).private_key,
        &x25519(run(0xe0)).public_key,
    )
    .unwrap();
    py.check("X25519(KX_K_new, SX_m)", hex(&dh));
    let rb = i.rb_from(i.k, run(0xf0));
    py.check("RB (K's new pair)", hex(rb.secret()));
    let row_c = row_ctx(&i.t, S, i.at, &i.m, &i.k);
    py.check(
        "row key (K's new pair)",
        hex(&*super::hkdf32(None, rb.secret(), row_c.as_bytes())),
    );
    py.check(
        "row (K's new pair)",
        sealed_at(rb.secret(), &row_c, &run(0x80)),
    );
    let row = py.bytes("row (K's new pair)");
    let pair = pair_with_dh(run(0xe0));
    let me = Me {
        m: i.m,
        keys: &pair,
    };
    let from_new = Holder::from_raw(i.k, &k_new.kx).unwrap();
    let at_m = RowBase::member_side(&i.t, S, &me, &from_new, &i.s_m()).unwrap();
    assert_eq!(at_m.secret(), rb.secret(), "m's side makes the same");
    assert_eq!(*at_m.open_row(i.at, &row).unwrap(), run(0x80));
    assert!(
        i.rb_at_m().open_row(i.at, &row).is_err(),
        "the old pair's row base opens no row of the new one"
    );
}

fn endorsements(i: &In, py: &mut Py) {
    let (kk_new, conn) = (kat_pair(0xc0, 0xf0), kat_pair(0x60, 0x28));
    let cases = [
        (
            Origin::VaultSeat,
            i.m,
            1,
            TIME,
            &i.seat,
            run(0x90),
            [
                "endorsement 0x01 message head",
                "endorsement 0x01 message SHA-256",
                "endorsement 0x01 sig",
            ],
        ),
        (
            Origin::Connection,
            i.k2,
            0,
            TIME + 100,
            &i.kk2,
            run(0x10),
            [
                "endorsement 0x02 message head",
                "endorsement 0x02 message SHA-256",
                "endorsement 0x02 sig",
            ],
        ),
        (
            Origin::Desktop,
            i.k,
            4,
            1_699_999_000,
            &i.kk,
            run(0xb0),
            [
                "endorsement 0x03 message head",
                "endorsement 0x03 message SHA-256",
                "endorsement 0x03 sig",
            ],
        ),
        (
            Origin::Desktop,
            i.k,
            5,
            TIME + 3000,
            &kk_new,
            run(0xb0),
            [
                "endorsement 0x03 K new pair message head",
                "endorsement 0x03 K new pair message SHA-256",
                "endorsement 0x03 K new pair sig",
            ],
        ),
        // A signed-in member's connection pair names the connection, and is
        // signed by the account's `IK` with the account's counter (§11.8).
        (
            Origin::Connection,
            MemberId::Conn(42),
            1,
            TIME + 200,
            &conn,
            run(0x90),
            [
                "endorsement 0x02 signed-in a:01…01 u=42 message head",
                "endorsement 0x02 signed-in a:01…01 u=42 message SHA-256",
                "endorsement 0x02 signed-in a:01…01 u=42 sig",
            ],
        ),
    ];
    for (origin, who, n, made, pair, ik, [head, digest, sig]) in cases {
        let msg = keys::endorsement_message(origin, &who, n, made, pair);
        assert_eq!(msg.len(), 1649);
        py.check(head, hex(&msg[..47]));
        py.check(digest, hex(&Sha256::digest(&msg)));
        let ik = identity(ik);
        let e = Endorsement::sign_with(&ik, origin, who, n, made, pair, &mut z()).unwrap();
        py.check(sig, hex(&e.sig));
        assert!(e.verify(ik.identity_key(), pair));
    }
}

/// Every value Python computed (`PY`) against this code's, on the script's
/// inputs. All mismatches are listed at once; every value in `PY` must be
/// checked.
#[test]
fn python_known_answers() {
    let i = In::new();
    let mut py = Py::new(PY);
    keys_and_tags(&i, &mut py);
    contexts(&i, &mut py);
    lists_and_roots(&i, &mut py);
    derived_keys(&i, &mut py);
    sealed_values(&i, &mut py);
    writer_blob_vectors(&i, &mut py);
    keyring_vectors(&i, &mut py);
    headers(&i, &mut py);
    let h3 = names_headers(&i, &mut py);
    let names_head = names_fold(&mut py, &h3);
    keyholders_replace(&i, &mut py, names_head);
    endorsements(&i, &mut py);
    py.all_match();
}

impl Py {
    /// Every value matched, and every value in the table was checked, once.
    fn all_match(&self) {
        assert!(
            self.wrong.is_empty(),
            "{} of Python's values differ:\n{}",
            self.wrong.len(),
            self.wrong.join("\n")
        );
        let unchecked: Vec<&str> = self
            .table
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !self.used.contains(n))
            .collect();
        assert!(unchecked.is_empty(), "not checked: {unchecked:?}");
        assert_eq!(self.used.len(), self.table.len(), "each name once");
    }
}

/// Every value `gen_kats.py` printed, under the name it printed it with
/// (`target/gk-c1/kat/final.json`), in its order.
const PY: &[(&str, &str)] = &[
    (
        "ser(KX_K.pub)",
        "05dc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d44",
    ),
    (
        "ser(SX_m.pub)",
        "05736845d54e87de09d6bb114aa7042c50a4a015bd9901d1a0026f5956533a1519",
    ),
    (
        "ser(KX_K'.pub)",
        "0534e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847",
    ),
    (
        "ser(IK_A.pub) = ser(IK_w)",
        "059fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615",
    ),
    (
        "ser(IK_B.pub)",
        "053f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945e",
    ),
    (
        "ser(IK_g9.pub)",
        "05d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66",
    ),
    (
        "ser(SKDM signing pub)",
        "056b3ee67463583cbe3dc08fe9d0765c2666ff5210dd527c9d8705e44927c80d55",
    ),
    (
        "tag(SK_m)",
        "4a7d5eaad621eda8",
    ),
    (
        "tag(SX_m)",
        "fcb6d7fc1937f21f",
    ),
    (
        "tag(KX_K)",
        "36d8a77015efceeb",
    ),
    (
        "tag(KK_K)",
        "5890a708318c0bbd",
    ),
    (
        "tag(KK_K')",
        "2acd85d268a738f8",
    ),
    (
        "tag(KX_K')",
        "9813a52504d423ea",
    ),
    (
        "postcard(keyholders) for KS",
        "0200020202020202020202020202020202020003043f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945edc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d445890a708318c0bbd0109000200d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff6634e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e58472acd85d268a738f8",
    ),
    (
        "KS",
        "b524a31f2896b079b5b374c55ee4169ed4f167397de43ff26ff2363bf1cdd5f8",
    ),
    (
        "ctx member",
        "voipc-gk/v1/member|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|a:01010101010101010101010101010101|4a7d5eaad621eda8|fcb6d7fc1937f21f",
    ),
    (
        "ctx welcome-seat",
        "voipc-gk/v1/welcome|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|kyber1024|seat|81985529216486895|3|a:01010101010101010101010101010101|4a7d5eaad621eda8|fcb6d7fc1937f21f|a:02020202020202020202020202020202|36d8a77015efceeb",
    ),
    (
        "ctx welcome-seed",
        "voipc-gk/v1/welcome|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|kyber1024|seed|a:01010101010101010101010101010101|4a7d5eaad621eda8|fcb6d7fc1937f21f|a:02020202020202020202020202020202|36d8a77015efceeb",
    ),
    (
        "ctx welcome-keyring",
        "voipc-gk/v1/welcome|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|kyber1024|keyring|7|b524a31f2896b079b5b374c55ee4169ed4f167397de43ff26ff2363bf1cdd5f8|g:9|2acd85d268a738f8|9813a52504d423ea|a:02020202020202020202020202020202|36d8a77015efceeb",
    ),
    (
        "ctx rowbase",
        "voipc-gk/v1/rowbase|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|a:01010101010101010101010101010101|fcb6d7fc1937f21f|a:02020202020202020202020202020202|36d8a77015efceeb",
    ),
    (
        "ctx row",
        "voipc-gk/v1/row|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|81985529216486895|3|a:01010101010101010101010101010101|a:02020202020202020202020202020202",
    ),
    (
        "ctx seal",
        "voipc-gk/v1/seal|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|81985529216486895|3",
    ),
    (
        "ctx ratchet",
        "voipc-gk/v1/ratchet|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|81985529216486895|3|18364758544493064720",
    ),
    (
        "ctx confirm",
        "voipc-gk/v1/confirm|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|3",
    ),
    (
        "ctx list",
        "voipc-gk/v1/list|t|c:kat|0102030405060708090a0b0c0d0e0f10|81985529216486895|3",
    ),
    (
        "ctx keyring-base",
        "voipc-gk/v1/keyring|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|0|2|b524a31f2896b079b5b374c55ee4169ed4f167397de43ff26ff2363bf1cdd5f8|base",
    ),
    (
        "ctx keyring-delta-3",
        "voipc-gk/v1/keyring|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|3|2|b524a31f2896b079b5b374c55ee4169ed4f167397de43ff26ff2363bf1cdd5f8|delta",
    ),
    (
        "ctx writer",
        "voipc-gk/v1/writer|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|a:01010101010101010101010101010101/42",
    ),
    (
        "ctx writer-sig",
        "voipc-gk/v1/writer-sig|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|a:01010101010101010101010101010101/42",
    ),
    (
        "ctx dist",
        "voipc-gk/v1/dist|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    ),
    (
        "ctx chain",
        "voipc-gk/v1/chain|t|c:kat|0102030405060708090a0b0c0d0e0f10|7|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|a:01010101010101010101010101010101|5|1",
    ),
    (
        "ctx media",
        "voipc-gk/v1/media|v|c:kat|0102030405060708090a0b0c0d0e0f10|7|202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f|a:01010101010101010101010101010101|fcb6d7fc1937f21f|3735928559",
    ),
    (
        "ctx self",
        "voipc-gk/v1/self|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|a:01010101010101010101010101010101|4a7d5eaad621eda8|fcb6d7fc1937f21f",
    ),
    (
        "ctx self-history",
        "voipc-gk/v1/self-history|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|a:01010101010101010101010101010101|4a7d5eaad621eda8|fcb6d7fc1937f21f",
    ),
    (
        "ctx member (conn m, s=u32 max)",
        "voipc-gk/v1/member|v|c:kat|0102030405060708090a0b0c0d0e0f10|4294967295|g:0|4a7d5eaad621eda8|fcb6d7fc1937f21f",
    ),
    (
        "ctx row (b=0, v=u64 max, conn K)",
        "voipc-gk/v1/row|t|c:kat|0102030405060708090a0b0c0d0e0f10|1|0|18446744073709551615|a:01010101010101010101010101010101|g:9",
    ),
    (
        "seat record a:01…01",
        "01010101010101010101010101010101014a7d5eaad621eda8fcb6d7fc1937f21f",
    ),
    (
        "seat record g:42",
        "020000000000000000000000000000002ac1c1c1c1c1c1c1c1c2c2c2c2c2c2c2c2",
    ),
    (
        "list(b,v)",
        "3d641aaedf83fb0452e3b04920492ceb243357e9f1fe5ec7dc10107d9ebad9c0",
    ),
    (
        "list(200,17) conns",
        "7e5454bd7ac08c1c2e678b03fe0fb9491d1ba9cbc924cf7ea68003c1ff0f445e",
    ),
    (
        "leaf L0 postcard",
        "0110003ea0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000",
    ),
    (
        "leaf L1 postcard",
        "c8011101017e5454bd7ac08c1c2e678b03fe0fb9491d1ba9cbc924cf7ea68003c1ff0f445e00",
    ),
    (
        "leaf L2 postcard",
        "ef9bafcdf8acd191010300023d641aaedf83fb0452e3b04920492ceb243357e9f1fe5ec7dc10107d9ebad9c00102",
    ),
    (
        "leaf L3 postcard",
        "8080808080808080800181808080808080808001003da3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a300",
    ),
    (
        "leaf L4 postcard",
        "ffffffffffffffffff0107013ea4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a40190e4d0b287d3aeeefe01",
    ),
    (
        "leaf_hash L2",
        "407be068d383a17ddd7e52a2207d90f56330441a122b2a9063336139e36be9a7",
    ),
    (
        "bucket_root (5 leaves)",
        "d30c172035d6261ce7fa4df9e644d43dde02ffff54edfaf9cbbb6abe50b2d517",
    ),
    (
        "Merkle path for leaf 2 of 5",
        "a6f25225fe6f9934e1637632d26ae097bb8ceaaacc37c1defa2ce103f9eea42f,f0088c1699ae3d83e63e57bb42ceaf562701c9df95b0df6c985caa3168b236da,fbbe6d6a5bc4419c976382a24c10606de8d115a921b5ec4c965787cb52e6b72c",
    ),
    (
        "Merkle path for leaf 4 of 5",
        "02d9a62c64bfbce0885613cceeeb13196533c8f0209e4a3b36bffea923c4d693",
    ),
    (
        "bucket_root (1 leaf: L2)",
        "407be068d383a17ddd7e52a2207d90f56330441a122b2a9063336139e36be9a7",
    ),
    (
        "bucket_root (3 leaves: L0..L2)",
        "0ddff2dc55f50c24cff7457edb62dcdea584236f26bfba99004ad219aef3d1c6",
    ),
    (
        "bucket_root (no leaves)",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "s_m",
        "8e95a058b8cbb1aa8e0d647c723185cb29d3dc2f518f0942c6a942ed0afe32e2",
    ),
    (
        "X25519(KX_K, SX_m)",
        "28150aa20f6f6c9c8177b9deded7464ebc5aac96029777ff7503cd8e8ca7143e",
    ),
    (
        "RB",
        "5803635b715d4177e44725c28c2e64fb3d8a871f59efef11f42e85a6895f5bd3",
    ),
    (
        "row key",
        "b606fb0262066f4e02ab4957ff91a97077bfe13acd24aaab1abfc9bc61e47ea1",
    ),
    (
        "seal key",
        "bd28a5e588fa92cf2cd8d1b9a3c74641497faf29dcb03a92d359e8e9e7b2792b",
    ),
    (
        "BK(b,v') ratchet",
        "6740710c52cbe4867ab9d208e180ceb3b590393d30b16778207927c3574a90ad",
    ),
    (
        "confirm",
        "4bfa4c849b5a20ea1fcbef811f0e868f70e164ce5cf0c0d90bd9871f25fefb14",
    ),
    (
        "media key MK",
        "7138feb16eb686aab4c79b95fd006dba1d0c8e050c28566c8bf9f19ddaa837de",
    ),
    (
        "writer blob key",
        "8d7c734df08f0b4f925fef4b68995870396a001f0a0f9e5e563ebca8afb449e7",
    ),
    (
        "chain seal key",
        "980b458a343e0099f20d19477b3a2aa5dae27ebdf053f50b049fffcc440cdef4",
    ),
    (
        "keyring base key",
        "417cf624db82aa328f2edfb740d01ffe381080794410145fc497dbf4a987cb82",
    ),
    (
        "self-row key",
        "9403d56bfdceb2af79a14113f4073a4db174fdb78fda3a1c99a8ee87a5a786c9",
    ),
    (
        "history-row key",
        "09387ee952de73c0987d76e6a1ebebc43c4164d77aa792cc0fc759d03b4ee311",
    ),
    (
        "dist(group, gen, e, D_e)",
        "7dddfe77-c98e-5c4f-997c-020aba469aa4",
    ),
    (
        "row",
        "0c0d0e0f10111213141516174334504e93c1df8245d77b5f2b0ade4d1984f9f0ab2bd740b69c15a7a6d3560657e4e32aeadce24ffbb67369f737683e",
    ),
    (
        "seal",
        "0c0d0e0f1011121314151617afbfb7c2d1d4397d1344875272fa0f0624359cabea42dad9b5ff228c3cfa2808ca53b2567ef23c2671aa97644deac75d",
    ),
    (
        "SKDM",
        "330a107dddfe77c98e5c4f997c020aba469aa410b42418002220707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f2a21056b3ee67463583cbe3dc08fe9d0765c2666ff5210dd527c9d8705e44927c80d55",
    ),
    (
        "writer-sig signed message",
        "766f6970632d676b2f76312f7772697465722d7369677c747c633a6b61747c30313032303330343035303630373038303930613062306330643065306631307c377c323032313232323332343235323632373238323932613262326332643265326633303331333233333334333533363337333833393361336233633364336533667c613a30313031303130313031303130313031303130313031303130313031303130312f34327c330a107dddfe77c98e5c4f997c020aba469aa410b42418002220707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f2a21056b3ee67463583cbe3dc08fe9d0765c2666ff5210dd527c9d8705e44927c80d55",
    ),
    (
        "writer sig",
        "66303236979ae2d7cbb538df72deaabc63f95f48e48077664522e94d12a43217cd425581bb1c4e0562350c21b35c70a390003e1cb538f6780220621dfb7b508e",
    ),
    (
        "blob plaintext",
        "005d330a107dddfe77c98e5c4f997c020aba469aa410b42418002220707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f2a21056b3ee67463583cbe3dc08fe9d0765c2666ff5210dd527c9d8705e44927c80d55059fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b61566303236979ae2d7cbb538df72deaabc63f95f48e48077664522e94d12a43217cd425581bb1c4e0562350c21b35c70a390003e1cb538f6780220621dfb7b508e",
    ),
    (
        "blob",
        "0c0d0e0f101112131415161782ed2c1024149dc2b3ed1437bdae10e2d90f249d39c831f4f0892d3ffdf122b7df04ea32d9ea63cc7a8f09b75bfce799c4a80baa8b100e20bf4e64cfa6c24afa6f24cd593154ac6750c784e4dec9af100b96c8461379d009fa266968f8b1c0c1fd10154a266a81b802046e543b7329847ee654ac7bff9fb4773863209cc6164fd54f753e6e8cfa91dc7b4925f9206861159164f6099ad8bac9a4df73095859dccac39b8cdefca69e4ff2a419cfb5a11f530d9706ff605553ef4556e06c80c425ec5ab199d91282e69f89bb7885b5f545",
    ),
    (
        "chain_seal",
        "0c0d0e0f1011121314151617e9718c5be78bd2358bc0c9d50afbd6ef7462f44c24162c2d9bb75f0231235de0b79f0030d2adf5c50bb155fdcef55f2e",
    ),
    (
        "self_row",
        "0c0d0e0f10111213141516177ebc371602431ea2b3800913cc2f1a11c5ea96801c20e365c1c213ddbb8a50dadec26b4ca65f39822caa0d657bc2a046",
    ),
    (
        "ctx rowbase (K'=g:9)",
        "voipc-gk/v1/rowbase|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|a:01010101010101010101010101010101|fcb6d7fc1937f21f|g:9|9813a52504d423ea",
    ),
    (
        "RB' (K'=g:9)",
        "1a2cff4002b2da8ecb8f6d3db42fb8e3b9d39eabe52f9d45fc77c48cf2f8e965",
    ),
    (
        "history_row plaintext",
        "02000202020202020202020202020202020236d8a77015efceeb5803635b715d4177e44725c28c2e64fb3d8a871f59efef11f42e85a6895f5bd301099813a52504d423ea1a2cff4002b2da8ecb8f6d3db42fb8e3b9d39eabe52f9d45fc77c48cf2f8e965",
    ),
    (
        "history_row",
        "0c0d0e0f10111213141516170eee73a29ee6e8dca2b8014729ca3eeb01756cc7ec1c2c39e482222ae235e747f7661ff88e110bd8449295faed7cb28c5f5cbfefa586ab613c5f04b5e7cce6a1a5a5785ece24218dcce2d2dd31809511c1dfad500ca2f99890ddd824ae34cb958724516a04ffd0dd467ed3fa588fd54fe4325f1b",
    ),
    (
        "keyring base plaintext",
        "0102030405060708090a0b0c0d0e0f10070002015e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0c020110003ea0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0bf093cfaa06ef9bafcdf8acd191010300023d641aaedf83fb0452e3b04920492ceb243357e9f1fe5ec7dc10107d9ebad9c00102808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9ff0c5cfaa06",
    ),
    (
        "keyring base (sealed)",
        "0c0d0e0f101112131415161750532ff7eea85167046f401adde9aaf017feabb527fb13b36c93e81467648ca5adb41bb1009adec4199c5f41b5ab6b95a2561ce65f53aff94737a664c979fef6a97f898f6dbb651f1a4a53324d9d64a6b06a8ed0587cfc4255d7b4ac2bad055e3e0b22424322701ee2dd81ae115968e7e1faa07bd0482f5580c81e14128cf7887e82805a64874b8a22219d223b16c2c7ff2a82e681b0f3ba0af95aa09aebc818a5351f2f43241485dacb839eef51c21c539e073b43ddfe95efd4cb4f881d08dbf97599b04fb128e13aa712abacecd43288db1e6553fdee6dd185907f841624f53a0df024cade7f3a08feaff7ba6179d4392a63dbdd88ebfffee6e4206548f6e5e36c3d2b7476f4b764ed1630fbff3a1d0a8c134b8ffaea9e4a19226fc07e7afa9ed3170b",
    ),
    (
        "H_7,0",
        "7017e5d1fe1f9a1cfd2fe71f004c1d7724fc1d1c02e4db9b3a18c851b510ac95",
    ),
    (
        "keyring delta 1 plaintext",
        "0101c8011101017e5454bd7ac08c1c2e678b03fe0fb9491d1ba9cbc924cf7ea68003c1ff0f445e000c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c80e2cfaa06",
    ),
    (
        "keyring delta 1 key",
        "b578e66b6576c36e2e0856e641b281691a89a9e39be8e840ee2a80ca14aac48a",
    ),
    (
        "keyring delta 1 (sealed)",
        "0c0d0e0f1011121314151617f8ca5bcf16a039648e5d881206458fe1991e2dc2fafc6449f0b033ea1f61b9173109340760dc3439fbfe06648701591d4fdf47cd37c458b3f7a682a00407362f102c541fd2612df6c8e5b35fff1cb5bf1ff1fff9359d150170e5a0c8ac",
    ),
    (
        "H_7,1",
        "485760e74c47a8175bccf731143db1e435e5fe866a8f249f48994c9f383e6fb7",
    ),
    (
        "keyring delta 2 plaintext",
        "0201ffffffffffffffffff0107013ea4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a40190e4d0b287d3aeeefe010d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0da4e2cfaa06",
    ),
    (
        "keyring delta 2 key",
        "620ef97a5a312cac663d794aff659e0c5f6359d0983077c7e53d64c8c76754e8",
    ),
    (
        "keyring delta 2 (sealed)",
        "0c0d0e0f1011121314151617e7c57b45aaffa9b2695efe93f414f5eb4446fc7f5ab12d0607cf0a338074390086a9fbe7919f555b0d619fdd89eb96fea139ed4921d787041480c890f0b9082cfa5edd8ff0bc0d59044b12e0b0c0c00d34e79540a8435da05041cb841139a8bd811a60997f5e5f81157c3da6483caa",
    ),
    (
        "H_7,2",
        "43d39992879990976fa7d6dcaf6a34215e3ead4e9f37396b744f83229e261475",
    ),
    (
        "keyring delta 3 plaintext",
        "0300",
    ),
    (
        "keyring delta 3 key",
        "4d959d49987a14e10afff5e6d1d6a74c9924ba3703bfe8d539f79817bf9e4f22",
    ),
    (
        "keyring delta 3 (sealed)",
        "0c0d0e0f1011121314151617a35c375f2ed108b7058f0e056a1feaeebe03",
    ),
    (
        "H_7,3",
        "5d1ac838c092cfe4aa594756494151592487d091b5b71b510f7270555636eb0d",
    ),
    (
        "header H1 body",
        "000005633a6b61740102030405060708090a0b0c0d0e0f1007030380e2cfaa061111111111111111111111111111111111111111111111111111111111111111202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f22222222222222222222222222222222222222222222222222222222222222220002020202020202020202020202020202000002010cac020501333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000000000100005555555555555555555555555555555555555555555555555555555555555555",
    ),
    (
        "D(H1)",
        "9476940109930e2e57a68590c777270be0d2a5c447b2d2bb12a5ad3f603485d2",
    ),
    (
        "header-sig message (H1)",
        "766f6970632d676b2f76312f6865616465722d7369677c9476940109930e2e57a68590c777270be0d2a5c447b2d2bb12a5ad3f603485d2",
    ),
    (
        "header sig (H1)",
        "4154f29c6b9f36233ab56f4626ba52d9c6fa6056705d47fe1b930c89e03999e13a9d58121fc351721d42ca1c3bcb3372fa8de0e4d81eff69555c62e95be9e80f",
    ),
    (
        "header sig (H1) with S + l",
        "4154f29c6b9f36233ab56f4626ba52d9c6fa6056705d47fe1b930c89e03999e127714e6f392664caf3dec1bf19c51287fa8de0e4d81eff69555c62e95be9e81f",
    ),
    (
        "postcard(added) H2",
        "010100020202020202020202020202020202023f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945eb1b1b1b1b1b1b1b1b2b2b2b2b2b2b2b20498dacfaa06",
    ),
    (
        "names step preimage H2 (Genesis)",
        "766f6970632d676b2f76312f6e616d65737c0000000000000000000000000000000000000000000000000000000000000000000000006553e2f0000000010000000039829a0aed63d2d56197eb8227f98dbe5895c91f61bb788777625d7516dff519",
    ),
    (
        "names_hash H2 (Genesis)",
        "119b1716bca69122bb578b1823cc2c2d144f70162501a9eeb71b501f3735a388",
    ),
    (
        "header H2 body",
        "000005633a6b61740102030405060708090a0b0c0d0e0f10010000f0c5cfaa0600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020202020202020202020202020202020100020202020202020202020202020202020003043f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945edc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d445890a708318c0bbd0101010001010066666666666666666666666666666666666666666666666666666666666666667777777777777777777777777777777777777777777777777777777777777777119b1716bca69122bb578b1823cc2c2d144f70162501a9eeb71b501f3735a388010100020202020202020202020202020202023f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945eb1b1b1b1b1b1b1b1b2b2b2b2b2b2b2b20498dacfaa0601008888888888888888888888888888888888888888888888888888888888888888",
    ),
    (
        "D(H2)",
        "4cac5df702e6ef1a0bc8417dfe737b9f52995cfac09d20aa11f782872c5f3b28",
    ),
    (
        "postcard(added) H3",
        "010200010101010101010101010101010101019fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b6154a7d5eaad621eda8fcb6d7fc1937f21f0180e2cfaa060003030303030303030303030303030303ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc3c3c3c3c3c3c3c3c4c4c4c4c4c4c4c40081e2cfaa06",
    ),
    (
        "names_hash H3 (Join after H2)",
        "1a395c81280c2df332d8ede9a7f2076e85bf5c89f5d3e9f5a4c309958455ed40",
    ),
    (
        "header H3 body",
        "000005633a6b61740102030405060708090a0b0c0d0e0f1001010380e2cfaa064cac5df702e6ef1a0bc8417dfe737b9f52995cfac09d20aa11f782872c5f3b284cac5df702e6ef1a0bc8417dfe737b9f52995cfac09d20aa11f782872c5f3b284cac5df702e6ef1a0bc8417dfe737b9f52995cfac09d20aa11f782872c5f3b28000202020202020202020202020202020200010101000302009999999999999999999999999999999999999999999999999999999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1a395c81280c2df332d8ede9a7f2076e85bf5c89f5d3e9f5a4c309958455ed40010200010101010101010101010101010101019fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b6154a7d5eaad621eda8fcb6d7fc1937f21f0180e2cfaa060003030303030303030303030303030303ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc3c3c3c3c3c3c3c3c4c4c4c4c4c4c4c40081e2cfaa060100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ),
    (
        "D(H3)",
        "d803a39fc8da3a3d066ee8f7df5af6dd702401a252a0109aa473b97188744b8b",
    ),
    (
        "KS voice",
        "10d73f85c8979e74a4685ac9ba3a1f874e99d9b20e8ca05c697f764c752e7211",
    ),
    (
        "header H4 body",
        "000105633a6b61740102030405060708090a0b0c0d0e0f10090005bce2cfaa06d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d10000000000000000000000000000000000000000000000000000000000000000d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d201050201050105020005050505050505050505050505050505050505050505050505050505050505051515151515151515151515151515151515151515151515151515151515151515252525252525252501ac0201ac0202000606060606060606060606060606060606060606060606060606060606060606161616161616161616161616161616161616161616161616161616161616161626262626262626260003028580808010040104d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4000000000000000000000000000000000000000000000000000000000000000000000002d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
    ),
    (
        "D(H4)",
        "48cb9ca9ec7702b21411feebf169f87dfa7a42d5465be0b9715a141c9b043302",
    ),
    (
        "postcard(removed) list",
        "010200010101010101010101010101010101014a7d5eaad621eda8fcb6d7fc1937f21f0003030303030303030303030303030303c3c3c3c3c3c3c3c3c4c4c4c4c4c4c4c4",
    ),
    (
        "postcard(added) F1",
        "010100040404040404040404040404040404044444444444444444444444444444444444444444444444444444444444444444414141414141414142424242424242420394e2cfaa06",
    ),
    (
        "list digest F1",
        "6a6876586357d23f72d48db0ca514fc63f405745aaecd2be5afd7da72d2f0c93",
    ),
    (
        "names step preimage F1",
        "766f6970632d676b2f76312f6e616d65737c1a395c81280c2df332d8ede9a7f2076e85bf5c89f5d3e9f5a4c309958455ed40000000006553f11e00000001000000026a6876586357d23f72d48db0ca514fc63f405745aaecd2be5afd7da72d2f0c93",
    ),
    (
        "names fold after F1",
        "aaec01b89f8b93323a3c088611232e237efeeb3cf3c8262f2ad4b871faca4af4",
    ),
    (
        "postcard(added) F2",
        "0102000505050505050505050505050505050555555555555555555555555555555555555555555555555555555555555555555151515151515151525252525252525200ace4cfaa06000707070707070707070707070707070777777777777777777777777777777777777777777777777777777777777777777171717171717171727272727272727201dee4cfaa06",
    ),
    (
        "list digest F2",
        "9aad173e1031bfdd92382a7ace5c3149a702eda11fffe908d69d088fc6cbfdea",
    ),
    (
        "names fold after F2",
        "8da59c173517a5663fd4c8874c0840100df59a1a461f4a2d13dcf30c12282058",
    ),
    (
        "postcard(added) F3",
        "0101000606060606060606060606060606060666666666666666666666666666666666666666666666666666666666666666666161616161616161626262626262626207acfdcfaa06",
    ),
    (
        "list digest F3",
        "cf6e13014f0e92bdf82f7db90626fe1e9c291e8c792143019eb575f89c926a13",
    ),
    (
        "names fold after F3",
        "4af3a8da4010f6570d3de645fe41feeed9dfc5d99476d99e062881be17219705",
    ),
    (
        "names fold head (H3 → F1, F2, F3)",
        "4af3a8da4010f6570d3de645fe41feeed9dfc5d99476d99e062881be17219705",
    ),
    (
        "names step F2 moved to F3's position (must not match)",
        "dbbd82f32ac99adfcc48ad8d9999228ee8229ed6e63b0acb6a65cd60b48cdfc1",
    ),
    (
        "names fold with F2's and F3's lists swapped (must not match)",
        "188a4cef69ecdeca737d2c2ddf2c08c2752ea68617b8249f22c3c086b2792a52",
    ),
    (
        "postcard(added) empty list",
        "0100",
    ),
    (
        "names_hash gate-on step (empty list)",
        "af3d527327794cc3322537d3312eaaa0ea9c7befafa7468bb688e3870bff6e7e",
    ),
    (
        "ser(KX_K_new.pub)",
        "053e73ce162827a32ff92378fcf4f36464d8cf0a8113638690a775f2b699abd66e",
    ),
    (
        "ser(KX_A.pub)",
        "056ab71182224ee3a8eef1a590dc471ade6dab86fdeef038907cba1a727d42704f",
    ),
    (
        "ser(conn pair X.pub) of a:01…01 u=42",
        "05492f1cb85847ffc7bb427865f64c5e8041ec0499b37a1da945a15b4102af027e",
    ),
    (
        "tag(KX_K_new)",
        "43a435f673b7ca1e",
    ),
    (
        "tag(KK_K_new)",
        "e2496397242dc928",
    ),
    (
        "tag(KX_A)",
        "c46c355a7557e07a",
    ),
    (
        "tag(KK_A)",
        "704d6b8d2fb21ebd",
    ),
    (
        "postcard(keyholders) H5",
        "0200010101010101010101010101010101010003019fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b6156ab71182224ee3a8eef1a590dc471ade6dab86fdeef038907cba1a727d42704f704d6b8d2fb21ebd00020202020202020202020202020202020003053f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945e3e73ce162827a32ff92378fcf4f36464d8cf0a8113638690a775f2b699abd66ee2496397242dc928",
    ),
    (
        "KS H5",
        "4a103b84dded0cdc64e5dbe773a53db542c04e48b9660deacd42979b09119014",
    ),
    (
        "postcard(removed) H5",
        "01020003030303030303030303030303030303c3c3c3c3c3c3c3c3c4c4c4c4c4c4c4c4000505050505050505050505050505050551515151515151515252525252525252",
    ),
    (
        "header H5 body (KeyholdersReplace)",
        "000005633a6b61740102030405060708090a0b0c0d0e0f10050006f4fecfaa06e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e10000000000000000000000000000000000000000000000000000000000000000e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e200020202020202020202020202020202020200010101010101010101010101010101010003019fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b6156ab71182224ee3a8eef1a590dc471ade6dab86fdeef038907cba1a727d42704f704d6b8d2fb21ebd00020202020202020202020202020202020003053f3e5f6d86926c9c128cf84581574f96840d98ee5ab53b1ec3b76e2bb25b945e3e73ce162827a32ff92378fcf4f36464d8cf0a8113638690a775f2b699abd66ee2496397242dc92801020128780300e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e44af3a8da4010f6570d3de645fe41feeed9dfc5d99476d99e062881be17219705010001020003030303030303030303030303030303c3c3c3c3c3c3c3c3c4c4c4c4c4c4c4c4000505050505050505050505050505050551515151515151515252525252525252e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
    ),
    (
        "D(H5)",
        "6b9b46728a297b760939ede2c47e5def37b1371260d444b5169720c76f81c773",
    ),
    (
        "header sig (H5)",
        "b234c4b9b02433ed11545a3de350f1baa22b15fc72105403ef55e32c5f17f2d03a2e792f9670a78ea1b4ac9612a707af83014838dd848f25839d78910d03d005",
    ),
    (
        "ctx welcome-keyring H5 to a:01…01",
        "voipc-gk/v1/welcome|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|kyber1024|keyring|5|4a103b84dded0cdc64e5dbe773a53db542c04e48b9660deacd42979b09119014|a:01010101010101010101010101010101|704d6b8d2fb21ebd|c46c355a7557e07a|a:02020202020202020202020202020202|36d8a77015efceeb",
    ),
    (
        "ctx welcome-keyring H5 to K's new pair",
        "voipc-gk/v1/welcome|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|kyber1024|keyring|5|4a103b84dded0cdc64e5dbe773a53db542c04e48b9660deacd42979b09119014|a:02020202020202020202020202020202|e2496397242dc928|43a435f673b7ca1e|a:02020202020202020202020202020202|36d8a77015efceeb",
    ),
    (
        "ctx keyring-base H5",
        "voipc-gk/v1/keyring|t|c:kat|0102030405060708090a0b0c0d0e0f10|5|0|2|4a103b84dded0cdc64e5dbe773a53db542c04e48b9660deacd42979b09119014|base",
    ),
    (
        "ctx rowbase (K's new pair)",
        "voipc-gk/v1/rowbase|t|c:kat|0102030405060708090a0b0c0d0e0f10|2|a:01010101010101010101010101010101|fcb6d7fc1937f21f|a:02020202020202020202020202020202|43a435f673b7ca1e",
    ),
    (
        "X25519(KX_K_new, SX_m)",
        "436d9746632a8cfc872619f075531235248aac750c8a015c45c0150d19dbd061",
    ),
    (
        "RB (K's new pair)",
        "28b4dfb8892fafdcdf35c57860b1a58867d1b84c56f29f01c28e022758d3bfdc",
    ),
    (
        "row key (K's new pair)",
        "3e461d871579756c4f10c99d2713c0938831dfe157bbdfb6fdf612cb0b99223f",
    ),
    (
        "row (K's new pair)",
        "0c0d0e0f101112131415161761537676c9f0ab68c2cb4e7ff7fc384c647bbd8dcf020a8808424e8ef5d5fd44b912e4c8c3bce1e081f6bba7224d1bf9",
    ),
    (
        "endorsement 0x01 message head",
        "766f6970632d676b2f76312f736561747c01010101010101010101010101010101010100000001000000006553f100",
    ),
    (
        "endorsement 0x01 message SHA-256",
        "2ac04a9aeff3073520aa223381908316de05472dac6d145778eacf788e6c0c0f",
    ),
    (
        "endorsement 0x01 sig",
        "c2449da40a00d34f6032179b72887560cec7241bcb3a1f653639f431298f142955d5d006fe4f058a1eb8f4bc7159da17bf9ceb15c83c19933d4d56a56d5f548c",
    ),
    (
        "endorsement 0x02 message head",
        "766f6970632d676b2f76312f736561747c02020000000000000000000000000000000900000000000000006553f164",
    ),
    (
        "endorsement 0x02 message SHA-256",
        "89227a4901357278af30b248377cc3b123babed442e302b1b700b37305eb8193",
    ),
    (
        "endorsement 0x02 sig",
        "5025956e9bb5578a157b79b736bca85559e9a2b54a8f910daa08a7e1f8217d1da8552c72977a41c45a4e606507591ea26201ba2e2e335d15892701744137c100",
    ),
    (
        "endorsement 0x03 message head",
        "766f6970632d676b2f76312f736561747c03010202020202020202020202020202020200000004000000006553ed18",
    ),
    (
        "endorsement 0x03 message SHA-256",
        "74f9f332216f3a632c83b74d9f23b0d566eb01a7fe8aca2ece87aea50d64e409",
    ),
    (
        "endorsement 0x03 sig",
        "8c522a7d93bed8fb63ae6046c87aa68e0ff24dbcb99998ef8427cc8b61c9b13eff463fc5009fa205bc335d39f305fbda5740ca35aaba83a709f523ef9dfba60d",
    ),
    (
        "endorsement 0x03 K new pair message head",
        "766f6970632d676b2f76312f736561747c03010202020202020202020202020202020200000005000000006553fcb8",
    ),
    (
        "endorsement 0x03 K new pair message SHA-256",
        "235e659e884004434b7e123b804161797a605dbf87b1929cc11362eade694d3f",
    ),
    (
        "endorsement 0x03 K new pair sig",
        "42be60feb87cbdea502c5c83cd0a3f4a26e703c127993a3bea7725e54d2d638bbbddc5ded53cc41246407cadcb104786881444af8da6fa56f572ad9cdc0aa305",
    ),
    (
        "endorsement 0x02 signed-in a:01…01 u=42 message head",
        "766f6970632d676b2f76312f736561747c02020000000000000000000000000000002a00000001000000006553f1c8",
    ),
    (
        "endorsement 0x02 signed-in a:01…01 u=42 message SHA-256",
        "a1b3e35883b648cc5c8262ff21ae6a5a829c9db1a79a6b259fbb53379969d577",
    ),
    (
        "endorsement 0x02 signed-in a:01…01 u=42 sig",
        "e7e9641ff0a97bfd612f56a11869b71c1da1a460724131c57b71a90f081784230a8753bf851292e10eb1a7db8501fd4ddd5cd4ee979fe0349eea32b0e4625982",
    ),
];
