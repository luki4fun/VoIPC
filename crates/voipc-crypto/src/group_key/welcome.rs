//! Hybrid welcomes (§3.2): from keyholder `K` to a seat or to another
//! keyholder `K'`, carrying `P`.
//!
//! ```text
//! (ct_q, ss_q) = Kyber1024.Encaps(RK)
//! ss_x         = X25519(eph, RX)
//! ss_k         = X25519(KX_K, RX)
//! salt         = SHA-256(ser(ct_q) ‖ ser(eph.pub) ‖ ser(RK.pub) ‖ ser(RX.pub) ‖ ser(KX_K.pub))
//! KEK          = HKDF-SHA256(salt, ikm = ss_q ‖ ss_x ‖ ss_k, info = c)
//! welcome      = ser(ct_q) (1569) ‖ ser(eph.pub) (33) ‖ AEAD(KEK, c, P)
//! ```
//!
//! Opening it takes both Kyber1024 and X25519 broken, and `ss_k` means only
//! `K` (or the recipient itself) can make one that opens: the relay cannot
//! hand anyone an `s_m`, a `BK` or a `KRK` of its choosing. The three kinds
//! differ in their context, so none opens as another.

use libsignal_protocol::KeyPair;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::ctx::{welcome_ctx, Group, HolderId, Version, WelcomeKind};
use super::keys::{agree, dh_public, Holder, Me, Them, DH_PUBLIC_BYTES, KEM_CT_BYTES};
use super::{hkdf32, open_under, seal_under, secret32, GkError};

/// A seat welcome: `P = s_m ‖ BK(b,v)`.
pub const SEAT_WELCOME_BYTES: usize = KEM_CT_BYTES + DH_PUBLIC_BYTES + 12 + 64 + 16;
/// A seed or keyring welcome: `P` is one 32-byte key.
pub const SMALL_WELCOME_BYTES: usize = KEM_CT_BYTES + DH_PUBLIC_BYTES + 12 + 32 + 16;

/// The KEK of §3.2. `ss_*` are secret; the salt binds every public value.
fn kek(ss: [&[u8]; 3], salt_parts: [&[u8]; 5], c: &str) -> Zeroizing<[u8; 32]> {
    let mut salt = Sha256::new();
    for p in salt_parts {
        salt.update(p);
    }
    let salt = salt.finalize();
    let ikm = Zeroizing::new(ss.concat());
    hkdf32(Some(&salt), &ikm, c.as_bytes())
}

/// What a welcome's maker draws and agrees (§3.2): the public bytes the
/// welcome starts with, and the three secrets its KEK is made of.
pub(super) struct Drawn {
    pub(super) ct_q: Box<[u8]>,
    pub(super) eph_pub: Box<[u8]>,
    /// `ss_q`, `ss_x` and `ss_k`, in the order the KEK takes them.
    pub(super) ss: [Zeroizing<Vec<u8>>; 3],
}

/// Encapsulates to `to`'s Kyber1024 key, then draws `eph`, both from `rng`
/// in that order (the known answers fix it), and agrees `eph` and `from`'s
/// `KX` with `to`'s X25519 key.
pub(super) fn draw<R: Rng + CryptoRng>(
    from: &Me,
    to: &Them,
    rng: &mut R,
) -> Result<Drawn, GkError> {
    let (ss_q, ct_q) = to
        .keys
        .kem
        .encapsulate(rng)
        .map_err(|_| GkError::Malformed)?;
    let ss_q = Zeroizing::new(ss_q.into_vec());
    let eph = KeyPair::generate(rng);
    let ss_x = agree(&eph.private_key, &to.keys.dh)?;
    let ss_k = agree(&from.keys.dh.private_key, &to.keys.dh)?;
    Ok(Drawn {
        ct_q,
        eph_pub: eph.public_key.serialize(),
        ss: [ss_q, ss_x, ss_k],
    })
}

impl Drawn {
    /// The KEK of a welcome from `from` to `to` under context `c`: what the
    /// recipient derives too, from `ct_q`, `eph.pub` and `from`'s `KX`.
    pub(super) fn kek(&self, from: &Me, to: &Them, c: &str) -> Zeroizing<[u8; 32]> {
        kek(
            [&self.ss[0][..], &self.ss[1][..], &self.ss[2][..]],
            [
                &self.ct_q,
                &self.eph_pub,
                &to.keys.kem.serialize(),
                &to.keys.dh.serialize(),
                &from.keys.dh.public_key.serialize(),
            ],
            c,
        )
    }

    /// `ser(ct_q) ‖ ser(eph.pub) ‖ AEAD(kek, c, P)`, at a random nonce: the
    /// only way a welcome is sealed outside the known-answer tests.
    pub(super) fn welcome(&self, kek: &[u8; 32], c: &str, p: &[u8]) -> Vec<u8> {
        [&self.ct_q[..], &self.eph_pub, &seal_under(kek, c, p)].concat()
    }
}

fn make_random(from: &Me, to: &Them, c: &str, p: &[u8]) -> Result<Vec<u8>, GkError> {
    let drawn = draw(from, to, &mut crate::rng())?;
    Ok(drawn.welcome(&drawn.kek(from, to, c), c, p))
}

/// `P` out of a welcome to us, `p_len` bytes of it.
fn open(
    me: &Me,
    from: &Holder,
    c: &str,
    welcome: &[u8],
    p_len: usize,
) -> Result<Zeroizing<Vec<u8>>, GkError> {
    if welcome.len() != KEM_CT_BYTES + DH_PUBLIC_BYTES + 12 + p_len + 16 {
        return Err(GkError::Malformed);
    }
    let (ct_q, rest) = welcome.split_at(KEM_CT_BYTES);
    let (eph_pub, sealed) = rest.split_at(DH_PUBLIC_BYTES);
    let eph = dh_public(eph_pub)?;
    let ss_q = me
        .keys
        .kem
        .secret_key
        .decapsulate(&Box::from(ct_q))
        .map_err(|_| GkError::Malformed)?;
    let ss_q = Zeroizing::new(ss_q.into_vec());
    let ss_x = agree(&me.keys.dh.private_key, &eph)?;
    let ss_k = agree(&me.keys.dh.private_key, &from.kx)?;
    let kek = kek(
        [&ss_q, &ss_x, &ss_k],
        [
            ct_q,
            eph_pub,
            &me.keys.kem.public_key.serialize(),
            &me.keys.dh.public_key.serialize(),
            &from.kx.serialize(),
        ],
        c,
    );
    open_under(&kek, c, sealed)
}

fn seat_ctx(g: &Group, s: u32, at: Version, to: &super::SeatRef, from: &HolderId) -> String {
    welcome_ctx(g, s, WelcomeKind::Seat { at, to }, from)
}

/// Seats `to` in bucket version `at`, the one the commit carrying this makes.
pub fn seat_welcome(
    g: &Group,
    s: u32,
    at: Version,
    from: &Me,
    to: &Them,
    s_m: &[u8; 32],
    bk: &[u8; 32],
) -> Result<Vec<u8>, GkError> {
    let c = seat_ctx(g, s, at, &to.keys.seat(to.m), &from.holder_id());
    let p = Zeroizing::new([&s_m[..], &bk[..]].concat());
    make_random(from, to, &c, &p)
}

/// `(s_m, BK(b,v))` from a seat welcome to us. Either all zero is refused.
#[allow(clippy::type_complexity)]
pub fn open_seat_welcome(
    g: &Group,
    s: u32,
    at: Version,
    me: &Me,
    from: &Holder,
    welcome: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), GkError> {
    let c = seat_ctx(g, s, at, &me.seat(), &from.id());
    let p = open(me, from, &c, welcome, 64)?;
    Ok((secret32(&p[..32])?, secret32(&p[32..])?))
}

/// `s_m` under the new seed `s` of a seed roll (§5.6). It changes no bucket,
/// so its context names none.
pub fn seed_welcome(
    g: &Group,
    s: u32,
    from: &Me,
    to: &Them,
    s_m: &[u8; 32],
) -> Result<Vec<u8>, GkError> {
    let c = welcome_ctx(
        g,
        s,
        WelcomeKind::Seed {
            to: &to.keys.seat(to.m),
        },
        &from.holder_id(),
    );
    make_random(from, to, &c, s_m)
}

pub fn open_seed_welcome(
    g: &Group,
    s: u32,
    me: &Me,
    from: &Holder,
    welcome: &[u8],
) -> Result<Zeroizing<[u8; 32]>, GkError> {
    let c = welcome_ctx(g, s, WelcomeKind::Seed { to: &me.seat() }, &from.id());
    secret32(&open(me, from, &c, welcome, 32)?)
}

fn keyring_ctx(g: &Group, s: u32, e: u32, ks: &[u8; 32], to: &Them, from: &HolderId) -> String {
    let to_id = HolderId {
        m: to.m,
        tag_kx: to.keys.tag_dh(),
    };
    welcome_ctx(
        g,
        s,
        WelcomeKind::Keyring {
            e,
            ks,
            to: &to_id,
            tag_kk: &to.keys.tag_kem(),
        },
        from,
    )
}

/// `KRK` for keyholder `to`, through its own keyholder pair (`KK`, `KX`) and
/// never its account's seat keys. `e` is the epoch whose opening header set
/// this `KRK`, `s` the head's seed, `ks` the digest of the keyholder set it
/// is for (§11.6).
pub fn keyring_welcome(
    g: &Group,
    s: u32,
    e: u32,
    ks: &[u8; 32],
    from: &Me,
    to: &Them,
    krk: &[u8; 32],
) -> Result<Vec<u8>, GkError> {
    let c = keyring_ctx(g, s, e, ks, to, &from.holder_id());
    make_random(from, to, &c, krk)
}

pub fn open_keyring_welcome(
    g: &Group,
    s: u32,
    e: u32,
    ks: &[u8; 32],
    me: &Me,
    from: &Holder,
    welcome: &[u8],
) -> Result<Zeroizing<[u8; 32]>, GkError> {
    let public = me.keys.public();
    let to = Them {
        m: me.m,
        keys: &public,
    };
    let c = keyring_ctx(g, s, e, ks, &to, &from.id());
    secret32(&open(me, from, &c, welcome, 32)?)
}
