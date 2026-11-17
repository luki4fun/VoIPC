//! The symmetric derivations (§3.1, §3.3–§3.6, §3.9–§3.11): member secrets,
//! rows, seals, the ratchet, key confirmation, chain seals, media keys and
//! self-rows. Each takes one key in and gives one key out, under a context
//! that names every field the value is bound to.

use zeroize::Zeroizing;

use super::ctx::{
    chain_ctx, confirm_ctx, media_ctx, member_ctx, ratchet_ctx, row_ctx, rowbase_ctx, seal_ctx,
    self_ctx, self_history_ctx, Epoch, Group, GroupKind, HolderId, MemberId, SeatRef, Version,
};
use super::keys::{agree, Holder, Me, Them};
use super::{
    encode_secret, hkdf32, open_derived, open_row_shaped, seal_derived, secret32, GkError,
};

/// `s_m = HKDF(seed_s, ctx(member; k, group, gen, s, m, tag(SK_m), tag(SX_m)))` (§3.1).
pub fn member_secret(g: &Group, s: u32, seed: &[u8; 32], seat: &SeatRef) -> Zeroizing<[u8; 32]> {
    hkdf32(None, seed, member_ctx(g, s, seat).as_bytes())
}

/// The row base `RB` between keyholder `K` and seat `m` under seed `s`
/// (§3.3), with what its rows are bound to. Both ends make it once and keep
/// it; a row after that costs one HKDF and one AES-GCM.
///
/// Its classical half is the static X25519 between `K`'s `KX` and `m`'s `SX`;
/// its post-quantum half is `s_m`, which reached `m` only in a welcome. A
/// removed keyholder that still holds `seed_s` derives `s_m` but not the DH,
/// so it opens no row another keyholder made.
///
/// A member keeps it under `key()`: the keyholder's member id with the tag
/// of its `KX`, and the seed. After a KeyholdersReplace the same member id
/// has a new `KX`, and a row base of the old pair must not stand in for the
/// new one (§3.3).
pub struct RowBase {
    rb: Zeroizing<[u8; 32]>,
    g: Group,
    s: u32,
    m: MemberId,
    k: HolderId,
}

impl RowBase {
    /// `seat` is `(m, tag(SX_m))`.
    fn derive(
        g: &Group,
        s: u32,
        dh: &[u8],
        salt: [&[u8]; 2],
        s_m: &[u8; 32],
        (m, tag_sx): (&MemberId, &[u8; 8]),
        k: &HolderId,
    ) -> RowBase {
        let ikm = Zeroizing::new([dh, &s_m[..]].concat());
        let c = rowbase_ctx(g, s, m, tag_sx, k);
        RowBase {
            rb: hkdf32(Some(&salt.concat()), &ikm, c.as_bytes()),
            g: g.clone(),
            s,
            m: *m,
            k: *k,
        }
    }

    /// The keyholder's side: our `KX` private key, the seat's `SX`.
    pub fn keyholder_side(
        g: &Group,
        s: u32,
        me: &Me,
        to: &Them,
        s_m: &[u8; 32],
    ) -> Result<RowBase, GkError> {
        let dh = agree(&me.keys.dh.private_key, &to.keys.dh)?;
        Ok(RowBase::derive(
            g,
            s,
            &dh,
            [&me.keys.dh.public_key.serialize(), &to.keys.dh_bytes()],
            s_m,
            (&to.m, &to.keys.tag_dh()),
            &me.holder_id(),
        ))
    }

    /// The member's side: our `SX` private key, the keyholder's `KX`.
    pub fn member_side(
        g: &Group,
        s: u32,
        me: &Me,
        from: &Holder,
        s_m: &[u8; 32],
    ) -> Result<RowBase, GkError> {
        let dh = agree(&me.keys.dh.private_key, &from.kx)?;
        let public = me.keys.public();
        Ok(RowBase::derive(
            g,
            s,
            &dh,
            [&from.kx.serialize(), &public.dh_bytes()],
            s_m,
            (&me.m, &public.tag_dh()),
            &from.id(),
        ))
    }

    /// A row base kept in a history row (§3.11), for seat keys whose private
    /// parts are gone: the history row keeps it with the keyholder's member
    /// id and `KX` tag.
    pub fn from_secret(g: &Group, s: u32, m: MemberId, k: HolderId, rb: &[u8; 32]) -> RowBase {
        RowBase {
            rb: Zeroizing::new(*rb),
            g: g.clone(),
            s,
            m,
            k,
        }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.rb
    }

    /// What a member keeps this row base under: `(K, tag(KX_K))` and `s`
    /// (§3.3). Never `K` and `s` alone.
    pub fn key(&self) -> (HolderId, u32) {
        (self.k, self.s)
    }

    /// `AEAD(HKDF(RB, c), c, BK(b,v))`, `c = ctx(row; k, group, gen, s, b, v, m, K)`.
    pub fn row(&self, at: Version, bk: &[u8; 32]) -> Vec<u8> {
        seal_derived(
            &self.rb,
            &row_ctx(&self.g, self.s, at, &self.m, &self.k.m),
            bk,
        )
    }

    pub fn open_row(&self, at: Version, row: &[u8]) -> Result<Zeroizing<[u8; 32]>, GkError> {
        open_row_shaped(
            &self.rb,
            &row_ctx(&self.g, self.s, at, &self.m, &self.k.m),
            row,
        )
    }
}

/// `CK_e` for bucket version `at` (§3.4): bound to `D_e`, so it opens only
/// with the header it was made for.
pub fn seal(g: &Group, ep: &Epoch, at: Version, bk: &[u8; 32], ck: &[u8; 32]) -> Vec<u8> {
    seal_derived(bk, &seal_ctx(g, ep, at), ck)
}

pub fn open_seal(
    g: &Group,
    ep: &Epoch,
    at: Version,
    bk: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>, GkError> {
    open_row_shaped(bk, &seal_ctx(g, ep, at), sealed)
}

/// `BK(b,v') = HKDF(BK(b,v), ctx(ratchet; k, group, gen, e, b, v, v'))` (§3.5),
/// only at a promotion. One way: a new keyholder given `BK(b,v')` opens no
/// seal from before. It binds the promoting epoch `e`, so a rebase ratchets
/// again under its new epoch. The version it makes keeps the `made` time of
/// `at` (`KeyringBucket::ratcheted`).
pub fn ratchet(g: &Group, e: u32, at: Version, v_new: u64, bk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(None, bk, ratchet_ctx(g, e, at, v_new).as_bytes())
}

/// `confirm = HKDF(CK_e, ctx(confirm; k, group, gen, e, j))` (§3.6): in every
/// header, so the relay cannot get a key it chose taken.
pub fn confirm(g: &Group, e: u32, j: u32, ck: &[u8; 32]) -> [u8; 32] {
    *hkdf32(None, ck, confirm_ctx(g, e, j).as_bytes())
}

/// Whether `ck` is the key header `(e, j)` names.
pub fn confirm_ok(g: &Group, e: u32, j: u32, ck: &[u8; 32], named: &[u8; 32]) -> bool {
    confirm(g, e, j, ck) == *named
}

/// A kept chain's start, sealed once under `CK_e` (§3.9). Kept history is
/// text only (`t` in §3.9's context), so a voice group is refused.
pub fn chain_seal(
    g: &Group,
    ep: &Epoch,
    owner: &MemberId,
    chain: u32,
    index: u32,
    ck: &[u8; 32],
    state: &[u8; 32],
) -> Result<Vec<u8>, GkError> {
    if g.kind() != GroupKind::Text {
        return Err(GkError::Malformed);
    }
    Ok(seal_derived(
        ck,
        &chain_ctx(g, ep, owner, chain, index),
        state,
    ))
}

pub fn open_chain_seal(
    g: &Group,
    ep: &Epoch,
    owner: &MemberId,
    chain: u32,
    index: u32,
    ck: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>, GkError> {
    if g.kind() != GroupKind::Text {
        return Err(GkError::Malformed);
    }
    open_row_shaped(ck, &chain_ctx(g, ep, owner, chain, index), sealed)
}

/// A voice sender's media key for one stream (§3.10): per sender seat
/// `(m, tag(SX_m))` and stream, so two senders never share a (key, nonce)
/// whatever stream or session ids the relay hands out. Voice groups only.
pub fn media_key(
    g: &Group,
    ep: &Epoch,
    m: &MemberId,
    tag_sx: &[u8; 8],
    stream: u32,
    ck: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, GkError> {
    if g.kind() != GroupKind::Voice {
        return Err(GkError::Malformed);
    }
    Ok(hkdf32(
        None,
        ck,
        media_ctx(g, ep, m, tag_sx, stream).as_bytes(),
    ))
}

/// What an account keeps of `s_m` for its other devices and later sessions
/// (§3.11), under the random self key of `item.seat_kem`: never under a key
/// from an X25519 private key or from KEM key bytes. Written only after a
/// row or seal under this `s_m` opened and `confirm` passed.
pub fn self_row(g: &Group, s: u32, seat: &SeatRef, self_key: &[u8; 32], s_m: &[u8; 32]) -> Vec<u8> {
    seal_derived(self_key, &self_ctx(g, s, seat), s_m)
}

pub fn open_self_row(
    g: &Group,
    s: u32,
    seat: &SeatRef,
    self_key: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>, GkError> {
    open_row_shaped(self_key, &self_ctx(g, s, seat), sealed)
}

/// One row base a history row keeps: the keyholder and its `KX` tag.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HistoryEntry {
    pub k: HolderId,
    pub rb: Zeroizing<[u8; 32]>,
}

/// One item of a history row as §11.7 encodes it, `(MemberId, [u8; 8],
/// [u8; 32])`, borrowing its row base rather than copying it.
fn history_item(e: &HistoryEntry) -> (MemberId, [u8; 8], &[u8; 32]) {
    (e.k.m, e.k.tag_kx, &e.rb)
}

/// §11.7: `postcard(Vec<(MemberId, [u8; 8], [u8; 32])>)`, sorted by each
/// item's encoding, each once. Every encoding is made from borrowed row
/// bases into a buffer of its exact size (`encode_secret`), so no row base is
/// left in a buffer freed unwiped.
fn history_bytes(entries: &[HistoryEntry]) -> Zeroizing<Vec<u8>> {
    let mut keyed: Vec<(Zeroizing<Vec<u8>>, &HistoryEntry)> = entries
        .iter()
        .map(|e| (encode_secret(&history_item(e)), e))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    let list: Vec<_> = keyed.iter().map(|(_, e)| history_item(e)).collect();
    encode_secret(&list)
}

/// A history row's plaintext read item by item, each row base straight into
/// its `Zeroizing`: on any error the ones read so far are wiped as they drop.
fn history_entries(plain: &[u8]) -> Result<Vec<HistoryEntry>, GkError> {
    let malformed = |_| GkError::Malformed;
    let (n, mut rest) = postcard::take_from_bytes::<usize>(plain).map_err(malformed)?;
    // An item takes at least 42 bytes, so an honest count reserves exactly
    // and the vector never grows (which would leave a copy behind).
    let mut entries = Vec::with_capacity(n.min(rest.len() / 42));
    for _ in 0..n {
        let ((m, tag_kx), after) =
            postcard::take_from_bytes::<(MemberId, [u8; 8])>(rest).map_err(malformed)?;
        let rb = secret32(after.get(..32).ok_or(GkError::Malformed)?)?;
        entries.push(HistoryEntry {
            k: HolderId { m, tag_kx },
            rb,
        });
        rest = &after[32..];
    }
    if !rest.is_empty() {
        return Err(GkError::Malformed);
    }
    Ok(entries)
}

/// The row bases of every keyholder that made rows to this seat under `s`
/// (§3.11, §5.11): kept history stays readable once the seat's private
/// parts are gone. Sorted by their encoding, each once.
pub fn history_row(
    g: &Group,
    s: u32,
    seat: &SeatRef,
    self_key: &[u8; 32],
    entries: &[HistoryEntry],
) -> Vec<u8> {
    seal_derived(
        self_key,
        &self_history_ctx(g, s, seat),
        &history_bytes(entries),
    )
}

pub fn open_history_row(
    g: &Group,
    s: u32,
    seat: &SeatRef,
    self_key: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<HistoryEntry>, GkError> {
    let plain = open_derived(self_key, &self_history_ctx(g, s, seat), sealed)?;
    let entries = history_entries(&plain)?;
    // Only our own seal makes these, so a list out of order is damage, not an attack.
    if history_bytes(&entries)[..] != plain[..] {
        return Err(GkError::Malformed);
    }
    Ok(entries)
}
