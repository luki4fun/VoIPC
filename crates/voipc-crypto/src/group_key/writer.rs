//! Writers and posts (§3.8, §5.8, §11.7).
//!
//! A writer's first post in an epoch carries its blob: its libsignal sender
//! key (the SKDM), its identity key and its signature over both, sealed under
//! `CK_e`. The SKDM's distribution id names the group, generation, epoch and
//! `D_e`, so libsignal files each epoch's sender key apart, and the two halves
//! of a fork apart. A post's plaintext starts with that same
//! `(gen, epoch, D_e)`, since `group_encrypt` takes no associated data.

use libsignal_protocol::{IdentityKey, IdentityKeyPair, SenderKeyDistributionMessage};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::ctx::{dist_ctx, writer_ctx, writer_sig_ctx, Epoch, Group, Writer};
use super::keys::{dh_public, sign_parts_with, verify_parts, DH_PUBLIC_BYTES};
use super::{open_derived, seal_derived, GkError};

/// `dist(group, gen, e, D_e)`: UUID v5, namespace OID, of
/// `ctx(dist; k, group, gen, e, D_e)` (§5.8).
pub fn dist(g: &Group, ep: &Epoch) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, dist_ctx(g, ep).as_bytes())
}

/// The signed message is `ctx(writer-sig; …) ‖ "|" ‖ SKDM`, signed in its
/// three parts: the SKDM carries the writer's chain key, and is never copied
/// into a buffer that would be freed unwiped.
fn sig_parts<'a>(c: &'a str, skdm: &'a [u8]) -> [&'a [u8]; 3] {
    [c.as_bytes(), b"|", skdm]
}

/// Whether `skdm` is a sender key filed under this epoch's distribution id.
fn skdm_for(g: &Group, ep: &Epoch, skdm: &[u8]) -> bool {
    SenderKeyDistributionMessage::try_from(skdm)
        .ok()
        .and_then(|m| m.distribution_id().ok())
        == Some(dist(g, ep))
}

/// The blob (§3.8): `AEAD(HKDF(CK_e, c), c, len(SKDM) u16 BE ‖ SKDM ‖
/// ser(IK_w) ‖ sig)`, `c = ctx(writer; k, group, gen, e, D_e, w)`. `Malformed`
/// for an SKDM over 64 KiB or filed under another distribution id.
pub fn writer_blob(
    g: &Group,
    ep: &Epoch,
    w: &Writer,
    ck: &[u8; 32],
    ik: &IdentityKeyPair,
    skdm: &[u8],
) -> Result<Vec<u8>, GkError> {
    let len = u16::try_from(skdm.len()).map_err(|_| GkError::Malformed)?;
    if !skdm_for(g, ep, skdm) {
        return Err(GkError::Malformed);
    }
    let c = writer_sig_ctx(g, ep, w);
    let sig = sign_parts_with(ik.private_key(), &sig_parts(&c, skdm), &mut crate::rng());
    let mut plain = Zeroizing::new(Vec::with_capacity(2 + skdm.len() + 33 + 64));
    plain.extend_from_slice(&len.to_be_bytes());
    plain.extend_from_slice(skdm);
    plain.extend_from_slice(&ik.identity_key().serialize());
    plain.extend_from_slice(&sig);
    Ok(seal_derived(ck, &writer_ctx(g, ep, w), &plain))
}

/// What a blob holds once it opened and its signature checked out.
pub struct OpenedBlob {
    pub skdm: Zeroizing<Vec<u8>>,
    /// The writer's identity key. Whether it is the pin of the account `w.m`,
    /// or the connection's own key for a guest, is the caller's to check
    /// before it takes a post (§5.8).
    pub ik: IdentityKey,
}

/// A blob opened under `CK_e` for this `D_e` and writer `w`, whose `u` must
/// be the post's sender. `Forged` when the signature is not by the key inside
/// or the SKDM is for another epoch; `WeakKey` for an identity key of low
/// order, under which anyone could have signed.
pub fn open_writer_blob(
    g: &Group,
    ep: &Epoch,
    w: &Writer,
    ck: &[u8; 32],
    blob: &[u8],
) -> Result<OpenedBlob, GkError> {
    let plain = open_derived(ck, &writer_ctx(g, ep, w), blob)?;
    let len_bytes: [u8; 2] = plain
        .get(..2)
        .and_then(|b| b.try_into().ok())
        .ok_or(GkError::Malformed)?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if plain.len() != 2 + len + DH_PUBLIC_BYTES + 64 {
        return Err(GkError::Malformed);
    }
    let skdm = &plain[2..2 + len];
    let ik_bytes = &plain[2 + len..2 + len + DH_PUBLIC_BYTES];
    let sig = &plain[2 + len + DH_PUBLIC_BYTES..];
    let ik = IdentityKey::new(dh_public(ik_bytes)?);
    let c = writer_sig_ctx(g, ep, w);
    if !verify_parts(ik.public_key(), &sig_parts(&c, skdm), sig) || !skdm_for(g, ep, skdm) {
        return Err(GkError::Forged);
    }
    Ok(OpenedBlob {
        skdm: Zeroizing::new(skdm.to_vec()),
        ik,
    })
}

/// A post's plaintext: `gen (16) ‖ epoch (u32 BE) ‖ D_e (32) ‖ body` (§11.7).
pub fn post_plaintext(gen: &[u8; 16], ep: &Epoch, body: &[u8]) -> Vec<u8> {
    [&gen[..], &ep.e.to_be_bytes(), &ep.d_e, body].concat()
}

/// The body of a decrypted post, only when its prefix is this
/// `(gen, epoch, D_e)`.
pub fn open_post<'a>(gen: &[u8; 16], ep: &Epoch, plain: &'a [u8]) -> Result<&'a [u8], GkError> {
    if plain.len() < 16 + 4 + 32 {
        return Err(GkError::Malformed);
    }
    let (prefix, body) = plain.split_at(16 + 4 + 32);
    if prefix[..16] != gen[..] || prefix[16..20] != ep.e.to_be_bytes() || prefix[20..] != ep.d_e {
        return Err(GkError::Sealed);
    }
    Ok(body)
}
