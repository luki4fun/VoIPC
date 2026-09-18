//! Symmetric AES-256-GCM encryption for voice/video media packets.
//!
//! Media encryption uses per-channel symmetric keys that are
//! distributed to channel members via pairwise Signal sessions.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// AES-256-GCM authentication tag size.
pub const GCM_TAG_SIZE: usize = 16;

/// Key ID size in packet header.
pub const KEY_ID_SIZE: usize = 2;

/// Total encryption overhead per packet.
pub const ENCRYPTION_OVERHEAD: usize = KEY_ID_SIZE + GCM_TAG_SIZE;

/// A per-channel symmetric key for media encryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct MediaKey {
    /// Incrementing key identifier (for key rotation transitions).
    pub key_id: u16,
    /// 256-bit AES-GCM key.
    pub key_bytes: [u8; 32],
    /// Which channel this key belongs to.
    pub channel_id: u32,
    /// Who minted it.
    ///
    /// Only ever needed to settle a tie. Members elect a minter from the
    /// roster they hold, and two members whose rosters disagree for a moment
    /// would otherwise mint two different keys under the same `key_id` and
    /// split the channel in half. The lower minter wins, everywhere, with
    /// nobody having to be asked.
    pub minter: u32,
    /// Cached AES key schedule — expanding it per packet costs more than the
    /// encryption itself at high packet rates. Clones share the cache.
    #[serde(skip, default)]
    aead_cache: std::sync::Arc<std::sync::OnceLock<LessSafeKey>>,
}

impl MediaKey {
    /// Construct a key from raw bytes (e.g. received from the server).
    pub fn new(channel_id: u32, key_id: u16, minter: u32, key_bytes: [u8; 32]) -> Self {
        Self {
            key_id,
            key_bytes,
            channel_id,
            minter,
            aead_cache: Default::default(),
        }
    }

    /// Generate a fresh random media key.
    pub fn generate(channel_id: u32, key_id: u16, minter: u32) -> anyhow::Result<Self> {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;
        Ok(Self {
            key_id,
            key_bytes,
            channel_id,
            minter,
            aead_cache: Default::default(),
        })
    }

    /// Whether this key should replace `current` for the same channel.
    ///
    /// A later generation always wins. Within one generation the lower minter
    /// wins, which is what makes two members who briefly disagreed about the
    /// roster converge instead of going deaf to each other.
    ///
    /// "Later" is counted the way a sequence number is, not the way a number
    /// is: generations only ever step by one and at most two are in flight, so
    /// the distance between two of them is small and its sign is the answer. A
    /// plain `>` would make `0xFFFF` the last generation there can ever be —
    /// and any member could send it, on the way out, to freeze the channel on
    /// the key they are walking away with.
    ///
    /// A key for another channel never supersedes: the ring holds one room's
    /// keys, and it is `MediaKeyRing::install` that decides when the room
    /// changed.
    pub fn supersedes(&self, current: Option<&MediaKey>) -> bool {
        match current {
            None => true,
            Some(cur) if cur.channel_id != self.channel_id => false,
            Some(cur) => match self.key_id.wrapping_sub(cur.key_id) as i16 {
                0 => self.minter < cur.minter,
                ahead => ahead > 0,
            },
        }
    }

    /// The generation after this one. Wraps, because `key_id` is a counter
    /// with no end rather than a limit — see `supersedes`.
    pub fn next_key_id(&self) -> u16 {
        self.key_id.wrapping_add(1)
    }

    /// The AES-256-GCM key for the raw bytes (key schedule cached).
    fn to_aead_key(&self) -> anyhow::Result<&LessSafeKey> {
        // 32 bytes is always a valid AES-256 key length, so init can't fail
        Ok(self.aead_cache.get_or_init(|| {
            let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
                .expect("AES-256 key is 32 bytes");
            LessSafeKey::new(unbound)
        }))
    }

    /// Serialize this key for transmission (encrypted by pairwise Signal session).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 + 4 + 4);
        buf.extend_from_slice(&self.key_id.to_be_bytes());
        buf.extend_from_slice(&self.key_bytes);
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf.extend_from_slice(&self.minter.to_be_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 42 {
            anyhow::bail!("media key data too short");
        }
        let key_id = u16::from_be_bytes([data[0], data[1]]);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[2..34]);
        let channel_id = u32::from_be_bytes([data[34], data[35], data[36], data[37]]);
        let minter = u32::from_be_bytes([data[38], data[39], data[40], data[41]]);
        Ok(Self {
            key_id,
            key_bytes,
            channel_id,
            minter,
            aead_cache: Default::default(),
        })
    }
}

/// Construct a unique 12-byte nonce from packet metadata.
/// Nonce = stream_id(4) || sequence_or_frame_id(4) || packet_type(1) || fragment_info(3)
///
/// The packet-type byte (taken from the AAD) domain-separates the media
/// streams: voice, screen audio, and video all encrypt under the same
/// channel key with independent sequence counters, so without it a user
/// talking while screen-sharing would reuse (key, nonce) pairs across
/// streams — catastrophic for AES-GCM.
///
/// `stream_id` is what separates two *people* under the one channel key, and
/// it is chosen by the sender. It used to be the session id, which the server
/// hands out — so a server that gave two members of a channel the same one got
/// identical (key, nonce) at every matching sequence and the XOR of two
/// people's voice. The relay is not trusted with anything else here; it is not
/// trusted with this either.
fn build_nonce(stream_id: u32, sequence: u32, extra: u32, aad_context: &[u8]) -> Nonce {
    // extra is a fragment index (wire format caps it at 255), so the top
    // byte is free for the domain tag.
    debug_assert!(extra <= 0x00FF_FFFF, "extra overflows into the domain byte");
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..4].copy_from_slice(&stream_id.to_be_bytes());
    nonce_bytes[4..8].copy_from_slice(&sequence.to_be_bytes());
    nonce_bytes[8..12].copy_from_slice(&extra.to_be_bytes());
    nonce_bytes[8] = aad_context.get(4).copied().unwrap_or(0);
    Nonce::assume_unique_for_key(nonce_bytes)
}

/// Maximum sequence number before a key rotation MUST occur.
/// At ~50 packets/sec (20ms voice frames), this is ~24 hours.
/// After this, nonce uniqueness cannot be guaranteed under the same key.
pub const MAX_SEQUENCE_BEFORE_ROTATION: u32 = u32::MAX - 1000;

/// Encrypt media data (voice or video payload) with AES-256-GCM.
///
/// Returns the ciphertext with appended 16-byte authentication tag.
/// The nonce is constructed deterministically from the sender's own stream id
/// and the sequence, which must be unique per packet (guaranteed by monotonic
/// sequence numbers).
///
/// `aad_context` binds channel_id and packet type to the ciphertext,
/// preventing cross-channel replay and packet type swapping.
pub fn media_encrypt(
    key: &MediaKey,
    stream_id: u32,
    sequence: u32,
    extra: u32,
    aad_context: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // bernd: refusing to encrypt is the whole answer here — reached only
    // after ~24 h of continuous speech on one connection, where the fix is to
    // rotate the key and re-roll the sender's `stream_id`. Do that if anybody
    // ever holds a call that long.
    if sequence >= MAX_SEQUENCE_BEFORE_ROTATION {
        anyhow::bail!(
            "sequence number {} exceeds rotation threshold — media key must be rotated",
            sequence
        );
    }

    let aead_key = key.to_aead_key()?;
    let nonce = build_nonce(stream_id, sequence, extra, aad_context);

    let mut in_out = plaintext.to_vec();
    aead_key
        .seal_in_place_append_tag(nonce, Aad::from(aad_context), &mut in_out)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    Ok(in_out)
}

/// Decrypt media data encrypted with AES-256-GCM.
///
/// Input is ciphertext with appended 16-byte authentication tag.
/// Returns the plaintext on success, or an error if authentication fails.
///
/// `aad_context` must match the value used during encryption.
pub fn media_decrypt(
    key: &MediaKey,
    stream_id: u32,
    sequence: u32,
    extra: u32,
    aad_context: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < GCM_TAG_SIZE {
        anyhow::bail!("ciphertext too short for GCM tag");
    }

    let aead_key = key.to_aead_key()?;
    let nonce = build_nonce(stream_id, sequence, extra, aad_context);

    let mut in_out = ciphertext.to_vec();
    let plaintext = aead_key
        .open_in_place(nonce, Aad::from(aad_context), &mut in_out)
        .map_err(|_| anyhow::anyhow!("decryption failed: invalid key or tampered data"))?;

    Ok(plaintext.to_vec())
}

/// The media keys a client holds for the channel it is in: the one it encrypts
/// with, and the one before it.
///
/// Two, because rotation is not instantaneous. When somebody leaves, the
/// remaining members re-key — but a packet already in flight, or one from a
/// member who has not yet received the new key, still carries the old
/// `key_id`. Dropping those would be an audible gap on every join and leave.
/// Keeping exactly one generation of slack is what makes the rotation
/// inaudible; keeping more would extend the window a departed member can still
/// read, which is the whole point of rotating.
pub struct MediaKeyRing {
    current: Option<MediaKey>,
    previous: Option<MediaKey>,
    stream_id: u32,
}

impl Default for MediaKeyRing {
    fn default() -> Self {
        Self {
            current: None,
            previous: None,
            stream_id: random_stream_id(),
        }
    }
}

/// A fresh nonce prefix for our own outgoing media.
fn random_stream_id() -> u32 {
    let mut bytes = [0u8; 4];
    // A failed RNG here would mean a nonce prefix of zero, which is what the
    // server used to choose for us — so treat it as fatal rather than quietly
    // going back to the thing this exists to prevent.
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("RNG failed while choosing a media stream id");
    u32::from_be_bytes(bytes)
}

impl MediaKeyRing {
    /// The nonce prefix our outgoing media carries.
    ///
    /// Ours alone and chosen here, so two members of a channel encrypting
    /// under the same key at the same sequence still never share a nonce —
    /// however the server numbers their sessions.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Install a key for the channel we are in, if it supersedes what we hold.
    /// Returns whether it did.
    ///
    /// `own_channel` is the room we are actually standing in, and a key for
    /// anywhere else is refused rather than kept: the sender of a key is a
    /// channel member, but the *channel inside it* is their claim, and
    /// believing it costs us every media path at once — `has_channel` gates
    /// sending, receiving and handing the key on, so one key naming a channel
    /// we are not in would leave us silent and deaf with nothing on screen to
    /// say why.
    pub fn install(&mut self, key: MediaKey, own_channel: u32) -> bool {
        if key.channel_id != own_channel {
            return false;
        }
        // The room we were in is not one we can still decrypt for. Normally
        // the caller has already cleared the ring on the way out; this is the
        // same decision made from what the ring holds, so the two cannot drift.
        if self
            .current
            .as_ref()
            .is_some_and(|cur| cur.channel_id != own_channel)
        {
            self.clear();
        }
        if !key.supersedes(self.current.as_ref()) {
            return false;
        }
        self.previous = self.current.take();
        self.current = Some(key);
        true
    }

    /// The key we encrypt with.
    pub fn current(&self) -> Option<&MediaKey> {
        self.current.as_ref()
    }

    /// The generation the member elected to mint should mint next for
    /// `channel_id`.
    ///
    /// One rule in one place, because the two clients each had their own copy
    /// of it and both got the same half wrong: holding no key was read as "wait
    /// for one", which is right for a member still catching up and wrong for
    /// the one now elected to mint — the member who held the key has left, and
    /// nobody else is going to send one. The channel then stays silent for as
    /// long as it exists, because the first mint only ever runs while handling
    /// a roster and every later arrival elects the same member, still waiting.
    /// So: the generation after ours where we hold one, and the channel's first
    /// where we do not.
    pub fn next_generation(&self, channel_id: u32) -> u16 {
        match self.current.as_ref() {
            Some(k) if k.channel_id == channel_id => k.next_key_id(),
            _ => 0,
        }
    }

    /// Whether we hold a key for this channel at all.
    pub fn has_channel(&self, channel_id: u32) -> bool {
        self.current
            .as_ref()
            .is_some_and(|k| k.channel_id == channel_id)
    }

    /// The key a received packet names, if we still hold it.
    pub fn get(&self, channel_id: u32, key_id: u16) -> Option<&MediaKey> {
        [self.current.as_ref(), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|k| k.channel_id == channel_id && k.key_id == key_id)
    }

    /// Forget everything — we left the channel.
    pub fn clear(&mut self) {
        self.current = None;
        self.previous = None;
        self.stream_id = random_stream_id();
    }
}

/// Build AAD context bytes for media encryption.
/// Binds the channel_id and packet_type to the ciphertext, preventing
/// cross-channel replay attacks and packet type confusion.
pub fn build_aad(channel_id: u32, packet_type: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5);
    aad.extend_from_slice(&channel_id.to_be_bytes());
    aad.push(packet_type);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let plaintext = b"hello voice data";
        let session_id = 42;
        let sequence = 100;
        let aad = build_aad(1, 0x01);

        let encrypted =
            media_encrypt(&key, session_id, sequence, 0, &aad, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(encrypted.len(), plaintext.len() + GCM_TAG_SIZE);

        let decrypted =
            media_decrypt(&key, session_id, sequence, 0, &aad, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = MediaKey::generate(1, 0, 1).unwrap();
        let key2 = MediaKey::generate(1, 1, 1).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let encrypted = media_encrypt(&key1, 1, 1, 0, &aad, plaintext).unwrap();
        let result = media_decrypt(&key2, 1, 1, 0, &aad, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let encrypted = media_encrypt(&key, 1, 1, 0, &aad, plaintext).unwrap();
        // Wrong sequence number
        let result = media_decrypt(&key, 1, 2, 0, &aad, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_data_fails() {
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let mut encrypted = media_encrypt(&key, 1, 1, 0, &aad, plaintext).unwrap();
        encrypted[0] ^= 0xFF; // flip a byte
        let result = media_decrypt(&key, 1, 1, 0, &aad, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let plaintext = b"secret";
        let aad1 = build_aad(1, 0x01);
        let aad2 = build_aad(2, 0x01); // different channel

        let encrypted = media_encrypt(&key, 1, 1, 0, &aad1, plaintext).unwrap();
        let result = media_decrypt(&key, 1, 1, 0, &aad2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_exceeds_rotation_threshold() {
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let result = media_encrypt(&key, 1, MAX_SEQUENCE_BEFORE_ROTATION, 0, &aad, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn packet_type_domain_separates_nonces() {
        // Voice (0x05), screen audio (0x15), and video (0x13/0x14) share the
        // channel key with independent sequence counters. The packet-type
        // byte in the AAD must reach the nonce, so identical
        // (session, sequence) pairs on different streams never produce the
        // same keystream.
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let plaintext = b"same plaintext";
        let voice_aad = build_aad(1, 0x05);
        let screen_aad = build_aad(1, 0x15);

        let voice_ct = media_encrypt(&key, 7, 42, 0, &voice_aad, plaintext).unwrap();
        let screen_ct = media_encrypt(&key, 7, 42, 0, &screen_aad, plaintext).unwrap();
        // Same nonce would leak: identical plaintext ⇒ identical ciphertext
        assert_ne!(voice_ct, screen_ct);

        // And a stream's packets can't be replayed into another stream
        assert!(media_decrypt(&key, 7, 42, 0, &screen_aad, &voice_ct).is_err());
    }

    #[test]
    fn media_key_serialization_roundtrip() {
        let key = MediaKey::generate(42, 7, 1).unwrap();
        let bytes = key.to_bytes();
        let restored = MediaKey::from_bytes(&bytes).unwrap();
        assert_eq!(restored.key_id, 7);
        assert_eq!(restored.channel_id, 42);
        assert_eq!(restored.key_bytes, key.key_bytes);
    }

    #[test]
    fn two_speakers_under_one_key_never_share_a_nonce() {
        let key = MediaKey::generate(1, 0, 1).unwrap();
        let aad = build_aad(1, 0x05);
        // Same key, same sequence, same everything the server controls — the
        // only difference is the stream id each speaker picked for itself.
        let alice = media_encrypt(&key, 0xA1A1_A1A1, 42, 0, &aad, b"hello").unwrap();
        let bob = media_encrypt(&key, 0xB2B2_B2B2, 42, 0, &aad, b"hello").unwrap();
        assert_ne!(alice, bob, "identical keystream for two speakers");
        assert!(media_decrypt(&key, 0xB2B2_B2B2, 42, 0, &aad, &alice).is_err());
    }

    #[test]
    fn the_lower_minter_wins_a_tie() {
        let mut ring = MediaKeyRing::default();
        assert!(ring.install(MediaKey::generate(1, 0, 9).unwrap(), 1));
        // A newer generation always wins.
        assert!(ring.install(MediaKey::generate(1, 1, 9).unwrap(), 1));
        // Same generation from a lower minter wins; from a higher one does not.
        assert!(ring.install(MediaKey::generate(1, 1, 4).unwrap(), 1));
        assert!(!ring.install(MediaKey::generate(1, 1, 7).unwrap(), 1));
        assert_eq!(ring.current().unwrap().minter, 4);
    }

    /// The channel inside a key is the sender's claim. Believing one for a
    /// channel we are not in costs every media path at once: `has_channel`
    /// gates sending, receiving and passing the key on.
    #[test]
    fn a_key_for_another_channel_is_refused() {
        let mut ring = MediaKeyRing::default();
        assert!(ring.install(MediaKey::generate(1, 0, 1).unwrap(), 1));
        assert!(!ring.install(MediaKey::generate(2, 9, 1).unwrap(), 1));
        assert!(ring.has_channel(1), "still the key of the room we are in");
        assert_eq!(ring.current().unwrap().key_id, 0);
        // And moving rooms is not blocked by what the old room left behind
        assert!(ring.install(MediaKey::generate(2, 0, 1).unwrap(), 2));
        assert!(ring.has_channel(2));
        assert!(ring.get(1, 0).is_none(), "the room we left is not ours to decrypt");
    }

    /// `key_id` is a counter, not a limit. If the last generation were really
    /// the last, any member could send `0xFFFF` on the way out and every
    /// rotation after it would be refused — freezing the channel on the key
    /// they walked away with, which is the one thing rotation exists to stop.
    #[test]
    fn a_rotation_past_the_last_generation_wraps_and_still_supersedes() {
        let mut ring = MediaKeyRing::default();
        assert!(ring.install(MediaKey::generate(1, u16::MAX, 9).unwrap(), 1));
        let next = ring.current().unwrap().next_key_id();
        assert_eq!(next, 0);
        assert!(ring.install(MediaKey::generate(1, next, 9).unwrap(), 1));
        assert_eq!(ring.current().unwrap().key_id, 0);
        // The generation before still decrypts what is in flight, and the old
        // one does not come back as "newer" on the way round.
        assert!(ring.get(1, u16::MAX).is_some());
        assert!(!ring.install(MediaKey::generate(1, u16::MAX, 9).unwrap(), 1));
    }

    /// The rule both clients used to keep their own version of.
    #[test]
    fn a_minter_with_no_key_starts_the_channel_rather_than_waiting() {
        let mut ring = MediaKeyRing::default();
        assert_eq!(ring.next_generation(5), 0, "an empty ring starts at the first generation");

        ring.install(MediaKey::new(5, 7, 1, [1u8; 32]), 5);
        assert_eq!(ring.next_generation(5), 8, "with a key it is the one after ours");
        // A key for a room we are not in is not ours to succeed; the ring is
        // cleared on the way out, and this is the same answer from what it holds.
        assert_eq!(ring.next_generation(6), 0);

        // ...and it wraps, like `next_key_id`: the last number is not the last
        // generation, or a member could send it on the way out and freeze the
        // channel on the key they walked away with.
        let mut wrapped = MediaKeyRing::default();
        wrapped.install(MediaKey::new(5, u16::MAX, 1, [2u8; 32]), 5);
        assert_eq!(wrapped.next_generation(5), 0);
    }

    #[test]
    fn every_ring_picks_its_own_stream_id() {
        let (a, b) = (MediaKeyRing::default(), MediaKeyRing::default());
        assert_ne!(a.stream_id(), b.stream_id());
        assert_ne!(a.stream_id(), 0);
    }

    #[test]
    fn a_rotation_keeps_one_generation_of_slack() {
        let mut ring = MediaKeyRing::default();
        ring.install(MediaKey::generate(1, 0, 1).unwrap(), 1);
        ring.install(MediaKey::generate(1, 1, 1).unwrap(), 1);
        assert!(ring.get(1, 0).is_some(), "packets in flight still decrypt");
        assert!(ring.get(1, 1).is_some());
        ring.install(MediaKey::generate(1, 2, 1).unwrap(), 1);
        assert!(ring.get(1, 0).is_none(), "and no longer than that");
        // A different channel is a different room; nothing is kept.
        ring.install(MediaKey::generate(2, 0, 1).unwrap(), 2);
        assert!(ring.get(1, 2).is_none());
        // ...and a new room gets a nonce prefix of its own
        assert_ne!(ring.stream_id(), 0);
    }

    #[test]
    fn a_media_key_survives_the_round_trip_with_its_minter() {
        let key = MediaKey::generate(7, 3, 11).unwrap();
        let back = MediaKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!((back.channel_id, back.key_id, back.minter), (7, 3, 11));
        assert!(MediaKey::from_bytes(&key.to_bytes()[..41]).is_err());
    }

}
