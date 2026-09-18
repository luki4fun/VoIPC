//! Browser build of the VoIPC protocol codec, Signal Protocol and media
//! crypto, exposed to JS through wasm-bindgen. The JS-facing contract lives in
//! client/src/web/backend/wasm.ts and must match this file name for name.
//!
//! Everything is synchronous; failures throw a JS `Error` with a message.
//! The logic lives in `signal` and `media` (plain Rust, host-testable); this
//! file only converts between JS and Rust values.

pub mod media;
pub mod signal;

use serde::Serialize;
use voipc_protocol::codec::{APP_VERSION, PROTOCOL_VERSION};
use voipc_protocol::messages::ClientMessage;
use voipc_protocol::types::PreKeyBundleData;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// JS Error carrying the whole anyhow context chain.
fn js_err(e: anyhow::Error) -> JsError {
    JsError::new(&format!("{e:#}"))
}

/// Plain JS object from key/value pairs.
fn js_object(fields: &[(&str, JsValue)]) -> JsValue {
    let obj = js_sys::Object::new();
    for (key, value) in fields {
        // Defining a data property on a fresh plain object cannot fail.
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(key), value);
    }
    obj.into()
}

fn uint8array(data: &[u8]) -> JsValue {
    js_sys::Uint8Array::from(data).into()
}

// ── Protocol codec ───────────────────────────────────────────────────────

#[wasm_bindgen(js_name = protocolVersion)]
pub fn protocol_version() -> u32 {
    PROTOCOL_VERSION
}

#[wasm_bindgen(js_name = appVersion)]
pub fn app_version() -> String {
    APP_VERSION.to_string()
}

/// Postcard bytes of a `ClientMessage` given in serde's externally tagged JS
/// form (`{ JoinChannel: {...} }`, `"Disconnect"`), without the u32 length
/// prefix. `Vec<u8>` fields may be arrays or Uint8Arrays, `Option`s
/// null/undefined, `u64`s numbers or bigints.
#[wasm_bindgen(js_name = encodeClientMsg)]
pub fn encode_client_msg(msg: JsValue) -> Result<Vec<u8>, JsError> {
    let msg: ClientMessage = serde_wasm_bindgen::from_value(msg)?;
    Ok(postcard::to_allocvec(&msg)?)
}

/// Decodes postcard bytes (no length prefix) into a `ServerMessage` object:
/// struct variants as `{ Variant: {...} }`, unit variants as strings, `u64`
/// as bigint, `Vec<u8>` as number[], `None` as undefined.
#[wasm_bindgen(js_name = decodeServerMsg)]
pub fn decode_server_msg(bytes: &[u8]) -> Result<JsValue, JsError> {
    let msg = voipc_protocol::codec::decode_server_msg(bytes)?;
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    Ok(msg.serialize(&serializer)?)
}

// ── Signal Protocol ──────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct SignalClient {
    core: signal::SignalCore,
}

#[wasm_bindgen]
impl SignalClient {
    /// Fresh ephemeral identity, registration id, signed pre-key 1 and 100
    /// one-time pre-keys.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<SignalClient, JsError> {
        Ok(Self {
            core: signal::SignalCore::new().map_err(js_err)?,
        })
    }

    /// `{ identity_key: number[], prekey_bundle: PreKeyBundleData }` for Authenticate.
    pub fn bundle(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&self.core.bundle().map_err(js_err)?)?)
    }

    /// X3DH with a peer's `PreKeyBundleData` (as decoded from `ServerMessage.PreKeyBundle`).
    #[wasm_bindgen(js_name = establishSession)]
    pub fn establish_session(&mut self, user_id: u32, bundle: JsValue) -> Result<(), JsError> {
        let bundle: PreKeyBundleData = serde_wasm_bindgen::from_value(bundle)?;
        self.core.establish_session(user_id, &bundle).map_err(js_err)
    }

    /// `{ ciphertext: Uint8Array, message_type: number }` (1 = PreKey, 2 = Whisper).
    pub fn encrypt(&mut self, user_id: u32, plaintext: &[u8]) -> Result<JsValue, JsError> {
        let (ciphertext, message_type) = self.core.encrypt(user_id, plaintext).map_err(js_err)?;
        Ok(js_object(&[
            ("ciphertext", uint8array(&ciphertext)),
            ("message_type", JsValue::from(message_type)),
        ]))
    }

    pub fn decrypt(
        &mut self,
        user_id: u32,
        ciphertext: &[u8],
        message_type: u8,
    ) -> Result<Vec<u8>, JsError> {
        self.core
            .decrypt(user_id, ciphertext, message_type)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = createSenderKeyDistribution)]
    pub fn create_sender_key_distribution(
        &mut self,
        own_user_id: u32,
        channel_id: u32,
    ) -> Result<Vec<u8>, JsError> {
        self.core
            .create_sender_key_distribution(own_user_id, channel_id)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = processSenderKeyDistribution)]
    pub fn process_sender_key_distribution(
        &mut self,
        from_user_id: u32,
        channel_id: u32,
        distribution: &[u8],
    ) -> Result<(), JsError> {
        self.core
            .process_sender_key_distribution(from_user_id, channel_id, distribution)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = groupEncrypt)]
    pub fn group_encrypt(
        &mut self,
        own_user_id: u32,
        channel_id: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.core
            .group_encrypt(own_user_id, channel_id, plaintext)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = groupDecrypt)]
    pub fn group_decrypt(
        &mut self,
        from_user_id: u32,
        channel_id: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.core
            .group_decrypt(from_user_id, channel_id, ciphertext)
            .map_err(js_err)
    }

    // ── Channel membership and sender-key bookkeeping ────────────────────
    //
    // The same `voipc_crypto::ChannelKeying` the native client uses, so the
    // browser answers "may I install this key / show this message / hand over
    // this history" from the same code rather than a hand-port of it.

    /// Whether `channel_id` is one we are in: the voice channel we stand in, or
    /// any text channel we subscribe to.
    #[wasm_bindgen(js_name = inChannel)]
    pub fn in_channel(&self, own_channel: u32, channel_id: u32) -> bool {
        self.core.keying.in_channel(own_channel, channel_id)
    }

    /// Whether `channel_id` is one we are in and `user_id` is in it with us.
    #[wasm_bindgen(js_name = sharesChannelWith)]
    pub fn shares_channel_with(&self, own_channel: u32, channel_id: u32, user_id: u32) -> bool {
        self.core
            .keying
            .shares_channel_with(own_channel, channel_id, user_id)
    }

    #[wasm_bindgen(js_name = isMember)]
    pub fn is_member(&self, channel_id: u32, user_id: u32) -> bool {
        self.core.keying.is_member(channel_id, user_id)
    }

    #[wasm_bindgen(js_name = isTextChannel)]
    pub fn is_text_channel(&self, channel_id: u32) -> bool {
        self.core.keying.is_text(channel_id)
    }

    #[wasm_bindgen(js_name = textChannels)]
    pub fn text_channels(&self) -> Vec<u32> {
        self.core.keying.text_channels()
    }

    #[wasm_bindgen(js_name = setMembers)]
    pub fn set_members(&mut self, channel_id: u32, user_ids: Vec<u32>) {
        self.core.keying.set_members(channel_id, user_ids);
    }

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(&mut self, channel_id: u32, user_id: u32) {
        self.core.keying.add_member(channel_id, user_id);
    }

    #[wasm_bindgen(js_name = dropMember)]
    pub fn drop_member(&mut self, channel_id: u32, user_id: u32) {
        self.core.keying.drop_member(channel_id, user_id);
    }

    /// Everybody in the channel except us.
    #[wasm_bindgen(js_name = othersIn)]
    pub fn others_in(&self, channel_id: u32, own_user_id: u32) -> Vec<u32> {
        self.core.keying.others_in(channel_id, own_user_id)
    }

    /// Subscribe to a text channel; `true` if it is new to us.
    #[wasm_bindgen(js_name = joinTextChannel)]
    pub fn join_text_channel(&mut self, channel_id: u32) -> bool {
        self.core.keying.join_text(channel_id)
    }

    /// Start a channel's group keying from nothing, our own chain included.
    #[wasm_bindgen(js_name = resetChannel)]
    pub fn reset_channel(&mut self, own_user_id: u32, channel_id: u32) {
        self.core.reset_channel(own_user_id, channel_id);
    }

    /// Leave a channel entirely: keys, roster and anything still wanted.
    #[wasm_bindgen(js_name = forgetChannel)]
    pub fn forget_channel(&mut self, own_user_id: u32, channel_id: u32) {
        self.core.forget_channel(own_user_id, channel_id);
    }

    /// Somebody left a channel we are still in: the next message we send there
    /// starts a fresh chain.
    #[wasm_bindgen(js_name = noteStale)]
    pub fn note_stale(&mut self, channel_id: u32) {
        self.core.keying.note_stale(channel_id);
    }

    /// If a rotation is pending, perform it and return who needs the new key.
    /// The chain is forgotten whether or not anybody is left to tell.
    #[wasm_bindgen(js_name = takeRotationTargets)]
    pub fn take_rotation_targets(&mut self, own_user_id: u32, channel_id: u32) -> Vec<u32> {
        self.core.take_rotation_targets(own_user_id, channel_id)
    }

    #[wasm_bindgen(js_name = recordDistributed)]
    pub fn record_distributed(&mut self, channel_id: u32, user_id: u32) {
        self.core.keying.record_distributed(channel_id, user_id);
    }

    #[wasm_bindgen(js_name = hasDistributed)]
    pub fn has_distributed(&self, channel_id: u32, user_id: u32) -> bool {
        self.core.keying.has_distributed(channel_id, user_id)
    }

    #[wasm_bindgen(js_name = anyoneHoldsOurKey)]
    pub fn anyone_holds_our_key(&self, channel_id: u32) -> bool {
        self.core.keying.anyone_holds_our_key(channel_id)
    }

    #[wasm_bindgen(js_name = recordReceived)]
    pub fn record_received(&mut self, channel_id: u32, user_id: u32) {
        self.core.keying.record_received(channel_id, user_id);
    }

    /// Note who to ask for a channel's recent chat.
    #[wasm_bindgen(js_name = wantHistoryFrom)]
    pub fn want_history_from(&mut self, channel_id: u32, user_ids: Vec<u32>) {
        self.core
            .keying
            .want_history_from(channel_id, user_ids.into_iter().collect());
    }

    /// Whether we were still waiting to ask this member; consumes the intent.
    #[wasm_bindgen(js_name = takeHistoryWanted)]
    pub fn take_history_wanted(&mut self, channel_id: u32, user_id: u32) -> bool {
        self.core.keying.take_history_wanted(channel_id, user_id)
    }

    /// Who mints the channel's next media key: the lowest remaining user id, so
    /// every member elects the same one without anybody being asked.
    #[wasm_bindgen(js_name = mediaKeyMinter)]
    pub fn media_key_minter(&self, channel_id: u32) -> Option<u32> {
        self.core.keying.media_key_minter(channel_id)
    }
}

// ── Message envelopes and history payloads ───────────────────────────────

/// How many control messages a second one connection may send. The server
/// charges a token per frame and drops what cannot pay, so we stay under it.
#[wasm_bindgen(js_name = controlMsgsPerSec)]
pub fn control_msgs_per_sec() -> u32 {
    voipc_protocol::codec::CONTROL_MSGS_PER_SEC
}

/// Largest opaque blob the relay will re-wrap and forward.
#[wasm_bindgen(js_name = maxRelayCiphertext)]
pub fn max_relay_ciphertext() -> usize {
    voipc_protocol::codec::MAX_RELAY_CIPHERTEXT
}

/// Of the members who offer a channel's recent chat, the few actually asked —
/// picked at random, so a whole server reconnecting does not aim every request
/// at the same two or three people.
#[wasm_bindgen(js_name = pickHistorySources)]
pub fn pick_history_sources(sharers: Vec<u32>) -> Vec<u32> {
    voipc_crypto::pick_history_sources(&sharers)
        .into_iter()
        .collect()
}

/// A fresh message id: 16 random bytes, hex.
#[wasm_bindgen(js_name = newMessageId)]
pub fn new_message_id() -> String {
    voipc_crypto::new_message_id()
}

/// Pack a message so it carries what the server never sees: the id, and the
/// destruction timer in seconds (0 or absent for a message with no timer).
#[wasm_bindgen(js_name = envelope)]
pub fn envelope(id: &str, text: &str, ttl_secs: Option<u32>) -> Vec<u8> {
    voipc_crypto::envelope(id, text, ttl_secs)
}

/// `{ id: string | null, text: string, ttl_secs: number | null }` from a
/// received message.
#[wasm_bindgen(js_name = openEnvelope)]
pub fn open_envelope(plaintext: &[u8]) -> JsValue {
    let m = voipc_crypto::open_envelope(plaintext);
    js_object(&[
        (
            "id",
            m.id.map(|s| JsValue::from_str(&s)).unwrap_or(JsValue::NULL),
        ),
        ("text", JsValue::from_str(&m.text)),
        (
            "ttl_secs",
            m.ttl_secs
                .map(|t| JsValue::from_f64(t as f64))
                .unwrap_or(JsValue::NULL),
        ),
    ])
}

/// Pack a channel's recent chat for one member, with the channel bound inside
/// the ciphertext rather than left to the envelope the server writes.
///
/// The messages cross as JSON text rather than as a JS value, in both
/// directions. A chat message has no fixed shape here — it is whatever the
/// sender's client stores — and `serde_wasm_bindgen` cannot carry a shapeless
/// object either way: reading one gives an empty map, and writing one gives a
/// JS `Map` that nothing on the other side treats as a message. Both failures
/// are silent, and the second is a whole conversation quietly discarded field
/// by field.
#[wasm_bindgen(js_name = historyPayload)]
pub fn history_payload(channel_id: u32, messages_json: &str) -> Result<Vec<u8>, JsError> {
    let messages: serde_json::Value = serde_json::from_str(messages_json)
        .map_err(|e| JsError::new(&format!("history messages are not JSON: {e}")))?;
    Ok(voipc_crypto::history_payload(channel_id, &messages))
}

/// The messages in a hand-off as JSON text, refusing one that names a
/// different channel than the server said it arrived in.
#[wasm_bindgen(js_name = openHistoryPayload)]
pub fn open_history_payload(channel_id: u32, payload: &[u8]) -> Result<String, JsError> {
    let messages = voipc_crypto::open_history_payload(channel_id, payload).map_err(js_err)?;
    Ok(serde_json::Value::Array(messages).to_string())
}

// ── Media keys and packets ───────────────────────────────────────────────

/// The media keys held for the channel we are in: the one we encrypt with, the
/// one before it, and our own nonce prefix (`voipc_crypto::MediaKeyRing`).
///
/// A ring rather than one key because a member leaving re-keys the channel, and
/// a packet already in flight still names the generation before.
#[wasm_bindgen]
pub struct MediaKeys {
    inner: voipc_crypto::MediaKeyRing,
}

impl Default for MediaKeys {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl MediaKeys {
    #[wasm_bindgen(constructor)]
    pub fn new() -> MediaKeys {
        Self {
            inner: voipc_crypto::MediaKeyRing::default(),
        }
    }

    /// Mint a generation of our own — the first member of a channel, or the
    /// member elected to re-key after somebody left.
    pub fn generate(&mut self, channel_id: u32, key_id: u16, minter: u32) -> Result<bool, JsError> {
        let key = voipc_crypto::MediaKey::generate(channel_id, key_id, minter).map_err(js_err)?;
        Ok(self.inner.install(key, channel_id))
    }

    /// Install a key received over a Signal session. Returns whether it
    /// superseded what we held — a later generation always does, and within
    /// one generation the lower minter does.
    ///
    /// `own_channel` is the room we are standing in. The channel named inside
    /// the key is the sender's claim, and one naming anywhere else is refused:
    /// `has_channel` gates sending, receiving and passing the key on, so
    /// believing it would leave us silent and deaf at once.
    pub fn install(&mut self, data: &[u8], own_channel: u32) -> Result<bool, JsError> {
        let key = voipc_crypto::MediaKey::from_bytes(data).map_err(js_err)?;
        Ok(self.inner.install(key, own_channel))
    }

    /// The generation after the one we hold. Wraps: `key_id` is a counter, not
    /// a limit, or a member could send the last one on the way out and freeze
    /// the channel on the key they walked away with.
    #[wasm_bindgen(js_name = nextKeyId)]
    pub fn next_key_id(&self) -> Option<u16> {
        self.inner.current().map(|k| k.next_key_id())
    }

    /// The key we encrypt with, serialized to hand to another member.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.inner.current().map(|k| k.to_bytes())
    }

    /// Whether we hold a key for this channel at all.
    /// The generation to mint next for a channel: the one after ours, or the
    /// channel's first where we hold no key — see `MediaKeyRing::next_generation`.
    #[wasm_bindgen(js_name = nextGeneration)]
    pub fn next_generation(&self, channel_id: u32) -> u16 {
        self.inner.next_generation(channel_id)
    }

    #[wasm_bindgen(js_name = hasChannel)]
    pub fn has_channel(&self, channel_id: u32) -> bool {
        self.inner.has_channel(channel_id)
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[wasm_bindgen(getter, js_name = channelId)]
    pub fn channel_id(&self) -> Option<u32> {
        self.inner.current().map(|k| k.channel_id)
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> Option<u16> {
        self.inner.current().map(|k| k.key_id)
    }
}

/// Encrypted voice packet (0x05); the AAD channel id comes from the key.
#[wasm_bindgen(js_name = buildVoicePacket)]
pub fn build_voice_packet(
    keys: &MediaKeys,
    session_id: u32,
    sequence: u32,
    opus: &[u8],
) -> Result<Vec<u8>, JsError> {
    media::build_voice_packet(&keys.inner, session_id, sequence, opus).map_err(js_err)
}

#[wasm_bindgen(js_name = buildEotPacket)]
pub fn build_eot_packet(session_id: u32, sequence: u32) -> Vec<u8> {
    media::build_eot_packet(session_id, sequence)
}

#[wasm_bindgen(js_name = buildPingPacket)]
pub fn build_ping_packet(session_id: u32, sequence: u32) -> Vec<u8> {
    media::build_ping_packet(session_id, sequence)
}

/// `{ packet_type, session_id, sequence }` of an EOT (0x02), Ping (0x03) or
/// Pong (0x04) packet. Encrypted voice goes through `decryptVoicePacket`.
#[wasm_bindgen(js_name = parseVoiceHeader)]
pub fn parse_voice_header(data: &[u8]) -> Result<JsValue, JsError> {
    let info = media::parse_voice_packet(None, 0, data).map_err(js_err)?;
    Ok(voice_info_object(&info))
}

/// `{ packet_type, session_id, sequence, opus }` from an encrypted voice
/// packet (0x05) decrypted with `key`; any other type is an error.
#[wasm_bindgen(js_name = decryptVoicePacket)]
pub fn decrypt_voice_packet(
    keys: &MediaKeys,
    channel_id: u32,
    data: &[u8],
) -> Result<JsValue, JsError> {
    let info = media::parse_voice_packet(Some(&keys.inner), channel_id, data).map_err(js_err)?;
    if info.opus.is_none() {
        return Err(JsError::new("not an encrypted voice packet"));
    }
    Ok(voice_info_object(&info))
}

/// Encrypted position beacon (0x06) for the room's "sync my position".
#[wasm_bindgen(js_name = buildPositionPacket)]
pub fn build_position_packet(
    keys: &MediaKeys,
    session_id: u32,
    sequence: u32,
    x: f32,
    y: f32,
    z: f32,
) -> Result<Vec<u8>, JsError> {
    media::build_position_packet(&keys.inner, session_id, sequence, x, y, z).map_err(js_err)
}

/// `{ session_id, x, y, z }` from a position beacon decrypted with `key`.
#[wasm_bindgen(js_name = decryptPositionPacket)]
pub fn decrypt_position_packet(
    keys: &MediaKeys,
    channel_id: u32,
    data: &[u8],
) -> Result<JsValue, JsError> {
    let info = media::parse_position_packet(&keys.inner, channel_id, data).map_err(js_err)?;
    Ok(js_object(&[
        ("session_id", JsValue::from(info.session_id)),
        ("x", JsValue::from(info.x)),
        ("y", JsValue::from(info.y)),
        ("z", JsValue::from(info.z)),
    ]))
}

fn voice_info_object(info: &media::VoiceInfo) -> JsValue {
    let mut fields = vec![
        ("packet_type", JsValue::from(info.packet_type)),
        ("session_id", JsValue::from(info.session_id)),
        ("sequence", JsValue::from(info.sequence)),
    ];
    if let Some(opus) = &info.opus {
        fields.push(("opus", uint8array(opus)));
    }
    js_object(&fields)
}

/// Encrypted screen-share audio packet (0x15) for one Opus frame of the
/// desktop audio a browser sharer captured.
#[wasm_bindgen(js_name = buildScreenAudioPacket)]
pub fn build_screen_audio_packet(
    keys: &MediaKeys,
    session_id: u32,
    sequence: u32,
    timestamp: u32,
    opus: &[u8],
) -> Result<Vec<u8>, JsError> {
    media::build_screen_audio_packet(&keys.inner, session_id, sequence, timestamp, opus)
        .map_err(js_err)
}

/// One encoded video frame as the body of its per-frame stream: encrypted
/// fragments, each behind a `u16` big-endian length. Write it to one
/// unidirectional WebTransport stream and close it.
#[wasm_bindgen(js_name = buildVideoFrameStream)]
pub fn build_video_frame_stream(
    keys: &MediaKeys,
    session_id: u32,
    frame_id: u32,
    timestamp: u32,
    is_keyframe: bool,
    frame: &[u8],
) -> Result<Vec<u8>, JsError> {
    media::build_video_frame_stream(
        &keys.inner,
        session_id,
        frame_id,
        timestamp,
        is_keyframe,
        frame,
    )
    .map_err(js_err)
}

/// `{ session_id, sequence, timestamp, opus }` from an encrypted screen-share
/// audio packet (0x15).
#[wasm_bindgen(js_name = parseScreenAudioPacket)]
pub fn parse_screen_audio_packet(
    keys: &MediaKeys,
    channel_id: u32,
    data: &[u8],
) -> Result<JsValue, JsError> {
    let info = media::parse_screen_audio_packet(&keys.inner, channel_id, data).map_err(js_err)?;
    Ok(js_object(&[
        ("session_id", JsValue::from(info.session_id)),
        ("sequence", JsValue::from(info.sequence)),
        ("timestamp", JsValue::from(info.timestamp)),
        ("opus", uint8array(&info.opus)),
    ]))
}

/// Reassembles encrypted video fragments (0x13/0x14) into whole frames.
#[wasm_bindgen]
pub struct VideoAssembler {
    core: media::VideoAssemblerCore,
}

#[wasm_bindgen]
impl VideoAssembler {
    #[wasm_bindgen(constructor)]
    pub fn new() -> VideoAssembler {
        Self {
            core: media::VideoAssemblerCore::new(),
        }
    }

    /// `{ frame?: Uint8Array, is_keyframe, timestamp, frame_dropped }`.
    pub fn push(
        &mut self,
        keys: &MediaKeys,
        channel_id: u32,
        data: &[u8],
    ) -> Result<JsValue, JsError> {
        let result = self.core.push(&keys.inner, channel_id, data).map_err(js_err)?;
        let mut fields = vec![
            ("is_keyframe", JsValue::from_bool(result.is_keyframe)),
            ("timestamp", JsValue::from(result.timestamp)),
            ("frame_dropped", JsValue::from_bool(result.frame_dropped)),
        ];
        if let Some(frame) = &result.frame {
            fields.push(("frame", uint8array(frame)));
        }
        Ok(js_object(&fields))
    }

    pub fn reset(&mut self) {
        self.core.reset();
    }
}
