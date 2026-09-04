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
}

// ── Media keys and packets ───────────────────────────────────────────────

/// Per-channel AES-256-GCM key (`voipc_crypto::MediaKey`).
#[wasm_bindgen]
pub struct MediaKey {
    inner: voipc_crypto::MediaKey,
}

#[wasm_bindgen]
impl MediaKey {
    pub fn generate(channel_id: u32, key_id: u16) -> Result<MediaKey, JsError> {
        Ok(Self {
            inner: voipc_crypto::MediaKey::generate(channel_id, key_id).map_err(js_err)?,
        })
    }

    /// From `toBytes()` output, e.g. a key received over a Signal session.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MediaKey, JsError> {
        Ok(Self {
            inner: voipc_crypto::MediaKey::from_bytes(data).map_err(js_err)?,
        })
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    #[wasm_bindgen(getter, js_name = channelId)]
    pub fn channel_id(&self) -> u32 {
        self.inner.channel_id
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> u16 {
        self.inner.key_id
    }
}

/// Encrypted voice packet (0x05); the AAD channel id comes from the key.
#[wasm_bindgen(js_name = buildVoicePacket)]
pub fn build_voice_packet(
    key: &MediaKey,
    session_id: u32,
    udp_token: u64,
    sequence: u32,
    opus: &[u8],
) -> Result<Vec<u8>, JsError> {
    media::build_voice_packet(&key.inner, session_id, udp_token, sequence, opus).map_err(js_err)
}

#[wasm_bindgen(js_name = buildEotPacket)]
pub fn build_eot_packet(session_id: u32, udp_token: u64, sequence: u32) -> Vec<u8> {
    media::build_eot_packet(session_id, udp_token, sequence)
}

#[wasm_bindgen(js_name = buildPingPacket)]
pub fn build_ping_packet(session_id: u32, udp_token: u64, sequence: u32) -> Vec<u8> {
    media::build_ping_packet(session_id, udp_token, sequence)
}

/// `{ packet_type, session_id, sequence }` of an EOT (0x02), Ping (0x03) or
/// Pong (0x04) packet. Encrypted voice goes through `decryptVoicePacket`.
#[wasm_bindgen(js_name = parseVoiceHeader)]
pub fn parse_voice_header(data: &[u8]) -> Result<JsValue, JsError> {
    let info = media::parse_voice_packet(None, data).map_err(js_err)?;
    Ok(voice_info_object(&info))
}

/// `{ packet_type, session_id, sequence, opus }` from an encrypted voice
/// packet (0x05) decrypted with `key`; any other type is an error.
#[wasm_bindgen(js_name = decryptVoicePacket)]
pub fn decrypt_voice_packet(key: &MediaKey, data: &[u8]) -> Result<JsValue, JsError> {
    let info = media::parse_voice_packet(Some(&key.inner), data).map_err(js_err)?;
    if info.opus.is_none() {
        return Err(JsError::new("not an encrypted voice packet"));
    }
    Ok(voice_info_object(&info))
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

/// `{ session_id, sequence, timestamp, opus }` from an encrypted screen-share
/// audio packet (0x15).
#[wasm_bindgen(js_name = parseScreenAudioPacket)]
pub fn parse_screen_audio_packet(key: &MediaKey, data: &[u8]) -> Result<JsValue, JsError> {
    let info = media::parse_screen_audio_packet(&key.inner, data).map_err(js_err)?;
    Ok(js_object(&[
        ("session_id", JsValue::from(info.session_id)),
        ("sequence", JsValue::from(info.sequence)),
        ("timestamp", JsValue::from(info.timestamp)),
        ("opus", uint8array(&info.opus)),
    ]))
}

/// Reassembles encrypted video fragments (0x13/0x14) into H.265 frames.
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
    pub fn push(&mut self, key: &MediaKey, data: &[u8]) -> Result<JsValue, JsError> {
        let result = self.core.push(&key.inner, data).map_err(js_err)?;
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
