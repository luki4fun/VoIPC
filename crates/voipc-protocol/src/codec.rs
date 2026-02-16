use bytes::{Buf, BytesMut};

use crate::error::ProtocolError;
use crate::messages::{ClientMessage, ServerMessage};

/// Maximum TCP message size: 64 KiB.
pub const MAX_MSG_SIZE: u32 = 65_536;

/// Current protocol version.
/// v2: Base protocol with screen share
/// v3: E2E encryption (Signal Protocol + AES-256-GCM media)
pub const PROTOCOL_VERSION: u32 = 3;

/// Application version, read from Cargo.toml at compile time.
/// Single source of truth: workspace root `Cargo.toml` `[workspace.package] version`.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Encode a `ClientMessage` into a length-prefixed byte buffer for TCP transmission.
pub fn encode_client_msg(msg: &ClientMessage) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_allocvec(msg)?;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a `ClientMessage` from a postcard-encoded payload (without length prefix).
pub fn decode_client_msg(payload: &[u8]) -> Result<ClientMessage, ProtocolError> {
    Ok(postcard::from_bytes(payload)?)
}

/// Encode a `ServerMessage` into a length-prefixed byte buffer for TCP transmission.
pub fn encode_server_msg(msg: &ServerMessage) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_allocvec(msg)?;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a `ServerMessage` from a postcard-encoded payload (without length prefix).
pub fn decode_server_msg(payload: &[u8]) -> Result<ServerMessage, ProtocolError> {
    Ok(postcard::from_bytes(payload)?)
}

/// Attempt to extract one complete length-prefixed frame from a byte buffer.
///
/// Returns `Ok(Some(payload))` if a complete message is available,
/// `Ok(None)` if more data is needed, or `Err` if the message is too large.
///
/// Advances the buffer past the consumed frame.
pub fn try_decode_frame(buf: &mut BytesMut) -> Result<Option<Vec<u8>>, ProtocolError> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    if length > MAX_MSG_SIZE as usize {
        return Err(ProtocolError::MessageTooLarge(length));
    }

    if buf.len() < 4 + length {
        return Ok(None);
    }

    buf.advance(4);
    let payload = buf.split_to(length).to_vec();
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_client_message() {
        let msg = ClientMessage::Authenticate {
            username: "alice".into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
        };
        let encoded = encode_client_msg(&msg).unwrap();
        // Skip the 4-byte length prefix
        let decoded = decode_client_msg(&encoded[4..]).unwrap();
        match decoded {
            ClientMessage::Authenticate {
                username,
                protocol_version,
                ..
            } => {
                assert_eq!(username, "alice");
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_server_message() {
        let msg = ServerMessage::Authenticated {
            user_id: 1,
            session_id: 42,
            udp_port: 9987,
            udp_token: 0xDEADBEEF,
        };
        let encoded = encode_server_msg(&msg).unwrap();
        let decoded = decode_server_msg(&encoded[4..]).unwrap();
        match decoded {
            ServerMessage::Authenticated {
                user_id,
                session_id,
                udp_port,
                udp_token,
            } => {
                assert_eq!(user_id, 1);
                assert_eq!(session_id, 42);
                assert_eq!(udp_port, 9987);
                assert_eq!(udp_token, 0xDEADBEEF);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn frame_decoding() {
        let msg = ClientMessage::Ping { timestamp: 12345 };
        let encoded = encode_client_msg(&msg).unwrap();

        let mut buf = BytesMut::new();

        // Partial data — should return None
        buf.extend_from_slice(&encoded[..3]);
        assert!(try_decode_frame(&mut buf).unwrap().is_none());

        // Complete data
        buf.extend_from_slice(&encoded[3..]);
        let payload = try_decode_frame(&mut buf).unwrap().unwrap();
        let decoded = decode_client_msg(&payload).unwrap();
        match decoded {
            ClientMessage::Ping { timestamp } => assert_eq!(timestamp, 12345),
            _ => panic!("wrong variant"),
        }

        // Buffer should be empty now
        assert!(buf.is_empty());
    }

    #[test]
    fn roundtrip_join_channel() {
        let msg = ClientMessage::JoinChannel {
            channel_id: 42,
            password: Some("secret".into()),
        };
        let encoded = encode_client_msg(&msg).unwrap();
        let decoded = decode_client_msg(&encoded[4..]).unwrap();
        match decoded {
            ClientMessage::JoinChannel { channel_id, password } => {
                assert_eq!(channel_id, 42);
                assert_eq!(password, Some("secret".into()));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_create_channel() {
        let msg = ClientMessage::CreateChannel {
            name: "TestRoom".into(),
            password: None,
        };
        let encoded = encode_client_msg(&msg).unwrap();
        let decoded = decode_client_msg(&encoded[4..]).unwrap();
        match decoded {
            ClientMessage::CreateChannel { name, password } => {
                assert_eq!(name, "TestRoom");
                assert!(password.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_disconnect() {
        let msg = ClientMessage::Disconnect;
        let encoded = encode_client_msg(&msg).unwrap();
        let decoded = decode_client_msg(&encoded[4..]).unwrap();
        assert!(matches!(decoded, ClientMessage::Disconnect));
    }

    #[test]
    fn roundtrip_screen_share_messages() {
        let msg = ClientMessage::StartScreenShare {
            source: "screen:0".into(),
            resolution: 1080,
        };
        let encoded = encode_client_msg(&msg).unwrap();
        let decoded = decode_client_msg(&encoded[4..]).unwrap();
        match decoded {
            ClientMessage::StartScreenShare { source, resolution } => {
                assert_eq!(source, "screen:0");
                assert_eq!(resolution, 1080);
            }
            _ => panic!("wrong variant"),
        }

        let msg = ClientMessage::WatchScreenShare { sharer_user_id: 7 };
        let encoded = encode_client_msg(&msg).unwrap();
        let decoded = decode_client_msg(&encoded[4..]).unwrap();
        assert!(matches!(decoded, ClientMessage::WatchScreenShare { sharer_user_id: 7 }));
    }

    #[test]
    fn roundtrip_encrypted_chat_messages() {
        let msg = ServerMessage::EncryptedChannelChatMessage {
            channel_id: 1,
            user_id: 5,
            username: "alice".into(),
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            timestamp: 999,
        };
        let encoded = encode_server_msg(&msg).unwrap();
        let decoded = decode_server_msg(&encoded[4..]).unwrap();
        match decoded {
            ServerMessage::EncryptedChannelChatMessage { channel_id, user_id, username, ciphertext, timestamp } => {
                assert_eq!(channel_id, 1);
                assert_eq!(user_id, 5);
                assert_eq!(username, "alice");
                assert_eq!(ciphertext, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(timestamp, 999);
            }
            _ => panic!("wrong variant"),
        }

        let msg = ServerMessage::EncryptedDirectChatMessage {
            from_user_id: 1,
            from_username: "bob".into(),
            to_user_id: 2,
            ciphertext: vec![0xCA, 0xFE],
            message_type: 2,
            timestamp: 1000,
        };
        let encoded = encode_server_msg(&msg).unwrap();
        let decoded = decode_server_msg(&encoded[4..]).unwrap();
        assert!(matches!(decoded, ServerMessage::EncryptedDirectChatMessage { .. }));
    }

    #[test]
    fn frame_message_too_large() {
        let mut buf = BytesMut::new();
        let bad_len = (MAX_MSG_SIZE + 1).to_be_bytes();
        buf.extend_from_slice(&bad_len);
        buf.extend_from_slice(&[0u8; 100]);
        let result = try_decode_frame(&mut buf);
        assert!(matches!(result, Err(ProtocolError::MessageTooLarge(_))));
    }

    #[test]
    fn frame_partial_length() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0, 0]); // only 2 bytes, need 4
        assert!(try_decode_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn frame_multiple_messages() {
        let msg1 = ClientMessage::Ping { timestamp: 1 };
        let msg2 = ClientMessage::Ping { timestamp: 2 };
        let enc1 = encode_client_msg(&msg1).unwrap();
        let enc2 = encode_client_msg(&msg2).unwrap();

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&enc1);
        buf.extend_from_slice(&enc2);

        let payload1 = try_decode_frame(&mut buf).unwrap().unwrap();
        let payload2 = try_decode_frame(&mut buf).unwrap().unwrap();
        match decode_client_msg(&payload1).unwrap() {
            ClientMessage::Ping { timestamp } => assert_eq!(timestamp, 1),
            _ => panic!("wrong variant"),
        }
        match decode_client_msg(&payload2).unwrap() {
            ClientMessage::Ping { timestamp } => assert_eq!(timestamp, 2),
            _ => panic!("wrong variant"),
        }
        assert!(buf.is_empty());
    }
}
