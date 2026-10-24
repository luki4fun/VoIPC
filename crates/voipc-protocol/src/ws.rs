//! RFC 6455 WebSocket framing, the part VoIPC speaks: binary messages for the
//! TCP fallback tunnel (`voipc-server/src/tunnel.rs` and the native client's
//! `transport.rs`) and text frames for the game SDK's loopback socket
//! (`client/src-tauri/src/sdk.rs`). Pure functions over bytes — the I/O, the
//! deadlines and the SHA-1 of the handshake stay with each caller.
//!
//! No extension is ever negotiated, so a frame with a reserved bit set is an
//! error: that is what a `permessage-deflate` frame, which browsers offer,
//! would look like.

use crate::error::ProtocolError;

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Appended to the client's key before hashing: `Sec-WebSocket-Accept` is
/// base64(SHA-1(key + GUID)) (RFC 6455 §1.3).
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// One frame as it was on the wire, payload unmasked.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

fn err(what: &'static str) -> ProtocolError {
    ProtocolError::WebSocket(what)
}

/// One frame from the front of `buf`, and how many bytes it used; `None`
/// while it is still incomplete.
///
/// `from_client` is the direction it travels: a client's frames must be
/// masked and a server's must not be (RFC 6455 §5.1). `max` bounds the
/// payload and is checked before the payload arrives, so a huge length claim
/// costs nothing.
pub fn parse_frame(
    buf: &[u8],
    from_client: bool,
    max: usize,
) -> Result<Option<(Frame, usize)>, ProtocolError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    let opcode = buf[0] & 0x0f;
    if buf[0] & 0x70 != 0 {
        return Err(err("reserved bits set, but no extension was negotiated"));
    }
    let masked = buf[1] & 0x80 != 0;
    if masked != from_client {
        return Err(err(if from_client {
            "unmasked client frame"
        } else {
            "masked server frame"
        }));
    }
    let (len, at) = match buf[1] & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as u64, 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            (
                u64::from_be_bytes(buf[2..10].try_into().expect("8 bytes")),
                10,
            )
        }
        n => (n as u64, 2),
    };
    // RFC 6455 §5.5: control frames are short and never fragmented
    if opcode & 0x8 != 0 && (len > 125 || !fin) {
        return Err(err("malformed control frame"));
    }
    if len > max as u64 {
        return Err(err("frame exceeds the size limit"));
    }
    let len = len as usize;
    let key_len = if masked { 4 } else { 0 };
    let end = at + key_len + len;
    if buf.len() < end {
        return Ok(None);
    }
    let mut payload = buf[at + key_len..end].to_vec();
    if masked {
        let key = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % 4];
        }
    }
    Ok(Some((
        Frame {
            fin,
            opcode,
            payload,
        },
        end,
    )))
}

/// Append one whole (FIN) frame whose payload is `parts`, back to back — so a
/// tag byte and the data it tags need no copy into one buffer first. A client
/// passes a fresh random `mask` for every frame; a server passes `None`.
pub fn encode_frame(out: &mut Vec<u8>, opcode: u8, parts: &[&[u8]], mask: Option<[u8; 4]>) {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    out.push(0x80 | opcode);
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            let mut i = 0;
            for part in parts {
                for b in *part {
                    out.push(b ^ key[i % 4]);
                    i += 1;
                }
            }
        }
        None => {
            for part in parts {
                out.extend_from_slice(part);
            }
        }
    }
}

/// What [`Decoder::next`] hands out: a whole data message, or a control frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Binary(Vec<u8>),
    Text(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

/// Bytes in, messages out. Continuation frames are joined — Chromium splits
/// large messages into several frames — and control frames come out between
/// them as they arrive.
///
/// Holds at most one incomplete frame plus whatever was fed last, and one
/// partial message of at most `max` bytes.
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the unparsed bytes in `buf` start.
    pos: usize,
    /// Opcode and data so far of a message whose FIN has not arrived.
    partial: Option<(u8, Vec<u8>)>,
    from_client: bool,
    max: usize,
}

impl Decoder {
    /// `from_client` as in [`parse_frame`]; `max` bounds every frame and every
    /// whole message.
    pub fn new(from_client: bool, max: usize) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            partial: None,
            from_client,
            max,
        }
    }

    /// The bytes just read. Messages come out of [`next`](Self::next).
    pub fn feed(&mut self, data: &[u8]) {
        // Once per read rather than once per frame: a read of video carries
        // a dozen frames, and draining after each moved the rest every time.
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next message, or `None` until more bytes are fed. An `Err` breaks
    /// the stream: the frame boundaries are lost, so nothing after it is read.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Message>, ProtocolError> {
        loop {
            let Some((frame, used)) =
                parse_frame(&self.buf[self.pos..], self.from_client, self.max)?
            else {
                return Ok(None);
            };
            self.pos += used;
            match (frame.opcode, self.partial.take()) {
                (OP_PING, partial) => {
                    self.partial = partial;
                    return Ok(Some(Message::Ping(frame.payload)));
                }
                (OP_PONG, partial) => {
                    self.partial = partial;
                    return Ok(Some(Message::Pong(frame.payload)));
                }
                (OP_CLOSE, _) => return Ok(Some(Message::Close)),
                (OP_TEXT | OP_BINARY, None) if frame.fin => {
                    return Ok(Some(whole(frame.opcode, frame.payload)))
                }
                (OP_TEXT | OP_BINARY, None) => self.partial = Some((frame.opcode, frame.payload)),
                (OP_CONTINUATION, Some((opcode, mut data))) => {
                    if data.len() + frame.payload.len() > self.max {
                        return Err(err("message exceeds the size limit"));
                    }
                    data.extend_from_slice(&frame.payload);
                    if frame.fin {
                        return Ok(Some(whole(opcode, data)));
                    }
                    self.partial = Some((opcode, data));
                }
                // A continuation with nothing to continue, a new message
                // before the last one ended, or an opcode RFC 6455 reserves
                _ => return Err(err("unexpected frame")),
            }
        }
    }
}

fn whole(opcode: u8, data: Vec<u8>) -> Message {
    if opcode == OP_TEXT {
        Message::Text(data)
    } else {
        Message::Binary(data)
    }
}

/// Where an HTTP head ends (just past its blank line), once it has arrived.
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The value of the header `name` (any case) in an HTTP head.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (n, value) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// What an upgrade request asked for, once it passed validation.
#[derive(Debug, PartialEq, Eq)]
pub struct Upgrade {
    pub path: String,
    pub key: String,
    pub origin: Option<String>,
}

/// Parse an HTTP/1.1 upgrade request head. `Err` is the status line to
/// answer with.
pub fn parse_upgrade(head: &str) -> Result<Upgrade, &'static str> {
    let Some(target) = head.lines().next().unwrap_or("").strip_prefix("GET ") else {
        return Err("405 Method Not Allowed");
    };
    let path = target.split(' ').next().unwrap_or("").to_string();
    let upgrade = header(head, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if !upgrade {
        return Err("400 Bad Request");
    }
    if header(head, "sec-websocket-version") != Some("13") {
        // RFC 6455 §4.2.2: the reply names the version we do speak
        return Err("426 Upgrade Required");
    }
    Ok(Upgrade {
        path,
        key: header(head, "sec-websocket-key")
            .filter(|k| !k.is_empty())
            .ok_or("400 Bad Request")?
            .to_string(),
        origin: header(head, "origin").map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];

    fn frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        encode_frame(&mut out, opcode, &[payload], mask);
        out
    }

    #[test]
    fn frames_round_trip_in_every_length_form() {
        for len in [0usize, 1, 125, 126, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            for (mask, from_client) in [(Some(KEY), true), (None, false)] {
                let bytes = frame(OP_BINARY, &payload, mask);
                let (parsed, used) = parse_frame(&bytes, from_client, 1 << 20).unwrap().unwrap();
                assert_eq!(used, bytes.len(), "len {len}");
                assert_eq!(
                    parsed,
                    Frame {
                        fin: true,
                        opcode: OP_BINARY,
                        payload: payload.clone()
                    }
                );
            }
        }
    }

    #[test]
    fn parts_are_one_payload() {
        let mut out = Vec::new();
        encode_frame(&mut out, OP_BINARY, &[&[0], b"control bytes"], Some(KEY));
        let (parsed, _) = parse_frame(&out, true, 1024).unwrap().unwrap();
        assert_eq!(parsed.payload, b"\0control bytes");
    }

    #[test]
    fn a_frame_is_none_until_all_of_it_arrived() {
        let bytes = frame(OP_BINARY, &[7; 300], Some(KEY));
        for cut in 0..bytes.len() {
            assert!(
                parse_frame(&bytes[..cut], true, 1024).unwrap().is_none(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn masking_must_match_the_direction() {
        // RFC 6455 §5.1: a client masks every frame, a server never does
        assert!(parse_frame(&frame(OP_BINARY, b"x", None), true, 1024).is_err());
        assert!(parse_frame(&frame(OP_BINARY, b"x", Some(KEY)), false, 1024).is_err());
    }

    #[test]
    fn reserved_bits_and_bad_control_frames_are_refused() {
        let mut compressed = frame(OP_BINARY, b"x", Some(KEY));
        compressed[0] |= 0x40; // RSV1, permessage-deflate
        assert!(parse_frame(&compressed, true, 1024).is_err());

        assert!(parse_frame(&frame(OP_PING, &[0; 126], Some(KEY)), true, 1024).is_err());
        let mut fragmented_ping = frame(OP_PING, b"x", Some(KEY));
        fragmented_ping[0] &= 0x7f;
        assert!(parse_frame(&fragmented_ping, true, 1024).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused_before_its_payload_arrives() {
        let header = &frame(OP_BINARY, &[0; 70_000], Some(KEY))[..14];
        assert!(parse_frame(header, true, 65_536).is_err());
    }

    #[test]
    fn the_decoder_joins_fragments_around_control_frames() {
        let mut first = frame(OP_BINARY, b"hello ", Some(KEY));
        first[0] &= 0x7f; // not FIN
        let mut wire = first;
        wire.extend(frame(OP_PING, b"p", Some(KEY)));
        wire.extend(frame(OP_CONTINUATION, b"world", Some(KEY)));
        wire.extend(frame(OP_CLOSE, &[], Some(KEY)));

        // Fed a byte at a time, so every split point is crossed
        let mut decoder = Decoder::new(true, 1024);
        let mut out = Vec::new();
        for b in wire {
            decoder.feed(&[b]);
            while let Some(m) = decoder.next().unwrap() {
                out.push(m);
            }
        }
        assert_eq!(
            out,
            [
                Message::Ping(b"p".to_vec()),
                Message::Binary(b"hello world".to_vec()),
                Message::Close
            ]
        );
    }

    #[test]
    fn the_decoder_bounds_the_whole_message_and_its_order() {
        // Two frames each under the cap, together over it
        let mut decoder = Decoder::new(true, 100);
        let mut first = frame(OP_BINARY, &[0; 60], Some(KEY));
        first[0] &= 0x7f;
        decoder.feed(&first);
        decoder.feed(&frame(OP_CONTINUATION, &[0; 60], Some(KEY)));
        assert!(decoder.next().is_err());

        // A continuation of nothing, and a new message inside an open one
        let mut decoder = Decoder::new(true, 100);
        decoder.feed(&frame(OP_CONTINUATION, b"x", Some(KEY)));
        assert!(decoder.next().is_err());
        let mut decoder = Decoder::new(true, 100);
        let mut open = frame(OP_BINARY, b"x", Some(KEY));
        open[0] &= 0x7f;
        decoder.feed(&open);
        decoder.feed(&frame(OP_BINARY, b"y", Some(KEY)));
        assert!(decoder.next().is_err());

        // Reserved opcodes
        let mut decoder = Decoder::new(true, 100);
        decoder.feed(&frame(0x3, b"x", Some(KEY)));
        assert!(decoder.next().is_err());
    }

    #[test]
    fn several_messages_in_one_read_come_out_in_order() {
        let mut wire = Vec::new();
        for i in 0..20u8 {
            wire.extend(frame(OP_BINARY, &[i; 50], None));
        }
        let mut decoder = Decoder::new(false, 1024);
        decoder.feed(&wire);
        for i in 0..20u8 {
            assert_eq!(decoder.next().unwrap(), Some(Message::Binary(vec![i; 50])));
        }
        assert_eq!(decoder.next().unwrap(), None);
    }

    const UPGRADE: &str = "GET /voipc HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Origin: https://example.org\r\nSec-WebSocket-Version: 13\r\n\r\n";

    #[test]
    fn an_upgrade_request_is_parsed_and_validated() {
        assert_eq!(
            parse_upgrade(UPGRADE),
            Ok(Upgrade {
                path: "/voipc".into(),
                key: "dGhlIHNhbXBsZSBub25jZQ==".into(),
                origin: Some("https://example.org".into()),
            })
        );
        let without = |name: &str| {
            UPGRADE
                .lines()
                .filter(|l| !l.to_ascii_lowercase().starts_with(name))
                .collect::<Vec<_>>()
                .join("\r\n")
        };
        assert_eq!(
            parse_upgrade(&UPGRADE.replacen("GET", "POST", 1)),
            Err("405 Method Not Allowed")
        );
        assert_eq!(parse_upgrade(&without("upgrade")), Err("400 Bad Request"));
        assert_eq!(
            parse_upgrade(&without("sec-websocket-version")),
            Err("426 Upgrade Required")
        );
        assert_eq!(
            parse_upgrade(&without("sec-websocket-key")),
            Err("400 Bad Request")
        );
        assert_eq!(header(UPGRADE, "HOST"), Some("127.0.0.1"));
        assert_eq!(find_header_end(UPGRADE.as_bytes()), Some(UPGRADE.len()));
    }
}
