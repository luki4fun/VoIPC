//! The media edge pool's own wire (1.15). An edge is a relay process of its own, often on
//! another machine, that forwards a screen share's sealed frames to the viewers its core
//! relay placed on it, so a share with thousands of viewers does not cost the core a copy
//! each. It sees no names, channels or keys. Two links speak this wire:
//!
//! - the core and its edges, on the core's UDP port at `POOL_PATH`: the edge says
//!   `EdgeMsg`, the core `CoreMsg`;
//! - an app and an edge, at `VIEW_PATH`: the app shows `ViewerMsg::Hello` with the ticket
//!   the core sent it (`messages::ServerMessage::WatchAt`), the edge answers
//!   `EdgeViewMsg`. A ticket is `postcard(TicketBody) ‖ HMAC-SHA256 tag`, sealed with a
//!   key only that core and that edge hold.
//!
//! Frames are a big-endian u32 length and postcard, as on the control stream, at most
//! `MAX_POOL_FRAME`. A decoder here reads a frame whole: bytes left over are an error, so
//! a later layout fails the decode instead of passing for this one.
//!
//! The pool has its own version, `POOL_VERSION`, because a core and its edges are updated
//! by hand and apart: any change to these enums or to `TicketBody` bumps it and records
//! `tests/golden/pool-v<N>.json`. A bump of the client protocol (`codec::PROTOCOL_VERSION`)
//! does not, nor the other way round. Two things never move, so any version can tell any
//! other "wrong version": `EdgeMsg::Hello` is variant 0 with `pool_version` first, and
//! `CoreMsg::Refused` is variant 1 with `pool_version` first. Each is read on its own,
//! before the whole decode (`hello_version`, `refused_version`).

use serde::{Deserialize, Serialize};

use crate::codec::{frame, MAX_MSG_SIZE};
use crate::error::ProtocolError;
use crate::types::SessionId;

/// The pool wire this build speaks. A core admits only its own; an edge of another
/// version is told `CoreMsg::Refused` and its viewers stay on the core.
pub const POOL_VERSION: u32 = 1;

/// Where an edge links to its core, on the core's UDP port.
pub const POOL_PATH: &str = "/voipc-edge";
/// Where an app fetches a share from an edge.
pub const VIEW_PATH: &str = "/voipc-view";
/// The longest frame payload either link takes: the control stream's bound, so
/// `codec::try_decode_frame` splits pool frames too.
pub const MAX_POOL_FRAME: usize = 64 * 1024;
const _: () = assert!(MAX_POOL_FRAME == MAX_MSG_SIZE as usize);

/// The most certificate hashes an edge names: its current certificate and those it may
/// still present while it rotates.
pub const MAX_CERT_HASHES: usize = 4;
/// The longest ticket an app passes on. A sealed `TicketBody` is under 70 bytes; the rest
/// is room for a later pool version.
pub const MAX_TICKET_BYTES: usize = 256;
/// The HMAC-SHA256 tag behind a ticket's body.
pub const TICKET_TAG_BYTES: usize = 32;

/// An edge to its core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeMsg {
    /// The first frame on the link. Variant 0 with `pool_version` first, for ever.
    /// `proof`: HMAC of the edge's secret over this TLS session's exporter and `name`, so
    /// it is good for this connection only. `public_host:public_port` and `cert_hashes`
    /// are what viewers are sent to; the rest are the edge's limits.
    Hello {
        pool_version: u32,
        name: String,
        proof: [u8; 32],
        public_host: String,
        public_port: u16,
        cert_hashes: Vec<[u8; 32]>,
        max_viewers: u32,
        egress_mbit: u32,
        max_shares: u32,
        /// The edge's build (`codec::APP_VERSION`), for the admin's view and logs.
        version: String,
    },
    /// Feed me this share: a viewer placed here arrived. The core feeds only a share it
    /// placed a viewer on this edge for.
    Subscribe { share: SessionId },
    /// Its last viewer here left some seconds ago: stop the feed.
    Unsubscribe { share: SessionId },
    /// A viewer here joined or lost frames and needs a keyframe of this share.
    KeyframeWanted { share: SessionId },
    /// What the edge carries, every 2 s: viewers in all and per share, what it sent
    /// (kbit/s), frames its viewers' queues dropped, tickets it refused, its own processor
    /// seconds and memory.
    Load {
        viewers: u32,
        per_share: Vec<(SessionId, u32)>,
        egress_kbps: u64,
        frames_dropped: u64,
        tickets_refused: u32,
        cpu_secs: u64,
        rss_mib: u32,
    },
    /// The edge's certificate changed: the hashes to send viewers from now on, newest
    /// first, at most `MAX_CERT_HASHES`.
    CertRotated { cert_hashes: Vec<[u8; 32]> },
}

/// A core to an edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreMsg {
    /// The edge is linked. `link`: a random number, new on every link, that each ticket
    /// for this link carries; the edge refuses a ticket of another link, so neither an edge
    /// nor a core that restarted takes one from before. `core_ms`: the core's clock (ms
    /// since it started), which ticket expiry is counted on.
    Welcome { link: u64, core_ms: u64 },
    /// Not linked: the core speaks `pool_version`. Variant 1 with `pool_version` first,
    /// for ever.
    Refused { pool_version: u32, reason: String },
    /// End the viewer of this ticket slot, or refuse the ticket if it has not come yet.
    /// `core_ms`: the core's clock when it said so. The slot's ticket was made before then,
    /// so it is good until `core_ms` plus a ticket's life at most, and the edge remembers the
    /// slot as revoked until then: its own reading of the core's clock runs behind the
    /// core's by however long the `Welcome` took, so a time read on arrival falls short.
    Revoke { slot: u64, core_ms: u64 },
    /// The share ended at `core_ms` on the core's clock: end its viewers and refuse its
    /// tickets made by then. A ticket of the same sharer's next share, made after, is good.
    ShareEnded { share: SessionId, core_ms: u64 },
}

/// An app to an edge, the first frame on `VIEW_PATH`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViewerMsg {
    /// The ticket of `types::EdgeView`, as the core sent it.
    Hello { ticket: Vec<u8> },
}

/// An edge to an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeViewMsg {
    /// The ticket is good: the share's frames follow.
    Ready,
    /// The edge ends the link: `"revoked"`, `"share ended"`, `"core lost"`,
    /// `"edge stopping"` or `"ticket refused"`.
    Ended { reason: String },
}

/// What a ticket says, for the edge it was sealed for. On the wire it is
/// `postcard(body) ‖ HMAC-SHA256 tag` (`TICKET_TAG_BYTES`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketBody {
    /// `CoreMsg::Welcome.link` of the link it was minted on.
    pub link: u64,
    /// The sharer's session.
    pub share: SessionId,
    /// Numbered per link: good once, and what `CoreMsg::Revoke` names.
    pub slot: u64,
    /// On the core's clock (`CoreMsg::Welcome.core_ms`).
    pub expires_ms: u64,
}

fn framed<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = postcard::to_allocvec(msg)?;
    if payload.len() > MAX_POOL_FRAME {
        return Err(ProtocolError::MessageTooLarge(payload.len()));
    }
    Ok(frame(payload))
}

/// One value that takes all of `bytes`: a later layout with more after it is not this one.
fn whole<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ProtocolError> {
    let (value, rest) = postcard::take_from_bytes(bytes)?;
    if !rest.is_empty() {
        return Err(ProtocolError::Serialization(
            postcard::Error::DeserializeBadEncoding,
        ));
    }
    Ok(value)
}

/// `msg` behind its length, to write on the link.
pub fn encode_edge_msg(msg: &EdgeMsg) -> Result<Vec<u8>, ProtocolError> {
    framed(msg)
}

/// A frame's payload (no length prefix), whole.
pub fn decode_edge_msg(payload: &[u8]) -> Result<EdgeMsg, ProtocolError> {
    whole(payload)
}

pub fn encode_core_msg(msg: &CoreMsg) -> Result<Vec<u8>, ProtocolError> {
    framed(msg)
}

pub fn decode_core_msg(payload: &[u8]) -> Result<CoreMsg, ProtocolError> {
    whole(payload)
}

pub fn encode_viewer_msg(msg: &ViewerMsg) -> Result<Vec<u8>, ProtocolError> {
    framed(msg)
}

pub fn decode_viewer_msg(payload: &[u8]) -> Result<ViewerMsg, ProtocolError> {
    whole(payload)
}

pub fn encode_edge_view_msg(msg: &EdgeViewMsg) -> Result<Vec<u8>, ProtocolError> {
    framed(msg)
}

pub fn decode_edge_view_msg(payload: &[u8]) -> Result<EdgeViewMsg, ProtocolError> {
    whole(payload)
}

/// A ticket's body as it is sealed: postcard alone, no length, since the tag follows.
pub fn encode_ticket_body(body: &TicketBody) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(body)?)
}

/// A ticket's body, once its tag is cut off and checked.
pub fn decode_ticket_body(bytes: &[u8]) -> Result<TicketBody, ProtocolError> {
    whole(bytes)
}

/// The pool version a `Hello` asks for, read from its start alone, so an edge of any
/// version, whatever its later fields, is told `Refused` instead of being dropped
/// unanswered. `None`: not a `Hello`. The core reads this before the whole decode.
pub fn hello_version(payload: &[u8]) -> Option<u32> {
    #[derive(Deserialize)]
    enum Head {
        Hello { pool_version: u32 },
    }
    match postcard::take_from_bytes::<Head>(payload) {
        Ok((Head::Hello { pool_version }, _)) => Some(pool_version),
        Err(_) => None,
    }
}

/// The pool version a core's `Refused` speaks, read from its start alone. An edge reads
/// this on any core frame that does not decode whole, so a core of a later version that
/// refuses it is understood. `None`: not a `Refused`.
pub fn refused_version(payload: &[u8]) -> Option<u32> {
    #[derive(Deserialize)]
    enum Head {
        _Welcome,
        Refused { pool_version: u32 },
    }
    match postcard::take_from_bytes::<Head>(payload) {
        Ok((Head::Refused { pool_version }, _)) => Some(pool_version),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> EdgeMsg {
        EdgeMsg::Hello {
            pool_version: POOL_VERSION,
            name: "e1".into(),
            proof: [7; 32],
            public_host: "edge1.example.org".into(),
            public_port: 9987,
            cert_hashes: vec![[1; 32], [2; 32]],
            max_viewers: 1000,
            egress_mbit: 8000,
            max_shares: 16,
            version: "1.15.0".into(),
        }
    }

    #[test]
    fn every_pool_message_and_a_ticket_body_round_trip() {
        let edge = [
            hello(),
            EdgeMsg::Subscribe { share: 4 },
            EdgeMsg::Unsubscribe { share: 4 },
            EdgeMsg::KeyframeWanted { share: 4 },
            EdgeMsg::Load {
                viewers: 9,
                per_share: vec![(4, 5), (6, 4)],
                egress_kbps: u64::MAX,
                frames_dropped: 3,
                tickets_refused: 2,
                cpu_secs: 77,
                rss_mib: 300,
            },
            EdgeMsg::CertRotated {
                cert_hashes: vec![[3; 32]],
            },
        ];
        for msg in edge {
            let bytes = encode_edge_msg(&msg).unwrap();
            assert_eq!(decode_edge_msg(&bytes[4..]).unwrap(), msg);
        }
        let core = [
            CoreMsg::Welcome {
                link: u64::MAX,
                core_ms: 12,
            },
            CoreMsg::Refused {
                pool_version: 2,
                reason: "this relay speaks pool v2".into(),
            },
            CoreMsg::Revoke {
                slot: 5,
                core_ms: u64::MAX,
            },
            CoreMsg::ShareEnded {
                share: 4,
                core_ms: 9,
            },
        ];
        for msg in core {
            let bytes = encode_core_msg(&msg).unwrap();
            assert_eq!(decode_core_msg(&bytes[4..]).unwrap(), msg);
        }
        let viewer = ViewerMsg::Hello {
            ticket: vec![9; MAX_TICKET_BYTES],
        };
        let bytes = encode_viewer_msg(&viewer).unwrap();
        assert_eq!(decode_viewer_msg(&bytes[4..]).unwrap(), viewer);
        for msg in [
            EdgeViewMsg::Ready,
            EdgeViewMsg::Ended {
                reason: "revoked".into(),
            },
        ] {
            let bytes = encode_edge_view_msg(&msg).unwrap();
            assert_eq!(decode_edge_view_msg(&bytes[4..]).unwrap(), msg);
        }
        let body = TicketBody {
            link: u64::MAX,
            share: u32::MAX,
            slot: u64::MAX,
            expires_ms: u64::MAX,
        };
        let bytes = encode_ticket_body(&body).unwrap();
        assert_eq!(decode_ticket_body(&bytes).unwrap(), body);
        // The longest body sealed still leaves a ticket well under the bound
        assert!(bytes.len() + TICKET_TAG_BYTES <= 70, "{}", bytes.len());
    }

    #[test]
    fn a_frame_carries_its_length_and_too_long_a_one_is_refused() {
        let bytes = encode_edge_view_msg(&EdgeViewMsg::Ready).unwrap();
        assert_eq!(bytes, [0, 0, 0, 1, 0]);
        let long = ViewerMsg::Hello {
            ticket: vec![0; MAX_POOL_FRAME],
        };
        assert!(matches!(
            encode_viewer_msg(&long),
            Err(ProtocolError::MessageTooLarge(_))
        ));
    }

    #[test]
    fn bytes_past_the_end_fail_the_whole_decode() {
        let revoke = CoreMsg::Revoke {
            slot: 5,
            core_ms: 6,
        };
        let mut bytes = encode_core_msg(&revoke).unwrap()[4..].to_vec();
        assert!(decode_core_msg(&bytes).is_ok());
        bytes.push(0);
        assert!(decode_core_msg(&bytes).is_err());
        let mut body = encode_ticket_body(&TicketBody {
            link: 1,
            share: 2,
            slot: 3,
            expires_ms: 4,
        })
        .unwrap();
        body.push(0);
        assert!(decode_ticket_body(&body).is_err());
    }

    /// A later pool version, as far as this one can tell: its own fields after the version.
    #[derive(Serialize)]
    enum EdgeMsg2 {
        Hello {
            pool_version: u32,
            name: String,
            key: Vec<u8>,
        },
    }

    #[derive(Serialize)]
    enum CoreMsg2 {
        _Welcome,
        Refused {
            pool_version: u32,
            reason: String,
            retry_secs: u32,
        },
    }

    #[test]
    fn a_hello_of_a_later_pool_version_is_read_for_its_version_alone() {
        let payload = postcard::to_allocvec(&EdgeMsg2::Hello {
            pool_version: 2,
            name: "e1".into(),
            key: vec![9; 8],
        })
        .unwrap();
        assert!(decode_edge_msg(&payload).is_err());
        assert_eq!(hello_version(&payload), Some(2));

        let today = encode_edge_msg(&hello()).unwrap();
        assert_eq!(hello_version(&today[4..]), Some(POOL_VERSION));
        // Not a Hello, or not a message
        let subscribe = encode_edge_msg(&EdgeMsg::Subscribe { share: 1 }).unwrap();
        assert_eq!(hello_version(&subscribe[4..]), None);
        for junk in [&[][..], &[0], &[0, 0xff], &[0xff; 8]] {
            assert_eq!(hello_version(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn a_refusal_of_a_later_pool_version_is_read_for_its_version_alone() {
        let payload = postcard::to_allocvec(&CoreMsg2::Refused {
            pool_version: 2,
            reason: "x".into(),
            retry_secs: 60,
        })
        .unwrap();
        assert!(decode_core_msg(&payload).is_err());
        assert_eq!(refused_version(&payload), Some(2));

        let today = encode_core_msg(&CoreMsg::Refused {
            pool_version: POOL_VERSION,
            reason: String::new(),
        })
        .unwrap();
        assert_eq!(refused_version(&today[4..]), Some(POOL_VERSION));
        for other in [
            CoreMsg::Welcome {
                link: 1,
                core_ms: 2,
            },
            CoreMsg::Revoke {
                slot: 1,
                core_ms: 2,
            },
            CoreMsg::ShareEnded {
                share: 1,
                core_ms: 2,
            },
        ] {
            let bytes = encode_core_msg(&other).unwrap();
            assert_eq!(refused_version(&bytes[4..]), None, "{other:?}");
        }
        for junk in [&[][..], &[1], &[0xff; 8]] {
            assert_eq!(refused_version(junk), None, "{junk:?}");
        }
    }
}
