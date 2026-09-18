//! What travels inside a channel ciphertext, and what travels inside a
//! hand-off of past ones.
//!
//! Both are the sender's own JSON, never the server's: the relay sees the
//! bytes and nothing else. Both are written and read here rather than in each
//! client, because the two used to disagree — one wrote `"v": 1` where the
//! other wrote `"v": 2`, and neither read the field at all.

use ring::rand::{SecureRandom, SystemRandom};

/// Longest message id we will keep.
///
/// The id comes from the sender and lands in the receiver's encrypted archive,
/// so an unbounded one is ~60 KiB of somebody else's choosing written to disk
/// per message. 32 hex characters is what we mint; 64 leaves room for a client
/// that mints differently.
pub const MAX_MESSAGE_ID: usize = 64;

/// Longest destruction timer a message may carry: 30 days.
///
/// The number comes from the sender and decides when a message is deleted
/// everywhere, so it is bounded on the way in like the id is. The bound keeps a
/// claimed timer from being a date nobody will live to see; the rest of the
/// protection is on the receiving side, which takes the shorter of what the
/// sender claims and what the channel itself says (`expiryFor`, chat-rules.ts).
pub const MAX_MESSAGE_TTL_SECS: u32 = 30 * 24 * 60 * 60;

/// A fresh message id: 16 random bytes, hex.
pub fn new_message_id() -> String {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).expect("RNG failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a sender puts inside the ciphertext, beside the text itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    /// Minted by the sender, so every copy of one message agrees what it is.
    pub id: Option<String>,
    pub text: String,
    /// Seconds this message is meant to live, counted from its own timestamp.
    /// `None` is a message with no timer at all.
    ///
    /// It travels in here, inside the end-to-end envelope, because a timer the
    /// relay could edit would be no timer: the point of it is that every copy
    /// of a message dies at the same moment, and the copies live in other
    /// people's archives.
    pub ttl_secs: Option<u32>,
}

/// Pack a message for sending.
///
/// A channel message used to be raw UTF-8 inside the sender-key ciphertext, and
/// a direct message still was until this release. It is a small JSON object so
/// that it can carry what the server never sees: the id, so that the sender's
/// own echo and every receiver's copy are recognised as one message, and the
/// destruction timer, so that all of them delete it at the same moment.
pub fn envelope(id: &str, text: &str, ttl_secs: Option<u32>) -> Vec<u8> {
    let mut obj = serde_json::json!({ "v": 2, "id": id, "text": text });
    if let Some(ttl) = ttl_secs.filter(|t| *t > 0) {
        obj["ttl"] = serde_json::json!(ttl.min(MAX_MESSAGE_TTL_SECS));
    }
    obj.to_string().into_bytes()
}

/// Unpack a received message.
///
/// Anything that is not one of our envelopes is taken as the text itself —
/// that is a sender from before v9, or a direct message from before the
/// envelope covered those, and losing their message would be worse than having
/// no id for it.
pub fn open_envelope(plaintext: &[u8]) -> Message {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(plaintext) {
        if let Some(serde_json::Value::String(text)) = map.get("text") {
            let id = match map.get("id") {
                Some(serde_json::Value::String(id)) if !id.is_empty() => {
                    Some(id.chars().take(MAX_MESSAGE_ID).collect())
                }
                _ => None,
            };
            // Bounded here, where it enters: what a sender claims decides when
            // this message is deleted, and the receiver then takes the shorter
            // of this and whatever the channel itself says.
            let ttl_secs = map
                .get("ttl")
                .and_then(|v| v.as_u64())
                .filter(|t| *t > 0)
                .map(|t| t.min(MAX_MESSAGE_TTL_SECS as u64) as u32);
            return Message { id, text: text.clone(), ttl_secs };
        }
    }
    Message {
        id: None,
        text: String::from_utf8_lossy(plaintext).into_owned(),
        ttl_secs: None,
    }
}

/// Pack a channel's recent chat for one member who asked for it.
///
/// The channel travels inside the ciphertext. Everything else already works
/// this way — a message and a sender key both name their channel under the
/// AEAD and are checked against what the server claims — and history was the
/// one path that did not, so a relay could hand Bob the history of a private
/// channel relabelled as a public one he is in, watch him merge it, archive
/// it, and offer it onward.
pub fn history_payload(channel_id: u32, messages: &serde_json::Value) -> Vec<u8> {
    serde_json::json!({ "v": 3, "channel": channel_id, "messages": messages })
        .to_string()
        .into_bytes()
}

/// Unpack a hand-off, refusing one that names a different channel than the
/// server said it arrived in.
pub fn open_history_payload(
    channel_id: u32,
    payload: &[u8],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let serde_json::Value::Object(map) = serde_json::from_slice(payload)? else {
        anyhow::bail!("history payload is not an object");
    };
    match map.get("channel").and_then(|v| v.as_u64()) {
        Some(claimed) if claimed == channel_id as u64 => {}
        // Written by a client that predates the binding. There is no such
        // client in the wild — a server refuses a build that is not its own —
        // so this is refused rather than trusted.
        _ => anyhow::bail!("history is for a different channel than it arrived in"),
    }
    match map.get("messages") {
        Some(serde_json::Value::Array(list)) => Ok(list.clone()),
        _ => anyhow::bail!("history payload has no messages"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_carries_its_id_and_survives_a_sender_that_sends_none() {
        let m = open_envelope(&envelope("abc", "hello", None));
        assert_eq!(m.id.as_deref(), Some("abc"));
        assert_eq!(m.text, "hello");
        assert_eq!(m.ttl_secs, None);
        let m = open_envelope(b"plain text from before v9");
        assert_eq!(m.id, None);
        assert_eq!(m.text, "plain text from before v9");
        assert_eq!(m.ttl_secs, None);
    }

    #[test]
    fn a_destruction_timer_travels_inside_the_envelope() {
        let m = open_envelope(&envelope("abc", "gone in an hour", Some(3600)));
        assert_eq!(m.ttl_secs, Some(3600));
        // A timer of zero is no timer, not a message that dies on arrival.
        assert_eq!(open_envelope(&envelope("abc", "hi", Some(0))).ttl_secs, None);
        // One longer than we will keep is cut down where it enters, rather than
        // being written into somebody's archive as a date in the year 40000.
        let far = open_envelope(&envelope("abc", "hi", Some(u32::MAX)));
        assert_eq!(far.ttl_secs, Some(MAX_MESSAGE_TTL_SECS));
        // The same bound on a claim we did not write ourselves.
        let forged = br#"{"v":2,"id":"x","text":"hi","ttl":999999999999}"#;
        assert_eq!(open_envelope(forged).ttl_secs, Some(MAX_MESSAGE_TTL_SECS));
        // A v1 envelope has no timer and still reads.
        let v1 = br#"{"v":1,"id":"x","text":"old"}"#;
        assert_eq!(open_envelope(v1).text, "old");
        assert_eq!(open_envelope(v1).ttl_secs, None);
    }

    #[test]
    fn an_absurd_message_id_is_cut_down_before_it_reaches_the_archive() {
        let huge = "a".repeat(60_000);
        let m = open_envelope(&envelope(&huge, "hi", None));
        assert_eq!(m.id.unwrap().len(), MAX_MESSAGE_ID);
    }

    #[test]
    fn history_relabelled_to_another_channel_is_refused() {
        let messages = serde_json::json!([{ "content": "secret" }]);
        let packed = history_payload(7, &messages);
        assert_eq!(open_history_payload(7, &packed).unwrap().len(), 1);
        assert!(
            open_history_payload(8, &packed).is_err(),
            "the server naming a different channel must not be believed"
        );
    }

    #[test]
    fn a_malformed_history_payload_is_an_error_not_a_panic() {
        assert!(open_history_payload(1, b"not json").is_err());
        assert!(open_history_payload(1, br#"{"channel":1}"#).is_err());
        assert!(open_history_payload(1, br#"{"channel":1,"messages":5}"#).is_err());
    }
}
