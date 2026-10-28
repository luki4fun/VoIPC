//! What travels inside a channel ciphertext, and what travels inside a
//! hand-off of past ones.
//!
//! Both are the sender's own JSON, never the server's: the relay sees the
//! bytes and nothing else. Both are written and read here rather than in each
//! client, because the two used to disagree — one wrote `"v": 1` where the
//! other wrote `"v": 2`, and neither read the field at all.

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::file::FileMeta;

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

/// The envelope version this build writes and reads. For 1.x: every envelope
/// keeps a human `text`; one with a `kind` this build does not know, or a
/// higher `v`, is shown as `NEWER_MESSAGE` and never acted on.
const ENVELOPE_V: u64 = 2;
/// The history hand-off version (`history_payload`).
const HISTORY_V: u64 = 3;

/// What a message from a newer VoIPC shows as.
pub const NEWER_MESSAGE: &str = "(a message from a newer VoIPC — update to see it)";

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
    /// A tombstone (`purge`): its writer deleted what they wrote in this
    /// conversation up to this moment (ms); readers drop their copies.
    pub purge_before: Option<u64>,
    /// What else the message points at.
    pub extras: Extras,
}

/// What a message may point at beside its text: the message it answers and
/// the thread it belongs to, both ids its readers already hold, and the file
/// it carries.
///
/// They ride as plain keys without a `kind`, so a reader from before 1.2
/// shows the text and nothing else. Only the id travels, never a quote of
/// the message answered: a quote would keep that text alive in every reply
/// after its own destruction timer had deleted it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extras {
    pub reply: Option<String>,
    pub thread: Option<String>,
    /// A file message's file; its text is then the caption (protocol 13).
    pub file: Option<FileRef>,
    /// Passed on from another conversation (protocol 13).
    pub fwd: Option<Forwarded>,
    /// Not a message but something done to one (protocol 13). An envelope
    /// with an event carries nothing else: no answer, thread, file or `fwd`.
    pub event: Option<ChatEvent>,
}

/// Longest name a forwarded message may say it came from, in characters.
pub const MAX_FWD_NAME: usize = 64;
/// Longest reaction, in UTF-8 bytes: one emoji, however many code points it
/// takes (a family of three with skin tones is 30). That it is one grapheme is
/// checked where it is drawn (`chat-rules.ts`), which has the segmenter.
pub const MAX_EMOJI_BYTES: usize = 32;
/// The largest moment a reader can hold exactly: JavaScript's safe integer.
const MAX_SAFE_MS: u64 = (1 << 53) - 1;

/// A message forwarded from another conversation: who wrote it there, and
/// when (ms). The forwarder's word for both, so it is a label and nothing
/// more: the message is the forwarder's own, and shown under their name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forwarded {
    pub name: String,
    pub at: u64,
}

impl Forwarded {
    /// A sender's claim, bounded: the name cleaned like a file's and cut to
    /// `MAX_FWD_NAME`, the moment one a reader can hold; else no label.
    pub fn checked(v: &serde_json::Value) -> Option<Forwarded> {
        let o = v.as_object()?;
        let at = o.get("at")?.as_u64().filter(|a| *a <= MAX_SAFE_MS)?;
        let name = clean(o.get("name")?.as_str()?, MAX_FWD_NAME);
        Some(Forwarded {
            name: if name.is_empty() {
                "someone".into()
            } else {
                name
            },
            at,
        })
    }
}

/// The kinds an event envelope may have (`ChatEvent`).
const EVENT_KINDS: [&str; 4] = ["edit", "delete", "react", "pin"];

/// What an event does to an earlier message of the same conversation, which
/// it names by id (`target`). Every reader on a protocol-13 relay knows these.
///
/// Who may do what is the reader's to check (`chat-rules.ts`), against who
/// sent the event: an edit or a delete only from the message's own writer, a
/// pin only from one of the channel's managers. An event carries the
/// conversation's destruction timer like a message does, so its copy in a
/// stored log never outlives what it points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ChatEvent {
    /// Its writer changed it: the envelope's `text` is the new text.
    Edit { target: String },
    /// Its writer took it back, for everyone.
    Delete { target: String },
    /// The sender put a reaction on it (`on`), or took theirs off.
    React {
        target: String,
        emoji: String,
        on: bool,
    },
    /// The sender pinned it in the channel (`on`), or unpinned it.
    Pin { target: String, on: bool },
}

impl ChatEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            ChatEvent::Edit { .. } => "edit",
            ChatEvent::Delete { .. } => "delete",
            ChatEvent::React { .. } => "react",
            ChatEvent::Pin { .. } => "pin",
        }
    }

    pub fn target(&self) -> &str {
        match self {
            ChatEvent::Edit { target }
            | ChatEvent::Delete { target }
            | ChatEvent::React { target, .. }
            | ChatEvent::Pin { target, .. } => target,
        }
    }

    /// An event from its keys, bounded where it enters: `kind`, the `target`
    /// cut like any id, a reaction's `emoji` (`MAX_EMOJI_BYTES`, nothing
    /// invisible or direction-turning) and `on`. None when any is missing or
    /// out of bounds. The same keys come from the front end (`{kind, target,
    /// emoji?, on?}`) and sit at the top of an event envelope.
    pub fn checked(o: &serde_json::Map<String, serde_json::Value>) -> Option<ChatEvent> {
        let target = bounded_id(o.get("target")?.as_str())?;
        let on = || o.get("on").and_then(|v| v.as_bool());
        Some(match o.get("kind")?.as_str()? {
            "edit" => ChatEvent::Edit { target },
            "delete" => ChatEvent::Delete { target },
            "react" => ChatEvent::React {
                target,
                emoji: checked_emoji(o.get("emoji")?.as_str()?)?,
                on: on()?,
            },
            "pin" => ChatEvent::Pin { target, on: on()? },
            _ => return None,
        })
    }
}

/// A reaction as it may be kept: one short run of visible characters.
fn checked_emoji(e: &str) -> Option<String> {
    let visible = e
        .chars()
        .all(|c| !c.is_control() && !c.is_whitespace() && !is_junk(c));
    (!e.is_empty() && e.len() <= MAX_EMOJI_BYTES && visible).then(|| e.to_string())
}

/// Longest file name kept, in characters.
pub const MAX_FILE_NAME: usize = 255;
/// Largest picture side a file message may claim, in pixels.
pub const MAX_FILE_SIDE: u32 = 16_384;
/// Longest playing time a file message may claim, in seconds: a week.
pub const MAX_FILE_DUR: u32 = 7 * 24 * 60 * 60;
/// The preview a picture's message carries: 16×16 RGB pixels, drawn as they
/// are, so no image decoder runs on anything before a click.
pub const PREVIEW_BYTES: usize = 16 * 16 * 3;
/// `PREVIEW_BYTES` as base64 (768 is a multiple of 3: no padding).
const PREVIEW_B64: usize = PREVIEW_BYTES / 3 * 4;
const MAX_MIME: usize = 127;

/// The file a message carries, all of it end to end: the relay sees only the
/// blob id, `hash`. The blob's part (`hash`, `key`, `size`, `z`) is
/// `FileMeta`'s, as text; the rest describes the file for its card. None of
/// it is believed for more than a card: the type that decides how a loaded
/// file is shown comes from its bytes (`file-sniff.ts`), never from `mime`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    pub hash: String,
    pub key: String,
    pub size: u64,
    pub z: bool,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<u32>,
    /// Seconds of audio or video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur: Option<u32>,
    /// `PREVIEW_BYTES` as base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub px: Option<String>,
}

impl std::fmt::Debug for FileRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRef")
            .field("hash", &self.hash)
            .field("size", &self.size)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl FileRef {
    /// A sender's claims, bounded where they enter: the blob's part as
    /// `FileMeta::from_parts` takes it, or no file at all; the name cut to
    /// `MAX_FILE_NAME` without control or direction-override characters; the
    /// rest dropped where it is out of bounds.
    pub fn checked(v: &serde_json::Value) -> Option<FileRef> {
        let o = v.as_object()?;
        let hash = o.get("hash")?.as_str()?;
        let key = o.get("key")?.as_str()?;
        let size = o.get("size")?.as_u64()?;
        let z = o.get("z")?.as_bool()?;
        FileMeta::from_parts(hash, key, size, z).ok()?;
        let name = o
            .get("name")
            .and_then(|n| n.as_str())
            .map(clean_name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "file".into());
        let mime = o
            .get("mime")
            .and_then(|m| m.as_str())
            .filter(|m| m.len() <= MAX_MIME && is_mime(m))
            .map(str::to_ascii_lowercase);
        let within = |k: &str, max: u32, least: u64| {
            o.get(k)
                .and_then(|n| n.as_u64())
                .filter(|n| (least..=max as u64).contains(n))
                .map(|n| n as u32)
        };
        let px = o
            .get("px")
            .and_then(|p| p.as_str())
            .filter(|p| {
                p.len() == PREVIEW_B64
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            })
            .map(String::from);
        Some(FileRef {
            hash: hash.into(),
            key: key.into(),
            size,
            z,
            name,
            mime,
            w: within("w", MAX_FILE_SIDE, 1),
            h: within("h", MAX_FILE_SIDE, 1),
            dur: within("dur", MAX_FILE_DUR, 0),
            px,
        })
    }
}

/// A file name as a card shows it: no control characters, none that turn
/// the text's direction (an `exe.jpg` that reads `gpj.exe`), no byte-order
/// mark (which JS's `trim` drops and Rust's does not), at most
/// `MAX_FILE_NAME` characters. Saving cleans it further, per system.
fn clean_name(name: &str) -> String {
    clean(name, MAX_FILE_NAME)
}

/// `clean_name`, at most `max` characters.
fn clean(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control() && !is_junk(*c))
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

/// The characters that turn the text's direction, and the byte-order mark.
fn is_junk(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// `type/subtype`, in the characters RFC 6838 allows.
fn is_mime(m: &str) -> bool {
    let token = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
    };
    matches!(m.split_once('/'), Some((a, b)) if token(a) && token(b))
}

/// What a tombstone shows where its kind is not known.
pub const PURGED: &str = "(earlier messages deleted by their writer)";

/// A tombstone, kept like a message and signed like one: everything its
/// writer wrote in this conversation up to `before` (ms) is to go from the
/// readers' copies too. A relay can withhold one, never forge one.
pub fn purge_envelope(id: &str, before: u64) -> Vec<u8> {
    serde_json::json!({ "v": 2, "id": id, "kind": "purge", "before": before, "text": PURGED })
        .to_string()
        .into_bytes()
}

/// Pack a message for sending.
///
/// A channel message used to be raw UTF-8 inside the sender-key ciphertext, and
/// a direct message still was until this release. It is a small JSON object so
/// that it can carry what the server never sees: the id, so that the sender's
/// own echo and every receiver's copy are recognised as one message, and the
/// destruction timer, so that all of them delete it at the same moment.
pub fn envelope(id: &str, text: &str, ttl_secs: Option<u32>) -> Vec<u8> {
    envelope_with(id, text, ttl_secs, &Extras::default())
}

/// `envelope`, plus what the message points at.
///
/// With an event (`extras.event`) it is that event's envelope instead: its
/// `kind` and keys, the text only for an edit (the new text), and nothing
/// else of `extras`.
pub fn envelope_with(id: &str, text: &str, ttl_secs: Option<u32>, extras: &Extras) -> Vec<u8> {
    let mut obj = serde_json::json!({ "v": 2, "id": id, "text": text });
    if let Some(ttl) = ttl_secs.filter(|t| *t > 0) {
        obj["ttl"] = serde_json::json!(ttl.min(MAX_MESSAGE_TTL_SECS));
    }
    if let Some(event) = &extras.event {
        obj["kind"] = serde_json::json!(event.kind());
        obj["target"] = serde_json::json!(event.target());
        match event {
            ChatEvent::Edit { .. } => {}
            ChatEvent::Delete { .. } => obj["text"] = serde_json::json!(""),
            ChatEvent::React { emoji, on, .. } => {
                obj["text"] = serde_json::json!("");
                obj["emoji"] = serde_json::json!(emoji);
                obj["on"] = serde_json::json!(on);
            }
            ChatEvent::Pin { on, .. } => {
                obj["text"] = serde_json::json!("");
                obj["on"] = serde_json::json!(on);
            }
        }
        return obj.to_string().into_bytes();
    }
    for (key, value) in [("reply", &extras.reply), ("thread", &extras.thread)] {
        if let Some(id) = bounded_id(value.as_deref()) {
            obj[key] = serde_json::json!(id);
        }
    }
    if let Some(file) = &extras.file {
        obj["file"] = serde_json::to_value(file).expect("a file serializes");
    }
    if let Some(fwd) = &extras.fwd {
        obj["fwd"] = serde_json::to_value(fwd).expect("a label serializes");
    }
    obj.to_string().into_bytes()
}

/// A claimed destruction timer, bounded where it enters: what a sender
/// claims decides when this message is deleted, and the receiver then takes
/// the shorter of this and whatever the conversation itself says.
fn bounded_ttl(map: &serde_json::Map<String, serde_json::Value>) -> Option<u32> {
    map.get("ttl")
        .and_then(|v| v.as_u64())
        .filter(|t| *t > 0)
        .map(|t| t.min(MAX_MESSAGE_TTL_SECS as u64) as u32)
}

/// A message id as we keep one: non-empty, at most `MAX_MESSAGE_ID` characters.
fn bounded_id(id: Option<&str>) -> Option<String> {
    id.filter(|i| !i.is_empty())
        .map(|i| i.chars().take(MAX_MESSAGE_ID).collect())
}

/// Unpack a received message.
///
/// Anything that is not one of our envelopes is taken as the text itself —
/// that is a sender from before v9, or a direct message from before the
/// envelope covered those, and losing their message would be worse than having
/// no id for it.
pub fn open_envelope(plaintext: &[u8]) -> Message {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(plaintext) {
        let id = || bounded_id(map.get("id").and_then(|v| v.as_str()));
        let newer = map
            .get("v")
            .and_then(|v| v.as_u64())
            .is_some_and(|v| v > ENVELOPE_V);
        let placeholder = || Message {
            id: id(),
            text: NEWER_MESSAGE.into(),
            ttl_secs: None,
            purge_before: None,
            extras: Extras::default(),
        };
        match map.get("kind").and_then(|k| k.as_str()) {
            Some("purge") if !newer => {
                if let Some(before) = map.get("before").and_then(|b| b.as_u64()) {
                    return Message {
                        id: id(),
                        text: PURGED.into(),
                        ttl_secs: None,
                        purge_before: Some(before),
                        extras: Extras::default(),
                    };
                }
            }
            // An event this build cannot read whole is never half done: it
            // shows as a message from a newer VoIPC, like a kind not known.
            Some(kind) if !newer && EVENT_KINDS.contains(&kind) => {
                let text = map.get("text").and_then(|t| t.as_str());
                return match ChatEvent::checked(&map) {
                    Some(event @ ChatEvent::Edit { .. }) if text.is_some() => Message {
                        id: id(),
                        text: text.unwrap_or_default().into(),
                        ttl_secs: bounded_ttl(&map),
                        purge_before: None,
                        extras: Extras {
                            event: Some(event),
                            ..Extras::default()
                        },
                    },
                    Some(ChatEvent::Edit { .. }) | None => placeholder(),
                    Some(event) => Message {
                        id: id(),
                        text: String::new(),
                        ttl_secs: bounded_ttl(&map),
                        purge_before: None,
                        extras: Extras {
                            event: Some(event),
                            ..Extras::default()
                        },
                    },
                };
            }
            None if !newer => {}
            _ => return placeholder(),
        }
        if let Some(serde_json::Value::String(text)) = map.get("text") {
            let id = id();
            let ttl_secs = bounded_ttl(&map);
            // Bounded like the message's own id: each lands in the receiver's
            // archive, and a reply to an id nobody holds is only shown as one
            // to a message that is not here.
            let extras = Extras {
                reply: bounded_id(map.get("reply").and_then(|v| v.as_str())),
                thread: bounded_id(map.get("thread").and_then(|v| v.as_str())),
                file: map.get("file").and_then(FileRef::checked),
                fwd: map.get("fwd").and_then(Forwarded::checked),
                event: None,
            };
            return Message {
                id,
                text: text.clone(),
                ttl_secs,
                purge_before: None,
                extras,
            };
        }
    }
    Message {
        id: None,
        text: String::from_utf8_lossy(plaintext).into_owned(),
        ttl_secs: None,
        purge_before: None,
        extras: Extras::default(),
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
    if map
        .get("v")
        .and_then(|v| v.as_u64())
        .is_some_and(|v| v > HISTORY_V)
    {
        anyhow::bail!("history from a newer VoIPC");
    }
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

    /// H2-04: an envelope from a newer VoIPC never shows as raw JSON, and
    /// what it asks for (a `kind`) is never done.
    #[test]
    fn an_envelope_from_a_newer_voipc_is_a_placeholder() {
        let later = br#"{"v":3,"id":"abc","text":"hi","kind":"edit","target":"x"}"#;
        assert_eq!(
            open_envelope(later),
            Message {
                id: Some("abc".into()),
                text: NEWER_MESSAGE.into(),
                ttl_secs: None,
                purge_before: None,
                extras: Extras::default(),
            }
        );
        let tomb = open_envelope(&purge_envelope("t1", 1_700_000_000_000));
        assert_eq!(
            (tomb.purge_before, tomb.text.as_str()),
            (Some(1_700_000_000_000), PURGED)
        );
        let bad = br#"{"v":2,"id":"t2","kind":"purge","text":"x"}"#;
        assert_eq!(
            open_envelope(bad).purge_before,
            None,
            "a tombstone without its moment is not one"
        );
        let no_text = br#"{"v":9,"id":"abc","reaction":"+1"}"#;
        assert_eq!(open_envelope(no_text).text, NEWER_MESSAGE);
        assert_eq!(
            open_envelope(&envelope("i", "plain", None)).text,
            "plain",
            "today's still read"
        );
        assert!(open_history_payload(1, br#"{"v":4,"channel":1,"messages":[]}"#).is_err());
    }

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
    fn a_reply_and_its_thread_travel_as_ids_that_an_old_reader_ignores() {
        let extras = Extras {
            reply: Some("r1".into()),
            thread: Some("t1".into()),
            ..Extras::default()
        };
        let packed = envelope_with("m1", "agreed", Some(60), &extras);
        let m = open_envelope(&packed);
        assert_eq!((m.text.as_str(), m.ttl_secs), ("agreed", Some(60)));
        assert_eq!(m.extras, extras);

        // What 1.0 and 1.1 do with it: their reader takes `id`, `text` and
        // `ttl` and looks for a `kind`; there is none, so the text shows.
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&packed).unwrap();
        assert_eq!(map["v"], 2, "still the version an old reader accepts");
        assert!(
            !map.contains_key("kind"),
            "a kind would turn it into a placeholder"
        );

        // Empty ids are no ids, and a claimed one is cut down where it enters
        let none = open_envelope(&envelope_with("m2", "hi", None, &Extras::default()));
        assert_eq!(none.extras, Extras::default());
        let empty = br#"{"v":2,"id":"m3","text":"hi","reply":"","thread":7}"#;
        assert_eq!(open_envelope(empty).extras, Extras::default());
        let huge = format!(
            r#"{{"v":2,"id":"m4","text":"hi","reply":"{}"}}"#,
            "a".repeat(60_000)
        );
        assert_eq!(
            open_envelope(huge.as_bytes()).extras.reply.unwrap().len(),
            MAX_MESSAGE_ID
        );
        // A newer kind still never carries what it points at into the archive
        let later = br#"{"v":3,"id":"m5","text":"hi","reply":"r1"}"#;
        assert_eq!(open_envelope(later).extras, Extras::default());
    }

    fn a_file() -> FileRef {
        FileRef {
            hash: "a".repeat(64),
            key: "b".repeat(64),
            size: 1234,
            z: true,
            name: "notes.txt".into(),
            mime: Some("text/plain".into()),
            w: None,
            h: None,
            dur: None,
            px: None,
        }
    }

    #[test]
    fn a_file_travels_with_its_caption_and_without_a_kind() {
        let mut file = a_file();
        file.w = Some(640);
        file.h = Some(480);
        file.px = Some("A".repeat(1024));
        let extras = Extras {
            file: Some(file.clone()),
            ..Extras::default()
        };
        let packed = envelope_with("f1", "a caption", Some(60), &extras);
        let m = open_envelope(&packed);
        assert_eq!((m.text.as_str(), m.extras.file), ("a caption", Some(file)));
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&packed).unwrap();
        assert!(
            !map.contains_key("kind"),
            "every 1.3 reader knows the field"
        );
        assert!(
            !format!("{:?}", a_file()).contains(&"b".repeat(64)),
            "no key in logs"
        );
    }

    #[test]
    fn a_files_claims_are_bounded_where_they_enter() {
        let with = |file: serde_json::Value| {
            let packed = serde_json::json!({ "v": 2, "id": "x", "text": "", "file": file });
            open_envelope(packed.to_string().as_bytes()).extras.file
        };
        let good = serde_json::to_value(a_file()).unwrap();
        // The blob's part is FileMeta's or there is no file
        for (k, bad) in [
            ("hash", serde_json::json!("A".repeat(64))),
            ("key", serde_json::json!("b")),
            ("size", serde_json::json!(64 * 1024 * 1024 + 1)),
            ("z", serde_json::json!(1)),
        ] {
            let mut f = good.clone();
            f[k] = bad;
            assert_eq!(with(f), None, "{k}");
        }
        // The rest is cut or dropped, and the file stays
        let mut f = good.clone();
        f["name"] = serde_json::json!(format!("\u{202e}gpj.exe\n{}", "x".repeat(300)));
        f["mime"] = serde_json::json!("text/html; charset=x");
        f["w"] = serde_json::json!(16_385);
        f["h"] = serde_json::json!(0);
        f["dur"] = serde_json::json!(-1);
        f["px"] = serde_json::json!("A".repeat(1023));
        let got = with(f).unwrap();
        assert_eq!(got.name.chars().count(), MAX_FILE_NAME);
        assert!(got.name.starts_with("gpj.exex"));
        assert_eq!(
            (got.mime, got.w, got.h, got.dur, got.px),
            (None, None, None, None, None)
        );
        let mut f = good.clone();
        f["name"] = serde_json::json!(" \u{7} ");
        f["mime"] = serde_json::json!("Image/PNG");
        assert_eq!(
            with(f).map(|f| (f.name, f.mime)),
            Some(("file".into(), Some("image/png".into())))
        );
    }

    fn with_event(event: ChatEvent) -> Extras {
        Extras {
            event: Some(event),
            ..Extras::default()
        }
    }

    /// Edit, delete, react and pin are kinds every 1.3 reader acts on, each
    /// carrying the conversation's timer and nothing a message carries.
    #[test]
    fn an_event_travels_as_its_kind_with_the_conversations_timer() {
        let react = ChatEvent::React {
            target: "m1".into(),
            emoji: "👍🏽".into(),
            on: true,
        };
        for (event, text) in [
            (
                ChatEvent::Edit {
                    target: "m1".into(),
                },
                "fixed typo",
            ),
            (
                ChatEvent::Delete {
                    target: "m1".into(),
                },
                "",
            ),
            (react.clone(), ""),
            (
                ChatEvent::Pin {
                    target: "m1".into(),
                    on: false,
                },
                "",
            ),
        ] {
            let kind = event.kind();
            // A sender's extras beside the event never ride along
            let mut extras = with_event(event.clone());
            extras.reply = Some("r1".into());
            extras.fwd = Some(Forwarded {
                name: "ann".into(),
                at: 5,
            });
            let packed = envelope_with("e1", "fixed typo", Some(60), &extras);
            let map: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&packed).unwrap();
            assert_eq!(
                (map["kind"].as_str(), map["v"].as_u64()),
                (Some(kind), Some(2))
            );
            assert!(
                !map.contains_key("reply") && !map.contains_key("fwd"),
                "{kind}"
            );
            let m = open_envelope(&packed);
            assert_eq!(m.id.as_deref(), Some("e1"));
            assert_eq!(m.text, text, "{kind}: only an edit has a text");
            assert_eq!(m.ttl_secs, Some(60), "{kind}: the conversation's timer");
            assert_eq!(m.extras, with_event(event), "{kind}");
        }
    }

    #[test]
    fn an_events_claims_are_bounded_where_they_enter() {
        let open = |v: serde_json::Value| open_envelope(v.to_string().as_bytes());
        let ok = |v: serde_json::Value| open(v).extras.event;
        // The target is cut like any id, and needed
        let long = ok(
            serde_json::json!({"v":2,"id":"e","kind":"delete","target":"a".repeat(500),"text":""}),
        );
        assert_eq!(long.unwrap().target().len(), MAX_MESSAGE_ID);
        // Anything missing or out of bounds is not half done: a placeholder
        for bad in [
            serde_json::json!({"v":2,"id":"e","kind":"delete","text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"delete","target":"","text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"edit","target":"m"}),
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"👍","text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"","on":true,"text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"x".repeat(33),"on":true,"text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"a b","on":true,"text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"\u{202e}x","on":true,"text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"\n","on":true,"text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"pin","target":"m","on":"yes","text":""}),
            serde_json::json!({"v":2,"id":"e","kind":"pin","target":7,"on":true,"text":""}),
        ] {
            let m = open(bad.clone());
            assert_eq!(
                (m.text.as_str(), m.extras.event),
                (NEWER_MESSAGE, None),
                "{bad}"
            );
        }
        // 32 bytes is the most: one emoji with its modifiers fits
        let family = "👩🏽‍👩🏽‍👧🏽"; // 31 bytes
        assert!(family.len() <= MAX_EMOJI_BYTES);
        assert!(ok(serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":family,"on":true,"text":""})).is_some());
        // A react's text is not shown, whatever it says
        let m = open(
            serde_json::json!({"v":2,"id":"e","kind":"react","target":"m","emoji":"🔥","on":false,"text":"spam"}),
        );
        assert_eq!(m.text, "");
        // The front end's own shape is the same keys
        let mine = serde_json::json!({"kind":"pin","target":"m","on":true});
        assert_eq!(
            ChatEvent::checked(mine.as_object().unwrap()),
            Some(ChatEvent::Pin {
                target: "m".into(),
                on: true
            })
        );
        assert_eq!(
            serde_json::to_value(ChatEvent::checked(mine.as_object().unwrap()).unwrap()).unwrap(),
            mine,
            "what a reader gets back is what was sent"
        );
    }

    #[test]
    fn a_forwarded_message_carries_its_label_bounded() {
        let fwd = Forwarded {
            name: "ann#0001".into(),
            at: 1_700_000_000_000,
        };
        let extras = Extras {
            fwd: Some(fwd.clone()),
            file: Some(a_file()),
            ..Extras::default()
        };
        let m = open_envelope(&envelope_with("f1", "look", None, &extras));
        assert_eq!((m.extras.fwd, m.extras.file), (Some(fwd), Some(a_file())));
        let with = |fwd: serde_json::Value| {
            let packed = serde_json::json!({ "v": 2, "id": "x", "text": "t", "fwd": fwd });
            open_envelope(packed.to_string().as_bytes()).extras.fwd
        };
        let cut =
            with(serde_json::json!({"name": format!("\u{202e}{}", "n".repeat(100)), "at": 1}))
                .unwrap();
        assert_eq!(cut.name.chars().count(), MAX_FWD_NAME);
        assert_eq!(
            with(serde_json::json!({"name": " ", "at": 1}))
                .unwrap()
                .name,
            "someone"
        );
        assert_eq!(
            with(serde_json::json!({"name": "a", "at": 1u64 << 53})),
            None
        );
        assert_eq!(with(serde_json::json!({"name": "a", "at": -1})), None);
        assert_eq!(with(serde_json::json!({"at": 1})), None);
        assert_eq!(with(serde_json::json!("ann")), None);
        // The message stays, without its label
        assert_eq!(
            open_envelope(br#"{"v":2,"id":"x","text":"t","fwd":7}"#).text,
            "t"
        );
    }

    #[test]
    fn a_destruction_timer_travels_inside_the_envelope() {
        let m = open_envelope(&envelope("abc", "gone in an hour", Some(3600)));
        assert_eq!(m.ttl_secs, Some(3600));
        // A timer of zero is no timer, not a message that dies on arrival.
        assert_eq!(
            open_envelope(&envelope("abc", "hi", Some(0))).ttl_secs,
            None
        );
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
