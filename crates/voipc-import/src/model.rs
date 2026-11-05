//! What is read of Discord's answers, and no more. Every field has a default, and a
//! field missing or null reads as that: the fixture mirrors the docs and not Discord, so
//! the shape is the thing most likely to surprise. Message text and names of people have
//! no `Debug` here, so that nobody can print one by accident.

use std::collections::HashMap;

use serde::de::{DeserializeOwned, Deserializer, IgnoredAny};
use serde::Deserialize;
use serde_json::Value;

pub const TEXT: u8 = 0;
pub const VOICE: u8 = 2;
pub const CATEGORY: u8 = 4;
pub const ANNOUNCEMENT: u8 = 5;
pub const ANNOUNCEMENT_THREAD: u8 = 10;
pub const PUBLIC_THREAD: u8 = 11;
pub const PRIVATE_THREAD: u8 = 12;
pub const STAGE: u8 = 13;
pub const FORUM: u8 = 15;
pub const MEDIA: u8 = 16;

/// What `flags` of `/applications/@me` says about the two privileged intents: one bit
/// for an app approved, one for an app that has it toggled on.
const FLAG_MEMBERS: u64 = (1 << 14) | (1 << 15);
const FLAG_CONTENT: u64 = (1 << 18) | (1 << 19);
/// `flags` of a message whose embeds are not sent, so one with nothing else reads as empty.
pub const SUPPRESS_EMBEDS: u64 = 1 << 2;

/// One of Discord's answers. The reason is fixed words: serde's own can quote the text.
pub fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, &'static str> {
    let mut value: Value = serde_json::from_slice(body).map_err(|_| "not JSON")?;
    drop_nulls(&mut value);
    serde_json::from_value(value).map_err(|_| "not the shape expected")
}

/// So that `#[serde(default)]` catches null too. Parsing stops at 128 levels, so this
/// cannot run out of stack.
fn drop_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(drop_nulls);
        }
        Value::Array(list) => list.iter_mut().for_each(drop_nulls),
        _ => {}
    }
}

/// A decimal string in Discord's JSON; a number is taken too. Anything else reads as 0,
/// which no real id is.
fn number(value: &Value) -> u64 {
    match value {
        Value::String(s) => s.parse().unwrap_or(0),
        Value::Number(n) => n.as_u64().unwrap_or(0),
        _ => 0,
    }
}

fn snowflake<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Value::deserialize(d).map(|v| number(&v))
}

fn snowflake_or_none<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Value::deserialize(d).map(|v| Some(number(&v)).filter(|id| *id != 0))
}

fn snowflakes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
    let list: Vec<Value> = Deserialize::deserialize(d)?;
    Ok(list.iter().map(number).filter(|id| *id != 0).collect())
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct User {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub username: String,
    pub global_name: Option<String>,
    pub bot: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Application {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub name: String,
    pub flags: u64,
}

impl Application {
    pub fn member_intent(&self) -> bool {
        self.flags & FLAG_MEMBERS != 0
    }

    pub fn content_intent(&self) -> bool {
        self.flags & FLAG_CONTENT != 0
    }
}

/// A row of `/users/@me/guilds`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GuildBrief {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub name: String,
    #[serde(deserialize_with = "snowflake")]
    pub permissions: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Guild {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub name: String,
    #[serde(deserialize_with = "snowflake")]
    pub owner_id: u64,
    pub mfa_level: u8,
    #[serde(deserialize_with = "snowflake_or_none")]
    pub rules_channel_id: Option<u64>,
    #[serde(deserialize_with = "snowflake_or_none")]
    pub system_channel_id: Option<u64>,
    pub approximate_member_count: u64,
    pub approximate_presence_count: u64,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Member {
    pub user: Option<User>,
    pub nick: Option<String>,
    #[serde(deserialize_with = "snowflakes")]
    pub roles: Vec<u64>,
    pub joined_at: Option<String>,
    pub pending: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RoleColors {
    pub primary_color: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Role {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub name: String,
    /// Deprecated for `colors`, and still what an older answer has.
    pub color: u32,
    pub colors: RoleColors,
    pub hoist: bool,
    pub position: u32,
    /// A decimal string, as an id is.
    #[serde(deserialize_with = "snowflake")]
    pub permissions: u64,
    pub managed: bool,
}

/// `/roles/member-counts`: role id to members. Leaves out @everyone.
pub fn role_counts(raw: HashMap<String, u64>) -> HashMap<u64, u64> {
    raw.into_iter()
        .filter_map(|(id, n)| Some((id.parse().ok()?, n)))
        .collect()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Overwrite {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    /// 0 a role, 1 a member.
    #[serde(rename = "type")]
    pub kind: u8,
    #[serde(deserialize_with = "snowflake")]
    pub allow: u64,
    #[serde(deserialize_with = "snowflake")]
    pub deny: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ThreadMeta {
    pub archived: bool,
    pub archive_timestamp: String,
}

/// A channel or a thread.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Channel {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: u8,
    pub name: String,
    pub topic: String,
    pub position: i64,
    #[serde(deserialize_with = "snowflake_or_none")]
    pub parent_id: Option<u64>,
    pub nsfw: bool,
    pub user_limit: u32,
    pub rate_limit_per_user: u32,
    /// May point at nothing, per the docs: it only ever says there is nothing new.
    #[serde(deserialize_with = "snowflake_or_none")]
    pub last_message_id: Option<u64>,
    pub permission_overwrites: Vec<Overwrite>,
    /// A thread's: who started it.
    #[serde(deserialize_with = "snowflake_or_none")]
    pub owner_id: Option<u64>,
    pub message_count: u32,
    pub thread_metadata: Option<ThreadMeta>,
}

impl Channel {
    pub fn is_voice(&self) -> bool {
        matches!(self.kind, VOICE | STAGE)
    }

    /// Its posts are threads: it holds no message of its own.
    pub fn is_forum(&self) -> bool {
        matches!(self.kind, FORUM | MEDIA)
    }

    /// Becomes a channel here. A directory, a thread or a kind that is new to this code
    /// does not.
    pub fn comes_over(&self) -> bool {
        matches!(
            self.kind,
            TEXT | VOICE | ANNOUNCEMENT | STAGE | FORUM | MEDIA
        )
    }

    /// Public threads may hang off it.
    pub fn has_threads(&self) -> bool {
        matches!(self.kind, TEXT | ANNOUNCEMENT | FORUM | MEDIA)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ThreadList {
    pub threads: Vec<Channel>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Emoji {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub name: String,
    pub animated: bool,
    /// False once a server lost the boost that paid for it. The docs make it optional.
    pub available: Option<bool>,
    #[serde(deserialize_with = "snowflakes")]
    pub roles: Vec<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Sticker {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub name: String,
    pub format_type: u8,
}

/// The name and the reason stay on the importer's screen.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Ban {
    pub user: User,
    pub reason: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Embed {
    pub title: String,
    pub description: String,
}

/// No URL: a signed one runs out, and nothing here ever fetches a member's file.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Attachment {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    pub filename: String,
    pub size: u64,
    pub content_type: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct StickerItem {
    pub name: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct ReactionEmoji {
    #[serde(deserialize_with = "snowflake_or_none")]
    pub id: Option<u64>,
    pub name: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Reaction {
    pub count: u32,
    pub emoji: ReactionEmoji,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct MessageReference {
    #[serde(deserialize_with = "snowflake_or_none")]
    pub message_id: Option<u64>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub message: SnapshotMessage,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct SnapshotMessage {
    pub content: String,
    pub mentions: Vec<User>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct PollText {
    pub text: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Poll {
    pub question: PollText,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct Message {
    #[serde(deserialize_with = "snowflake")]
    pub id: u64,
    /// The docs: unset reads as 0.
    #[serde(rename = "type")]
    pub kind: u8,
    pub author: User,
    #[serde(deserialize_with = "snowflake_or_none")]
    pub webhook_id: Option<u64>,
    pub content: String,
    pub pinned: bool,
    pub mentions: Vec<User>,
    pub embeds: Vec<Embed>,
    pub attachments: Vec<Attachment>,
    pub sticker_items: Vec<StickerItem>,
    pub reactions: Vec<Reaction>,
    pub message_reference: Option<MessageReference>,
    pub message_snapshots: Vec<Snapshot>,
    pub poll: Option<Poll>,
    pub components: Vec<IgnoredAny>,
    /// A Rich Presence invite, which needs no text of its own.
    pub activity: Option<IgnoredAny>,
    pub flags: u64,
}

/// `/messages/search`: a count for the dry-run, and only that is kept of it.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Search {
    pub total_results: Option<u64>,
    pub retry_after: f64,
}

/// A day counted from 1970-01-01, by the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if month <= 2 { 1 } else { 0 }, month, day)
}

/// `2015-04-26T06:26:56.936000+00:00` in Unix seconds. None: not that shape.
pub fn unix_of(iso: &str) -> Option<i64> {
    fn num(s: &str) -> Option<i64> {
        s.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| s.parse().ok())
            .flatten()
    }
    let date = iso.get(..10)?;
    let time = iso.get(11..19)?;
    if !matches!(iso.as_bytes().get(10), Some(b'T' | b' ')) {
        return None;
    }
    let (year, month, day) = (
        num(date.get(..4)?)?,
        num(date.get(5..7)?)?,
        num(date.get(8..10)?)?,
    );
    let (hour, minute, second) = (
        num(time.get(..2)?)?,
        num(time.get(3..5)?)?,
        num(time.get(6..8)?)?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let rest = iso.get(19..)?;
    let rest = match rest.strip_prefix('.') {
        Some(frac) => frac.trim_start_matches(|c: char| c.is_ascii_digit()),
        None => rest,
    };
    let offset = match rest.as_bytes().first() {
        None | Some(b'Z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let secs = num(rest.get(1..3)?)? * 3600 + num(rest.get(4..6)?)? * 60;
            if *sign == b'+' {
                secs
            } else {
                -secs
            }
        }
        _ => return None,
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// The latest second that still has a four-digit year.
const LAST_SECOND: i64 = 253_402_300_799;

/// Unix seconds as `2021-04-20T21:20:30Z`. None: out of what that can say.
pub fn iso_of(secs: i64) -> Option<String> {
    if !(0..=LAST_SECOND).contains(&secs) {
        return None;
    }
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_reads_as_the_default() {
        let c: Channel = parse(
            br#"{"id":"123","type":0,"topic":null,"parent_id":null,"last_message_id":null,
                 "permission_overwrites":null,"name":"x","user_limit":null}"#,
        )
        .unwrap();
        assert_eq!(c.id, 123);
        assert_eq!(c.topic, "");
        assert_eq!(c.parent_id, None);
        assert_eq!(c.last_message_id, None);
        assert!(c.permission_overwrites.is_empty());
    }

    #[test]
    fn ids_and_bits_come_as_strings_and_stay_whole() {
        let r: Role =
            parse(br#"{"id":"1454987148113234751","permissions":"2251799813685247"}"#).unwrap();
        assert_eq!(r.id, 1_454_987_148_113_234_751);
        assert_eq!(r.permissions, 2_251_799_813_685_247);
        // Past 2^53, so a float along the way would have changed it
        assert_ne!(r.id, (r.id as f64) as u64 + 1);
    }

    #[test]
    fn an_answer_it_cannot_read_says_nothing_of_itself() {
        let err = parse::<Channel>(br#"{"id":"1","name":{"secret":"words"}}"#).err();
        assert_eq!(err, Some("not the shape expected"));
        assert_eq!(parse::<Channel>(b"<html>secret").err(), Some("not JSON"));
    }

    #[test]
    fn dates_go_there_and_back() {
        assert_eq!(unix_of("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(
            unix_of("2021-04-20T21:20:30.123456+00:00"),
            Some(1_618_953_630)
        );
        assert_eq!(unix_of("2021-04-20T23:20:30+02:00"), Some(1_618_953_630));
        assert_eq!(unix_of("2021-04-20T21:20:30Z"), Some(1_618_953_630));
        assert_eq!(iso_of(1_618_953_630).unwrap(), "2021-04-20T21:20:30Z");
        assert_eq!(iso_of(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(iso_of(951_782_400).unwrap(), "2000-02-29T00:00:00Z");
        assert_eq!(iso_of(LAST_SECOND).unwrap(), "9999-12-31T23:59:59Z");
        assert_eq!(iso_of(LAST_SECOND + 1), None);
        assert_eq!(iso_of(-1), None);
        for bad in [
            "",
            "yesterday",
            "2021-13-01T00:00:00Z",
            "2021-04-20X21:20:30Z",
        ] {
            assert_eq!(unix_of(bad), None, "{bad}");
        }
    }
}
