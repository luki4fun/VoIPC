//! One channel list. It goes in one message to everyone at every connect, and one that
//! does not fit is not sent: everybody would arrive at a server with no channels. Discord's
//! 500 channels at the longest name fit once topics give way, so topics do, and the
//! relay still refuses whatever would not fit.

use std::collections::HashMap;

use crate::names::clip_bytes;

/// What a row takes beside its name and topic, at the most an imported one needs. A test
/// holds this to the real encoding.
pub const ROW_BYTES: usize = 52;
/// Kept free: names on the relay change, and people join.
pub const RESERVE: usize = 2 * 1024;
/// A description's limit (`validate_entries`).
pub const TOPIC_BYTES: usize = 256;

#[derive(Debug, Clone)]
pub struct FitRow {
    pub id: u64,
    pub name: String,
    pub topic: String,
    pub text: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fitted {
    /// What each channel that fits gets to say.
    pub topics: HashMap<u64, String>,
    /// How many lost some of theirs.
    pub clipped: u32,
    /// What cannot come at all, from the end, voice before text. Each is named in the
    /// report, and its messages are not walked.
    pub left_out: Vec<u64>,
}

/// How long the longest topic may be so that all of them come to at most `budget`: short
/// ones stay whole, long ones share what is left.
fn level(lengths: &mut [usize], budget: usize) -> usize {
    lengths.sort_unstable();
    let mut left = budget;
    let mut others = lengths.len();
    for len in lengths.iter() {
        if len * others > left {
            return left / others;
        }
        left -= len;
        others -= 1;
    }
    usize::MAX
}

/// `rows` in their final order. `list_bytes`: the relay's list as it stands now.
pub fn fit(rows: &[FitRow], list_bytes: usize, limit: usize) -> Fitted {
    let room = limit.saturating_sub(list_bytes + RESERVE);
    let mut kept: Vec<&FitRow> = rows.iter().collect();
    let mut left_out = Vec::new();
    let mut fixed: usize = kept.iter().map(|r| ROW_BYTES + r.name.len()).sum();
    while fixed > room {
        let last = kept
            .iter()
            .rposition(|r| !r.text)
            .or(kept.len().checked_sub(1));
        let Some(last) = last else { break };
        let row = kept.remove(last);
        fixed -= ROW_BYTES + row.name.len();
        left_out.push(row.id);
    }
    let budget = room.saturating_sub(fixed);
    let mut lengths: Vec<usize> = kept
        .iter()
        .map(|r| r.topic.len().min(TOPIC_BYTES))
        .collect();
    let top = level(&mut lengths, budget).min(TOPIC_BYTES);
    let mut topics = HashMap::with_capacity(kept.len());
    let mut clipped = 0;
    for row in kept {
        let topic = clip_bytes(&row.topic, top).trim_end();
        if topic.len() < row.topic.trim_end().len() {
            clipped += 1;
        }
        topics.insert(row.id, topic.to_string());
    }
    Fitted {
        topics,
        clipped,
        left_out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voipc_protocol::codec::{encode_server_msg, MAX_MSG_SIZE};
    use voipc_protocol::messages::ServerMessage;
    use voipc_protocol::types::{ChannelInfo, ProximityMode};

    /// The relay's `LIST_LIMIT`, which it reports in `ImportFacts`.
    const LIMIT: usize = 60 * 1024;

    fn row(id: u64, name: &str, topic: &str, text: bool) -> FitRow {
        FitRow {
            id,
            name: name.into(),
            topic: topic.into(),
            text,
        }
    }

    /// As the relay will hold it, at the most an imported channel can be: a large id, a
    /// stage's limit, a busy channel, Discord's longest slow mode.
    fn info(i: u64, row: &FitRow, topic: &str) -> ChannelInfo {
        ChannelInfo {
            channel_id: 2_000_000 + i as u32,
            name: row.name.clone(),
            description: topic.to_string(),
            max_users: 10_000,
            user_count: 16_000,
            has_password: false,
            created_by: None,
            proximity: ProximityMode::Off,
            hidden: false,
            anonymous: false,
            screen_share: true,
            hide_members: false,
            text: row.text,
            auto_join: false,
            message_ttl_secs: 0,
            routed: false,
            announce: false,
            slow_mode_secs: 21_600,
            nsfw: false,
            log: format!("c:dc-{}", 1_454_987_148_113_234_751u64 + i),
        }
    }

    fn real_list(rows: &[FitRow], fitted: &Fitted) -> Result<usize, String> {
        let channels: Vec<ChannelInfo> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| !fitted.left_out.contains(&r.id))
            .map(|(i, r)| info(i as u64, r, &fitted.topics[&r.id]))
            .collect();
        encode_server_msg(&ServerMessage::ChannelList { channels })
            .map(|b| b.len())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn row_bytes_holds_for_the_real_encoding() {
        let empty = encode_server_msg(&ServerMessage::ChannelList { channels: vec![] })
            .unwrap()
            .len();
        for (name, topic) in [
            ("x".repeat(64), "t".repeat(256)),
            ("x".repeat(64), String::new()),
            ("x".to_string(), "t".to_string()),
        ] {
            let r = row(1, &name, &topic, true);
            let one = encode_server_msg(&ServerMessage::ChannelList {
                channels: vec![info(0, &r, &topic)],
            })
            .unwrap()
            .len();
            let used = one - empty - name.len() - topic.len();
            assert!(used <= ROW_BYTES, "a row took {used} besides its text");
        }
    }

    #[test]
    fn five_hundred_longest_names_fit_one_real_channel_list() {
        // Discord's most, at the longest name, each with a full topic
        let rows: Vec<FitRow> = (0..500u64)
            .map(|i| {
                let name = format!("{i:03}-{}", "n".repeat(60));
                row(i, &name, &"t".repeat(256), i % 2 == 0)
            })
            .collect();
        let fitted = fit(&rows, 0, LIMIT);
        assert!(fitted.left_out.is_empty());
        assert_eq!(fitted.clipped, 500);
        let len = real_list(&rows, &fitted).unwrap();
        assert!(len <= LIMIT, "{len} over {LIMIT}");
        assert!(len <= MAX_MSG_SIZE as usize);
        // The control: left alone, the list could not be framed at all
        let whole = Fitted {
            topics: rows.iter().map(|r| (r.id, r.topic.clone())).collect(),
            ..Fitted::default()
        };
        assert!(real_list(&rows, &whole).is_err());
    }

    #[test]
    fn multi_byte_names_and_topics_fit_too_and_are_never_cut_mid_character() {
        let rows: Vec<FitRow> = (0..500u64)
            .map(|i| {
                let name = format!("{:03}{}", i, "\u{1F389}".repeat(15));
                row(i, &name, &"\u{e9}".repeat(128), true)
            })
            .collect();
        let fitted = fit(&rows, 0, LIMIT);
        assert!(fitted.left_out.is_empty());
        assert!(real_list(&rows, &fitted).unwrap() <= LIMIT);
        // `String` holds only whole characters, so this also says none was cut
        for topic in fitted.topics.values() {
            assert!(topic.chars().all(|c| c == '\u{e9}'));
        }
    }

    #[test]
    fn topics_share_what_is_left_fairly() {
        let (long, longer, short) = ("l".repeat(200), "L".repeat(250), "s".repeat(10));
        let rows = [
            row(1, "a", &long, true),
            row(2, "b", &longer, true),
            row(3, "c", &short, true),
        ];
        // Room for all of it: nothing changes
        let fitted = fit(&rows, 0, LIMIT);
        assert_eq!(fitted.clipped, 0);
        assert_eq!(fitted.topics[&2], longer);
        // Room for 3 rows and 210 of topic: the short one stays whole, the two long ones
        // get the same of what is left
        let fixed: usize = rows.iter().map(|r| ROW_BYTES + r.name.len()).sum();
        let fitted = fit(&rows, 0, RESERVE + fixed + 210);
        assert_eq!(fitted.topics[&3], short);
        assert_eq!(fitted.topics[&1].len(), 100);
        assert_eq!(fitted.topics[&2].len(), 100);
        assert_eq!(fitted.clipped, 2);
        // No room for topics at all: the channels still come
        let fitted = fit(&rows, 0, RESERVE + fixed);
        assert!(fitted.left_out.is_empty());
        assert!(fitted.topics.values().all(String::is_empty));
    }

    #[test]
    fn no_topic_passes_what_a_description_may_be() {
        let rows = [row(1, "a", &"t".repeat(400), true)];
        let fitted = fit(&rows, 0, LIMIT);
        assert_eq!(fitted.topics[&1].len(), TOPIC_BYTES);
        assert_eq!(fitted.clipped, 1);
    }

    #[test]
    fn a_full_relay_leaves_out_voice_first_and_says_so() {
        let rows = [
            row(1, "text-one", "topic", true),
            row(2, "voice-one", "topic", false),
            row(3, "text-two", "topic", true),
            row(4, "voice-two", "topic", false),
        ];
        let each = |n: &str| ROW_BYTES + n.len();
        // Room for two rows: both voice channels go, the last first
        let room = each("text-one") + each("text-two");
        let fitted = fit(&rows, LIMIT - RESERVE - room, LIMIT);
        assert_eq!(fitted.left_out, [4, 2]);
        assert_eq!(fitted.topics.len(), 2);
        assert!(fitted.topics.contains_key(&1) && fitted.topics.contains_key(&3));
        // Room for one: then text, from the end
        let fitted = fit(&rows, LIMIT - RESERVE - each("text-one"), LIMIT);
        assert_eq!(fitted.left_out, [4, 2, 3]);
        // Nothing free at all, or past the limit: nothing comes, and nothing panics
        for bytes in [LIMIT - RESERVE, LIMIT, LIMIT * 2] {
            let fitted = fit(&rows, bytes, LIMIT);
            assert_eq!(fitted.left_out.len(), 4);
            assert!(fitted.topics.is_empty());
        }
    }

    #[test]
    fn no_rows_is_no_work() {
        assert_eq!(fit(&[], 0, LIMIT), Fitted::default());
    }
}
