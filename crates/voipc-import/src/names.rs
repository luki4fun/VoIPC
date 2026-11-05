//! What things are called here. The relay refuses a name it cannot take, and a default
//! Discord server has two of those: voice `General` and text `general`.

use std::collections::HashSet;

use voipc_protocol::types::EMOTE_NAME_MAX;

/// A channel's or category's longest name, in bytes (`validate_entries`).
pub const NAME_BYTES: usize = 64;
/// The lobby's name. A voice channel may not have it; a text channel may.
const LOBBY: &str = "general";

/// The relay's `session::bad_name_char`, which this crate cannot reach: control characters,
/// and the ones that print as nothing or reorder what follows them.
pub fn bad_name_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
        )
}

/// The start of `s`, at most `max` bytes, never half a character.
pub fn clip_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The start of `s`, at most `max` characters.
pub fn clip_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((end, _)) => &s[..end],
        None => s,
    }
}

fn clean(raw: &str, max: usize) -> String {
    let kept: String = raw.chars().filter(|c| !bad_name_char(*c)).collect();
    clip_bytes(kept.trim(), max).trim().to_string()
}

/// A category's name. Two may share one.
pub fn category_name(raw: &str, id: u64) -> String {
    let name = clean(raw, NAME_BYTES);
    if name.is_empty() {
        return format!("category-{:04}", id % 10_000);
    }
    name
}

/// A name with nothing invisible, at most `max` characters.
pub fn clean_chars(raw: &str, max: usize) -> String {
    let kept: String = raw.chars().filter(|c| !bad_name_char(*c)).collect();
    clip_chars(kept.trim(), max).trim().to_string()
}

/// What a person is shown as: at most 64 characters.
pub fn display_name(raw: &str) -> String {
    clean_chars(raw, 64)
}

/// A topic for one line under a channel's name. `fit.rs` decides how much of it stays.
pub fn clean_topic(raw: &str) -> String {
    let kept: String = raw
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .filter(|c| !bad_name_char(*c))
        .collect();
    kept.trim().to_string()
}

/// The names taken here, case-insensitively, as `channel_create` compares them.
#[derive(Debug, Clone, Default)]
pub struct Taken {
    names: HashSet<String>,
    text_general: bool,
}

impl Taken {
    /// `(name, is text)` of what the relay has now. The lobby is voice, so a text
    /// `general` passes beside it.
    pub fn new<'a>(existing: impl IntoIterator<Item = (&'a str, bool)>) -> Self {
        let mut taken = Taken::default();
        for (name, text) in existing {
            let lower = name.to_lowercase();
            if text && lower == LOBBY {
                taken.text_general = true;
            }
            taken.names.insert(lower);
        }
        taken
    }

    fn is_taken(&self, lower: &str, text: bool) -> bool {
        if text && lower == LOBBY {
            return self.text_general;
        }
        self.names.contains(lower)
    }

    fn take(&mut self, lower: String, text: bool) {
        if text && lower == LOBBY {
            self.text_general = true;
        }
        self.names.insert(lower);
    }

    /// What `raw` becomes, without taking it: a channel a run already made keeps what it has.
    pub fn base_name(raw: &str, id: u64, text: bool) -> String {
        let name = clean(raw, NAME_BYTES);
        if name.is_empty() {
            return format!("channel-{:04}", id % 10_000);
        }
        if !text && name.to_lowercase() == LOBBY {
            return format!("{name} voice");
        }
        name
    }

    /// Takes a name a run already made, so that no new channel asks for it.
    pub fn hold(&mut self, name: &str, text: bool) {
        self.take(name.to_lowercase(), text);
    }

    /// A name no other has, and holds it.
    pub fn channel_name(&mut self, raw: &str, id: u64, text: bool) -> String {
        let base = Self::base_name(raw, id, text);
        let mut name = base.clone();
        let mut n = 2u32;
        while self.is_taken(&name.to_lowercase(), text) {
            let tail = format!("-{n}");
            name = format!(
                "{}{tail}",
                clip_bytes(&base, NAME_BYTES - tail.len()).trim_end()
            );
            n += 1;
        }
        self.take(name.to_lowercase(), text);
        name
    }
}

/// An emote's name from Discord's: as `nameFrom` in emote-rules.ts. None: nothing of it
/// fits `^[a-z0-9_]{2,30}$`.
fn emote_base(raw: &str) -> Option<String> {
    let mut out = String::new();
    for c in raw.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = clip_bytes(out.trim_end_matches('_'), EMOTE_NAME_MAX).trim_end_matches('_');
    (out.len() >= 2).then(|| out.to_string())
}

/// `<base>_2`, `<base>_3`: as `uniqueName` in emote-rules.ts. None: every name is taken.
pub fn emote_name(raw: &str, id: u64, taken: impl Fn(&str) -> bool) -> Option<String> {
    let base = emote_base(raw).unwrap_or_else(|| format!("emote_{:04}", id % 10_000));
    if !taken(&base) {
        return Some(base);
    }
    (2..1000).find_map(|n| {
        let tail = format!("_{n}");
        let name = format!(
            "{}{tail}",
            clip_bytes(&base, EMOTE_NAME_MAX - tail.len()).trim_end_matches('_')
        );
        (!taken(&name)).then_some(name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lobby() -> Taken {
        Taken::new([("General", false)])
    }

    #[test]
    fn two_names_one_channel_get_two_names() {
        let mut taken = lobby();
        assert_eq!(taken.channel_name("chat", 1, true), "chat");
        assert_eq!(taken.channel_name("Chat", 2, true), "Chat-2");
        assert_eq!(taken.channel_name("CHAT", 3, false), "CHAT-3");
        // A name a suffix made is taken too
        assert_eq!(taken.channel_name("chat-2", 4, true), "chat-2-2");
        // What the relay has counts as much as what came before
        let mut taken = Taken::new([("rules", true)]);
        assert_eq!(taken.channel_name("rules", 1, true), "rules-2");
    }

    #[test]
    fn voice_general_is_renamed_text_general_stays() {
        let mut taken = lobby();
        assert_eq!(taken.channel_name("general", 1, true), "general");
        assert_eq!(taken.channel_name("General", 2, false), "General voice");
        assert_eq!(taken.channel_name("general", 3, false), "general voice-2");
        // A second text one is a clash with the first, not with the lobby
        assert_eq!(taken.channel_name("General", 4, true), "General-2");
        // A relay with a text `general` of its own
        let mut taken = Taken::new([("General", false), ("general", true)]);
        assert_eq!(taken.channel_name("general", 1, true), "general-2");
    }

    #[test]
    fn clip_never_cuts_a_character() {
        // Four bytes each: 64 bytes is 16 of them, and 65 would cut one
        let s = "\u{1F389}".repeat(20);
        assert_eq!(clip_bytes(&s, 65).len(), 64);
        assert_eq!(clip_bytes(&s, 63).len(), 60);
        let mut taken = Taken::default();
        let name = taken.channel_name(&s, 1, true);
        assert_eq!(name.len(), 64);
        // ... and a suffix makes room for itself the same way
        let second = taken.channel_name(&s, 2, true);
        assert!(second.len() <= 64 && second.ends_with("-2"), "{second}");
        assert!(second.starts_with('\u{1F389}'));
        // A space left at the end by the clip goes
        let s = format!("{} tail", "a".repeat(63));
        assert_eq!(Taken::default().channel_name(&s, 1, true), "a".repeat(63));
        assert_eq!(clip_chars("\u{e9}\u{e9}\u{e9}", 2), "\u{e9}\u{e9}");
    }

    #[test]
    fn invisible_characters_go() {
        let mut taken = Taken::default();
        assert_eq!(
            taken.channel_name("ad\u{200B}min\u{202E}", 1, true),
            "admin"
        );
        assert_eq!(taken.channel_name("  spaced\u{0007}  ", 2, true), "spaced");
        // Nothing left: a name of its id, as the relay refuses an empty one
        assert_eq!(
            taken.channel_name("\u{200B}\u{FEFF}", 1_234_567, true),
            "channel-4567"
        );
        assert_eq!(taken.channel_name("", 5, true), "channel-0005");
        assert_eq!(category_name("\u{200B}", 5), "category-0005");
        // Once cleaned it clashes like any other
        assert_eq!(taken.channel_name("spa\u{200D}ced", 6, true), "spaced-2");
        // Looks fine, and is not what the relay refuses
        assert_eq!(taken.channel_name("caf\u{e9}", 7, true), "caf\u{e9}");
        // A topic is one line
        assert_eq!(clean_topic(" a\nb\t\u{200B}c "), "a b c");
        // A person's name
        assert_eq!(display_name(" Dan\u{202E} D "), "Dan D");
        assert_eq!(display_name(&"\u{e9}".repeat(70)).chars().count(), 64);
    }

    #[test]
    fn two_categories_may_share_a_name() {
        assert_eq!(category_name("Text", 1), category_name("Text", 2));
        assert_eq!(category_name(&"c".repeat(70), 3).len(), 64);
    }

    #[test]
    fn an_emotes_name_follows_the_apps_rule() {
        let none = |_: &str| false;
        assert_eq!(emote_name("PogChamp", 1, none).unwrap(), "pogchamp");
        assert_eq!(emote_name("cool emote!", 1, none).unwrap(), "cool_emote");
        assert_eq!(emote_name("__x_y__", 1, none).unwrap(), "x_y");
        assert_eq!(
            emote_name(&"y".repeat(40), 1, none).unwrap(),
            "y".repeat(30)
        );
        // Nothing of it fits: its id
        assert_eq!(
            emote_name("\u{1F389}", 123_456, none).unwrap(),
            "emote_3456"
        );
        assert_eq!(emote_name("a", 7, none).unwrap(), "emote_0007");
        // The app's own cases (emote-rules.test.ts)
        let taken = |n: &str| ["pog", "pog_2"].contains(&n);
        assert_eq!(emote_name("pog", 1, taken).unwrap(), "pog_3");
        let long = "y".repeat(30);
        let taken = |n: &str| n == long;
        assert_eq!(
            emote_name(&long, 1, taken).unwrap(),
            format!("{}_2", "y".repeat(28))
        );
        // All of them taken
        assert_eq!(emote_name("pog", 1, |_| true), None);
        // What it gives, the relay takes
        for raw in ["PogChamp", "\u{1F389}", &"x".repeat(50)] {
            let name = emote_name(raw, 1, none).unwrap();
            assert!(voipc_protocol::types::valid_emote_name(&name), "{name}");
        }
    }
}
