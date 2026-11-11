//! What a name may hold, for the relay and the desktop importer alike (W3-33: the
//! importer kept a copy of the relay's list, which could drift).

/// A character no user or channel name may contain: control characters, and
/// the ones that print as nothing or reorder what follows them — with those,
/// "admin\u{200B}" passes for "admin" and an RTL override turns a tag around.
/// Look-alike letters from other scripts are not caught here.
pub fn bad_name_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'                      // soft hyphen
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers
            | '\u{200B}'..='\u{200F}'       // zero-width space/joiners, LRM, RLM
            | '\u{202A}'..='\u{202E}'       // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'       // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}'       // bidi isolates
            | '\u{FEFF}'                    // zero-width no-break space
        )
}

/// What a name is read without when comparing it to others: these draw nothing, so
/// `bobby` with one in it looks like `bobby`. Allowed in a name, since an emoji or a
/// Persian spelling needs some. l4f's `blank` less what `bad_name_char` refuses, and
/// `DRAWS_NOTHING` in profile-rules.ts.
pub fn draws_nothing(c: char) -> bool {
    matches!(c,
        '\u{034f}'
        | '\u{17b4}' | '\u{17b5}'
        | '\u{180b}'..='\u{180f}'
        | '\u{200c}' | '\u{200d}'
        | '\u{2800}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{fff0}'..='\u{fff8}'
        | '\u{13430}'..='\u{1343f}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{e0000}'..='\u{e0fff}'
    )
}

/// Whether a name shows anything at all. One of only U+2800, the usual trick for a blank
/// Discord name, or variation selectors, would be a blank row where a name stands (W1-36):
/// such a name counts as none.
pub fn draws_something(name: &str) -> bool {
    name.chars()
        .any(|c| !c.is_whitespace() && !draws_nothing(c) && !bad_name_char(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_of_only_what_draws_nothing_shows_nothing() {
        for blank in [
            "",
            "  ",
            "\u{2800}",
            "\u{2800} \u{2800}",
            "\u{fe0f}\u{34f}",
            "\u{200b}",
        ] {
            assert!(!draws_something(blank), "{blank:?}");
        }
        for name in [
            "Dan",
            "Dan\u{2800}",
            "\u{2764}\u{fe0f}",
            "\u{1f469}\u{200d}\u{1f4bb}",
            "日本",
        ] {
            assert!(draws_something(name), "{name:?}");
        }
    }
}
