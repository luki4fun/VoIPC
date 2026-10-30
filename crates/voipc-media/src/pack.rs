//! Emote packs: the pictures in a .zip (a .wastickers is one) read in memory,
//! and what an emote may be called.
//!
//! Only what this needs of zip is read: the central directory, and entries
//! stored or deflated. A name in the archive only ever names an emote, never a
//! path; nothing of an archive touches the disk. Every size is checked while
//! inflating, since the sizes an archive states can lie.

use crate::{Error, Result};

pub const MAX_PACK_ENTRIES: usize = 1000;
pub const MAX_ENTRY_BYTES: usize = 16 << 20;
pub const MAX_PACK_BYTES: usize = 200 << 20;

/// The longest emote name: `:name:` must fit a reaction (`MAX_EMOJI_BYTES`, 32).
pub const NAME_MAX: usize = 30;

/// One file of a pack: its own name (the last part of its path) and bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Pack {
    /// A WhatsApp pack's `title.txt`.
    pub title: Option<String>,
    pub entries: Vec<Entry>,
}

fn bad(why: &str) -> Error {
    Error::Corrupt(format!("not a zip archive this reads: {why}"))
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    b.get(i..i + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The files of a zip archive, without its folders, its macOS leftovers and
/// hidden files, encrypted entries, or entries packed some other way.
pub fn read_pack(b: &[u8]) -> Result<Pack> {
    // The end record: in the last 22 bytes, or before a comment of up to 64 KiB
    let lowest = b.len().saturating_sub(22 + 0xFFFF);
    let end = (lowest..=b.len().saturating_sub(22))
        .rev()
        .find(|&i| u32_at(b, i) == Some(0x0605_4B50))
        .ok_or_else(|| bad("no end record"))?;
    let disk = u16_at(b, end + 4).ok_or_else(|| bad("short end record"))?;
    let count = u16_at(b, end + 10).ok_or_else(|| bad("short end record"))?;
    let at = u32_at(b, end + 16).ok_or_else(|| bad("short end record"))?;
    if disk != 0 || count == 0xFFFF || at == 0xFFFF_FFFF {
        return Err(Error::Unsupported("a split or zip64 archive"));
    }
    if usize::from(count) > MAX_PACK_ENTRIES {
        return Err(Error::TooLarge("the pack has too many files"));
    }
    let mut pack = Pack::default();
    let mut total = 0usize;
    let mut tray: Vec<Entry> = Vec::new();
    let mut i = at as usize;
    for _ in 0..count {
        if u32_at(b, i) != Some(0x0201_4B50) {
            return Err(bad("a broken directory"));
        }
        let field = |o: usize| u16_at(b, i + o).ok_or_else(|| bad("a short directory entry"));
        let (flags, method) = (field(8)?, field(10)?);
        let packed = u32_at(b, i + 20).ok_or_else(|| bad("a short directory entry"))? as usize;
        let size = u32_at(b, i + 24).ok_or_else(|| bad("a short directory entry"))? as usize;
        let (name_len, extra_len, comment_len) = (
            usize::from(field(28)?),
            usize::from(field(30)?),
            usize::from(field(32)?),
        );
        let local = u32_at(b, i + 42).ok_or_else(|| bad("a short directory entry"))? as usize;
        let path = b
            .get(i + 46..i + 46 + name_len)
            .ok_or_else(|| bad("a short directory entry"))?;
        let path = String::from_utf8_lossy(path).into_owned();
        i += 46 + name_len + extra_len + comment_len;

        let name = path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .chars()
            .take(255)
            .collect::<String>();
        let skip = path.ends_with('/')
            || path.starts_with("__MACOSX/")
            || name.starts_with('.')
            || name.is_empty();
        // Encrypted (bit 0), or packed in a way not read here
        if skip || flags & 1 != 0 || (method != 0 && method != 8) {
            continue;
        }
        if size > MAX_ENTRY_BYTES {
            return Err(Error::TooLarge("a file in the pack is too big"));
        }
        if u32_at(b, local) != Some(0x0403_4B50) {
            return Err(bad("a broken entry"));
        }
        let start = local
            + 30
            + usize::from(u16_at(b, local + 26).unwrap_or(0))
            + usize::from(u16_at(b, local + 28).unwrap_or(0));
        let data = b
            .get(start..start.saturating_add(packed))
            .ok_or_else(|| bad("an entry past its end"))?;
        let limit = size.min(MAX_PACK_BYTES - total);
        let bytes = if method == 0 {
            data.to_vec()
        } else {
            miniz_oxide::inflate::decompress_to_vec_with_limit(data, limit)
                .map_err(|_| Error::TooLarge("a file in the pack unpacks to more than it says"))?
        };
        if bytes.len() != size {
            return Err(bad("an entry of the wrong size"));
        }
        total += bytes.len();
        if total > MAX_PACK_BYTES {
            return Err(Error::TooLarge("the pack unpacks to too much"));
        }
        let lower = name.to_ascii_lowercase();
        if lower == "title.txt" {
            pack.title = Some(label(&bytes));
        } else if lower == "author.txt" {
        } else if lower.starts_with("tray") {
            tray.push(Entry { name, bytes });
        } else {
            pack.entries.push(Entry { name, bytes });
        }
    }
    // A WhatsApp pack's tray icon is not one of its stickers
    if pack.title.is_none() {
        pack.entries.extend(tray);
    }
    Ok(pack)
}

/// A pack's title as a person may see it: one line, no control or direction
/// characters, at most 64 characters.
fn label(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'))
        .take(64)
        .collect::<String>()
        .trim()
        .to_string()
}

/// `^[a-z0-9_]{2,30}$`: what an emote may be called, here and on the relay.
pub fn valid_name(s: &str) -> bool {
    (2..=NAME_MAX).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// An emote name from a file name: its stem in lower case, anything else as
/// `_` (once, not at either end), cut to 30. None if under two characters
/// are left.
pub fn name_from(file: &str) -> Option<String> {
    let stem = match file.rsplit_once('.') {
        Some((s, ext)) if !s.is_empty() && ext.len() <= 5 => s,
        _ => file,
    };
    let mut out = String::new();
    for c in stem.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let mut out = out.trim_end_matches('_').to_string();
    out.truncate(NAME_MAX);
    let out = out.trim_end_matches('_').to_string();
    valid_name(&out).then_some(out)
}

/// `base`, or `base_2`, `base_3`… cut to fit: the first `taken` says is free.
pub fn unique_name(base: &str, taken: &dyn Fn(&str) -> bool) -> Option<String> {
    if !taken(base) {
        return Some(base.to_string());
    }
    (2..1000).find_map(|n| {
        let tail = format!("_{n}");
        let mut head = base.to_string();
        head.truncate(NAME_MAX - tail.len());
        let name = format!("{}{tail}", head.trim_end_matches('_'));
        (valid_name(&name) && !taken(&name)).then_some(name)
    })
}
