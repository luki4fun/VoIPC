//! Emote packs: the pictures in a .zip (a .wastickers is one) read in memory.
//!
//! Only what this needs of zip is read: the central directory, and entries
//! stored or deflated. A name in the archive only ever names an emote, never a
//! path; nothing of an archive touches the disk. Every size is checked while
//! inflating, since the sizes an archive states can lie. A file that cannot be
//! read is set aside with why, and the rest of the pack still is.

use crate::{Error, Result};

pub const MAX_PACK_ENTRIES: usize = 1000;
pub const MAX_ENTRY_BYTES: usize = 16 << 20;
pub const MAX_PACK_BYTES: usize = 200 << 20;

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
    /// Files not read, by name, with why (for a person).
    pub skipped: Vec<(String, &'static str)>,
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
        if path.ends_with('/')
            || path.starts_with("__MACOSX/")
            || name.starts_with('.')
            || name.is_empty()
        {
            continue;
        }
        let why = if flags & 1 != 0 {
            Some("it is encrypted")
        } else if method != 0 && method != 8 {
            Some("it is packed in a way not read here")
        } else if size > MAX_ENTRY_BYTES {
            Some("it is too big")
        } else {
            None
        };
        if let Some(why) = why {
            pack.skipped.push((name, why));
            continue;
        }
        // Counted whether it reads or not: a pack of lying files is bounded
        // like a pack of honest ones
        total += size;
        if total > MAX_PACK_BYTES {
            return Err(Error::TooLarge("the pack unpacks to too much"));
        }
        let bytes = match entry_bytes(b, local, packed, method, size) {
            Ok(bytes) => bytes,
            Err(why) => {
                pack.skipped.push((name, why));
                continue;
            }
        };
        let lower = name.to_ascii_lowercase();
        if lower == "title.txt" {
            pack.title = Some(label(&bytes));
        } else if lower == "author.txt" {
        } else if lower.starts_with("tray") && lower.ends_with(".png") {
            // WhatsApp's stickers are WebP; its tray icon is a PNG
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

/// An entry's `size` bytes, from its local header, or why not.
fn entry_bytes(
    b: &[u8],
    local: usize,
    packed: usize,
    method: u16,
    size: usize,
) -> std::result::Result<Vec<u8>, &'static str> {
    use miniz_oxide::inflate::{decompress_to_vec_with_limit, TINFLStatus};
    if u32_at(b, local) != Some(0x0403_4B50) {
        return Err("it is damaged");
    }
    let start = local
        + 30
        + usize::from(u16_at(b, local + 26).unwrap_or(0))
        + usize::from(u16_at(b, local + 28).unwrap_or(0));
    let data = b
        .get(start..start.saturating_add(packed))
        .ok_or("it is damaged")?;
    let bytes = if method == 0 {
        data.to_vec()
    } else {
        decompress_to_vec_with_limit(data, size).map_err(|e| {
            if e.status == TINFLStatus::HasMoreOutput {
                "it unpacks to more than it says"
            } else {
                "it is damaged"
            }
        })?
    };
    if bytes.len() != size {
        return Err("it is not the size it says");
    }
    Ok(bytes)
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
