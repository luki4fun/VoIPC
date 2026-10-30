//! A picture's file without what it says about where it came from: its
//! metadata (EXIF, with a phone's place and serial; XMP; comments; colour
//! profiles, which carry names) dropped, its pixels and frames as they were.
//! What an admin's "original" upload goes as: a server's emotes and stickers
//! are readable by every member.
//!
//! Only the container is rewritten, chunk by chunk: nothing is decoded here,
//! and what is kept is copied byte for byte.

use crate::decode::{sniff, Format};
use crate::{exif, Error, Result};

/// `b` with its metadata dropped, else why not: a JPEG its EXIF turns (the
/// turn would be lost with it), or a file not laid out as its format says.
pub fn strip(b: &[u8]) -> Result<Vec<u8>> {
    match sniff(b).map_err(Error::Unsupported)? {
        Format::Png => png(b),
        Format::Gif => gif(b),
        Format::WebP => webp(b),
        Format::Jpeg => jpeg(b),
    }
}

fn bad() -> Error {
    Error::Corrupt("not laid out as its format says".into())
}

fn be32(b: &[u8], i: usize) -> Result<usize> {
    let s = b.get(i..i + 4).ok_or_else(bad)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize)
}

fn le32(b: &[u8], i: usize) -> Result<usize> {
    let s = b.get(i..i + 4).ok_or_else(bad)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
}

/// The picture, its palette and transparency, and its animation: no text,
/// time, colour profile or EXIF chunk.
fn png(b: &[u8]) -> Result<Vec<u8>> {
    const KEEP: [&[u8]; 8] = [
        b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"acTL", b"fcTL", b"fdAT", b"IEND",
    ];
    let mut out = b[..8].to_vec();
    let mut i = 8;
    loop {
        let end = be32(b, i)?.checked_add(i + 12).ok_or_else(bad)?;
        let chunk = b.get(i..end).ok_or_else(bad)?;
        let kind = &chunk[4..8];
        if KEEP.contains(&kind) {
            out.extend_from_slice(chunk);
        }
        if kind == b"IEND" {
            return Ok(out);
        }
        i = end;
    }
}

/// The frames, their timing and the loop count: no comment, no plain text,
/// no other application's block.
fn gif(b: &[u8]) -> Result<Vec<u8>> {
    let table = |flags: u8| {
        if flags & 0x80 != 0 {
            3usize << ((flags & 7) + 1)
        } else {
            0
        }
    };
    // A run of data sub-blocks from `i`, through the empty one that ends it
    let blocks = |mut i: usize| -> Result<usize> {
        loop {
            let n = usize::from(*b.get(i).ok_or_else(bad)?);
            i += 1 + n;
            if n == 0 {
                return Ok(i);
            }
        }
    };
    let mut i = 13 + table(*b.get(10).ok_or_else(bad)?);
    let mut out = b.get(..i).ok_or_else(bad)?.to_vec();
    loop {
        match *b.get(i).ok_or_else(bad)? {
            0x3B => {
                out.push(0x3B);
                return Ok(out);
            }
            0x2C => {
                let flags = *b.get(i + 9).ok_or_else(bad)?;
                // The descriptor, its colours, the code size, then the data
                let end = blocks(i + 10 + table(flags) + 1)?;
                out.extend_from_slice(b.get(i..end).ok_or_else(bad)?);
                i = end;
            }
            0x21 => {
                let label = *b.get(i + 1).ok_or_else(bad)?;
                let end = blocks(i + 2)?;
                let looping = matches!(b.get(i + 3..i + 14), Some(b"NETSCAPE2.0" | b"ANIMEXTS1.0"));
                if label == 0xF9 || (label == 0xFF && looping) {
                    out.extend_from_slice(b.get(i..end).ok_or_else(bad)?);
                }
                i = end;
            }
            _ => return Err(bad()),
        }
    }
}

/// Every chunk but EXIF, XMP and the colour profile, and the VP8X flags that
/// announced them cleared.
fn webp(b: &[u8]) -> Result<Vec<u8>> {
    let end = le32(b, 4)?
        .checked_add(8)
        .filter(|&n| n <= b.len())
        .ok_or_else(bad)?;
    let mut out = b"RIFF\0\0\0\0WEBP".to_vec();
    let mut i = 12;
    while i < end {
        let kind = b.get(i..i + 4).ok_or_else(bad)?;
        let len = le32(b, i + 4)?;
        let data_end = (i + 8)
            .checked_add(len)
            .filter(|&n| n <= end)
            .ok_or_else(bad)?;
        let chunk = &b[i..data_end];
        match kind {
            b"EXIF" | b"XMP " | b"ICCP" => {}
            b"VP8X" if len >= 1 => {
                out.extend_from_slice(chunk);
                // ICC (0x20), EXIF (0x08), XMP (0x04)
                let flags = out.len() - len;
                out[flags] &= !0x2C;
            }
            _ => out.extend_from_slice(chunk),
        }
        if len % 2 == 1 && kind != b"EXIF" && kind != b"XMP " && kind != b"ICCP" {
            out.push(0);
        }
        i = data_end + len % 2;
    }
    let size = u32::try_from(out.len() - 8).map_err(|_| bad())?;
    out[4..8].copy_from_slice(&size.to_le_bytes());
    Ok(out)
}

/// Every segment but APP1–APP13 and APP15 (EXIF, XMP, ICC, Photoshop's IPTC)
/// and comments, up to the first scan; from there, as it is. APP14 stays: it
/// says how Adobe's colours are to be read. shortcut: a comment
/// between the scans of a progressive JPEG stays; drop it there too if one
/// ever matters.
fn jpeg(b: &[u8]) -> Result<Vec<u8>> {
    use zune_core::{bytestream::ZCursor, options::DecoderOptions};
    let mut d =
        zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(b), DecoderOptions::default());
    d.decode_headers()
        .map_err(|e| Error::Corrupt(format!("{e:?}")))?;
    if d.exif().map_or(1, |e| exif::orientation(e)) > 1 {
        return Err(Error::Unsupported("a turned JPEG kept as it is"));
    }
    let mut out = vec![0xFF, 0xD8];
    let mut i = 2;
    loop {
        if b.get(i) != Some(&0xFF) {
            return Err(bad());
        }
        let marker = *b.get(i + 1).ok_or_else(bad)?;
        match marker {
            // A fill byte before a marker
            0xFF => i += 1,
            // The first scan: the picture's data, and what follows it
            0xDA => {
                out.extend_from_slice(&b[i..]);
                return Ok(out);
            }
            _ => {
                let len = usize::from(u16::from_be_bytes([
                    *b.get(i + 2).ok_or_else(bad)?,
                    *b.get(i + 3).ok_or_else(bad)?,
                ]));
                let end = i + 2 + len;
                let segment = b.get(i..end).ok_or_else(bad)?;
                if !((0xE1..=0xED).contains(&marker) || marker == 0xEF || marker == 0xFE) {
                    out.extend_from_slice(segment);
                }
                i = end;
            }
        }
    }
}
