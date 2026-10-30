//! The one thing of a photo's EXIF that is kept: which way up it is. A phone
//! saves a picture as its sensor saw it and says how to turn it; without that
//! a portrait photo lies on its side. Everything else in EXIF (where, when,
//! which camera) goes with the rest of the file.

/// The Orientation tag (1-8) of an EXIF block, 1 where it has none or makes
/// no sense. `b` is the TIFF data, with or without JPEG's "Exif\0\0" before it.
pub fn orientation(b: &[u8]) -> u8 {
    let b = b.strip_prefix(b"Exif\0\0").unwrap_or(b);
    let big = match b.get(0..2) {
        Some(b"MM") => true,
        Some(b"II") => false,
        _ => return 1,
    };
    let u16_at = |i: usize| {
        b.get(i..i + 2).map(|s| {
            if big {
                u16::from_be_bytes([s[0], s[1]])
            } else {
                u16::from_le_bytes([s[0], s[1]])
            }
        })
    };
    let u32_at = |i: usize| {
        b.get(i..i + 4).map(|s| {
            let a = [s[0], s[1], s[2], s[3]];
            if big {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            }
        })
    };
    if u16_at(2) != Some(42) {
        return 1;
    }
    let Some(ifd) = u32_at(4).map(|o| o as usize) else {
        return 1;
    };
    let Some(count) = u16_at(ifd) else { return 1 };
    for n in 0..usize::from(count) {
        let e = ifd + 2 + n * 12;
        // Tag 0x0112, a SHORT, one of it
        if u16_at(e) == Some(0x0112) && u16_at(e + 2) == Some(3) && u32_at(e + 4) == Some(1) {
            return match u16_at(e + 8) {
                Some(o @ 1..=8) => o as u8,
                _ => 1,
            };
        }
    }
    1
}

/// `rgba` (`w` × `h`) turned as orientation `o` says: the picture and its new
/// width and height.
pub fn orient(rgba: &[u8], w: u32, h: u32, o: u8) -> (Vec<u8>, u32, u32) {
    let (tw, th) = if o >= 5 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; rgba.len()];
    for y in 0..th {
        for x in 0..tw {
            let (sx, sy) = match o {
                2 => (w - 1 - x, y),
                3 => (w - 1 - x, h - 1 - y),
                4 => (x, h - 1 - y),
                5 => (y, x),
                6 => (y, h - 1 - x),
                7 => (w - 1 - y, h - 1 - x),
                8 => (w - 1 - y, x),
                _ => (x, y),
            };
            let s = ((sy * w + sx) * 4) as usize;
            let d = ((y * tw + x) * 4) as usize;
            out[d..d + 4].copy_from_slice(&rgba[s..s + 4]);
        }
    }
    (out, tw, th)
}
