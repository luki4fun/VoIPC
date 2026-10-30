//! Pictures from other people, made safe to show.
//!
//! A picture somebody else made (a chat photo, a server's emote or sticker)
//! is never handed to a WebView's own decoder: a crafted file there (libwebp's
//! CVE-2023-4863 was one) runs code in the app. Here it is decoded by
//! memory-safe Rust under fixed budgets, fitted into a box, and written out
//! again as a PNG (APNG when it moves) whose every byte this crate chose. Only
//! that goes on screen.
//!
//! - `sanitize`: any PNG/APNG, GIF, WebP or JPEG in, a fresh PNG out.
//! - `read_pack`: the pictures in a .zip or .wastickers, in memory only.

#![forbid(unsafe_code)]

mod decode;
mod encode;
mod exif;
mod pack;
mod resize;
mod strip;

#[cfg(any(test, fuzzing))]
pub mod fuzz;
#[cfg(test)]
mod tests;

pub use decode::probe;
pub use pack::{read_pack, Entry, Pack};
pub use strip::strip;

/// Bumped whenever what `sanitize` writes may change: a copy cached under an
/// older version is made again (a decoder fix reaches every cached picture).
pub const SANITIZER_VERSION: u32 = 1;

/// What a picture is shown as, and so how big it may be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Inline in text: fits 128 × 128.
    Emote,
    /// A message of its own: fits 320 × 320.
    Sticker,
    /// A picture in the chat: at most 2560 on its long side, and a moving one
    /// as its `Motion` says. Saving it keeps the original; this is only what
    /// is drawn.
    Photo,
}

/// How much of a moving picture is kept: fitted into `side` × `side` (never
/// past its profile's box), and at most `keep` bytes of frames, past which
/// every other frame goes (it plays choppier, as long). A chat picture's come
/// from its server (`FileLimits`); the default is any other's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Motion {
    pub side: u32,
    pub keep: usize,
}

impl Default for Motion {
    fn default() -> Motion {
        Motion {
            side: 1024,
            keep: 128 << 20,
        }
    }
}

impl Profile {
    pub fn from_u32(n: u32) -> Option<Profile> {
        [Profile::Emote, Profile::Sticker, Profile::Photo]
            .get(n as usize)
            .copied()
    }

    fn side(self) -> u32 {
        match self {
            Profile::Emote => 128,
            Profile::Sticker => 320,
            Profile::Photo => 2560,
        }
    }

    /// The most bytes taken in: an emote or sticker file before it is made
    /// smaller for upload, or a chat file (64 MiB, `MAX_FILE_PLAIN`).
    fn max_input(self) -> usize {
        match self {
            Profile::Emote | Profile::Sticker => 16 << 20,
            Profile::Photo => 64 << 20,
        }
    }

    /// The most a picture written here may take before its animation is
    /// thinned: what this device keeps of it.
    pub fn max_output(self) -> usize {
        match self {
            Profile::Emote => 2 << 20,
            Profile::Sticker => 8 << 20,
            Profile::Photo => usize::MAX,
        }
    }
}

/// A picture as it may be shown.
#[derive(Debug)]
pub struct Clean {
    /// The PNG (an APNG when `frames` > 1).
    pub png: Vec<u8>,
    /// Its first frame alone, when it moves: for "animate on hover" and for
    /// reduced motion.
    pub still: Option<Vec<u8>>,
    pub w: u32,
    pub h: u32,
    pub frames: usize,
    /// Frames were dropped, or only the first kept, to stay under the cap.
    pub trimmed: bool,
}

/// Why a picture is not shown. The text is for people (the importer's report,
/// a chat card).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not a format read here, with what it seems to be.
    Unsupported(&'static str),
    /// Over a budget: too big, too many frames, too much work.
    TooLarge(&'static str),
    /// Broken, or not what it starts like.
    Corrupt(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unsupported(what) => write!(f, "{what} is not supported"),
            Error::TooLarge(what) => write!(f, "{what}"),
            Error::Corrupt(why) => write!(f, "the picture is damaged ({why})"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// `bytes` as a PNG written here, fitted into `profile`'s box, under its
/// output cap. Nothing of the input but its pixels and frame times survives:
/// no metadata, no colour profile, no chunk this crate did not write.
pub fn sanitize(bytes: &[u8], profile: Profile) -> Result<Clean> {
    sanitize_capped(bytes, profile, profile.max_output(), Motion::default())
}

/// `sanitize`, with at most `max_out` bytes of PNG (an animation over it
/// loses every other frame until a few are left, then all but its first),
/// and a moving picture kept as `motion` says.
pub fn sanitize_capped(
    bytes: &[u8],
    profile: Profile,
    max_out: usize,
    motion: Motion,
) -> Result<Clean> {
    if bytes.len() > profile.max_input() {
        return Err(Error::TooLarge("the file is too big"));
    }
    let mut sink = resize::Fit::new(profile.side(), motion);
    let orientation = decode::decode(bytes, &mut sink)?;
    let (mut frames, mut w, mut h, thinned) = sink.finish()?;
    if orientation > 1 {
        let (mut ow, mut oh) = (w, h);
        for f in &mut frames {
            (f.rgba, ow, oh) = exif::orient(&f.rgba, w, h, orientation);
        }
        (w, h) = (ow, oh);
    }
    let compression = if profile == Profile::Photo {
        png::Compression::Fast
    } else {
        png::Compression::Balanced
    };
    let mut trimmed = thinned;
    loop {
        let png = encode::write(&frames, w, h, compression)?;
        if png.len() <= max_out {
            let still = if frames.len() > 1 {
                Some(encode::write(&frames[..1], w, h, compression)?)
            } else {
                None
            };
            return Ok(Clean {
                png,
                still,
                w,
                h,
                frames: frames.len(),
                trimmed,
            });
        }
        trimmed = true;
        match frames.len() {
            1 => {
                return Err(Error::TooLarge(
                    "the picture is too big even after resizing",
                ))
            }
            n if n <= 8 => frames.truncate(1),
            _ => frames = resize::every_other(frames),
        }
    }
}
