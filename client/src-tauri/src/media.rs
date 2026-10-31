//! Pictures other people made, made safe to show (`voipc_media`): decoded by
//! memory-safe Rust, written out again as PNG. A few at a time, off the async
//! threads, and never more pixels at once than a budget: two 50-megapixel
//! photos on a phone would be over a gigabyte. A decoder that panics fails
//! that one picture, nothing more. Its budgets bound the time one takes, so
//! no clock stops it.

use std::sync::Mutex;

use tokio::sync::Semaphore;
use voipc_media::{Clean, Motion, Profile};

/// Pictures sanitized at once.
static SLOTS: Semaphore = Semaphore::const_new(if cfg!(target_os = "android") { 2 } else { 4 });
/// Megapixels of canvas being sanitized at once: each holds about 4 bytes a
/// pixel, and a photo's decoder as much again.
const PIXELS: u32 = if cfg!(target_os = "android") { 50 } else { 100 };
static MEGAPIXELS: Semaphore = Semaphore::const_new(PIXELS as usize);

/// What a picture weighs against `MEGAPIXELS`: its canvas from its header, at
/// least one; half the budget where its header says nothing.
fn weight(bytes: &[u8]) -> u32 {
    voipc_media::probe(bytes).map_or(PIXELS / 2, |(w, h)| {
        (u64::from(w) * u64::from(h))
            .div_ceil(1_000_000)
            .clamp(1, u64::from(PIXELS)) as u32
    })
}

pub async fn sanitize(
    bytes: Vec<u8>,
    profile: Profile,
    max_out: usize,
    motion: Motion,
) -> Result<Clean, String> {
    let _slot = SLOTS.acquire().await.map_err(|e| e.to_string())?;
    // Its header is a peer's or a relay's: read off the async threads, and a
    // panic in it costs the picture, not the app
    let (bytes, pixels) = tokio::task::spawn_blocking(move || {
        let w = std::panic::catch_unwind(|| weight(&bytes)).unwrap_or(PIXELS / 2);
        (bytes, w)
    })
    .await
    .map_err(|_| "the picture could not be read".to_string())?;
    let _pixels = MEGAPIXELS
        .acquire_many(pixels)
        .await
        .map_err(|e| e.to_string())?;
    let run = move || {
        std::panic::catch_unwind(|| voipc_media::sanitize_capped(&bytes, profile, max_out, motion))
    };
    match tokio::task::spawn_blocking(run).await {
        Ok(Ok(Ok(clean))) => Ok(clean),
        Ok(Ok(Err(e))) => Err(e.to_string()),
        Ok(Err(_)) | Err(_) => Err("the picture could not be read".into()),
    }
}

/// Chat pictures made lately, by file and how (`file_image`): a channel's
/// cards come and go as it scrolls or is switched to, and making one again is
/// a decrypt and hundreds of ms of sanitizing. The newest last.
static MADE: Mutex<Vec<(String, Made)>> = Mutex::new(Vec::new());
/// What `MADE` may hold, in bytes.
const MADE_BYTES: usize = 64 << 20;

/// A chat picture as made: its PNG, its first frame when it moves, and why it
/// stands still when a moving one does (`Clean::stilled`).
#[derive(Clone)]
pub struct Made {
    pub png: Vec<u8>,
    pub first: Option<Vec<u8>>,
    pub stilled: Option<&'static str>,
}

impl From<Clean> for Made {
    fn from(c: Clean) -> Made {
        Made {
            png: c.png,
            first: c.still,
            stilled: c.stilled,
        }
    }
}

/// A picture made as `key` before.
pub fn made(key: &str) -> Option<Made> {
    let mut all = MADE.lock().unwrap_or_else(|e| e.into_inner());
    let at = all.iter().position(|(k, _)| k == key)?;
    let hit = all.remove(at);
    let out = hit.1.clone();
    all.push(hit);
    Some(out)
}

/// Let go of what was made of the file `hash` (blob id, hex; the keys start
/// `<hash>:`): its copy left this device, so its picture must not go on
/// showing from memory.
pub fn forget_made(hash: &str) {
    let mut all = MADE.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|(k, _)| {
        !k.split_once(':')
            .is_some_and(|(h, _)| h.eq_ignore_ascii_case(hash))
    });
}

/// Let go of everything made: the file cache is wiped.
pub fn forget_all_made() {
    MADE.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Keep what was made as `key`; the least recently asked for go past the cap.
pub fn keep_made(key: String, made: Made) {
    let size = |e: &(String, Made)| e.1.png.len() + e.1.first.as_ref().map_or(0, Vec::len);
    let mut all = MADE.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|(k, _)| *k != key);
    all.push((key, made));
    let mut total: usize = all.iter().map(size).sum();
    while total > MADE_BYTES && all.len() > 1 {
        total -= size(&all.remove(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_gone_from_this_device_takes_what_was_made_of_it() {
        let made_one = || Made {
            png: vec![1],
            first: None,
            stilled: None,
        };
        // Keys of their own: MADE is shared with any other test
        for key in [
            "f0e1:k1-Photo-0-0",
            "F0E1:k2-Photo-0-0",
            "f0e12:k-Photo-0-0",
        ] {
            keep_made(key.into(), made_one());
        }
        forget_made("f0e1");
        assert!(made("f0e1:k1-Photo-0-0").is_none());
        assert!(made("F0E1:k2-Photo-0-0").is_none(), "hex in either case");
        assert!(made("f0e12:k-Photo-0-0").is_some(), "another file stays");
    }
}
