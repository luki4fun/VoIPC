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
    let _pixels = MEGAPIXELS
        .acquire_many(weight(&bytes))
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
static MADE: Mutex<Vec<Made>> = Mutex::new(Vec::new());
/// A picture's key, its PNG, and its first frame when it moves.
type Made = (String, Vec<u8>, Option<Vec<u8>>);
/// What `MADE` may hold, in bytes.
const MADE_BYTES: usize = 64 << 20;

/// A picture made as `key` before: its PNG, and its first frame when it moves.
pub fn made(key: &str) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let mut all = MADE.lock().unwrap_or_else(|e| e.into_inner());
    let at = all.iter().position(|(k, ..)| k == key)?;
    let hit = all.remove(at);
    let out = (hit.1.clone(), hit.2.clone());
    all.push(hit);
    Some(out)
}

/// Keep what was made as `key`; the least recently asked for go past the cap.
pub fn keep_made(key: String, png: Vec<u8>, still: Option<Vec<u8>>) {
    let size = |e: &Made| e.1.len() + e.2.as_ref().map_or(0, Vec::len);
    let mut all = MADE.lock().unwrap_or_else(|e| e.into_inner());
    all.retain(|(k, ..)| *k != key);
    all.push((key, png, still));
    let mut total: usize = all.iter().map(size).sum();
    while total > MADE_BYTES && all.len() > 1 {
        total -= size(&all.remove(0));
    }
}
