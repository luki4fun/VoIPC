//! Pictures other people made, made safe to show (`voipc_media`): decoded by
//! memory-safe Rust, written out again as PNG. Two at a time, off the async
//! threads; a decoder that panics fails that one picture, nothing more. Its
//! budgets bound the time one takes, so no clock stops it.

use tokio::sync::Semaphore;
use voipc_media::{Clean, Profile};

/// Pictures sanitized at once: each may hold a large canvas.
static SLOTS: Semaphore = Semaphore::const_new(2);

pub async fn sanitize(bytes: Vec<u8>, profile: Profile, max_out: usize) -> Result<Clean, String> {
    let _slot = SLOTS.acquire().await.map_err(|e| e.to_string())?;
    let run =
        move || std::panic::catch_unwind(|| voipc_media::sanitize_capped(&bytes, profile, max_out));
    match tokio::task::spawn_blocking(run).await {
        Ok(Ok(Ok(clean))) => Ok(clean),
        Ok(Ok(Err(e))) => Err(e.to_string()),
        Ok(Err(_)) | Err(_) => Err("the picture could not be read".into()),
    }
}
