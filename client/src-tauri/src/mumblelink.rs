//! MumbleLink: where the player is, from a game that will not tell a mod.
//!
//! A handful of games write their own avatar's position into a shared memory
//! block that Mumble defined and everyone copied. Guild Wars 2 is the reason
//! this file exists: ArenaNet writes it natively at about 25 Hz and documents
//! it, so proximity voice there needs no addon, no injection and no grey area —
//! which is more than can be said for every other way into an MMO.
//!
//! What this is **not**: a way to see other players. The block holds one
//! avatar, so this feeds [beacon mode](crate::sdk) — VoIPC broadcasts the one
//! position to the channel, encrypted like voice, and every other member's
//! client does the same. That broadcast is the only thing here that leaves the
//! machine, and like every beacon it happens only if the user allowed it
//! (Settings → Game Integration).
//!
//! ## Reading it safely
//!
//! The block is world-writable by convention: on Linux it is a file in
//! `/dev/shm` that any process can create, and on Windows a named mapping any
//! process can open. So it is treated exactly like the game SDK socket — an
//! untrusted local input that happens to be convenient:
//!
//! - only the first 44 bytes are read, which is version, tick and the three
//!   vectors. The fields after them (`name`, `description`, `identity`,
//!   `context`) name the player's game account and which server they are on;
//!   VoIPC has no use for them, so it does not look at them and cannot leak
//!   what it never read;
//! - `uiVersion` must be 2 and every float must be finite, for the same reason
//!   a NaN from a mod is refused: one would reach the mixer's gain ramp and
//!   silence a source for good;
//! - a `uiTick` that stops advancing means the game closed without clearing
//!   the block. A frozen position is worse than none — it would be beaconed to
//!   the channel for as long as the app runs — so it stops the feed instead.

use std::sync::atomic::Ordering;

use tauri::{Emitter, Manager};
use tracing::{info, warn};

use crate::app_state::{AppState, Motion};

/// How often the block is read. Guild Wars 2 writes at about 25 Hz; polling
/// faster buys nothing and polling much slower shows as stepping.
const POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// No new `uiTick` for this long means the game is gone (or paused in a menu
/// that stops updating), and the last position is stale.
const STALE: std::time::Duration = std::time::Duration::from_secs(1);

/// Bytes of the block we read: `uiVersion` (4) + `uiTick` (4) + three
/// `[f32; 3]` vectors (36). Everything after this is text about the player.
const HEAD: usize = 44;

/// The only version of the layout anyone writes.
const LINK_VERSION: u32 = 2;

/// The part of `LinkedMem` this reads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Link {
    pub tick: u32,
    /// Metres, VoIPC's frame: x/y on the ground, z up.
    pub pos: [f32; 3],
    /// Unit forward vector in the ground plane.
    pub fwd: [f32; 2],
}

/// Parse the head of a MumbleLink block, or `None` if it is not one we trust.
///
/// Free-standing and pure, so every rule above can be checked without a game,
/// a mapping or an app.
pub fn parse_link(buf: &[u8]) -> Option<Link> {
    if buf.len() < HEAD {
        return None;
    }
    let u32_at = |i: usize| u32::from_le_bytes(buf[i..i + 4].try_into().expect("4 bytes"));
    let f32_at = |i: usize| f32::from_le_bytes(buf[i..i + 4].try_into().expect("4 bytes"));
    if u32_at(0) != LINK_VERSION {
        return None;
    }
    let tick = u32_at(4);
    // A block nobody has written yet reads as zeroes, which is a valid
    // position at the origin — the tick is what tells the two apart.
    if tick == 0 {
        return None;
    }
    let avatar_pos = [f32_at(8), f32_at(12), f32_at(16)];
    let avatar_front = [f32_at(20), f32_at(24), f32_at(28)];
    if !avatar_pos.iter().chain(avatar_front.iter()).all(|c| c.is_finite()) {
        return None;
    }
    // Mumble's frame is the one games render in: Y up, and metres. VoIPC's is
    // the one games *simulate* in, which GTA and every mod so far agree on:
    // x/y on the ground, z up. So y and z swap.
    let pos = [avatar_pos[0], avatar_pos[2], avatar_pos[1]];
    let fwd = {
        let (x, y) = (avatar_front[0], avatar_front[2]);
        let len = (x * x + y * y).sqrt();
        if len > 1e-6 {
            [x / len, y / len]
        } else {
            // Looking straight up or down: keep the default rather than
            // dividing by nothing.
            [0.0, 1.0]
        }
    };
    Some(Link { tick, pos, fwd })
}

/// Where the block lives, and how to read it.
#[cfg(target_os = "linux")]
mod source {
    /// Mumble's own path, per-uid so two users on one machine do not collide.
    fn path() -> String {
        format!("/dev/shm/MumbleLink.{}", unsafe { libc::getuid() })
    }

    /// Open the block if something is publishing one.
    pub struct Block(std::fs::File);

    impl Block {
        pub fn open() -> Option<Self> {
            std::fs::File::open(path()).ok().map(Block)
        }

        pub fn read(&mut self, buf: &mut [u8]) -> bool {
            use std::io::{Read, Seek};
            self.0.rewind().is_ok() && self.0.read_exact(buf).is_ok()
        }
    }
}

#[cfg(target_os = "windows")]
mod source {
    use windows::core::w;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Memory::{
        MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS,
    };

    /// The mapping, held open for as long as the link is being read.
    pub struct Block {
        handle: HANDLE,
        view: MEMORY_MAPPED_VIEW_ADDRESS,
    }

    // The view is read-only memory owned by this struct; nothing else touches it.
    unsafe impl Send for Block {}

    impl Block {
        pub fn open() -> Option<Self> {
            unsafe {
                let handle = OpenFileMappingW(FILE_MAP_READ.0, false, w!("MumbleLink")).ok()?;
                let view = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, super::HEAD);
                if view.Value.is_null() {
                    let _ = CloseHandle(handle);
                    return None;
                }
                Some(Block { handle, view })
            }
        }

        pub fn read(&mut self, buf: &mut [u8]) -> bool {
            unsafe {
                std::ptr::copy_nonoverlapping(self.view.Value as *const u8, buf.as_mut_ptr(), buf.len());
            }
            true
        }
    }

    impl Drop for Block {
        fn drop(&mut self) {
            unsafe {
                let _ = UnmapViewOfFile(self.view);
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Nothing to read from: macOS has no convention for this, and Android has no
/// games writing one.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod source {
    pub struct Block;

    impl Block {
        pub fn open() -> Option<Self> {
            None
        }
        pub fn read(&mut self, _buf: &mut [u8]) -> bool {
            false
        }
    }
}

/// Watch the `mumblelink_enabled` setting and follow the link while it is on.
///
/// Shaped like [`crate::sdk::spawn`] and for the same reason: the setting can
/// be switched at any moment, and switching it off has to hand the mix back
/// rather than leave a game driving through a reader that no longer reads.
pub fn spawn(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut block: Option<source::Block> = None;
        let mut buf = vec![0u8; HEAD];
        let mut last_tick: Option<(u32, std::time::Instant)> = None;
        let mut driving = false;

        loop {
            tokio::time::sleep(POLL).await;
            let enabled = {
                let state = app.state::<AppState>();
                let config = match state.config.lock() {
                    Ok(c) => c,
                    Err(poisoned) => poisoned.into_inner(),
                };
                config.mumblelink_enabled
            };
            if !enabled {
                if driving {
                    driving = false;
                    block = None;
                    last_tick = None;
                    stop_driving(&app).await;
                }
                continue;
            }

            if block.is_none() {
                block = source::Block::open();
            }
            let Some(b) = block.as_mut() else { continue };
            let link = if b.read(&mut buf) {
                parse_link(&buf)
            } else {
                // The publisher went away and took the file with it
                block = None;
                None
            };

            let Some(link) = link else {
                if driving && last_tick.is_some_and(|(_, at)| at.elapsed() >= STALE) {
                    driving = false;
                    last_tick = None;
                    stop_driving(&app).await;
                }
                continue;
            };

            // A tick that has stopped advancing is a game that closed without
            // clearing the block. Beaconing a frozen position to the channel
            // for the rest of the session is worse than beaconing none.
            match last_tick {
                Some((tick, _)) if tick == link.tick => {
                    if driving && last_tick.is_some_and(|(_, at)| at.elapsed() >= STALE) {
                        info!("MumbleLink went stale — handing positions back");
                        driving = false;
                        stop_driving(&app).await;
                    }
                    continue;
                }
                _ => last_tick = Some((link.tick, std::time::Instant::now())),
            }

            if !driving {
                if start_driving(&app).await {
                    driving = true;
                } else {
                    continue;
                }
            }
            apply(&app, link).await;
        }
    });
}

/// Take over the listener's position, the way a `hello` in beacon mode does.
///
/// Returns whether it took: it will not while the user is not connected, and
/// it will not fight a game that already has the mix.
async fn start_driving(app: &tauri::AppHandle) -> bool {
    let state = app.state::<AppState>();
    let allowed = {
        let config = match state.config.lock() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        config.sdk_beacon_allowed
    };
    let conn = state.connection.read().await;
    let Some(connection) = conn.as_ref() else {
        return false;
    };
    {
        let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());
        if spatial.sdk_active {
            return false; // a game with the whole picture is already driving
        }
        spatial.clear_positions();
        spatial.sdk_channel = Some(connection.current_channel_id.load(Ordering::Relaxed));
        // Exactly the bookkeeping `on_hello` does for beacon mode, including
        // the part that matters: nothing goes on the wire unless the user
        // allowed it, and their own switch is remembered so closing the game
        // hands it straight back.
        spatial.user_sync = spatial.sync;
        spatial.beacon = true;
        spatial.sync = allowed;
    }
    if !allowed {
        warn!("MumbleLink is placing you locally; peers will not see you until you allow it");
    }
    let _ = app.emit(
        "sdk-status",
        serde_json::json!({
            "connected": true,
            "game": "MumbleLink",
            "resource": "",
            "beacon": allowed,
            "transmit": false,
        }),
    );
    info!("MumbleLink is driving this channel");
    true
}

/// Hand the positions back, exactly as a game disconnecting does.
async fn stop_driving(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    {
        let conn = state.connection.read().await;
        if let Some(connection) = conn.as_ref() {
            let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());
            spatial.clear_positions();
        }
    }
    state.sdk_event(crate::app_state::SdkEvent::Detached);
    let _ = app.emit(
        "sdk-status",
        serde_json::json!({"connected": false, "game": "", "resource": ""}),
    );
}

/// One reading, glided on from the last so 25 Hz does not step.
async fn apply(app: &tauri::AppHandle, link: Link) {
    let state = app.state::<AppState>();
    let conn = state.connection.read().await;
    let Some(connection) = conn.as_ref() else { return };
    let mut spatial = connection.spatial.lock().unwrap_or_else(|p| p.into_inner());
    let now = std::time::Instant::now();
    let over = spatial
        .last_update
        .map_or(POLL, |t| now.duration_since(t))
        .clamp(crate::app_state::MIN_GLIDE, crate::app_state::MAX_GLIDE);
    spatial.last_update = Some(now);

    let target = voipc_audio::spatial::Listener {
        pos: link.pos,
        fwd: link.fwd,
    };
    let motion = match spatial.listener_motion {
        Some(prev) => Motion {
            fwd: Some((prev.fwd_at(now), target.fwd)),
            ..Motion::glide(&prev, target.pos, over, now)
        },
        None => Motion {
            fwd: Some((target.fwd, target.fwd)),
            ..Motion::snap(target.pos, now)
        },
    };
    spatial.listener = target;
    spatial.listener_motion = Some(motion);
    spatial.dirty = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block as a game writes it: version, tick, then avatar position,
    /// front and top in Mumble's Y-up frame.
    fn block(version: u32, tick: u32, pos: [f32; 3], front: [f32; 3]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEAD);
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&tick.to_le_bytes());
        for v in pos.iter().chain(front.iter()).chain([0.0f32, 1.0, 0.0].iter()) {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf
    }

    #[test]
    fn a_reading_swaps_mumbles_frame_into_ours() {
        // Mumble is Y-up, in metres. VoIPC is Z-up, in metres — the frame
        // every game *simulation* uses and the one every mod sends.
        let link = parse_link(&block(2, 7, [1.0, 2.0, 3.0], [0.0, 0.0, 1.0]))
            .expect("a valid block was refused");
        assert_eq!(link.tick, 7);
        assert_eq!(link.pos, [1.0, 3.0, 2.0], "y and z did not swap");
        assert_eq!(link.fwd, [0.0, 1.0]);

        // Facing is normalised, and its height component is dropped
        let link = parse_link(&block(2, 8, [0.0; 3], [3.0, 9.0, 4.0])).unwrap();
        let len = (link.fwd[0] * link.fwd[0] + link.fwd[1] * link.fwd[1]).sqrt();
        assert!((len - 1.0).abs() < 1e-5, "facing is not a unit vector: {:?}", link.fwd);
        assert!(link.fwd[0] > 0.0 && link.fwd[1] > 0.0);

        // Looking straight up has no direction in the ground plane
        let link = parse_link(&block(2, 9, [0.0; 3], [0.0, 1.0, 0.0])).unwrap();
        assert_eq!(link.fwd, [0.0, 1.0]);
    }

    #[test]
    fn anything_but_a_block_we_trust_is_refused() {
        // The segment is world-writable by convention, so this is a trust
        // boundary and not a parser.
        assert!(parse_link(&[]).is_none(), "an empty read was accepted");
        assert!(parse_link(&block(2, 1, [0.0; 3], [0.0, 0.0, 1.0])[..20]).is_none());
        assert!(parse_link(&block(1, 1, [0.0; 3], [0.0, 0.0, 1.0])).is_none(), "wrong version");
        // Untouched shared memory is all zeroes, which is a valid position;
        // the tick is what says somebody actually wrote it.
        assert!(parse_link(&block(2, 0, [0.0; 3], [0.0, 0.0, 1.0])).is_none());
        // One NaN would reach the mixer's gain ramp and silence a source for
        // good — the same reason the SDK refuses one.
        assert!(parse_link(&block(2, 1, [f32::NAN, 0.0, 0.0], [0.0, 0.0, 1.0])).is_none());
        assert!(parse_link(&block(2, 1, [0.0; 3], [f32::INFINITY, 0.0, 1.0])).is_none());
    }

    #[test]
    fn nothing_after_the_head_is_ever_read() {
        // The fields past byte 44 are `name`, `description`, `identity` and
        // `context`: the player's game account and which server they are on.
        // VoIPC has no use for them, and what it does not read it cannot leak.
        let mut buf = block(2, 3, [1.0, 2.0, 3.0], [0.0, 0.0, 1.0]);
        let clean = parse_link(&buf).unwrap();
        buf.extend_from_slice(&[0xAB; 512]);
        assert_eq!(parse_link(&buf).unwrap(), clean);
    }
}
