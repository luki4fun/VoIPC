#[cfg(not(target_os = "android"))]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
#[cfg(not(target_os = "android"))]
use std::sync::{Arc, PoisonError};
#[cfg(not(target_os = "android"))]
use std::time::{Duration, Instant};

use base64::Engine;
use tauri::{Emitter, Manager};
#[cfg(not(target_os = "android"))]
use tokio::sync::mpsc;
use tracing::warn;

#[cfg(not(target_os = "android"))]
use tracing::info;
#[cfg(not(target_os = "android"))]
use voipc_protocol::video::{fragment_frame, ScreenShareAudioPacket};
#[cfg(not(target_os = "android"))]
use voipc_video::convert;

// ── Platform-specific capture backends ───────────────────────────────────

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    enumerate_displays, enumerate_windows, share_session, spawn_capture_task, x11_parent,
    CaptureSession,
};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
mod windows_preview;
#[cfg(target_os = "windows")]
pub use windows::{
    enumerate_displays, enumerate_windows, request_screencast, spawn_capture_task, CaptureSession,
};
#[cfg(target_os = "windows")]
pub use windows_preview::source_picture;

// ── Android stubs ────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
pub struct CaptureSession;

#[cfg(target_os = "android")]
pub fn enumerate_displays() -> Vec<DisplayInfo> {
    Vec::new()
}

#[cfg(target_os = "android")]
pub fn enumerate_windows() -> Vec<WindowInfo> {
    Vec::new()
}

// ── Source enumeration types (cross-platform) ─────────────────────────────

/// Information about an available display/monitor for screen capture.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisplayInfo {
    pub id: String,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
}

/// Information about an available window for screen capture.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WindowInfo {
    pub id: String,
    pub title: String,
    pub app_name: String,
}

// ── Shared types ─────────────────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
#[derive(Debug, Clone, Copy, PartialEq)]
// Windows capture only ever delivers BGRA; PipeWire delivers the rest
#[cfg_attr(windows, allow(dead_code))]
pub(crate) enum PixFmt {
    Bgra,
    Bgrx,
    Rgba,
    Rgbx,
    Unknown,
}

#[cfg(not(target_os = "android"))]
/// Opus parameters for screen share audio (desktop audio, not voice).
pub(crate) const SCREEN_AUDIO_FRAME_SIZE: usize = 960; // 20ms at 48kHz
#[cfg(not(target_os = "android"))]
pub(crate) const SCREEN_AUDIO_BITRATE: i32 = 64_000; // 64 kbps

// ── Capture → Encode decoupling ─────────────────────────────────────────

#[cfg(not(target_os = "android"))]
/// Raw captured frame data passed from the capture thread to the encode thread.
pub(crate) struct CapturedFrame {
    pub pixels: Vec<u8>,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub fmt: PixFmt,
}

#[cfg(not(target_os = "android"))]
/// Single-slot buffer for passing the latest captured frame to the encode thread.
/// Older frames are silently overwritten — the encoder always processes the most
/// recent frame. This prevents the capture thread from ever blocking on encoding.
pub(crate) struct FrameSlot {
    frame: std::sync::Mutex<Option<CapturedFrame>>,
    notify: std::sync::Condvar,
    active: Arc<AtomicBool>,
    /// Consumed pixel buffers returned by the encode thread for reuse.
    /// Without this, `put` only hands back a buffer when it displaces an
    /// unconsumed frame — i.e. the keeping-up case allocates every frame.
    spare: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(not(target_os = "android"))]
impl FrameSlot {
    pub fn new(active: Arc<AtomicBool>) -> Self {
        Self {
            frame: std::sync::Mutex::new(None),
            notify: std::sync::Condvar::new(),
            active,
            spare: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Return a consumed frame's buffer to the capture thread (capped at 2).
    pub fn recycle(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut spares = self.spare.lock().unwrap_or_else(PoisonError::into_inner);
        if spares.len() < 2 {
            spares.push(buf);
        }
    }

    /// Grab a recycled buffer, if one is available.
    pub fn take_spare(&self) -> Option<Vec<u8>> {
        self.spare
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    /// Store a new frame, returning the old one (if any) for buffer reuse.
    pub fn put(&self, frame: CapturedFrame) -> Option<CapturedFrame> {
        let mut slot = self.frame.lock().unwrap_or_else(PoisonError::into_inner);
        let old = slot.replace(frame);
        self.notify.notify_one();
        old
    }

    /// Take the current frame, waiting up to `timeout` for one
    /// (`Duration::ZERO` just looks). `None` on timeout or once active is
    /// cleared.
    pub fn take_timeout(&self, timeout: Duration) -> Option<CapturedFrame> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.frame.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if !self.active.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(frame) = slot.take() {
                return Some(frame);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            // Capped: teardown only clears `active`, it does not notify
            let (guard, _) = self
                .notify
                .wait_timeout(slot, (deadline - now).min(Duration::from_millis(50)))
                .unwrap_or_else(|p| p.into_inner());
            slot = guard;
        }
    }
}

/// Longest the encode thread waits for a captured frame before it looks at
/// the last one again. Damage-driven capture (PipeWire screencast, WGC)
/// sends nothing while the screen is still, so neither a viewer's keyframe
/// request nor the periodic IDR could be served from new frames, and a late
/// joiner waited on a blank viewer until something moved.
#[cfg(not(target_os = "android"))]
const IDLE_TICK: Duration = Duration::from_millis(200);

/// When to encode a frame that arrived at `now` while the next encode is
/// `due`: at once if at most a quarter interval early (compositor jitter, or
/// two buffers handed over in one loop pass), else at `due`, as whatever
/// frame is newest by then, so the last one of a burst is never the one
/// dropped.
#[cfg(not(target_os = "android"))]
fn encode_at(due: Instant, now: Instant, interval: Duration) -> Instant {
    if now + interval / 4 >= due {
        now
    } else {
        due
    }
}

/// Whether the periodic IDR is due. Timed, not counted, since a still screen
/// has no frames to count.
#[cfg(not(target_os = "android"))]
fn idr_due(last_idr: Option<Instant>) -> bool {
    last_idr.is_none_or(|t| {
        t.elapsed() >= Duration::from_secs(voipc_video::KEYFRAME_INTERVAL_SECS as u64)
    })
}

/// The encode side of both capture backends: paces the captured frames to
/// the ladder's fps by time, and while nothing new arrives re-encodes the
/// last one whenever a keyframe is owed or due.
///
/// The idle re-encode keeps the last `CapturedFrame` and re-runs `process()`,
/// which survives converter rebuilds and the scalar fallback; the cost is one
/// held capture buffer and one conversion per idle IDR.
#[cfg(not(target_os = "android"))]
pub(crate) fn run_encode_loop(slot: &FrameSlot, mut processor: FrameProcessor) {
    let mut last: Option<CapturedFrame> = None;
    let mut due = Instant::now();
    while processor.active.load(Ordering::Relaxed) {
        let Some(mut frame) = slot.take_timeout(IDLE_TICK) else {
            if let Some(frame) = &last {
                // A preview switched on over a still screen has nothing new
                // coming; it gets the last frame once
                if processor.preview_at.is_none() {
                    processor.render_preview(frame);
                }
                if processor.keyframe_requested.load(Ordering::Relaxed)
                    || idr_due(processor.last_idr)
                {
                    processor.process(frame);
                }
            }
            continue;
        };
        let interval = processor.frame_interval();
        let now = Instant::now();
        let at = encode_at(due, now, interval);
        if at > now {
            std::thread::sleep(at - now);
            if let Some(newer) = slot.take_timeout(Duration::ZERO) {
                slot.recycle(std::mem::replace(&mut frame, newer).pixels);
            }
        }
        due = (due + interval).max(at);
        // Fresh frames only: the idle re-encode above repeats `last`, and a
        // still screen does not need the same picture sent to the UI again.
        processor.render_preview(&frame);
        processor.process(&frame);
        if let Some(old) = last.replace(frame) {
            slot.recycle(old.pixels);
        }
    }
}

// ── Shared frame processing pipeline ─────────────────────────────────────

/// Video frame_id and screen-audio sequence feed the AES-GCM nonce
/// (session_id ‖ counter ‖ type/fragment) under the channel media key, which
/// outlives individual shares — so the counters must never restart while the
/// process runs, or share #2 would reuse share #1's nonces. Process-wide
/// monotonic, same reasoning as `voice_sequence` on the connection.
#[cfg(not(target_os = "android"))]
static SHARE_FRAME_ID: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_os = "android"))]
static SHARE_AUDIO_SEQ: AtomicU32 = AtomicU32::new(0);

/// Milliseconds since the Unix epoch — the clock shared by loss signals
/// (`ActiveConnection::share_loss_ms`) and the encoder's ladder.
pub fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Congestion control ───────────────────────────────────────────────────
//
// Viewers report frame loss every 2 s (VideoLossReport, relayed by the
// server) and the sender's own video queue reports backpressure; both land
// in `loss_ms`. The encoder then steps down a ladder of (bitrate scale, fps
// divisor) instead of re-sending ever more keyframes into a link that is
// already too small, and climbs back once the loss stays away.

/// Bitrate scale and fps divisor per level; level 0 is the configured quality.
#[cfg(not(target_os = "android"))]
const LEVELS: [(f32, u32); 4] = [(1.0, 1), (0.6, 1), (0.4, 2), (0.25, 2)];
/// A loss signal younger than this counts as current.
#[cfg(not(target_os = "android"))]
const LOSS_RECENT_MS: u64 = 2_000;
/// Minimum time between two step-downs, so one burst of reports is one step.
#[cfg(not(target_os = "android"))]
const STEP_DOWN_HOLD_MS: u64 = 3_000;
/// Loss-free time (and time since the last change) before stepping back up.
#[cfg(not(target_os = "android"))]
const STEP_UP_AFTER_MS: u64 = 30_000;
/// Where a share's video starts: one level below its configured quality.
#[cfg(not(target_os = "android"))]
pub(super) const START_LEVEL: u8 = 1;
/// Loss-free time from the start of a share's video before its first climb.
#[cfg(not(target_os = "android"))]
const FIRST_CLIMB_MS: u64 = 5_000;

/// The ladder's last change: the share's video starting, a climb, or a step down.
#[cfg(not(target_os = "android"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Change {
    Start,
    Up,
    Down,
}

/// Next ladder level given the age of the last loss signal, the time since the
/// last level change (both in ms) and what that change was (share-rules.ts
/// nextLevel, verbatim). A share's video starts at [`START_LEVEL`]: started at
/// full quality, it overloaded a small uplink for the seconds before the first
/// loss report came back, and voice lost frames meanwhile (capped-link lane,
/// 2026-11-23). The first climb comes once the link has carried the start
/// [`FIRST_CLIMB_MS`] with no loss at all (counted from the first frame out).
/// Once a loss came after the start, climbs wait [`STEP_UP_AFTER_MS`] of quiet,
/// as every later climb does. A climb that meets loss goes back at once,
/// without the hold, so a link too small for the level above pays one loss
/// report for trying it.
#[cfg(not(target_os = "android"))]
fn next_level(level: u8, loss_age_ms: u64, since_change_ms: u64, last: Change) -> u8 {
    let max = (LEVELS.len() - 1) as u8;
    if loss_age_ms < LOSS_RECENT_MS {
        if level < max && (last == Change::Up || since_change_ms >= STEP_DOWN_HOLD_MS) {
            level + 1
        } else {
            level
        }
    } else if level == 0 {
        level
    } else if last == Change::Start && loss_age_ms >= since_change_ms {
        // No loss since the video started (any loss is older than the start)
        if since_change_ms >= FIRST_CLIMB_MS {
            level - 1
        } else {
            level
        }
    } else if loss_age_ms >= STEP_UP_AFTER_MS && since_change_ms >= STEP_UP_AFTER_MS {
        level - 1
    } else {
        level
    }
}

/// Bitrate (kbps) and frame rate of `level` for a share configured at `kbps` and `fps`.
#[cfg(not(target_os = "android"))]
pub(super) fn level_rate(kbps: u32, fps: u32, level: u8) -> (u32, u32) {
    let (scale, divisor) = LEVELS[level as usize];
    (((kbps as f32) * scale) as u32, (fps / divisor).max(1))
}

#[cfg(all(test, not(target_os = "android")))]
mod ladder_tests {
    use super::*;

    #[test]
    fn steps_down_on_recent_loss_with_hold_and_up_after_quiet() {
        use Change::*;
        // Fresh loss, long since the last change: one step down
        assert_eq!(next_level(0, 100, 10_000, Down), 1);
        // A burst of reports within the hold time is one step, not many
        assert_eq!(next_level(1, 100, 500, Down), 1);
        // Never past the last rung
        assert_eq!(next_level(3, 100, 10_000, Down), 3);
        // Loss just stopped: hold the level
        assert_eq!(next_level(2, 5_000, 5_000, Down), 2);
        // Quiet long enough (and not right after a change): climb one rung
        assert_eq!(next_level(2, 31_000, 31_000, Down), 1);
        assert_eq!(next_level(2, 31_000, 1_000, Down), 2);
        // Level 0 with no loss ever (loss_ms = 0 → huge age) stays put
        assert_eq!(next_level(0, u64::MAX, 60_000, Up), 0);
        // Every rung keeps at least 1 fps and a positive bitrate
        for (scale, divisor) in LEVELS {
            assert!(scale > 0.0 && divisor >= 1);
        }
    }

    /// share-rules.test.ts "a share starts one level low...", the same cases.
    #[test]
    fn a_share_starts_one_level_low_climbs_after_quiet_and_a_climb_meeting_loss_goes_back() {
        use Change::*;
        assert_eq!(START_LEVEL, 1);
        assert_eq!(level_rate(3000, 30, START_LEVEL), (1800, 30));
        let never = u64::MAX;
        assert_eq!(
            next_level(START_LEVEL, never, 4_999, Start),
            1,
            "not before 5 s"
        );
        assert_eq!(
            next_level(START_LEVEL, never, 5_000, Start),
            0,
            "5 s without loss"
        );
        // A loss after the start, 3 s ago and over now: no quick climb on that link
        assert_eq!(next_level(START_LEVEL, 3_000, 6_000, Start), 1);
        // A loss from before this video started does not count
        assert_eq!(next_level(START_LEVEL, 9_000, 6_000, Start), 0);
        // Loss at the start level steps down with the hold, as any loss does
        assert_eq!(next_level(START_LEVEL, 100, 1_000, Start), 1);
        assert_eq!(next_level(START_LEVEL, 100, 3_000, Start), 2);
        // The climb met loss: back at once, without the hold
        assert_eq!(next_level(0, 100, 200, Up), 1);
        assert_eq!(
            next_level(1, 100, 200, Down),
            1,
            "the next step down holds again"
        );
        // After a climb back from loss, the next climb waits the long quiet
        assert_eq!(next_level(1, 10_000, 10_000, Down), 1);
        assert_eq!(next_level(1, 30_000, 30_000, Down), 0);
        // A loss in the start's first second, none since: the long quiet, never stuck at 60 %
        assert_eq!(next_level(START_LEVEL, 40_000, 41_000, Start), 0);
        assert_eq!(next_level(START_LEVEL, 599_500, 600_000, Start), 0);
        assert_eq!(next_level(START_LEVEL, 29_999, 30_500, Start), 1);
        // A loss at the very moment the video started counts as before it
        assert_eq!(next_level(START_LEVEL, 5_000, 5_000, Start), 0);
        // Start at level 0 (a rebuild at the video's start failed): nothing to climb
        assert_eq!(next_level(0, never, 60_000, Start), 0);
        assert_eq!(next_level(0, 100, 3_000, Start), 1);
        // After a successful climb above level 0, the next one waits the long quiet
        assert_eq!(next_level(2, 10_000, 10_000, Up), 2);
        assert_eq!(next_level(2, 30_000, 30_000, Up), 1);
    }

    /// The browser sharer's rule gives the same table (share-rules.test.ts, same grid and
    /// order): a change to one sharer's rule alone fails here or there.
    #[test]
    fn next_level_gives_the_table_the_browser_sharer_is_held_to() {
        const AGES: [u64; 9] = [
            100,
            1_999,
            2_000,
            3_000,
            4_999,
            5_000,
            6_000,
            30_000,
            1_000_000_000_000,
        ];
        let mut got = String::new();
        for level in 0..LEVELS.len() as u8 {
            for age in AGES {
                for since in AGES {
                    for change in [Change::Start, Change::Up, Change::Down] {
                        got.push(char::from(b'0' + next_level(level, age, since, change)));
                    }
                }
            }
        }
        let want = include_str!("../../../src/lib/share-ladder-grid.txt").trim();
        assert_eq!(got, want);
    }

    /// Indices of the arrivals `run_encode_loop` encodes, on a fake clock
    /// (the loop's pacing with the sleeps taken out).
    fn encoded(arrivals_us: &[u64], fps: u32) -> Vec<usize> {
        let t0 = Instant::now();
        let t = |us: u64| t0 + Duration::from_micros(us);
        let interval = Duration::from_secs(1) / fps;
        let (mut due, mut out, mut i) = (t0, Vec::new(), 0);
        while i < arrivals_us.len() {
            let at = encode_at(due, t(arrivals_us[i]), interval);
            while i + 1 < arrivals_us.len() && t(arrivals_us[i + 1]) <= at {
                i += 1;
            }
            out.push(i);
            due = (due + interval).max(at);
            i += 1;
        }
        out
    }

    #[test]
    fn pacing_holds_the_rate_without_dropping_the_last_frame() {
        // Paired buffers (two process callbacks in one loop pass) at 60 fps
        let paired: Vec<u64> = (0..60)
            .map(|k| (k / 2) * 33_333 + (k % 2) * 1_000)
            .collect();
        assert_eq!(encoded(&paired, 60).len(), 60);
        // A 144 Hz compositor paced to 60 fps, ending on its last frame
        let fast: Vec<u64> = (0..144).map(|k| k * 6_944).collect();
        let out = encoded(&fast, 60);
        assert!((59..=61).contains(&out.len()), "{} encoded", out.len());
        assert_eq!(out.last(), Some(&143));
    }

    #[test]
    fn periodic_idr_is_timed() {
        assert!(idr_due(None));
        assert!(!idr_due(Some(Instant::now())));
    }
}

#[cfg(not(target_os = "android"))]
/// State for the encode → fragment → encrypt → send video pipeline.
/// Used by both Linux (PipeWire) and Windows (WGC) capture backends.
pub(crate) struct FrameProcessor {
    pub encoder: voipc_video::encoder::Encoder,
    /// Codec of this share; the ladder rebuilds the encoder with it.
    pub codec: voipc_protocol::types::VideoCodec,
    pub i420_buf: Vec<u8>,
    pub full_res_i420_buf: Vec<u8>,
    /// SIMD-accelerated BGRA/RGBA → YUV420P converter (lazy-initialized on first frame).
    pub converter: Option<convert::FrameConverter>,
    /// Current frame's id — assigned from [`SHARE_FRAME_ID`] per frame, never
    /// incremented locally (nonce uniqueness across share sessions).
    pub frame_id: u32,
    /// When a keyframe last went out whole; the periodic IDR is timed from it.
    pub last_idr: Option<Instant>,
    pub start_time: Instant,
    pub target_width: u32,
    pub target_height: u32,
    pub active: Arc<AtomicBool>,
    pub keyframe_requested: Arc<AtomicBool>,
    /// Epoch ms of the last loss signal (viewer report or local
    /// backpressure), 0 = none. See `next_level`.
    pub loss_ms: Arc<AtomicU64>,
    /// Configured quality; the ladder scales it.
    pub base_bitrate_kbps: u32,
    pub base_fps: u32,
    /// Ladder level currently applied to the encoder.
    pub level: u8,
    pub level_changed: Instant,
    /// What the last level change was (`next_level`).
    pub last_change: Change,
    /// A frame went out since the video started: until one does, the first
    /// climb's quiet does not count.
    pub sent_since_start: bool,
    pub video_tx: mpsc::Sender<Vec<u8>>,
    pub session_id: u32,
    pub media_key: Arc<std::sync::Mutex<voipc_crypto::MediaKeyRing>>,
    pub channel_id: Arc<AtomicU32>,
    pub frames_sent: Arc<AtomicU32>,
    pub bytes_sent: Arc<AtomicU64>,
    /// People watching (`ActiveConnection::share_viewers`). Capture also runs
    /// for the sharer's own preview with nobody watching; nothing is encoded
    /// or sent then.
    pub viewers: Arc<AtomicU32>,
    /// Whether the last frame had anyone to go to: the first one that does
    /// is a keyframe.
    pub watched: bool,
    /// The sharer's own preview is on screen (`set_share_preview`).
    pub preview: Arc<AtomicBool>,
    pub app: tauri::AppHandle,
    /// Source → stream size in RGB, for the preview JPEG. Rebuilt like the
    /// encoder's converter when the source changes.
    pub preview_conv: Option<convert::FrameConverter>,
    pub preview_jpeg: Option<turbojpeg::Compressor>,
    /// Last preview rendered; None while it is off, or not drawn yet.
    pub preview_at: Option<Instant>,
}

/// How often the sharer's own preview is redrawn. It is a check of what goes
/// out, not the stream itself, and every frame of it is a JPEG over IPC.
#[cfg(not(target_os = "android"))]
const PREVIEW_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(not(target_os = "android"))]
impl FrameProcessor {
    /// Show the sharer what they send: the frame at the stream's own size and
    /// scaling, as a JPEG data URL on `screenshare-preview`, at most every
    /// `PREVIEW_INTERVAL`.
    ///
    /// bernd: a second scale/convert pass beside the encoder's, which on most
    /// encoders already holds the same picture in YUV. Reuse that if this
    /// ever shows in a profile.
    pub fn render_preview(&mut self, frame: &CapturedFrame) {
        if !self.preview.load(Ordering::Relaxed) {
            // Shown again later, it starts from the last frame (run_encode_loop)
            self.preview_at = None;
            return;
        }
        if self
            .preview_at
            .is_some_and(|t| t.elapsed() < PREVIEW_INTERVAL)
        {
            return;
        }
        let fmt = match frame.fmt {
            PixFmt::Bgra | PixFmt::Bgrx => convert::Pixel::BGRA,
            PixFmt::Rgba | PixFmt::Rgbx => convert::Pixel::RGBA,
            PixFmt::Unknown => return,
        };
        let (src_w, src_h) = (frame.width as u32, frame.height as u32);
        if self
            .preview_conv
            .as_ref()
            .is_some_and(|c| c.src_dims() != (src_w, src_h) || c.input_format() != fmt)
        {
            self.preview_conv = None;
        }
        let (tw, th) = (self.target_width, self.target_height);
        let conv = match &mut self.preview_conv {
            Some(c) => c,
            None => {
                match convert::FrameConverter::new(fmt, src_w, src_h, tw, th, convert::Pixel::RGB24)
                {
                    Ok(c) => self.preview_conv.insert(c),
                    Err(e) => {
                        warn!("preview converter: {e}");
                        // Retried at the preview's rate, not on every frame
                        self.preview_at = Some(Instant::now());
                        return;
                    }
                }
            }
        };
        self.preview_at = Some(Instant::now());
        let rgb = match conv.convert_strided(&frame.pixels, frame.stride) {
            Ok(f) => f,
            Err(e) => {
                warn!("preview convert: {e}");
                self.preview_conv = None;
                return;
            }
        };
        if self.preview_jpeg.is_none() {
            match FrameDecodeBuffers::new() {
                Ok(b) => self.preview_jpeg = Some(b.compressor),
                Err(e) => {
                    warn!("preview JPEG: {e}");
                    return;
                }
            }
        }
        let Some(jpeg) = self.preview_jpeg.as_mut() else {
            return;
        };
        let image = turbojpeg::Image {
            pixels: rgb.data(0),
            width: tw as usize,
            pitch: rgb.stride(0),
            height: th as usize,
            format: turbojpeg::PixelFormat::RGB,
        };
        match jpeg.compress_to_vec(image) {
            Ok(data) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                let data_url = format!("data:image/jpeg;base64,{b64}");
                // The main window's: the popout shows somebody else's share
                let _ = self.app.emit_to("main", "screenshare-preview", &data_url);
            }
            Err(e) => warn!("preview JPEG encode: {e}"),
        }
    }

    /// Step the quality ladder if the loss picture changed: rebuilds the
    /// encoder at the new bitrate/fps (a fresh encoder starts with an IDR,
    /// which the viewers need anyway). Keeps the old encoder if the rebuild
    /// fails.
    fn adapt(&mut self) {
        let loss_age = epoch_ms().saturating_sub(self.loss_ms.load(Ordering::Relaxed));
        // Nothing has crossed the link yet (no media key, a still screen): no quiet to count
        let since_change = if self.last_change == Change::Start && !self.sent_since_start {
            0
        } else {
            self.level_changed.elapsed().as_millis() as u64
        };
        let next = next_level(self.level, loss_age, since_change, self.last_change);
        if next == self.level {
            return;
        }
        let change = if next < self.level {
            Change::Up
        } else {
            Change::Down
        };
        self.set_level(next, change);
    }

    /// Applies ladder level `next` to the encoder: in place where it can, else
    /// a rebuild. Keeps the old encoder (and level) if the rebuild fails.
    fn set_level(&mut self, next: u8, change: Change) {
        let (kbps, fps) = level_rate(self.base_bitrate_kbps, self.base_fps, next);
        // In place where the encoder can, without the IDR a rebuild forces
        // into the congested link (H3-08)
        if self.encoder.set_rate(kbps, fps) {
            info!(
                from = self.level,
                to = next,
                kbps,
                fps,
                "screen share quality level changed in place"
            );
            self.level = next;
            self.last_change = change;
            self.level_changed = Instant::now();
            return;
        }
        match voipc_video::encoder::Encoder::new(
            self.codec,
            self.target_width,
            self.target_height,
            kbps,
            fps,
        ) {
            Ok(encoder) => {
                // The converter's output format follows the encoder (NV12 for QSV)
                if encoder.pixel_format() != self.encoder.pixel_format() {
                    self.converter = None;
                }
                self.encoder = encoder;
                self.keyframe_requested.store(true, Ordering::Relaxed);
                info!(
                    from = self.level,
                    to = next,
                    kbps,
                    fps,
                    "screen share quality level changed"
                );
                self.level = next;
                self.last_change = change;
            }
            Err(e) => {
                warn!("could not rebuild the encoder for level {next}: {e}");
                // Counted as tried, so a step back after a climb holds too
                self.last_change = Change::Down;
            }
        }
        // Also after a failure, so the rebuild is not retried every frame
        self.level_changed = Instant::now();
    }

    /// Time between two encodes at the current ladder level.
    fn frame_interval(&self) -> Duration {
        Duration::from_secs(LEVELS[self.level as usize].1 as u64) / self.base_fps.max(1)
    }

    /// Process a single captured frame: convert → encode → fragment → encrypt → send.
    pub fn process(&mut self, frame: &CapturedFrame) {
        let CapturedFrame {
            pixels: ref frame_bytes,
            width: src_w,
            height: src_h,
            stride,
            fmt,
        } = *frame;

        // Nobody watching: capture runs for the sharer's preview alone. Before
        // the ladder, the media key and the keyframe swap, so an owed keyframe
        // stays owed; and the first watched frame is one, since a viewer
        // arriving within the IDR interval would otherwise start on deltas and
        // the server's keyframe relay is rate-limited.
        let watched = self.viewers.load(Ordering::Relaxed) > 0;
        if watched && !self.watched {
            self.keyframe_requested.store(true, Ordering::Relaxed);
            // Its video starts one level low and climbs once the link carries
            // it (`next_level`); a level the ladder stepped below that stays, and
            // its quiet counts again from now: time with nobody watching tells
            // nothing of the link.
            if self.level <= START_LEVEL {
                if self.level != START_LEVEL {
                    self.set_level(START_LEVEL, Change::Start);
                }
                self.last_change = Change::Start;
                self.sent_since_start = false;
            }
            self.level_changed = Instant::now();
        }
        self.watched = watched;
        if !watched {
            return;
        }

        // Congestion control first: a new level rebuilds the encoder and owes
        // an IDR; its fps divisor is paced by time in `run_encode_loop`.
        self.adapt();
        // No media key yet: spend neither an encode nor a frame id, and an
        // owed IDR stays owed
        if self
            .media_key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .current()
            .is_none()
        {
            return;
        }

        let tw = self.target_width;
        let th = self.target_height;

        let ffmpeg_fmt = match fmt {
            PixFmt::Bgra | PixFmt::Bgrx => convert::Pixel::BGRA,
            PixFmt::Rgba | PixFmt::Rgbx => convert::Pixel::RGBA,
            PixFmt::Unknown => return,
        };

        // Rebuild the converter if the source changed size or pixel format
        // (portal renegotiation, window resize) — a stale SwsContext would read
        // with the old stride, or swap red and blue.
        if self.converter.as_ref().is_some_and(|c| {
            c.src_dims() != (src_w as u32, src_h as u32) || c.input_format() != ffmpeg_fmt
        }) {
            info!(
                "source format changed to {}x{} {:?} — rebuilding converter",
                src_w, src_h, fmt
            );
            self.converter = None;
        }

        // Lazy-init the SIMD converter on first frame (or if source dimensions change)
        let converter = match &mut self.converter {
            Some(c) => c,
            None => {
                // Output format must match what the encoder was opened with
                // (NV12 for QSV, YUV420P otherwise).
                let enc_pf = self.encoder.pixel_format();
                match convert::FrameConverter::new(
                    ffmpeg_fmt,
                    src_w as u32,
                    src_h as u32,
                    tw,
                    th,
                    enc_pf,
                ) {
                    Ok(c) => {
                        info!(
                            "FrameConverter: initialized SwsContext ({}x{} {:?} → {}x{} {:?})",
                            src_w, src_h, fmt, tw, th, enc_pf
                        );
                        self.converter = Some(c);
                        self.converter.as_mut().unwrap()
                    }
                    Err(e) => {
                        warn!("FrameConverter init failed: {} — falling back to scalar", e);
                        self.process_scalar(frame_bytes, src_w, src_h, stride, fmt);
                        return;
                    }
                }
            }
        };

        // Convert BGRA/RGBA → YUV420P using FFmpeg's SIMD-optimized SwsContext.
        // convert_strided handles stride padding natively — no separate strip needed.
        let yuv_frame = match converter.convert_strided(frame_bytes, stride) {
            Ok(f) => f,
            Err(e) => {
                warn!("FrameConverter error: {} — falling back to scalar", e);
                self.converter = None;
                self.process_scalar(frame_bytes, src_w, src_h, stride, fmt);
                return;
            }
        };

        self.frame_id = SHARE_FRAME_ID.fetch_add(1, Ordering::Relaxed);
        let force_keyframe =
            self.keyframe_requested.swap(false, Ordering::Relaxed) || idr_due(self.last_idr);

        let timestamp = self.start_time.elapsed().as_millis() as u32;
        let encoded = self.encoder.encode_video_frame(yuv_frame, force_keyframe);
        self.send_or_owe(encoded, force_keyframe, timestamp);
    }

    /// Fallback: process using the naive scalar BGRA→I420 conversion.
    /// Only used if FrameConverter initialization or conversion fails.
    fn process_scalar(
        &mut self,
        frame_bytes: &[u8],
        src_w: usize,
        src_h: usize,
        stride: usize,
        fmt: PixFmt,
    ) {
        let tw = self.target_width as usize;
        let th = self.target_height as usize;

        let pixel_data: &[u8] = if stride == src_w * 4 && frame_bytes.len() >= src_w * src_h * 4 {
            &frame_bytes[..src_w * src_h * 4]
        } else {
            &[]
        };

        let owned_pixels;
        let pixel_data = if pixel_data.is_empty() {
            owned_pixels = strip_stride_padding(frame_bytes, src_w, src_h, stride);
            &owned_pixels
        } else {
            pixel_data
        };

        if pixel_data.len() < src_w * src_h * 4 {
            return;
        }

        let needs_resize = src_w != tw || src_h != th;

        if needs_resize {
            match fmt {
                PixFmt::Bgra | PixFmt::Bgrx => {
                    convert::bgra_to_i420(pixel_data, src_w, src_h, &mut self.full_res_i420_buf);
                }
                PixFmt::Rgba | PixFmt::Rgbx => {
                    convert::rgba_to_i420(pixel_data, src_w, src_h, &mut self.full_res_i420_buf);
                }
                PixFmt::Unknown => return,
            }
            convert::scale_i420_nearest(
                &self.full_res_i420_buf,
                src_w,
                src_h,
                &mut self.i420_buf,
                tw,
                th,
            );
        } else {
            match fmt {
                PixFmt::Bgra | PixFmt::Bgrx => {
                    convert::bgra_to_i420(pixel_data, tw, th, &mut self.i420_buf);
                }
                PixFmt::Rgba | PixFmt::Rgbx => {
                    convert::rgba_to_i420(pixel_data, tw, th, &mut self.i420_buf);
                }
                PixFmt::Unknown => return,
            }
        }

        self.frame_id = SHARE_FRAME_ID.fetch_add(1, Ordering::Relaxed);
        let force_keyframe =
            self.keyframe_requested.swap(false, Ordering::Relaxed) || idr_due(self.last_idr);

        let timestamp = self.start_time.elapsed().as_millis() as u32;
        let encoded = self
            .encoder
            .encode(&self.i420_buf, self.frame_id as i64, force_keyframe);
        self.send_or_owe(encoded, force_keyframe, timestamp);
    }

    /// Send what the encoder produced. A forced IDR that did not go out
    /// whole is owed again; the next frame or the idle tick retries.
    fn send_or_owe(
        &mut self,
        encoded: anyhow::Result<Vec<voipc_video::encoder::EncodedFrame>>,
        force_keyframe: bool,
        timestamp: u32,
    ) {
        let sent_key = match encoded {
            Ok(frames) => self.send_encoded_frames(frames, timestamp),
            Err(e) => {
                warn!("{:?} encode error: {}", self.codec, e);
                false
            }
        };
        if force_keyframe && !sent_key {
            self.keyframe_requested.store(true, Ordering::Relaxed);
        }
    }

    /// Fragment → encrypt → send encoded frames over the video channel.
    /// Shared by both the fast (SwsContext) and scalar fallback paths.
    /// Returns whether a keyframe went out whole.
    fn send_encoded_frames(
        &mut self,
        encoded_frames: Vec<voipc_video::encoder::EncodedFrame>,
        timestamp: u32,
    ) -> bool {
        let mut total_bytes: u64 = 0;
        let mut send_failed = false;
        let mut sent_key = false;

        // Clone the key (small: id + 32B) instead of holding the mutex across
        // fragmenting/encrypting/sending — voice paths share this mutex.
        let (key, stream_id) = {
            let guard = self
                .media_key
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (guard.current().cloned(), guard.stream_id())
        };
        // Never send plaintext: no key means we are still waiting for the
        // channel's media key (the viewer sees a gap).
        let Some(key) = key else {
            return false;
        };

        for ef in encoded_frames {
            // The smaller fragment size accounts for the GCM tag (16B) +
            // key_id header (2B) — keeps the total packet under
            // MAX_VIDEO_PACKET_SIZE (VPN-safe).
            let packets = fragment_frame(
                &ef.data,
                ef.is_keyframe,
                self.session_id,
                self.frame_id,
                timestamp,
                voipc_protocol::video::MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE,
            );

            // Pre-check: ensure channel has room for ALL fragments before
            // sending any. This guarantees all-or-nothing delivery — no
            // partial frames that would corrupt the viewer's decoder.
            let fragment_count = packets.len();
            let must_block = if self.video_tx.capacity() < fragment_count {
                if ef.is_keyframe {
                    true
                } else {
                    warn!(
                        "video channel low ({} < {} fragments) — skipping delta frame {}",
                        self.video_tx.capacity(),
                        fragment_count,
                        self.frame_id
                    );
                    self.keyframe_requested.store(true, Ordering::Relaxed);
                    // Our own uplink is the bottleneck: counts as loss for the ladder
                    self.loss_ms.store(epoch_ms(), Ordering::Relaxed);
                    break;
                }
            } else {
                false
            };

            let mut whole = true;
            for pkt in packets {
                let ch_id = self.channel_id.load(Ordering::Relaxed);
                let pkt_type = if ef.is_keyframe { 0x14u8 } else { 0x13u8 };
                let aad = voipc_crypto::media_keys::build_aad(ch_id, pkt_type, self.session_id);
                let final_pkt = match voipc_crypto::media_encrypt(
                    &key,
                    stream_id,
                    self.frame_id,
                    pkt.fragment_index as u32,
                    &aad,
                    &pkt.payload,
                ) {
                    Ok(encrypted) => {
                        use voipc_protocol::video::VideoPacket;
                        VideoPacket::encrypted_fragment(
                            ef.is_keyframe,
                            self.session_id,
                            self.frame_id,
                            pkt.fragment_index,
                            pkt.fragment_count,
                            timestamp,
                            key.key_id,
                            stream_id,
                            encrypted,
                        )
                    }
                    Err(e) => {
                        warn!("Video encryption failed: {}", e);
                        whole = false;
                        continue;
                    }
                };

                let bytes = final_pkt.to_bytes();
                let byte_len = bytes.len() as u64;

                if must_block {
                    // Wait for room rather than corrupt the frame, but stay
                    // interruptible: teardown signals only through `active`,
                    // and the stop/switch paths drop the task handle after a
                    // short timeout, so a parked send would strand this
                    // pipeline (and its encoder and capture session) alongside
                    // the next one.
                    let mut pending = bytes;
                    loop {
                        match self.video_tx.try_send(pending) {
                            Ok(()) => {
                                total_bytes += byte_len;
                                break;
                            }
                            Err(mpsc::error::TrySendError::Full(returned)) => {
                                if !self.active.load(Ordering::Relaxed) {
                                    return false;
                                }
                                pending = returned;
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                self.active.store(false, Ordering::Relaxed);
                                return false;
                            }
                        }
                    }
                } else {
                    match self.video_tx.try_send(bytes) {
                        Ok(()) => {
                            total_bytes += byte_len;
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!(
                                "unexpected channel full during frame {} send",
                                self.frame_id
                            );
                            self.keyframe_requested.store(true, Ordering::Relaxed);
                            // Our own uplink is the bottleneck: counts as loss for the ladder
                            self.loss_ms.store(epoch_ms(), Ordering::Relaxed);
                            send_failed = true;
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            self.active.store(false, Ordering::Relaxed);
                            return false;
                        }
                    }
                }
            }
            if send_failed {
                break;
            }
            if ef.is_keyframe && whole {
                sent_key = true;
                self.last_idr = Some(Instant::now());
            }
        }

        // The first frame out since the video started: the first climb's quiet counts from here
        if !self.sent_since_start {
            self.sent_since_start = true;
            if self.last_change == Change::Start {
                self.level_changed = Instant::now();
            }
        }
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(total_bytes, Ordering::Relaxed);
        sent_key
    }
}

// ── Shared audio processing pipeline ─────────────────────────────────────

#[cfg(not(target_os = "android"))]
/// State for screen share audio: accumulate → Opus encode → encrypt → send.
pub(crate) struct AudioProcessor {
    pub encoder: Option<voipc_audio::encoder::Encoder>,
    pub accumulator: Vec<f32>,
    pub sequence: u32,
    pub session_id: u32,
    pub start_time: Instant,
    pub audio_tx: mpsc::Sender<Vec<u8>>,
    pub active: Arc<AtomicBool>,
    pub audio_enabled: Arc<AtomicBool>,
    pub packet_count: Arc<AtomicU32>,
    pub sample_rate: u32,
    pub channels: u32,
    pub media_key: Arc<std::sync::Mutex<voipc_crypto::MediaKeyRing>>,
    pub channel_id: Arc<AtomicU32>,
    /// Device-rate → 48kHz resampler, lazily built when `sample_rate` isn't
    /// 48kHz (WASAPI loopback runs at the output device's rate). Keyed by the
    /// rate it was built for so a renegotiation rebuilds it.
    pub resampler: Option<(u32, voipc_audio::resample::Resampler)>,
    /// Scratch for the downmixed mono chunk before resampling.
    pub mono_buf: Vec<f32>,
    /// People watching; with none, capture runs for the video preview only
    /// and no screen audio is sent.
    pub viewers: Arc<AtomicU32>,
}

#[cfg(not(target_os = "android"))]
impl AudioProcessor {
    /// Process raw f32 audio bytes: downmix to mono, accumulate, Opus-encode, send.
    pub fn process(&mut self, raw_data: &[u8]) {
        if !self.audio_enabled.load(Ordering::Relaxed) || self.viewers.load(Ordering::Relaxed) == 0
        {
            self.accumulator.clear();
            return;
        }

        let encoder = match self.encoder.as_mut() {
            Some(e) => e,
            None => return,
        };

        let channels = self.channels as usize;
        if channels == 0 {
            return;
        }

        let sample_count = raw_data.len() / 4;
        // Read, not cast: a PipeWire or WASAPI buffer need not be 4-aligned,
        // and a `&[f32]` over one that is not is undefined behaviour (H3-17)
        let sample =
            |i: usize| f32::from_ne_bytes(raw_data[i * 4..i * 4 + 4].try_into().expect("4 bytes"));

        let frame_count = sample_count / channels;
        let rate = self.sample_rate;
        if rate != 0 && rate != 48_000 {
            // Device delivers at its own rate (WASAPI loopback especially);
            // Opus frames must be 48kHz — downmix, then resample into the
            // accumulator. Without this the audio plays pitch-shifted.
            self.mono_buf.clear();
            for i in 0..frame_count {
                let mut sum = 0.0f32;
                for ch in 0..channels {
                    sum += sample(i * channels + ch);
                }
                self.mono_buf.push(sum / channels as f32);
            }
            if self.resampler.as_ref().is_none_or(|(r, _)| *r != rate) {
                self.resampler = Some((rate, voipc_audio::resample::Resampler::new(rate, 48_000)));
            }
            let (_, resampler) = self.resampler.as_mut().expect("just set");
            resampler.process(&self.mono_buf, &mut self.accumulator);
        } else {
            for i in 0..frame_count {
                let mut sum = 0.0f32;
                for ch in 0..channels {
                    sum += sample(i * channels + ch);
                }
                self.accumulator.push(sum / channels as f32);
            }
        }

        while self.accumulator.len() >= SCREEN_AUDIO_FRAME_SIZE {
            let frame: Vec<f32> = self.accumulator.drain(..SCREEN_AUDIO_FRAME_SIZE).collect();
            // Assigned per frame, never incremented locally (nonce uniqueness
            // across share sessions — see SHARE_AUDIO_SEQ).
            self.sequence = SHARE_AUDIO_SEQ.fetch_add(1, Ordering::Relaxed);

            let opus_data = match encoder.encode(&frame) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Screen audio Opus encode error: {}", e);
                    continue;
                }
            };

            let timestamp = self.start_time.elapsed().as_millis() as u32;

            // Clone instead of holding the shared mutex across encrypt+send.
            let (key_opt, stream_id) = {
                let guard = self
                    .media_key
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                (guard.current().cloned(), guard.stream_id())
            };

            let packet = if let Some(key) = key_opt.as_ref() {
                let ch_id = self.channel_id.load(Ordering::Relaxed);
                let aad = voipc_crypto::media_keys::build_aad(ch_id, 0x15, self.session_id);
                match voipc_crypto::media_encrypt(
                    key,
                    stream_id,
                    self.sequence,
                    0,
                    &aad,
                    &opus_data,
                ) {
                    Ok(encrypted) => ScreenShareAudioPacket::new_encrypted(
                        self.session_id,
                        self.sequence,
                        timestamp,
                        key.key_id,
                        stream_id,
                        encrypted,
                    ),
                    Err(e) => {
                        warn!("Screen audio encryption failed: {}", e);
                        continue;
                    }
                }
            } else {
                // Never send plaintext (see the video path above)
                continue;
            };

            match self.audio_tx.try_send(packet.to_bytes()) {
                Ok(()) => {
                    self.packet_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.active.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
    }
}

// ── Shared helper functions ──────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
/// Strip row padding from capture buffer (when stride > width * 4).
pub(crate) fn strip_stride_padding(
    data: &[u8],
    width: usize,
    height: usize,
    stride: usize,
) -> Vec<u8> {
    let row_bytes = width * 4;
    let mut tight = Vec::with_capacity(width * height * 4);
    for row in 0..height {
        let start = row * stride;
        let end = start + row_bytes;
        if end <= data.len() {
            tight.extend_from_slice(&data[start..end]);
        }
    }
    tight
}

// ── Frame decoding (viewer side — cross-platform) ────────────────────────

/// Reusable state for frame decoding + JPEG encoding. Android too: its
/// pure-Rust path (I420 → RGB → `image` JPEG) took 32 ms a 1080p frame on a
/// desktop core, several times that on a phone; TurboJPEG from the YUV takes
/// 2 (H3-07).
pub struct FrameDecodeBuffers {
    pub compressor: turbojpeg::Compressor,
}

impl FrameDecodeBuffers {
    pub fn new() -> anyhow::Result<Self> {
        let mut compressor = turbojpeg::Compressor::new()
            .map_err(|e| anyhow::anyhow!("Failed to create TurboJPEG compressor: {e}"))?;
        // q90: at q70 the viewer's JPEG lost 15 dB more on text than the video
        // codec did (H3-04). It costs about 75 % more IPC; binary frames to a
        // WebGL viewer are the 1.x answer.
        compressor
            .set_quality(90)
            .map_err(|e| anyhow::anyhow!("Failed to set JPEG quality: {e}"))?;
        Ok(Self { compressor })
    }
}

/// Render a decoded frame to the frontend as a base64 JPEG, in JPEG's own
/// YCbCr: only the frame shown pays for that conversion.
pub fn render_frame(
    frame: &mut voipc_video::decoder::DecodedFrame,
    app_handle: &tauri::AppHandle,
    buffers: &mut FrameDecodeBuffers,
) {
    let started = std::time::Instant::now();
    voipc_video::to_jpeg_ycbcr(
        &mut frame.i420_data,
        frame.width as usize,
        frame.height as usize,
        frame.full_range,
        frame.bt709,
    );
    let yuv_image = turbojpeg::YuvImage {
        pixels: frame.i420_data.as_slice(),
        width: frame.width as usize,
        height: frame.height as usize,
        align: 1,
        subsamp: turbojpeg::Subsamp::Sub2x2,
    };

    let converted = std::time::Instant::now();
    let jpeg_data = match buffers.compressor.compress_yuv_to_vec(yuv_image) {
        Ok(data) => data,
        Err(e) => {
            warn!("TurboJPEG encode error: {}", e);
            return;
        }
    };
    let compressed = std::time::Instant::now();

    let b64 = base64::engine::general_purpose::STANDARD.encode(&jpeg_data);
    let url = format!("data:image/jpeg;base64,{}", b64);
    let (seq, at_ms) = crate::view_timing::stamp();
    // Only to the window that draws it: the pop-out while one is open, the
    // main window otherwise. `emit` went to every window, so a popped-out
    // share was serialised and delivered twice a frame — once to a main
    // window that was showing "popped out" instead of the picture.
    let target = if app_handle.get_webview_window(POPOUT_LABEL).is_some() {
        POPOUT_LABEL
    } else {
        "main"
    };
    let _ = app_handle.emit_to(
        target,
        "screenshare-frame",
        &SharedFrame { url, seq, at_ms },
    );
    crate::view_timing::rendered(
        converted - started,
        compressed - converted,
        compressed.elapsed(),
    );
}

/// A shown frame as the WebView gets it: the picture, its number, and the wall-clock ms
/// it went out at, for `report_view_timing`.
#[derive(serde::Serialize)]
struct SharedFrame {
    url: String,
    seq: u64,
    at_ms: u64,
}

// ── Share picker pictures (Windows; pure, so they test anywhere) ───────────

/// A picker tile's picture: the source's still as a JPEG data URL, and a window's icon as a
/// PNG one, the tile's picture when there is no still (minimised, protected, one colour).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SourcePicture {
    pub picture: Option<String>,
    pub icon: Option<String>,
}

/// The largest a picker tile's picture is made.
pub(crate) const PREVIEW_MAX: (u32, u32) = (320, 180);

/// The size a source's picture is drawn at: within `PREVIEW_MAX`, its aspect kept, never
/// larger than the source, at least one pixel a side.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn preview_size(w: u32, h: u32) -> (u32, u32) {
    if w == 0 || h == 0 {
        return (1, 1);
    }
    let (mw, mh) = PREVIEW_MAX;
    let scale = (mw as f64 / w as f64).min(mh as f64 / h as f64).min(1.0);
    let fit = |v: u32| ((v as f64 * scale).round() as u32).max(1);
    (fit(w), fit(h))
}

/// A BGRA picture made smaller by area averaging: each output pixel is the mean of the source
/// pixels it covers, so text and edges blur instead of flickering in and out.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn downscale_bgra(
    src: &[u8],
    w: usize,
    h: usize,
    stride: usize,
    ow: usize,
    oh: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; ow * oh * 4];
    if w == 0 || h == 0 || ow == 0 || oh == 0 || src.len() < stride * (h - 1) + w * 4 {
        return out;
    }
    for oy in 0..oh {
        let (y0, y1) = (oy * h / oh, ((oy + 1) * h / oh).max(oy * h / oh + 1).min(h));
        for ox in 0..ow {
            let (x0, x1) = (ox * w / ow, ((ox + 1) * w / ow).max(ox * w / ow + 1).min(w));
            let mut sum = [0u32; 4];
            for y in y0..y1 {
                let row = &src[y * stride..];
                for x in x0..x1 {
                    for (c, s) in sum.iter_mut().enumerate() {
                        *s += row[x * 4 + c] as u32;
                    }
                }
            }
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            let o = (oy * ow + ox) * 4;
            for c in 0..4 {
                out[o + c] = (sum[c] / n) as u8;
            }
        }
    }
    out
}

/// Whether a picture is (nearly) one colour: black from a minimised, protected or GPU-only
/// window says nothing, and the tile shows the window's icon instead. Samples a 16x16 grid.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn one_colour(bgra: &[u8], w: usize, h: usize) -> bool {
    if w == 0 || h == 0 || bgra.len() < w * h * 4 {
        return true;
    }
    let at = |x: usize, y: usize| {
        let o = (y * w + x) * 4;
        [bgra[o], bgra[o + 1], bgra[o + 2]]
    };
    let first = at(0, 0);
    (0..16).all(|j| {
        (0..16).all(|i| {
            let p = at(i * (w - 1) / 15, j * (h - 1) / 15);
            (0..3).all(|c| p[c].abs_diff(first[c]) <= 6)
        })
    })
}

/// A tile's picture as a JPEG data URL, or None for one that says nothing (`one_colour`).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn preview_url(bgra: &[u8], w: usize, h: usize) -> Option<String> {
    if one_colour(bgra, w, h) {
        return None;
    }
    let image = turbojpeg::Image {
        pixels: bgra,
        width: w,
        pitch: w * 4,
        height: h,
        format: turbojpeg::PixelFormat::BGRA,
    };
    let jpeg = turbojpeg::compress(image, 80, turbojpeg::Subsamp::Sub2x2).ok()?;
    Some(format!(
        "data:image/jpeg;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(&*jpeg)
    ))
}

/// The pop-out viewer's window label (commands.rs `open_share_popout`).
pub const POPOUT_LABEL: &str = "screenshare-popout";

#[cfg(test)]
mod picker_tests {
    use super::*;

    #[test]
    fn a_tile_fits_its_box_and_keeps_the_aspect() {
        assert_eq!(preview_size(1920, 1080), (320, 180));
        assert_eq!(preview_size(2560, 1440), (320, 180));
        assert_eq!(preview_size(1080, 1920), (101, 180), "portrait");
        assert_eq!(preview_size(3440, 1440), (320, 134), "ultra-wide");
        assert_eq!(preview_size(200, 100), (200, 100), "never enlarged");
        assert_eq!(preview_size(0, 50), (1, 1));
    }

    #[test]
    fn a_smaller_picture_is_the_mean_of_what_it_covers() {
        // 4x2, a stride with padding: left half black, right half white
        let mut src = vec![9u8; 20 * 2];
        for y in 0..2 {
            for x in 0..4 {
                let v = if x < 2 { 0 } else { 255 };
                src[y * 20 + x * 4..y * 20 + x * 4 + 4].copy_from_slice(&[v, v, v, 255]);
            }
        }
        assert_eq!(
            downscale_bgra(&src, 4, 2, 20, 2, 1),
            vec![0, 0, 0, 255, 255, 255, 255, 255]
        );
        // Everything into one pixel: grey
        assert_eq!(
            downscale_bgra(&src, 4, 2, 20, 1, 1),
            vec![127, 127, 127, 255]
        );
        assert_eq!(
            downscale_bgra(&src[..10], 4, 2, 20, 1, 1),
            vec![0; 4],
            "too short: blank"
        );
    }

    #[test]
    fn a_picture_of_one_colour_says_nothing() {
        let black = vec![0u8; 64 * 36 * 4];
        assert!(one_colour(&black, 64, 36));
        assert_eq!(preview_url(&black, 64, 36), None);
        let mut ramp = black.clone();
        for (i, p) in ramp.chunks_mut(4).enumerate() {
            p[1] = (i % 64 * 4) as u8;
        }
        assert!(!one_colour(&ramp, 64, 36));
        assert!(
            preview_url(&ramp, 64, 36).is_some_and(|u| u.starts_with("data:image/jpeg;base64,"))
        );
        // Noise of a few levels (a nearly black window) is still one colour
        let mut dim = black;
        dim[4 * 70] = 5;
        assert!(one_colour(&dim, 64, 36));
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod group_key_tests {
    use super::*;
    use crate::network::tests::{voice_keys, Epoch, ROOM};
    use voipc_crypto::MediaKeyRing;

    /// Whether a screen-audio packet opens under `ring`, read as the datagram receiver
    /// reads one (`ScreenShareAudioPacket::from_bytes`, then `open_media`).
    fn opens(ring: &std::sync::Mutex<MediaKeyRing>, bytes: &[u8]) -> bool {
        let p = ScreenShareAudioPacket::from_bytes(bytes).unwrap();
        let opened = crate::network::open_media(
            &mut ring.lock().unwrap(),
            ROOM,
            0x15,
            p.session_id,
            p.stream_id,
            p.key_id,
            (p.sequence, 0),
            &p.opus_data,
        );
        p.encrypted && opened.is_some_and(|o| o.is_ok())
    }

    /// Plan part 5: a share's audio goes under its sharer's own key from the room's epoch
    /// key, with no change to the share's send site (`current()`, the ring's stream). Every
    /// member the roster seats opens it; after a leave the share goes on under the next
    /// epoch, which the leaver cannot open.
    #[test]
    fn under_the_group_key_a_shares_audio_opens_for_the_room_and_not_for_a_leaver() {
        let e1: Epoch = (1, rand::random(), rand::random());
        let e2: Epoch = (2, rand::random(), rand::random());
        let rings: Vec<Arc<std::sync::Mutex<MediaKeyRing>>> =
            (0..3).map(|_| Arc::default()).collect();
        let take = |sid: u32, epochs: &[Epoch], roster: &[u32]| {
            let keys = voice_keys(sid, epochs, roster);
            let ring = &rings[sid as usize - 1];
            assert!(ring.lock().unwrap().install_gk(&keys, ROOM));
        };
        for sid in 1..=3 {
            take(sid, &[e1], &[1, 2, 3]);
        }
        let (audio_tx, mut audio_rx) = mpsc::channel(8);
        let mut share = AudioProcessor {
            encoder: Some(
                voipc_audio::encoder::Encoder::new_screen_audio(SCREEN_AUDIO_BITRATE).unwrap(),
            ),
            accumulator: Vec::new(),
            sequence: 0,
            session_id: 1,
            start_time: Instant::now(),
            audio_tx,
            active: Arc::new(AtomicBool::new(true)),
            audio_enabled: Arc::new(AtomicBool::new(true)),
            packet_count: Arc::default(),
            sample_rate: 48_000,
            channels: 1,
            media_key: rings[0].clone(),
            channel_id: Arc::new(AtomicU32::new(ROOM)),
            resampler: None,
            mono_buf: Vec::new(),
            viewers: Arc::new(AtomicU32::new(2)),
        };
        let tone: Vec<u8> = (0..SCREEN_AUDIO_FRAME_SIZE)
            .flat_map(|i| ((i as f32 / 8.0).sin() * 0.25).to_ne_bytes())
            .collect();

        share.process(&tone);
        let first = audio_rx.try_recv().unwrap();
        assert!(opens(&rings[1], &first) && opens(&rings[2], &first));

        // Member 3 leaves: the opening's epoch reaches the sharer and member 2 only
        take(1, &[e1, e2], &[1, 2]);
        take(2, &[e1, e2], &[1, 2]);
        share.process(&tone);
        let next = audio_rx.try_recv().unwrap();
        assert_eq!(ScreenShareAudioPacket::from_bytes(&next).unwrap().key_id, 2);
        assert!(opens(&rings[1], &next), "the room hears the share go on");
        assert!(!opens(&rings[2], &next), "the leaver does not");
    }
}
