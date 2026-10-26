#[cfg(not(target_os = "android"))]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
#[cfg(not(target_os = "android"))]
use std::sync::Arc;
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
    enumerate_displays, enumerate_windows, request_screencast, spawn_capture_task, CaptureSession,
};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{
    enumerate_displays, enumerate_windows, request_screencast, spawn_capture_task, CaptureSession,
};

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
        let mut spares = self.spare.lock().unwrap_or_else(|p| p.into_inner());
        if spares.len() < 2 {
            spares.push(buf);
        }
    }

    /// Grab a recycled buffer, if one is available.
    pub fn take_spare(&self) -> Option<Vec<u8>> {
        self.spare.lock().unwrap_or_else(|p| p.into_inner()).pop()
    }

    /// Store a new frame, returning the old one (if any) for buffer reuse.
    pub fn put(&self, frame: CapturedFrame) -> Option<CapturedFrame> {
        let mut slot = self.frame.lock().unwrap_or_else(|p| p.into_inner());
        let old = slot.replace(frame);
        self.notify.notify_one();
        old
    }

    /// Take the current frame, waiting up to `timeout` for one
    /// (`Duration::ZERO` just looks). `None` on timeout or once active is
    /// cleared.
    pub fn take_timeout(&self, timeout: Duration) -> Option<CapturedFrame> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.frame.lock().unwrap_or_else(|p| p.into_inner());
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

/// Next ladder level given the age of the last loss signal and the time
/// since the last level change (both in ms).
#[cfg(not(target_os = "android"))]
fn next_level(level: u8, loss_age_ms: u64, since_change_ms: u64) -> u8 {
    let max = (LEVELS.len() - 1) as u8;
    if loss_age_ms < LOSS_RECENT_MS {
        if since_change_ms >= STEP_DOWN_HOLD_MS && level < max {
            level + 1
        } else {
            level
        }
    } else if loss_age_ms >= STEP_UP_AFTER_MS && since_change_ms >= STEP_UP_AFTER_MS && level > 0 {
        level - 1
    } else {
        level
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod ladder_tests {
    use super::*;

    #[test]
    fn steps_down_on_recent_loss_with_hold_and_up_after_quiet() {
        // Fresh loss, long since the last change: one step down
        assert_eq!(next_level(0, 100, 10_000), 1);
        // A burst of reports within the hold time is one step, not many
        assert_eq!(next_level(1, 100, 500), 1);
        // Never past the last rung
        assert_eq!(next_level(3, 100, 10_000), 3);
        // Loss just stopped: hold the level
        assert_eq!(next_level(2, 5_000, 5_000), 2);
        // Quiet long enough (and not right after a change): climb one rung
        assert_eq!(next_level(2, 31_000, 31_000), 1);
        assert_eq!(next_level(2, 31_000, 1_000), 2);
        // Level 0 with no loss ever (loss_ms = 0 → huge age) stays put
        assert_eq!(next_level(0, u64::MAX, 60_000), 0);
        // Every rung keeps at least 1 fps and a positive bitrate
        for (scale, divisor) in LEVELS {
            assert!(scale > 0.0 && divisor >= 1);
        }
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
        let since_change = self.level_changed.elapsed().as_millis() as u64;
        let next = next_level(self.level, loss_age, since_change);
        if next == self.level {
            return;
        }
        let (scale, divisor) = LEVELS[next as usize];
        let kbps = ((self.base_bitrate_kbps as f32) * scale) as u32;
        let fps = (self.base_fps / divisor).max(1);
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
            }
            Err(e) => warn!("could not rebuild the encoder for level {next}: {e}"),
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
            .unwrap_or_else(|p| p.into_inner())
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
            let guard = self.media_key.lock().unwrap_or_else(|poisoned| {
                warn!("media key mutex poisoned — recovering");
                poisoned.into_inner()
            });
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
                let guard = self.media_key.lock().unwrap_or_else(|poisoned| {
                    warn!("media key mutex poisoned — recovering");
                    poisoned.into_inner()
                });
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

    let jpeg_data = match buffers.compressor.compress_yuv_to_vec(yuv_image) {
        Ok(data) => data,
        Err(e) => {
            warn!("TurboJPEG encode error: {}", e);
            return;
        }
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(&jpeg_data);
    let data_url = format!("data:image/jpeg;base64,{}", b64);
    // Only to the window that draws it: the pop-out while one is open, the
    // main window otherwise. `emit` went to every window, so a popped-out
    // share was serialised and delivered twice a frame — once to a main
    // window that was showing "popped out" instead of the picture.
    let target = if app_handle.get_webview_window(POPOUT_LABEL).is_some() {
        POPOUT_LABEL
    } else {
        "main"
    };
    let _ = app_handle.emit_to(target, "screenshare-frame", &data_url);
}

/// The pop-out viewer's window label (commands.rs `open_share_popout`).
pub const POPOUT_LABEL: &str = "screenshare-popout";
