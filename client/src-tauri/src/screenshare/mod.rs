#[cfg(not(target_os = "android"))]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
#[cfg(not(target_os = "android"))]
use std::sync::Arc;
#[cfg(not(target_os = "android"))]
use std::time::{Duration, Instant};

#[cfg(not(target_os = "android"))]
use base64::Engine;
#[cfg(not(target_os = "android"))]
use tauri::Emitter;
#[cfg(not(target_os = "android"))]
use tokio::sync::mpsc;
#[cfg(not(target_os = "android"))]
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
    CaptureSession, enumerate_displays, enumerate_windows, request_screencast, spawn_capture_task,
};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{
    CaptureSession, enumerate_displays, enumerate_windows, request_screencast, spawn_capture_task,
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

#[cfg(target_os = "android")]
pub struct FrameDecodeBuffers {
    jpeg_buf: Vec<u8>,
}

#[cfg(target_os = "android")]
impl FrameDecodeBuffers {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            jpeg_buf: Vec::with_capacity(512 * 1024),
        })
    }
}

#[cfg(target_os = "android")]
pub fn render_frame(
    frame: &voipc_video::decoder::DecodedFrame,
    app_handle: &tauri::AppHandle,
    buffers: &mut FrameDecodeBuffers,
) {
    use base64::Engine;
    use tauri::Emitter;

    let w = frame.width as usize;
    let h = frame.height as usize;

    // I420 (YUV420P) → RGB using the pure-Rust converter from voipc-video.
    // RGB, not RGBA: the `image` crate's JPEG encoder rejects an alpha channel
    // ("does not support the color type Rgba8"), which silently dropped every
    // frame and left the viewer on "Waiting for video stream...".
    let rgb = voipc_video::convert::i420_to_rgb(&frame.i420_data, w, h);

    // Encode RGB → JPEG using the `image` crate (pure Rust, no native deps)
    buffers.jpeg_buf.clear();
    let mut cursor = std::io::Cursor::new(&mut buffers.jpeg_buf);
    let Some(img) = image::RgbImage::from_raw(frame.width, frame.height, rgb) else {
        tracing::warn!("render_frame: invalid RGB buffer dimensions");
        return;
    };
    if let Err(e) = img.write_to(&mut cursor, image::ImageFormat::Jpeg) {
        tracing::warn!("JPEG encode error: {}", e);
        return;
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(&buffers.jpeg_buf);
    let data_url = format!("data:image/jpeg;base64,{}", b64);
    let _ = app_handle.emit("screenshare-frame", &data_url);
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

    /// Take the current frame, blocking until one is available or active becomes false.
    pub fn take(&self) -> Option<CapturedFrame> {
        let mut slot = self.frame.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if !self.active.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(frame) = slot.take() {
                return Some(frame);
            }
            let (guard, _) = self
                .notify
                .wait_timeout(slot, Duration::from_millis(50))
                .unwrap_or_else(|p| p.into_inner());
            slot = guard;
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
    pub keyframe_interval: u32,
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
    /// Captured frames seen — fps reduction skips every Nth.
    pub frame_counter: u32,
    pub video_tx: mpsc::Sender<Vec<u8>>,
    pub session_id: u32,
    pub media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    pub channel_id: Arc<AtomicU32>,
    pub frames_sent: Arc<AtomicU32>,
    pub bytes_sent: Arc<AtomicU64>,
}

#[cfg(not(target_os = "android"))]
impl FrameProcessor {
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
                self.keyframe_interval = voipc_video::KEYFRAME_INTERVAL_SECS * fps;
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

    /// Process a single captured frame: convert → encode → fragment → encrypt → send.
    pub fn process(
        &mut self,
        frame_bytes: &[u8],
        src_w: usize,
        src_h: usize,
        stride: usize,
        fmt: PixFmt,
    ) {
        // Congestion control first, and before a frame id is consumed:
        // frames skipped for the fps divisor must not leave gaps that the
        // viewers' assemblers would read as loss.
        self.adapt();
        self.frame_counter = self.frame_counter.wrapping_add(1);
        if self.frame_counter % LEVELS[self.level as usize].1 != 0 {
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
        let force_keyframe = self.keyframe_requested.swap(false, Ordering::Relaxed)
            || (self.frame_id % self.keyframe_interval == 0);

        let timestamp = self.start_time.elapsed().as_millis() as u32;
        let encoded_frames = match self.encoder.encode_video_frame(yuv_frame, force_keyframe) {
            Ok(frames) => frames,
            Err(e) => {
                warn!("{:?} encode error: {}", self.codec, e);
                return;
            }
        };

        self.send_encoded_frames(encoded_frames, timestamp);
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
                &self.full_res_i420_buf, src_w, src_h,
                &mut self.i420_buf, tw, th,
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
        let force_keyframe = self.keyframe_requested.swap(false, Ordering::Relaxed)
            || (self.frame_id % self.keyframe_interval == 0);

        let timestamp = self.start_time.elapsed().as_millis() as u32;
        let encoded_frames =
            match self
                .encoder
                .encode(&self.i420_buf, self.frame_id as i64, force_keyframe)
            {
                Ok(frames) => frames,
                Err(e) => {
                    warn!("{:?} encode error (scalar fallback): {}", self.codec, e);
                    return;
                }
            };

        self.send_encoded_frames(encoded_frames, timestamp);
    }

    /// Fragment → encrypt → send encoded frames over the video channel.
    /// Shared by both the fast (SwsContext) and scalar fallback paths.
    fn send_encoded_frames(
        &mut self,
        encoded_frames: Vec<voipc_video::encoder::EncodedFrame>,
        timestamp: u32,
    ) {
        let mut total_bytes: u64 = 0;
        let mut send_failed = false;

        // Clone the key (small: id + 32B) instead of holding the mutex across
        // fragmenting/encrypting/sending — voice paths share this mutex.
        let key_opt = self
            .media_key
            .lock()
            .unwrap_or_else(|poisoned| {
                warn!("media key mutex poisoned — recovering");
                poisoned.into_inner()
            })
            .clone();
        let key_opt = key_opt.as_ref();

        for ef in encoded_frames {

            // Use smaller fragment size when encrypting to account for
            // GCM tag (16B) + key_id header (2B) — keeps total packet
            // under MAX_VIDEO_PACKET_SIZE (VPN-safe).
            let max_payload = if key_opt.is_some() {
                voipc_protocol::video::MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE
            } else {
                voipc_protocol::video::MAX_VIDEO_PAYLOAD_SIZE
            };
            let packets = fragment_frame(
                &ef.data,
                ef.is_keyframe,
                self.session_id,
                self.frame_id,
                timestamp,
                max_payload,
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
                        self.video_tx.capacity(), fragment_count, self.frame_id
                    );
                    self.keyframe_requested.store(true, Ordering::Relaxed);
                    // Our own uplink is the bottleneck: counts as loss for the ladder
                    self.loss_ms.store(epoch_ms(), Ordering::Relaxed);
                    break;
                }
            } else {
                false
            };

            for pkt in packets {
                let final_pkt = if let Some(key) = key_opt {
                    let ch_id = self.channel_id.load(Ordering::Relaxed);
                    let pkt_type = if ef.is_keyframe { 0x14u8 } else { 0x13u8 };
                    let aad = voipc_crypto::media_keys::build_aad(ch_id, pkt_type);
                    match voipc_crypto::media_encrypt(
                        key,
                        self.session_id,
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
                                encrypted,
                            )
                        }
                        Err(e) => {
                            warn!("Video encryption failed: {}", e);
                            continue;
                        }
                    }
                } else {
                    // Never send plaintext: no key means we are still waiting
                    // for the channel's media key (the viewer sees a gap).
                    continue;
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
                                    return;
                                }
                                pending = returned;
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                self.active.store(false, Ordering::Relaxed);
                                return;
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
                            return;
                        }
                    }
                }
            }
            if send_failed {
                break;
            }
        }

        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(total_bytes, Ordering::Relaxed);
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
    pub media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    pub channel_id: Arc<AtomicU32>,
    /// Device-rate → 48kHz resampler, lazily built when `sample_rate` isn't
    /// 48kHz (WASAPI loopback runs at the output device's rate). Keyed by the
    /// rate it was built for so a renegotiation rebuilds it.
    pub resampler: Option<(u32, voipc_audio::resample::LinearResampler)>,
    /// Scratch for the downmixed mono chunk before resampling.
    pub mono_buf: Vec<f32>,
}

#[cfg(not(target_os = "android"))]
impl AudioProcessor {
    /// Process raw f32 audio bytes: downmix to mono, accumulate, Opus-encode, send.
    pub fn process(&mut self, raw_data: &[u8]) {
        if !self.audio_enabled.load(Ordering::Relaxed) {
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
        let samples: &[f32] =
            unsafe { std::slice::from_raw_parts(raw_data.as_ptr() as *const f32, sample_count) };

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
                    sum += samples[i * channels + ch];
                }
                self.mono_buf.push(sum / channels as f32);
            }
            if self.resampler.as_ref().is_none_or(|(r, _)| *r != rate) {
                self.resampler =
                    Some((rate, voipc_audio::resample::LinearResampler::new(rate, 48_000)));
            }
            let (_, resampler) = self.resampler.as_mut().expect("just set");
            resampler.process(&self.mono_buf, &mut self.accumulator);
        } else {
            for i in 0..frame_count {
                let mut sum = 0.0f32;
                for ch in 0..channels {
                    sum += samples[i * channels + ch];
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
            let key_opt = self
                .media_key
                .lock()
                .unwrap_or_else(|poisoned| {
                    warn!("media key mutex poisoned — recovering");
                    poisoned.into_inner()
                })
                .clone();

            let packet = if let Some(key) = key_opt.as_ref() {
                let ch_id = self.channel_id.load(Ordering::Relaxed);
                let aad = voipc_crypto::media_keys::build_aad(ch_id, 0x15);
                match voipc_crypto::media_encrypt(
                    key,
                    self.session_id,
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

// Android uses the pure-Rust image-crate path further up (no turbojpeg on NDK).
#[cfg(not(target_os = "android"))]
/// Reusable state for frame decoding + JPEG encoding.
pub struct FrameDecodeBuffers {
    pub compressor: turbojpeg::Compressor,
}

#[cfg(not(target_os = "android"))]
impl FrameDecodeBuffers {
    pub fn new() -> anyhow::Result<Self> {
        let mut compressor = turbojpeg::Compressor::new()
            .map_err(|e| anyhow::anyhow!("Failed to create TurboJPEG compressor: {e}"))?;
        compressor
            .set_quality(70)
            .map_err(|e| anyhow::anyhow!("Failed to set JPEG quality: {e}"))?;
        Ok(Self { compressor })
    }
}

#[cfg(not(target_os = "android"))]
/// Render a decoded frame to the frontend as a base64 JPEG.
pub fn render_frame(
    frame: &voipc_video::decoder::DecodedFrame,
    app_handle: &tauri::AppHandle,
    buffers: &mut FrameDecodeBuffers,
) {
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
    let _ = app_handle.emit("screenshare-frame", &data_url);
}
