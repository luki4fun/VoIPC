use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use tauri::Emitter;
use tokio::sync::mpsc;
use tracing::warn;

use tracing::info;
use voipc_protocol::video::{fragment_frame, ScreenShareAudioPacket};
use voipc_video::convert;

// ── Platform-specific capture backends ───────────────────────────────────

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{CaptureSession, request_screencast, spawn_capture_task};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{CaptureSession, request_screencast, spawn_capture_task};

// ── Shared types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum PixFmt {
    Bgra,
    Bgrx,
    Rgba,
    Rgbx,
    Unknown,
}

/// Opus parameters for screen share audio (desktop audio, not voice).
pub(crate) const SCREEN_AUDIO_FRAME_SIZE: usize = 960; // 20ms at 48kHz
pub(crate) const SCREEN_AUDIO_BITRATE: i32 = 64_000; // 64 kbps

// ── Capture → Encode decoupling ─────────────────────────────────────────

/// Raw captured frame data passed from the capture thread to the encode thread.
pub(crate) struct CapturedFrame {
    pub pixels: Vec<u8>,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub fmt: PixFmt,
}

/// Single-slot buffer for passing the latest captured frame to the encode thread.
/// Older frames are silently overwritten — the encoder always processes the most
/// recent frame. This prevents the capture thread from ever blocking on encoding.
pub(crate) struct FrameSlot {
    frame: std::sync::Mutex<Option<CapturedFrame>>,
    notify: std::sync::Condvar,
    active: Arc<AtomicBool>,
}

impl FrameSlot {
    pub fn new(active: Arc<AtomicBool>) -> Self {
        Self {
            frame: std::sync::Mutex::new(None),
            notify: std::sync::Condvar::new(),
            active,
        }
    }

    /// Store a new frame, returning the old one (if any) for buffer reuse.
    pub fn put(&self, frame: CapturedFrame) -> Option<CapturedFrame> {
        let mut slot = self.frame.lock().unwrap();
        let old = slot.replace(frame);
        self.notify.notify_one();
        old
    }

    /// Take the current frame, blocking until one is available or active becomes false.
    pub fn take(&self) -> Option<CapturedFrame> {
        let mut slot = self.frame.lock().unwrap();
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
                .unwrap();
            slot = guard;
        }
    }
}

// ── Shared frame processing pipeline ─────────────────────────────────────

/// State for the encode → fragment → encrypt → send video pipeline.
/// Used by both Linux (PipeWire) and Windows (scrap) capture backends.
pub(crate) struct FrameProcessor {
    pub encoder: voipc_video::encoder::Encoder,
    pub i420_buf: Vec<u8>,
    pub full_res_i420_buf: Vec<u8>,
    /// SIMD-accelerated BGRA/RGBA → YUV420P converter (lazy-initialized on first frame).
    pub converter: Option<convert::FrameConverter>,
    pub frame_id: u32,
    pub keyframe_interval: u32,
    pub start_time: Instant,
    pub target_width: u32,
    pub target_height: u32,
    pub active: Arc<AtomicBool>,
    pub keyframe_requested: Arc<AtomicBool>,
    pub video_tx: mpsc::Sender<Vec<u8>>,
    pub session_id: u32,
    pub udp_token: u64,
    pub media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    pub channel_id: Arc<AtomicU32>,
    pub frames_sent: Arc<AtomicU32>,
    pub bytes_sent: Arc<AtomicU64>,
}

impl FrameProcessor {
    /// Process a single captured frame: convert → encode → fragment → encrypt → send.
    pub fn process(
        &mut self,
        frame_bytes: &[u8],
        src_w: usize,
        src_h: usize,
        stride: usize,
        fmt: PixFmt,
    ) {
        let tw = self.target_width;
        let th = self.target_height;

        let ffmpeg_fmt = match fmt {
            PixFmt::Bgra | PixFmt::Bgrx => convert::Pixel::BGRA,
            PixFmt::Rgba | PixFmt::Rgbx => convert::Pixel::RGBA,
            PixFmt::Unknown => return,
        };

        // Lazy-init the SIMD converter on first frame (or if source dimensions change)
        let converter = match &mut self.converter {
            Some(c) => c,
            None => {
                match convert::FrameConverter::new(
                    ffmpeg_fmt,
                    src_w as u32,
                    src_h as u32,
                    tw,
                    th,
                ) {
                    Ok(c) => {
                        info!(
                            "FrameConverter: initialized SwsContext ({}x{} {:?} → {}x{} YUV420P)",
                            src_w, src_h, fmt, tw, th
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

        let force_keyframe = self.keyframe_requested.swap(false, Ordering::Relaxed)
            || (self.frame_id % self.keyframe_interval == 0);

        let timestamp = self.start_time.elapsed().as_millis() as u32;
        let encoded_frames = match self.encoder.encode_video_frame(yuv_frame, force_keyframe) {
            Ok(frames) => frames,
            Err(e) => {
                warn!("H.265 encode error: {}", e);
                self.frame_id = self.frame_id.saturating_add(1);
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
                    warn!("H.265 encode error (scalar fallback): {}", e);
                    self.frame_id = self.frame_id.saturating_add(1);
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

        for ef in encoded_frames {
            let key_guard = self.media_key.lock().unwrap_or_else(|poisoned| {
                warn!("media key mutex poisoned — recovering");
                poisoned.into_inner()
            });
            let key_opt = key_guard.as_ref();

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
                self.udp_token,
                self.frame_id,
                timestamp,
                max_payload,
            );

            // Pre-check: ensure channel has room for ALL fragments before
            // sending any. This guarantees all-or-nothing delivery — no
            // partial frames that would corrupt the viewer's H.265 decoder.
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
                    send_failed = true;
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
                                self.udp_token,
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
                    pkt
                };

                let bytes = final_pkt.to_bytes();
                let byte_len = bytes.len() as u64;

                if must_block {
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        if handle.block_on(self.video_tx.send(bytes)).is_err() {
                            self.active.store(false, Ordering::Relaxed);
                            return;
                        }
                        total_bytes += byte_len;
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
        self.frame_id = self.frame_id.saturating_add(1);
    }
}

// ── Shared audio processing pipeline ─────────────────────────────────────

/// State for screen share audio: accumulate → Opus encode → encrypt → send.
pub(crate) struct AudioProcessor {
    pub encoder: Option<voipc_audio::encoder::Encoder>,
    pub accumulator: Vec<f32>,
    pub sequence: u32,
    pub session_id: u32,
    pub udp_token: u64,
    pub start_time: Instant,
    pub audio_tx: mpsc::Sender<Vec<u8>>,
    pub active: Arc<AtomicBool>,
    pub audio_enabled: Arc<AtomicBool>,
    pub packet_count: Arc<AtomicU32>,
    pub sample_rate: u32,
    pub channels: u32,
    pub media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    pub channel_id: Arc<AtomicU32>,
}

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
        for i in 0..frame_count {
            let mut sum = 0.0f32;
            for ch in 0..channels {
                sum += samples[i * channels + ch];
            }
            self.accumulator.push(sum / channels as f32);
        }

        while self.accumulator.len() >= SCREEN_AUDIO_FRAME_SIZE {
            let frame: Vec<f32> = self.accumulator.drain(..SCREEN_AUDIO_FRAME_SIZE).collect();

            let opus_data = match encoder.encode(&frame) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Screen audio Opus encode error: {}", e);
                    continue;
                }
            };

            let timestamp = self.start_time.elapsed().as_millis() as u32;

            let key_guard = self.media_key.lock().unwrap_or_else(|poisoned| {
                warn!("media key mutex poisoned — recovering");
                poisoned.into_inner()
            });
            let key_opt = key_guard.as_ref();

            let packet = if let Some(key) = key_opt {
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
                        self.udp_token,
                        self.sequence,
                        timestamp,
                        key.key_id,
                        encrypted,
                    ),
                    Err(e) => {
                        warn!("Screen audio encryption failed: {}", e);
                        self.sequence = self.sequence.saturating_add(1);
                        continue;
                    }
                }
            } else {
                ScreenShareAudioPacket::new(
                    self.session_id,
                    self.udp_token,
                    self.sequence,
                    timestamp,
                    opus_data,
                )
            };
            self.sequence = self.sequence.saturating_add(1);

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

/// Reusable state for frame decoding + JPEG encoding.
pub struct FrameDecodeBuffers {
    pub compressor: turbojpeg::Compressor,
}

impl FrameDecodeBuffers {
    pub fn new() -> Self {
        let mut compressor =
            turbojpeg::Compressor::new().expect("Failed to create TurboJPEG compressor");
        compressor
            .set_quality(70)
            .expect("Failed to set JPEG quality");
        Self { compressor }
    }
}

/// Render a decoded VP8 frame to the frontend as a base64 JPEG.
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
