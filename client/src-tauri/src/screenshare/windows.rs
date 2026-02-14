use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::{
    AudioProcessor, CapturedFrame, FrameProcessor, FrameSlot, PixFmt, SCREEN_AUDIO_BITRATE,
    SCREEN_AUDIO_FRAME_SIZE,
};

// ── Public API ──────────────────────────────────────────────────────────

/// An active screen capture session on Windows.
/// Stores which display to capture; the actual `scrap::Capturer` is created
/// inside the capture thread (it is not `Send`).
pub struct CaptureSession {
    display_index: usize,
}

/// Open the primary display for screen sharing.
///
/// On Windows there is no native portal picker like on Linux; we default to
/// the primary display. The frontend could be extended later to let the user
/// choose from `scrap::Display::all()`.
pub async fn request_screencast() -> Result<CaptureSession, String> {
    // Validate that the primary display is accessible.
    let _display =
        scrap::Display::primary().map_err(|e| format!("Failed to access display: {e}"))?;
    Ok(CaptureSession { display_index: 0 })
}

/// Spawn the DXGI screen capture + H.265 encode + fragment task.
///
/// Internally spawns two threads:
/// - **Capture thread** (fast): DXGI frame acquisition → memcpy → release.
/// - **Encode thread** (CPU-heavy): BGRA→I420 → H.265 encode → fragment → send.
///
/// Connected by a single-slot "latest frame wins" buffer so capture never
/// blocks on encoding and DXGI frames are released immediately.
#[allow(clippy::too_many_arguments)]
pub fn spawn_capture_task(
    session: &CaptureSession,
    target_width: u32,
    target_height: u32,
    target_fps: u32,
    bitrate: u32,
    session_id: u32,
    udp_token: u64,
    active: Arc<AtomicBool>,
    keyframe_requested: Arc<AtomicBool>,
    video_tx: mpsc::Sender<Vec<u8>>,
    audio_tx: mpsc::Sender<Vec<u8>>,
    audio_enabled: Arc<AtomicBool>,
    audio_send_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    frames_sent: Arc<AtomicU32>,
    bytes_sent: Arc<AtomicU64>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let display_index = session.display_index;

    // Get display dimensions before spawning (needed for encoder setup).
    let displays =
        scrap::Display::all().map_err(|e| format!("Failed to enumerate displays: {e}"))?;
    let display = displays
        .into_iter()
        .nth(display_index)
        .ok_or_else(|| format!("Display index {} not found", display_index))?;
    let src_w = display.width();
    let src_h = display.height();
    drop(display);

    Ok(tokio::task::spawn_blocking(move || {
        if let Err(e) = run_capture_and_encode(
            display_index,
            src_w,
            src_h,
            target_width,
            target_height,
            target_fps,
            bitrate,
            session_id,
            udp_token,
            active,
            keyframe_requested,
            video_tx,
            audio_tx,
            audio_enabled,
            audio_send_count,
            media_key,
            channel_id,
            frames_sent,
            bytes_sent,
        ) {
            error!("Screen capture error: {}", e);
        }
    }))
}

// ── Orchestrator ────────────────────────────────────────────────────────

/// Set up the two-thread capture+encode pipeline and WASAPI audio.
#[allow(clippy::too_many_arguments)]
fn run_capture_and_encode(
    display_index: usize,
    src_w: usize,
    src_h: usize,
    target_width: u32,
    target_height: u32,
    target_fps: u32,
    bitrate: u32,
    session_id: u32,
    udp_token: u64,
    active: Arc<AtomicBool>,
    keyframe_requested: Arc<AtomicBool>,
    video_tx: mpsc::Sender<Vec<u8>>,
    audio_tx: mpsc::Sender<Vec<u8>>,
    audio_enabled: Arc<AtomicBool>,
    audio_send_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    channel_id: Arc<AtomicU32>,
    frames_sent: Arc<AtomicU32>,
    bytes_sent: Arc<AtomicU64>,
) -> Result<(), String> {
    let encoder = voipc_video::encoder::Encoder::new(target_width, target_height, bitrate, target_fps)
        .map_err(|e| format!("Failed to create H.265 encoder: {e}"))?;

    info!(
        "DXGI capture started: {}x{} -> encode {}x{} @ {} fps",
        src_w, src_h, target_width, target_height, target_fps
    );

    let start_time = Instant::now();

    // Shared frame slot between capture and encode threads
    let slot = Arc::new(FrameSlot::new(active.clone()));

    // ── Spawn DXGI capture thread ────────────────────────────────────────
    // scrap::Capturer is !Send, so it must be created on its own thread.
    let capture_slot = slot.clone();
    let capture_active = active.clone();
    let capture_thread = std::thread::Builder::new()
        .name("dxgi-capture".into())
        .spawn(move || {
            run_capture_loop(display_index, src_w, src_h, target_fps, capture_active, capture_slot);
        })
        .map_err(|e| format!("Failed to spawn capture thread: {e}"))?;

    // ── Audio loopback setup (non-fatal if it fails) ─────────────────────
    let _audio_stream = setup_loopback_audio(
        session_id,
        udp_token,
        start_time,
        audio_tx,
        active.clone(),
        audio_enabled,
        audio_send_count,
        media_key.clone(),
        channel_id.clone(),
    );

    // ── Run encode loop on this thread ───────────────────────────────────
    let mut processor = FrameProcessor {
        encoder,
        i420_buf: Vec::new(),
        full_res_i420_buf: Vec::new(),
        converter: None,
        frame_id: 0,
        keyframe_interval: target_fps,
        start_time,
        target_width,
        target_height,
        active: active.clone(),
        keyframe_requested,
        video_tx,
        session_id,
        udp_token,
        media_key,
        channel_id,
        frames_sent,
        bytes_sent,
    };

    while let Some(frame) = slot.take() {
        processor.process(&frame.pixels, frame.width, frame.height, frame.stride, frame.fmt);
    }

    // ── Cleanup ──────────────────────────────────────────────────────────
    let _ = capture_thread.join();
    // _audio_stream is dropped here, stopping WASAPI loopback capture.
    info!("DXGI capture stopped");
    Ok(())
}

// ── DXGI capture loop (runs on dedicated thread) ────────────────────────

/// Fast DXGI Desktop Duplication capture loop.
///
/// Acquires frames, copies pixel data to an owned buffer, and immediately
/// releases the DXGI frame so the next one can be acquired without waiting
/// for encoding to finish.
fn run_capture_loop(
    display_index: usize,
    src_w: usize,
    src_h: usize,
    target_fps: u32,
    active: Arc<AtomicBool>,
    slot: Arc<FrameSlot>,
) {
    // Re-open display on this thread (scrap::Display/Capturer are !Send).
    let displays = match scrap::Display::all() {
        Ok(d) => d,
        Err(e) => {
            error!("Capture thread: failed to enumerate displays: {}", e);
            return;
        }
    };
    let display = match displays.into_iter().nth(display_index) {
        Some(d) => d,
        None => {
            error!("Capture thread: display index {} not found", display_index);
            return;
        }
    };
    let mut capturer = match scrap::Capturer::new(display) {
        Ok(c) => c,
        Err(e) => {
            error!("Capture thread: failed to create capturer: {}", e);
            return;
        }
    };

    let frame_interval = Duration::from_secs_f64(1.0 / target_fps as f64);
    // Reusable pixel buffer — after the first frame, `slot.put()` returns
    // the old buffer so we avoid allocating on every frame.
    let mut buf: Vec<u8> = Vec::new();

    while active.load(Ordering::Relaxed) {
        let frame_start = Instant::now();

        match capturer.frame() {
            Ok(frame) => {
                // DXGI frames are BGRA. Stride may include row padding.
                let stride = if src_h > 0 {
                    frame.len() / src_h
                } else {
                    src_w * 4
                };

                // Copy pixel data to owned buffer — releases DXGI frame reference
                // at the end of this block so the next frame can be acquired.
                buf.clear();
                buf.extend_from_slice(&frame);
                drop(frame);

                let captured = CapturedFrame {
                    pixels: std::mem::take(&mut buf),
                    width: src_w,
                    height: src_h,
                    stride,
                    fmt: PixFmt::Bgra,
                };

                // Store latest frame; get back old buffer for reuse (zero-alloc steady state).
                if let Some(old) = slot.put(captured) {
                    buf = old.pixels;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No new frame available yet — DXGI only yields when the
                // desktop has changed. Falls through to rate limiter.
            }
            Err(e) => {
                warn!("DXGI capture error: {}", e);
                // DXGI can transiently fail (e.g. desktop switch, UAC prompt).
                // Sleep briefly and retry rather than aborting immediately.
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        }

        // Rate-limit to target FPS
        let elapsed = frame_start.elapsed();
        if elapsed < frame_interval {
            std::thread::sleep(frame_interval - elapsed);
        }
    }
}

// ── WASAPI loopback audio capture ────────────────────────────────────────

/// Set up WASAPI loopback capture for desktop audio.
///
/// On the WASAPI backend, calling `build_input_stream()` on an output device
/// triggers loopback mode, capturing all audio being played through that device.
///
/// Returns the cpal stream handle (held to keep capture alive) or `None` if
/// loopback setup fails (non-fatal — screen share continues without audio).
fn setup_loopback_audio(
    session_id: u32,
    udp_token: u64,
    start_time: Instant,
    audio_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<AtomicBool>,
    audio_enabled: Arc<AtomicBool>,
    audio_send_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    channel_id: Arc<AtomicU32>,
) -> Option<cpal::Stream> {
    match setup_loopback_audio_inner(
        session_id,
        udp_token,
        start_time,
        audio_tx,
        active,
        audio_enabled,
        audio_send_count,
        media_key,
        channel_id,
    ) {
        Ok(stream) => {
            info!("WASAPI loopback audio capture started");
            Some(stream)
        }
        Err(e) => {
            warn!(
                "Failed to set up WASAPI loopback audio: {}. \
                 Screen share will continue without desktop audio.",
                e
            );
            None
        }
    }
}

fn setup_loopback_audio_inner(
    session_id: u32,
    udp_token: u64,
    start_time: Instant,
    audio_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<AtomicBool>,
    audio_enabled: Arc<AtomicBool>,
    audio_send_count: Arc<AtomicU32>,
    media_key: Arc<std::sync::Mutex<Option<voipc_crypto::MediaKey>>>,
    channel_id: Arc<AtomicU32>,
) -> Result<cpal::Stream, String> {
    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or("No default output device found")?;

    let config = device
        .default_output_config()
        .map_err(|e| format!("Failed to get output config: {e}"))?;

    let sample_rate = config.sample_rate().0;
    let channels = config.channels() as u32;

    info!(
        "WASAPI loopback: device={}, rate={}Hz, channels={}",
        device.name().unwrap_or_default(),
        sample_rate,
        channels
    );

    if sample_rate != 48_000 {
        warn!(
            "WASAPI loopback sample rate is {}Hz (expected 48000Hz), \
             audio may not work correctly",
            sample_rate
        );
    }

    // Create the Opus encoder up front (unlike Linux where PipeWire negotiates
    // format first). WASAPI loopback delivers audio in the output device's format.
    let encoder = voipc_audio::encoder::Encoder::new_screen_audio(SCREEN_AUDIO_BITRATE)
        .map_err(|e| format!("Failed to create Opus encoder: {e}"))?;

    let audio_processor = Arc::new(std::sync::Mutex::new(AudioProcessor {
        encoder: Some(encoder),
        accumulator: Vec::with_capacity(SCREEN_AUDIO_FRAME_SIZE * 2),
        sequence: 0,
        session_id,
        udp_token,
        start_time,
        audio_tx,
        active: active.clone(),
        audio_enabled,
        packet_count: audio_send_count,
        sample_rate,
        channels,
        media_key,
        channel_id,
    }));

    let stream_config = cpal::StreamConfig {
        channels: config.channels(),
        sample_rate: config.sample_rate(),
        buffer_size: cpal::BufferSize::Default,
    };

    // Build an input stream on the output device — triggers WASAPI loopback.
    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => {
            let proc = audio_processor.clone();
            let flag = active.clone();
            device
                .build_input_stream(
                    &stream_config,
                    move |data: &[f32], _: &cpal::InputCallbackInfo| {
                        if !flag.load(Ordering::Relaxed) {
                            return;
                        }
                        let byte_slice = unsafe {
                            std::slice::from_raw_parts(
                                data.as_ptr() as *const u8,
                                data.len() * std::mem::size_of::<f32>(),
                            )
                        };
                        if let Ok(mut p) = proc.lock() {
                            p.process(byte_slice);
                        }
                    },
                    |err| error!("WASAPI loopback error: {}", err),
                    None,
                )
                .map_err(|e| format!("Failed to build loopback stream: {e}"))?
        }
        cpal::SampleFormat::I16 => {
            let proc = audio_processor.clone();
            let flag = active.clone();
            device
                .build_input_stream(
                    &stream_config,
                    move |data: &[i16], _: &cpal::InputCallbackInfo| {
                        if !flag.load(Ordering::Relaxed) {
                            return;
                        }
                        // Convert i16 samples to f32 then pass as bytes.
                        let f32_data: Vec<f32> =
                            data.iter().map(|&s| s as f32 / i16::MAX as f32).collect();
                        let byte_slice = unsafe {
                            std::slice::from_raw_parts(
                                f32_data.as_ptr() as *const u8,
                                f32_data.len() * std::mem::size_of::<f32>(),
                            )
                        };
                        if let Ok(mut p) = proc.lock() {
                            p.process(byte_slice);
                        }
                    },
                    |err| error!("WASAPI loopback error: {}", err),
                    None,
                )
                .map_err(|e| format!("Failed to build loopback stream (i16): {e}"))?
        }
        format => {
            return Err(format!("Unsupported loopback sample format: {:?}", format));
        }
    };

    stream
        .play()
        .map_err(|e| format!("Failed to start loopback stream: {e}"))?;

    Ok(stream)
}
