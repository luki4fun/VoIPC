use std::cell::RefCell;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::{
    AudioProcessor, CapturedFrame, DisplayInfo, FrameProcessor, FrameSlot, PixFmt, WindowInfo,
    SCREEN_AUDIO_BITRATE, SCREEN_AUDIO_FRAME_SIZE,
};

/// An active XDG Desktop Portal ScreenCast session.
/// Dropping this signals the keep-alive task to call `Session::close()` on
/// the D-Bus portal session, which tells the compositor to stop the screencast.
pub struct CaptureSession {
    /// Dropping this sender signals the keep-alive task to close the portal session.
    _shutdown_guard: Option<tokio::sync::oneshot::Sender<()>>,
    /// Task that holds the D-Bus session alive; closes it on shutdown signal.
    _keep_alive: tokio::task::JoinHandle<()>,
    pw_fd: OwnedFd,
    node_id: u32,
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self._shutdown_guard.take();
        self._keep_alive.abort();
    }
}

/// Enumerate available displays. On Linux/Wayland, the portal handles source
/// enumeration — returns an empty list. The frontend shows a message instead.
pub fn enumerate_displays() -> Vec<DisplayInfo> {
    Vec::new()
}

/// Enumerate available windows. On Linux/Wayland, the portal handles source
/// enumeration — returns an empty list. The frontend shows a message instead.
pub fn enumerate_windows() -> Vec<WindowInfo> {
    Vec::new()
}

/// Request a ScreenCast session via the XDG Desktop Portal.
///
/// `source_type` controls which sources the portal picker shows:
/// - `"display"` → monitors only
/// - `"window"` → application windows only
/// - anything else → both (backwards compat)
///
/// `source_id` is ignored on Linux (the portal picker handles selection).
///
/// Returns a `CaptureSession` containing the PipeWire FD and node ID.
/// The session stays alive until the `CaptureSession` is dropped.
pub async fn request_screencast(
    source_type: &str,
    _source_id: &str,
) -> Result<CaptureSession, String> {
    use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
    use ashpd::desktop::PersistMode;
    use ashpd::WindowIdentifier;

    let portal_source_type = match source_type {
        "display" => SourceType::Monitor.into(),
        "window" => SourceType::Window.into(),
        _ => SourceType::Monitor | SourceType::Window,
    };

    let (result_tx, result_rx) =
        tokio::sync::oneshot::channel::<Result<(OwnedFd, u32), String>>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let keep_alive = tokio::spawn(async move {
        let setup = async {
            let proxy = Screencast::new()
                .await
                .map_err(|e| format!("Failed to create ScreenCast proxy: {e}"))?;

            let session = proxy
                .create_session()
                .await
                .map_err(|e| format!("Failed to create session: {e}"))?;

            proxy
                .select_sources(
                    &session,
                    CursorMode::Embedded,
                    portal_source_type,
                    false,
                    None,
                    PersistMode::DoNot,
                )
                .await
                .map_err(|e| format!("Failed to select sources: {e}"))?;

            let response = proxy
                .start(&session, &WindowIdentifier::default())
                .await
                .map_err(|e| format!("Portal start failed (user cancelled?): {e}"))?
                .response()
                .map_err(|e| format!("Portal response error: {e}"))?;

            let streams = response.streams();
            if streams.is_empty() {
                return Err("No streams returned by portal".into());
            }
            let node_id = streams[0].pipe_wire_node_id();

            let fd = proxy
                .open_pipe_wire_remote(&session)
                .await
                .map_err(|e| format!("Failed to open PipeWire remote: {e}"))?;

            let fd_clone = fd
                .try_clone()
                .map_err(|e| format!("Failed to dup PipeWire FD: {e}"))?;

            Ok::<_, String>((fd_clone, node_id, fd, session))
        };

        match setup.await {
            Ok((fd_clone, node_id, _fd, session)) => {
                let _ = result_tx.send(Ok((fd_clone, node_id)));
                let _ = shutdown_rx.await;
                if let Err(e) = session.close().await {
                    warn!("failed to close portal session: {e}");
                }
                info!("portal session closed");
            }
            Err(e) => {
                let _ = result_tx.send(Err(e));
            }
        }
    });

    match result_rx.await {
        Ok(Ok((fd, node_id))) => Ok(CaptureSession {
            _shutdown_guard: Some(shutdown_tx),
            _keep_alive: keep_alive,
            pw_fd: fd,
            node_id,
        }),
        Ok(Err(e)) => {
            keep_alive.abort();
            Err(e)
        }
        Err(_) => {
            keep_alive.abort();
            Err("Portal session task panicked".into())
        }
    }
}

/// Spawn the PipeWire screen capture + VP8 encode + fragment task.
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
    let fd = session
        .pw_fd
        .try_clone()
        .map_err(|e| format!("Failed to dup PipeWire FD: {e}"))?;
    let node_id = session.node_id;

    Ok(tokio::task::spawn_blocking(move || {
        if let Err(e) = run_pipewire_capture(
            fd,
            node_id,
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
            error!("PipeWire capture error: {}", e);
        }
    }))
}

/// PipeWire capture main loop.
fn run_pipewire_capture(
    pw_fd: OwnedFd,
    node_id: u32,
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
    pipewire::init();

    let mainloop =
        pipewire::main_loop::MainLoop::new(None).map_err(|e| format!("MainLoop::new: {e}"))?;
    let context = pipewire::context::Context::new(&mainloop)
        .map_err(|e| format!("Context::new: {e}"))?;
    let core = context
        .connect_fd(pw_fd, None)
        .map_err(|e| format!("connect_fd: {e}"))?;

    let props = {
        use pipewire::properties::properties;
        properties! {
            *pipewire::keys::MEDIA_TYPE => "Video",
            *pipewire::keys::MEDIA_CATEGORY => "Capture",
            *pipewire::keys::MEDIA_ROLE => "Screen",
        }
    };

    let stream = pipewire::stream::Stream::new(&core, "voipc-screenshare", props)
        .map_err(|e| format!("Stream::new: {e}"))?;

    let format_pod = build_video_format_pod(target_width, target_height, target_fps);

    let start_time = Instant::now();

    // ── Create encoder + processor upfront (like Windows) ────────────────
    let encoder =
        voipc_video::encoder::Encoder::new(target_width, target_height, bitrate, target_fps)
            .map_err(|e| format!("Failed to create H.265 encoder: {e}"))?;

    let processor = FrameProcessor {
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
        keyframe_requested: keyframe_requested.clone(),
        video_tx,
        session_id,
        udp_token,
        media_key: media_key.clone(),
        channel_id: channel_id.clone(),
        frames_sent,
        bytes_sent,
    };

    // ── Shared frame slot between PipeWire callback and encode thread ────
    let slot = Arc::new(FrameSlot::new(active.clone()));

    // ── Spawn encode thread ──────────────────────────────────────────────
    let encode_slot = slot.clone();
    let encode_thread = std::thread::Builder::new()
        .name("pw-encode".into())
        .spawn(move || {
            let mut processor = processor;
            while let Some(frame) = encode_slot.take() {
                processor.process(
                    &frame.pixels,
                    frame.width,
                    frame.height,
                    frame.stride,
                    frame.fmt,
                );
            }
            info!("PipeWire encode thread stopped");
        })
        .map_err(|e| format!("Failed to spawn encode thread: {e}"))?;

    info!(
        "PipeWire capture started: encode {}x{} @ {} fps",
        target_width, target_height, target_fps
    );

    // ── PipeWire video stream ────────────────────────────────────────────
    // The process callback is now lightweight (memcpy only); encoding
    // happens on the separate encode thread via the FrameSlot.
    let capture_state = RefCell::new(PwVideoState {
        slot: slot.clone(),
        reuse_buf: Vec::new(),
        negotiated_width: 0,
        negotiated_height: 0,
        negotiated_stride: 0,
        negotiated_format: PixFmt::Unknown,
    });

    let _listener = stream
        .add_local_listener_with_user_data(capture_state)
        .param_changed(|_stream, user_data, id, param| {
            let Some(param) = param else { return };
            if id != pipewire::spa::param::ParamType::Format.as_raw() {
                return;
            }
            if let Some((w, h, stride, fmt)) = parse_video_format(param) {
                let mut state = user_data.borrow_mut();
                state.negotiated_width = w;
                state.negotiated_height = h;
                state.negotiated_stride = stride;
                state.negotiated_format = fmt;
                info!(
                    "PipeWire negotiated: {}x{} stride={} {:?}",
                    w, h, stride, fmt
                );
            }
        })
        .process(|stream, user_data| {
            let mut buf = match stream.dequeue_buffer() {
                None => return,
                Some(buf) => buf,
            };

            let datas = buf.datas_mut();
            if datas.is_empty() {
                return;
            }
            let data = &mut datas[0];

            let chunk = data.chunk();
            let offset = chunk.offset() as usize;
            let size = chunk.size() as usize;
            let chunk_stride = chunk.stride() as usize;

            let Some(raw_data) = data.data() else {
                return;
            };

            if size == 0 || offset + size > raw_data.len() {
                return;
            }

            let Ok(mut state) = user_data.try_borrow_mut() else {
                return;
            };

            if state.negotiated_width == 0 {
                return; // Format not negotiated yet
            }

            // Copy frame data out of PipeWire buffer (returned to PipeWire on callback exit).
            let mut pixels = std::mem::take(&mut state.reuse_buf);
            pixels.clear();
            pixels.extend_from_slice(&raw_data[offset..offset + size]);

            // Use per-buffer stride from PipeWire (handles compositor alignment padding).
            // Fall back to width*4 if PipeWire reports 0 (some compositors don't set it).
            let stride = if chunk_stride > 0 {
                chunk_stride
            } else {
                state.negotiated_stride as usize
            };

            let captured = CapturedFrame {
                pixels,
                width: state.negotiated_width as usize,
                height: state.negotiated_height as usize,
                stride,
                fmt: state.negotiated_format,
            };

            // Store latest frame; get back old buffer for reuse (zero-alloc steady state).
            if let Some(old) = state.slot.put(captured) {
                state.reuse_buf = old.pixels;
            }
        })
        .register()
        .map_err(|e| format!("Stream listener: {e}"))?;

    let pod = pipewire::spa::pod::Pod::from_bytes(&format_pod)
        .ok_or("Failed to parse serialized format pod")?;
    stream
        .connect(
            pipewire::spa::utils::Direction::Input,
            Some(node_id),
            pipewire::stream::StreamFlags::AUTOCONNECT | pipewire::stream::StreamFlags::MAP_BUFFERS,
            &mut [pod],
        )
        .map_err(|e| format!("Stream connect: {e}"))?;

    info!("PipeWire video stream started (node {})", node_id);
    keyframe_requested.store(true, Ordering::Relaxed);

    // ── Audio stream (desktop audio via default sink monitor) ──
    let audio_props = {
        use pipewire::properties::properties;
        properties! {
            *pipewire::keys::MEDIA_TYPE => "Audio",
            *pipewire::keys::MEDIA_CATEGORY => "Capture",
            *pipewire::keys::MEDIA_ROLE => "Screen",
            "stream.capture.sink" => "true",
        }
    };

    let audio_stream =
        pipewire::stream::Stream::new(&core, "voipc-screenshare-audio", audio_props)
            .map_err(|e| format!("Audio Stream::new: {e}"))?;

    let audio_format_pod = build_audio_format_pod();

    let audio_state = RefCell::new(AudioProcessor {
        encoder: None,
        accumulator: Vec::with_capacity(SCREEN_AUDIO_FRAME_SIZE * 2),
        sequence: 0,
        session_id,
        udp_token,
        start_time,
        audio_tx,
        active: active.clone(),
        audio_enabled,
        packet_count: audio_send_count,
        sample_rate: 0,
        channels: 0,
        media_key: media_key.clone(),
        channel_id: channel_id.clone(),
    });

    let _audio_listener = audio_stream
        .add_local_listener_with_user_data(audio_state)
        .param_changed(|_stream, user_data, id, param| {
            let Some(param) = param else { return };
            if id != pipewire::spa::param::ParamType::Format.as_raw() {
                return;
            }
            if let Some((rate, channels)) = parse_audio_format(param) {
                {
                    let mut state = user_data.borrow_mut();
                    state.sample_rate = rate;
                    state.channels = channels;
                }

                if rate != 48_000 {
                    warn!(
                        "PipeWire audio negotiated {}Hz (expected 48000Hz), audio may not work correctly",
                        rate
                    );
                }

                match voipc_audio::encoder::Encoder::new_screen_audio(SCREEN_AUDIO_BITRATE) {
                    Ok(enc) => {
                        user_data.borrow_mut().encoder = Some(enc);
                        info!(
                            "PipeWire audio negotiated: {}Hz {}ch -> Opus mono 48kHz",
                            rate, channels
                        );
                    }
                    Err(e) => error!("Failed to create screen audio Opus encoder: {}", e),
                }
            }
        })
        .process(|stream, user_data| {
            let mut buf = match stream.dequeue_buffer() {
                None => return,
                Some(buf) => buf,
            };

            let datas = buf.datas_mut();
            if datas.is_empty() {
                return;
            }
            let data = &mut datas[0];

            let chunk = data.chunk();
            let offset = chunk.offset() as usize;
            let size = chunk.size() as usize;

            let Some(raw_data) = data.data() else {
                return;
            };

            if size == 0 || offset + size > raw_data.len() {
                return;
            }

            let audio_bytes = &raw_data[offset..offset + size];

            let Ok(mut state) = user_data.try_borrow_mut() else {
                return;
            };
            state.process(audio_bytes);
        })
        .register()
        .map_err(|e| format!("Audio stream listener: {e}"))?;

    let audio_pod = pipewire::spa::pod::Pod::from_bytes(&audio_format_pod)
        .ok_or("Failed to parse serialized audio format pod")?;
    audio_stream
        .connect(
            pipewire::spa::utils::Direction::Input,
            None,
            pipewire::stream::StreamFlags::AUTOCONNECT
                | pipewire::stream::StreamFlags::MAP_BUFFERS,
            &mut [audio_pod],
        )
        .map_err(|e| format!("Audio stream connect: {e}"))?;

    info!("PipeWire audio stream started (default sink monitor)");

    let loop_ = mainloop.loop_();
    while active.load(Ordering::Relaxed) {
        loop_.iterate(std::time::Duration::from_millis(5));
    }

    // Wait for encode thread to finish (it will exit when active becomes false)
    let _ = encode_thread.join();
    info!("PipeWire capture stopped");
    Ok(())
}

// ── Internal PipeWire state ──────────────────────────────────────────────

/// Lightweight video callback state for the PipeWire process callback.
/// Only stores format info and the FrameSlot — encoding happens on a
/// separate thread that reads from the slot.
struct PwVideoState {
    slot: Arc<FrameSlot>,
    reuse_buf: Vec<u8>,
    negotiated_width: u32,
    negotiated_height: u32,
    negotiated_stride: u32,
    negotiated_format: PixFmt,
}

// ── SPA format pod building/parsing ─────────────────────────────────────

fn build_video_format_pod(width: u32, height: u32, fps: u32) -> Vec<u8> {
    use pipewire::spa;
    use pipewire::spa::pod::serialize::PodSerializer;

    let obj = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id,
            spa::param::format::MediaType::Video
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id,
            spa::param::format::MediaSubtype::Raw
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::BGRA,
            spa::param::video::VideoFormat::RGBx,
            spa::param::video::VideoFormat::RGBA
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle { width, height },
            spa::utils::Rectangle {
                width: 1,
                height: 1
            },
            spa::utils::Rectangle {
                width: 4096,
                height: 4096
            }
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: fps, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction {
                num: 60,
                denom: 1
            }
        ),
    );

    PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .expect("Failed to serialize SPA format pod")
    .0
    .into_inner()
}

fn parse_video_format(param: &pipewire::spa::pod::Pod) -> Option<(u32, u32, u32, PixFmt)> {
    use pipewire::spa::param::format_utils;
    use pipewire::spa::param::video::{VideoFormat, VideoInfoRaw};

    let (media_type, media_subtype) = format_utils::parse_format(param).ok()?;

    if media_type != pipewire::spa::param::format::MediaType::Video
        || media_subtype != pipewire::spa::param::format::MediaSubtype::Raw
    {
        return None;
    }

    let mut video_info = VideoInfoRaw::new();
    video_info.parse(param).ok()?;

    let size = video_info.size();
    let width = size.width;
    let height = size.height;

    if width == 0 || height == 0 {
        return None;
    }

    let format = match video_info.format() {
        VideoFormat::BGRx => PixFmt::Bgrx,
        VideoFormat::BGRA => PixFmt::Bgra,
        VideoFormat::RGBx => PixFmt::Rgbx,
        VideoFormat::RGBA => PixFmt::Rgba,
        _ => PixFmt::Unknown,
    };

    if format == PixFmt::Unknown {
        return None;
    }

    let stride = width * 4;
    Some((width, height, stride, format))
}

fn build_audio_format_pod() -> Vec<u8> {
    use pipewire::spa;
    use pipewire::spa::pod::serialize::PodSerializer;

    let mut audio_info = spa::param::audio::AudioInfoRaw::new();
    audio_info.set_format(spa::param::audio::AudioFormat::F32LE);

    let obj = pipewire::spa::pod::Object {
        type_: spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: spa::param::ParamType::EnumFormat.as_raw(),
        properties: audio_info.into(),
    };

    PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .expect("Failed to serialize SPA audio format pod")
    .0
    .into_inner()
}

fn parse_audio_format(param: &pipewire::spa::pod::Pod) -> Option<(u32, u32)> {
    use pipewire::spa::param::audio::AudioInfoRaw;
    use pipewire::spa::param::format_utils;

    let (media_type, media_subtype) = format_utils::parse_format(param).ok()?;

    if media_type != pipewire::spa::param::format::MediaType::Audio
        || media_subtype != pipewire::spa::param::format::MediaSubtype::Raw
    {
        return None;
    }

    let mut audio_info = AudioInfoRaw::new();
    audio_info.parse(param).ok()?;

    let rate = audio_info.rate();
    let channels = audio_info.channels();

    if rate == 0 || channels == 0 {
        return None;
    }

    Some((rate, channels))
}
