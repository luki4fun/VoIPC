use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use super::{
    AudioProcessor, CapturedFrame, DisplayInfo, FrameProcessor, FrameSlot, PixFmt, WindowInfo,
    SCREEN_AUDIO_BITRATE, SCREEN_AUDIO_FRAME_SIZE,
};

// ── Win32 imports for window/monitor enumeration ──────────────────────────

use windows::Win32::Foundation::{BOOL, HWND, LPARAM, RECT, TRUE};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowLongW, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowVisible, GWL_EXSTYLE, GWL_STYLE, WS_CHILD, WS_EX_TOOLWINDOW,
};

// ── WGC imports for screen capture (displays + windows) ──────────────────

use windows::Graphics::Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem};
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11Resource, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::core::Interface;

// ── Public API ──────────────────────────────────────────────────────────

/// Describes which source to capture.
#[derive(Debug, Clone)]
pub enum CaptureSource {
    /// Capture an entire display/monitor by its HMONITOR handle.
    Display { hmonitor: isize },
    /// Capture a single window by its HWND.
    Window { hwnd: isize },
}

/// An active screen capture session on Windows.
/// Stores which source to capture; the actual capturer is created inside the
/// capture thread (it is not `Send`).
pub struct CaptureSession {
    pub(crate) source: CaptureSource,
}

/// Enumerate available displays using Win32 `EnumDisplayMonitors`.
pub fn enumerate_displays() -> Vec<DisplayInfo> {
    let mut monitors: Vec<DisplayInfo> = Vec::new();

    unsafe {
        let _ = EnumDisplayMonitors(
            HDC::default(),
            None,
            Some(enum_monitors_callback),
            LPARAM(&mut monitors as *mut Vec<DisplayInfo> as isize),
        );
    }

    // Sort primary monitor first, then by HMONITOR value for stable ordering
    monitors.sort_by(|a, b| b.is_primary.cmp(&a.is_primary));

    // Re-number display names after sorting
    for (i, m) in monitors.iter_mut().enumerate() {
        m.name = format!("Display {} ({}x{})", i + 1, m.width, m.height);
    }

    monitors
}

unsafe extern "system" fn enum_monitors_callback(
    hmonitor: HMONITOR,
    _hdc: HDC,
    _lprect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    let monitors = &mut *(lparam.0 as *mut Vec<DisplayInfo>);

    let mut info = MONITORINFO::default();
    info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;

    if GetMonitorInfoW(hmonitor, &mut info).as_bool() {
        let rc = info.rcMonitor;
        let w = (rc.right - rc.left) as u32;
        let h = (rc.bottom - rc.top) as u32;
        let is_primary = (info.dwFlags & 1) != 0; // MONITORINFOF_PRIMARY

        monitors.push(DisplayInfo {
            id: (hmonitor.0 as isize).to_string(),
            name: String::new(), // filled in after sorting
            width: w,
            height: h,
            is_primary,
        });
    }

    TRUE
}

/// Enumerate visible top-level windows with non-empty titles.
pub fn enumerate_windows() -> Vec<WindowInfo> {
    let mut windows: Vec<WindowInfo> = Vec::new();

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_callback),
            LPARAM(&mut windows as *mut Vec<WindowInfo> as isize),
        );
    }

    windows
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let windows = &mut *(lparam.0 as *mut Vec<WindowInfo>);

    // Skip invisible windows
    if !IsWindowVisible(hwnd).as_bool() {
        return TRUE;
    }

    // Skip child windows
    let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
    if style & WS_CHILD.0 != 0 {
        return TRUE;
    }

    // Skip tool windows (tooltips, floating toolbars, etc.)
    let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
    if ex_style & WS_EX_TOOLWINDOW.0 != 0 {
        return TRUE;
    }

    // Skip cloaked windows (UWP background apps, virtual desktop hidden windows)
    let mut cloaked: u32 = 0;
    let _ = DwmGetWindowAttribute(
        hwnd,
        DWMWA_CLOAKED,
        &mut cloaked as *mut u32 as *mut _,
        std::mem::size_of::<u32>() as u32,
    );
    if cloaked != 0 {
        return TRUE;
    }

    // Skip windows with no title
    let title_len = GetWindowTextLengthW(hwnd);
    if title_len == 0 {
        return TRUE;
    }

    // Get window title
    let mut title_buf = vec![0u16; (title_len + 1) as usize];
    let len = GetWindowTextW(hwnd, &mut title_buf);
    let title = String::from_utf16_lossy(&title_buf[..len as usize]);

    if title.is_empty() {
        return TRUE;
    }

    // Get process name
    let mut process_id: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut process_id));
    let app_name = get_process_name(process_id);

    windows.push(WindowInfo {
        id: (hwnd.0 as isize).to_string(),
        title,
        app_name,
    });

    TRUE
}

/// Get the process executable name from a PID.
fn get_process_name(pid: u32) -> String {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        let Ok(handle) = handle else {
            return String::new();
        };

        let mut buf = [0u16; 260];
        let len = GetModuleFileNameExW(handle, None, &mut buf);
        let _ = windows::Win32::Foundation::CloseHandle(handle);

        if len == 0 {
            return String::new();
        }

        let full_path = String::from_utf16_lossy(&buf[..len as usize]);
        full_path
            .rsplit('\\')
            .next()
            .unwrap_or(&full_path)
            .to_string()
    }
}

/// Validate a capture source and return a `CaptureSession`.
///
/// - `"display"` + `"0"` → validates display at that index exists
/// - `"window"` + `"<hwnd>"` → validates the HWND is a visible window
pub async fn request_screencast(
    source_type: &str,
    source_id: &str,
) -> Result<CaptureSession, String> {
    match source_type {
        "display" => {
            let hmonitor_val: isize = source_id
                .parse()
                .map_err(|_| format!("Invalid monitor handle: {}", source_id))?;

            // Validate the HMONITOR is still valid
            let hmon = HMONITOR(hmonitor_val as *mut _);
            let mut info = MONITORINFO::default();
            info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            unsafe {
                if !GetMonitorInfoW(hmon, &mut info).as_bool() {
                    return Err("Invalid or disconnected monitor".into());
                }
            }

            Ok(CaptureSession {
                source: CaptureSource::Display { hmonitor: hmonitor_val },
            })
        }
        "window" => {
            let hwnd_val: isize = source_id
                .parse()
                .map_err(|_| format!("Invalid window handle: {}", source_id))?;
            let hwnd = HWND(hwnd_val as *mut _);
            unsafe {
                if !IsWindowVisible(hwnd).as_bool() {
                    return Err("Selected window is not visible".into());
                }
            }
            Ok(CaptureSession {
                source: CaptureSource::Window { hwnd: hwnd_val },
            })
        }
        _ => Err(format!("Unknown source type: {}", source_type)),
    }
}

/// Spawn the screen capture + H.265 encode + fragment task.
///
/// Dispatches to DXGI (display capture) or WGC (window capture) based on
/// the `CaptureSource` in the session.
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
    let source = session.source.clone();

    // Get source dimensions before spawning (needed for encoder setup).
    let (src_w, src_h) = get_source_dimensions(&source)?;

    Ok(tokio::task::spawn_blocking(move || {
        if let Err(e) = run_capture_and_encode(
            source,
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

/// Get source dimensions (width, height) for encoder initialization.
fn get_source_dimensions(source: &CaptureSource) -> Result<(usize, usize), String> {
    match source {
        CaptureSource::Display { hmonitor } => {
            let hmon = HMONITOR(*hmonitor as *mut _);
            let mut info = MONITORINFO::default();
            info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
            unsafe {
                if !GetMonitorInfoW(hmon, &mut info).as_bool() {
                    return Err("Failed to get monitor info".into());
                }
            }
            let w = (info.rcMonitor.right - info.rcMonitor.left).max(1) as usize;
            let h = (info.rcMonitor.bottom - info.rcMonitor.top).max(1) as usize;
            Ok((w, h))
        }
        CaptureSource::Window { hwnd } => {
            // Get window client rect for initial dimensions
            unsafe {
                let hwnd = HWND(*hwnd as *mut _);
                let mut rect = windows::Win32::Foundation::RECT::default();
                windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rect)
                    .map_err(|e| format!("Failed to get window rect: {e}"))?;
                let w = (rect.right - rect.left).max(1) as usize;
                let h = (rect.bottom - rect.top).max(1) as usize;
                Ok((w, h))
            }
        }
    }
}

// ── Orchestrator ────────────────────────────────────────────────────────

/// Set up the capture+encode pipeline and WASAPI audio.
#[allow(clippy::too_many_arguments)]
fn run_capture_and_encode(
    source: CaptureSource,
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

    let source_desc = match &source {
        CaptureSource::Display { hmonitor } => format!("WGC monitor 0x{:x}", hmonitor),
        CaptureSource::Window { hwnd } => format!("WGC window 0x{:x}", hwnd),
    };

    info!(
        "{} capture started: {}x{} -> encode {}x{} @ {} fps",
        source_desc, src_w, src_h, target_width, target_height, target_fps
    );

    let start_time = Instant::now();

    // Shared frame slot between capture and encode threads
    let slot = Arc::new(FrameSlot::new(active.clone()));

    // ── Spawn WGC capture thread ─────────────────────────────────────────
    let capture_slot = slot.clone();
    let capture_active = active.clone();
    let capture_source = source.clone();
    let capture_thread = std::thread::Builder::new()
        .name("wgc-capture".into())
        .spawn(move || {
            if let Err(e) = run_wgc_capture_loop(capture_source, target_fps, capture_active, capture_slot) {
                error!("WGC capture error: {}", e);
            }
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
    info!("{} capture stopped", source_desc);
    Ok(())
}

// ── Unified WGC capture loop (runs on dedicated thread) ──────────────────

/// Windows.Graphics.Capture-based capture loop for both displays and windows.
///
/// Uses the WinRT GraphicsCapture API with hardware acceleration.
/// - Displays: `CreateForMonitor(HMONITOR)` — handles multi-adapter correctly
/// - Windows: `CreateForWindow(HWND)`
///
/// Frames are BGRA, stored in the FrameSlot for the encode thread to consume.
fn run_wgc_capture_loop(
    source: CaptureSource,
    target_fps: u32,
    active: Arc<AtomicBool>,
    slot: Arc<FrameSlot>,
) -> Result<(), String> {
    // WGC requires COM to be initialized on this thread.
    unsafe {
        windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_MULTITHREADED,
        )
        .ok()
        .map_err(|e| format!("CoInitializeEx failed: {e}"))?;
    }

    // Create D3D11 device for WGC frame pool
    let (d3d_device, d3d_context) = create_d3d11_device()?;
    let dxgi_device: IDXGIDevice = d3d_device.cast()
        .map_err(|e| format!("Failed to cast to IDXGIDevice: {e}"))?;

    let inspectable = unsafe {
        CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device)
    }
    .map_err(|e| format!("CreateDirect3D11DeviceFromDXGIDevice: {e}"))?;

    let direct3d_device: windows::Graphics::DirectX::Direct3D11::IDirect3DDevice =
        inspectable.cast()
            .map_err(|e| format!("Failed to cast to IDirect3DDevice: {e}"))?;

    // Create capture item from the source (monitor or window)
    let item = create_capture_item(&source)?;
    let size = item.Size().map_err(|e| format!("Failed to get capture item size: {e}"))?;

    // Create frame pool
    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &direct3d_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        1,
        size,
    )
    .map_err(|e| format!("Failed to create frame pool: {e}"))?;

    // Create and start capture session
    let capture_session = pool
        .CreateCaptureSession(&item)
        .map_err(|e| format!("Failed to create capture session: {e}"))?;

    capture_session
        .StartCapture()
        .map_err(|e| format!("Failed to start WGC capture: {e}"))?;

    let source_desc = match &source {
        CaptureSource::Display { hmonitor } => format!("monitor 0x{:x}", hmonitor),
        CaptureSource::Window { hwnd } => format!("window 0x{:x}", hwnd),
    };
    info!("WGC capture started for {}", source_desc);

    let frame_interval = Duration::from_secs_f64(1.0 / target_fps as f64);
    let mut buf: Vec<u8> = Vec::new();

    while active.load(Ordering::Relaxed) {
        let frame_start = Instant::now();

        if let Ok(frame) = pool.TryGetNextFrame() {
            // Get the D3D11 texture from the captured frame
            let surface = match frame.Surface() {
                Ok(s) => s,
                Err(e) => {
                    warn!("WGC: failed to get frame surface: {}", e);
                    continue;
                }
            };

            let access: IDirect3DDxgiInterfaceAccess = match surface.cast() {
                Ok(a) => a,
                Err(e) => {
                    warn!("WGC: failed to cast surface: {}", e);
                    continue;
                }
            };

            let texture: ID3D11Texture2D = match unsafe { access.GetInterface() } {
                Ok(t) => t,
                Err(e) => {
                    warn!("WGC: failed to get texture: {}", e);
                    continue;
                }
            };

            // Get texture dimensions (may change if window is resized)
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            unsafe { texture.GetDesc(&mut desc) };
            let width = desc.Width as usize;
            let height = desc.Height as usize;

            if width == 0 || height == 0 {
                continue;
            }

            // Create staging texture for CPU readback
            let staging_desc = D3D11_TEXTURE2D_DESC {
                Width: desc.Width,
                Height: desc.Height,
                MipLevels: 1,
                ArraySize: 1,
                Format: desc.Format,
                SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };

            let staging = unsafe {
                let mut staging_opt: Option<ID3D11Texture2D> = None;
                if let Err(e) = d3d_device.CreateTexture2D(&staging_desc, None, Some(&mut staging_opt)) {
                    warn!("WGC: failed to create staging texture: {}", e);
                    continue;
                }
                match staging_opt {
                    Some(s) => s,
                    None => {
                        warn!("WGC: CreateTexture2D returned None");
                        continue;
                    }
                }
            };

            // Cast textures to ID3D11Resource for CopyResource/Map/Unmap
            let staging_res: ID3D11Resource = match staging.cast() {
                Ok(r) => r,
                Err(e) => {
                    warn!("WGC: failed to cast staging to ID3D11Resource: {}", e);
                    continue;
                }
            };
            let texture_res: ID3D11Resource = match texture.cast() {
                Ok(r) => r,
                Err(e) => {
                    warn!("WGC: failed to cast texture to ID3D11Resource: {}", e);
                    continue;
                }
            };

            // Copy from GPU texture to staging texture
            unsafe {
                d3d_context.CopyResource(&staging_res, &texture_res);
            }

            // Map the staging texture for CPU read
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            if unsafe {
                d3d_context.Map(&staging_res, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
            }
            .is_err()
            {
                warn!("WGC: failed to map staging texture");
                continue;
            }

            let stride = mapped.RowPitch as usize;
            let total_bytes = stride * height;

            // Copy pixel data to owned buffer
            buf.clear();
            buf.reserve(total_bytes);
            unsafe {
                let src = std::slice::from_raw_parts(mapped.pData as *const u8, total_bytes);
                buf.extend_from_slice(src);
            }

            unsafe { d3d_context.Unmap(&staging_res, 0) };

            let captured = CapturedFrame {
                pixels: std::mem::take(&mut buf),
                width,
                height,
                stride,
                fmt: PixFmt::Bgra,
            };

            if let Some(old) = slot.put(captured) {
                buf = old.pixels;
            }
        }

        // Rate-limit to target FPS
        let elapsed = frame_start.elapsed();
        if elapsed < frame_interval {
            std::thread::sleep(frame_interval - elapsed);
        }
    }

    // Stop capture session
    let _ = capture_session.Close();
    let _ = pool.Close();
    info!("WGC capture stopped for {}", source_desc);
    Ok(())
}

/// Create a D3D11 device for WGC frame processing.
fn create_d3d11_device() -> Result<(ID3D11Device, windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext), String> {
    let mut device = None;
    let mut context = None;

    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(|e| format!("D3D11CreateDevice failed: {e}"))?;
    }

    Ok((
        device.ok_or("D3D11 device is None")?,
        context.ok_or("D3D11 context is None")?,
    ))
}

/// Create a `GraphicsCaptureItem` from a `CaptureSource`.
///
/// - `Display { hmonitor }` → `IGraphicsCaptureItemInterop::CreateForMonitor`
/// - `Window { hwnd }` → `IGraphicsCaptureItemInterop::CreateForWindow`
fn create_capture_item(source: &CaptureSource) -> Result<GraphicsCaptureItem, String> {
    use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;

    let interop: IGraphicsCaptureItemInterop =
        windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
            .map_err(|e| format!("Failed to get IGraphicsCaptureItemInterop: {e}"))?;

    unsafe {
        match source {
            CaptureSource::Display { hmonitor } => {
                let hmon = HMONITOR(*hmonitor as *mut _);
                interop
                    .CreateForMonitor(hmon)
                    .map_err(|e| format!("Failed to create capture item for monitor: {e}"))
            }
            CaptureSource::Window { hwnd } => {
                let hwnd = HWND(*hwnd as *mut _);
                interop
                    .CreateForWindow(hwnd)
                    .map_err(|e| format!("Failed to create capture item for window: {e}"))
            }
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
