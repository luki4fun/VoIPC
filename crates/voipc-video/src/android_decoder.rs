//! Screen-share video decoder for Android using the NDK AMediaCodec API.
//!
//! Uses raw FFI bindings to `libmediandk.so` (available since API 21).
//! The decoder is lazily configured on the first keyframe: H.264/H.265 need
//! their parameter sets as codec-specific data (CSD), VP8/VP9 need nothing.

use anyhow::{anyhow, Result};
use std::ptr;
use voipc_protocol::types::VideoCodec;

// ---------------------------------------------------------------------------
// FFI bindings for NDK AMediaCodec / AMediaFormat
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod ffi {
    use std::os::raw::{c_char, c_void};

    pub type media_status_t = i32;
    pub const AMEDIA_OK: media_status_t = 0;
    pub const AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED: isize = -2;
    pub const AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED: isize = -3;
    pub const AMEDIACODEC_INFO_TRY_AGAIN_LATER: isize = -1;
    pub const AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG: u32 = 2;

    // Common color formats
    pub const COLOR_FormatYUV420Planar: i32 = 19; // I420
    pub const COLOR_FormatYUV420SemiPlanar: i32 = 21; // NV12
    pub const COLOR_FormatYUV420Flexible: i32 = 0x7F420888;

    #[repr(C)]
    pub struct AMediaCodec {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct AMediaFormat {
        _private: [u8; 0],
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct AMediaCodecBufferInfo {
        pub offset: i32,
        pub size: i32,
        pub presentation_time_us: i64,
        pub flags: u32,
    }

    #[link(name = "mediandk")]
    extern "C" {
        pub fn AMediaCodec_createDecoderByType(mime_type: *const c_char) -> *mut AMediaCodec;
        pub fn AMediaCodec_delete(codec: *mut AMediaCodec) -> media_status_t;
        pub fn AMediaCodec_configure(
            codec: *mut AMediaCodec,
            format: *const AMediaFormat,
            surface: *mut c_void,
            crypto: *mut c_void,
            flags: u32,
        ) -> media_status_t;
        pub fn AMediaCodec_start(codec: *mut AMediaCodec) -> media_status_t;
        pub fn AMediaCodec_stop(codec: *mut AMediaCodec) -> media_status_t;
        pub fn AMediaCodec_flush(codec: *mut AMediaCodec) -> media_status_t;
        pub fn AMediaCodec_dequeueInputBuffer(codec: *mut AMediaCodec, timeout_us: i64) -> isize;
        pub fn AMediaCodec_getInputBuffer(
            codec: *mut AMediaCodec,
            idx: usize,
            out_size: *mut usize,
        ) -> *mut u8;
        pub fn AMediaCodec_queueInputBuffer(
            codec: *mut AMediaCodec,
            idx: usize,
            offset: u32,
            size: u32,
            time_us: u64,
            flags: u32,
        ) -> media_status_t;
        pub fn AMediaCodec_dequeueOutputBuffer(
            codec: *mut AMediaCodec,
            info: *mut AMediaCodecBufferInfo,
            timeout_us: i64,
        ) -> isize;
        pub fn AMediaCodec_getOutputBuffer(
            codec: *mut AMediaCodec,
            idx: usize,
            out_size: *mut usize,
        ) -> *mut u8;
        pub fn AMediaCodec_releaseOutputBuffer(
            codec: *mut AMediaCodec,
            idx: usize,
            render: bool,
        ) -> media_status_t;
        pub fn AMediaCodec_getOutputFormat(codec: *mut AMediaCodec) -> *mut AMediaFormat;

        pub fn AMediaFormat_new() -> *mut AMediaFormat;
        pub fn AMediaFormat_delete(format: *mut AMediaFormat) -> media_status_t;
        pub fn AMediaFormat_setString(
            format: *mut AMediaFormat,
            name: *const c_char,
            value: *const c_char,
        );
        pub fn AMediaFormat_setInt32(format: *mut AMediaFormat, name: *const c_char, value: i32);
        pub fn AMediaFormat_getInt32(
            format: *mut AMediaFormat,
            name: *const c_char,
            out: *mut i32,
        ) -> bool;
        pub fn AMediaFormat_setBuffer(
            format: *mut AMediaFormat,
            name: *const c_char,
            data: *const u8,
            size: usize,
        );
    }
}

/// Largest width or height believed, from a parameter set or from the codec.
const MAX_DIMENSION: i32 = 8192;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A decoded video frame in I420 format.
#[derive(Clone, Debug)]
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    /// I420 data: the Y plane, then U and V at half size rounded up.
    pub i420_data: Vec<u8>,
    /// What the stream says it carries: full range, and the BT.709 matrix.
    /// [`crate::to_jpeg_ycbcr`] turns the frame into JPEG's YCbCr when it is
    /// shown; it is not done here, for frames that are only decoded.
    pub full_range: bool,
    pub bt709: bool,
}

/// Screen-share decoder backed by Android's hardware MediaCodec.
pub struct Decoder {
    codec: *mut ffi::AMediaCodec,
    video_codec: VideoCodec,
    configured: bool,
    width: u32,
    height: u32,
    stride: u32,
    slice_height: u32,
    color_format: i32,
    pts_counter: u64,
    /// The stream's range and matrix, from the output format.
    full_range: bool,
    bt709: bool,
    /// Time spent copying pictures out since `take_copy_time` last asked (the viewer's
    /// `share view:` line).
    copy_time: std::time::Duration,
}

// SAFETY: The decoder is only used from a single blocking tokio task.
unsafe impl Send for Decoder {}

impl Decoder {
    /// Create a decoder for `video_codec`.
    ///
    /// The codec is allocated but not configured until the first keyframe
    /// (H.264/H.265 also need its parameter sets as CSD).
    pub fn new(video_codec: VideoCodec) -> Result<Self> {
        let mime: &[u8] = match video_codec {
            VideoCodec::H264 => b"video/avc\0",
            VideoCodec::H265 => b"video/hevc\0",
            VideoCodec::Vp8 => b"video/x-vnd.on2.vp8\0",
            VideoCodec::Vp9 => b"video/x-vnd.on2.vp9\0",
        };
        let codec = unsafe { ffi::AMediaCodec_createDecoderByType(mime.as_ptr() as *const _) };
        if codec.is_null() {
            return Err(anyhow!(
                "AMediaCodec: no {video_codec:?} decoder available on this device"
            ));
        }
        tracing::info!("AMediaCodec: {video_codec:?} decoder created");
        Ok(Self {
            codec,
            video_codec,
            configured: false,
            width: 0,
            height: 0,
            stride: 0,
            slice_height: 0,
            color_format: ffi::COLOR_FormatYUV420SemiPlanar,
            pts_counter: 0,
            full_range: matches!(video_codec, VideoCodec::Vp8 | VideoCodec::Vp9),
            bt709: false,
            copy_time: std::time::Duration::ZERO,
        })
    }

    /// The codec this decoder was opened for.
    ///
    /// Mirrors the desktop decoder's accessor, which the shared client code
    /// uses to notice a codec change and rebuild the decoder. It cannot be
    /// named after the `codec` field here — that one is the MediaCodec handle.
    pub fn codec(&self) -> VideoCodec {
        self.video_codec
    }

    /// What copying the pictures out cost since the last ask: part of `decode`'s time.
    pub fn take_copy_time(&mut self) -> std::time::Duration {
        std::mem::take(&mut self.copy_time)
    }

    /// Decode one encoded frame (Annex B with start codes for H.264/H.265,
    /// raw frames for VP8/VP9).
    ///
    /// On the first call, H.264/H.265 data must be a keyframe carrying its
    /// parameter sets so that the codec can be configured.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<DecodedFrame>> {
        if !self.configured {
            self.configure_from_keyframe(data)?;
        }

        match self.queue_input(data) {
            Ok(()) => self.drain_output(),
            // A codec holds its inputs while its pictures wait to be taken out, so a decode that
            // fell behind ran out of inputs here and, never draining again, stayed frozen for
            // the rest of the share (1.13, seen on the emulator). Take the pictures out, which
            // frees inputs, and try this frame once more; if it still finds none, it is lost,
            // and the error says so.
            Err(first) => {
                let mut frames = self.drain_output()?;
                self.queue_input(data).map_err(|_| first)?;
                frames.extend(self.drain_output()?);
                Ok(frames)
            }
        }
    }

    /// Configure the codec from the first keyframe: parameter sets as CSD-0 for
    /// H.264/H.265, nothing for VP8/VP9 (MediaCodec reads their keyframe header;
    /// the real size arrives through INFO_OUTPUT_FORMAT_CHANGED).
    fn configure_from_keyframe(&mut self, data: &[u8]) -> Result<()> {
        let mime: &[u8] = match self.video_codec {
            VideoCodec::H264 => b"video/avc\0",
            VideoCodec::H265 => b"video/hevc\0",
            VideoCodec::Vp8 => b"video/x-vnd.on2.vp8\0",
            VideoCodec::Vp9 => b"video/x-vnd.on2.vp9\0",
        };
        let needs_csd = matches!(self.video_codec, VideoCodec::H264 | VideoCodec::H265);

        // Find CSD (everything up to the first non-parameter-set NAL unit).
        // H.264 wants SPS in csd-0 and PPS in csd-1; HEVC takes VPS+SPS+PPS
        // concatenated in csd-0 (Android's documented layout for each).
        let csd = if needs_csd {
            extract_csd(self.video_codec, data)
        } else {
            &[][..]
        };
        if needs_csd && csd.is_empty() {
            return Err(anyhow!(
                "AMediaCodec: first frame has no parameter sets — waiting for keyframe"
            ));
        }
        let (csd0, csd1) = if self.video_codec == VideoCodec::H264 {
            split_h264_csd(csd)
        } else {
            (csd, &[][..])
        };

        // Parse width/height from the SPS if possible, otherwise use defaults
        // HEVC only: for every other codec the configure hint is the 1920x1080 fallback, and
        // the real size arrives with INFO_OUTPUT_FORMAT_CHANGED, which MediaCodec raises before
        // the first decoded buffer (`update_output_format` resets stride and slice height).
        let (w, h) = Some(self.video_codec)
            .filter(|c| *c == VideoCodec::H265)
            .and_then(|c| crate::frame_size::keyframe_size(c, data))
            .filter(|&(w, h)| crate::frame_size::fits(w, h))
            .unwrap_or((1920, 1080));

        let format = unsafe { ffi::AMediaFormat_new() };
        if format.is_null() {
            return Err(anyhow!("AMediaFormat_new returned null"));
        }

        unsafe {
            ffi::AMediaFormat_setString(
                format,
                b"mime\0".as_ptr() as *const _,
                mime.as_ptr() as *const _,
            );
            ffi::AMediaFormat_setInt32(format, b"width\0".as_ptr() as *const _, w as i32);
            ffi::AMediaFormat_setInt32(format, b"height\0".as_ptr() as *const _, h as i32);
            // KEY_LOW_LATENCY (API 30+; older decoders ignore the key): hand
            // each frame out as soon as it is decoded, rather than after a
            // few more for reordering a screen share never uses (H3-07)
            ffi::AMediaFormat_setInt32(format, b"low-latency\0".as_ptr() as *const _, 1);
            // Parameter sets, with start codes
            if !csd0.is_empty() {
                ffi::AMediaFormat_setBuffer(
                    format,
                    b"csd-0\0".as_ptr() as *const _,
                    csd0.as_ptr(),
                    csd0.len(),
                );
            }
            if !csd1.is_empty() {
                ffi::AMediaFormat_setBuffer(
                    format,
                    b"csd-1\0".as_ptr() as *const _,
                    csd1.as_ptr(),
                    csd1.len(),
                );
            }

            let status =
                ffi::AMediaCodec_configure(self.codec, format, ptr::null_mut(), ptr::null_mut(), 0);
            ffi::AMediaFormat_delete(format);

            if status != ffi::AMEDIA_OK {
                return Err(anyhow!("AMediaCodec_configure failed: status {}", status));
            }

            let status = ffi::AMediaCodec_start(self.codec);
            if status != ffi::AMEDIA_OK {
                // Back to unconfigured, or the next keyframe's configure is
                // refused for a codec that already is, and so is every one after
                ffi::AMediaCodec_stop(self.codec);
                return Err(anyhow!("AMediaCodec_start failed: status {}", status));
            }
        }

        self.configured = true;
        self.width = w;
        self.height = h;
        self.stride = w;
        self.slice_height = h;
        tracing::info!("AMediaCodec: configured {}x{}", w, h);
        Ok(())
    }

    /// Queue a single NAL unit / access unit into an input buffer.
    fn queue_input(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            let idx = ffi::AMediaCodec_dequeueInputBuffer(self.codec, 10_000); // 10ms
            if idx < 0 {
                // The frame is lost, and that has to be said: a silently
                // dropped frame breaks the reference chain while every later
                // delta still decodes. An error makes the caller suppress
                // rendering and ask for a keyframe.
                return Err(anyhow!(
                    "AMediaCodec: no input buffer within 10 ms, frame dropped"
                ));
            }
            let idx = idx as usize;

            let mut buf_size: usize = 0;
            let buf = ffi::AMediaCodec_getInputBuffer(self.codec, idx, &mut buf_size);
            if buf.is_null() || buf_size < data.len() {
                // Release the buffer without data
                ffi::AMediaCodec_queueInputBuffer(self.codec, idx, 0, 0, 0, 0);
                return Err(anyhow!(
                    "AMediaCodec: input buffer too small ({} < {})",
                    buf_size,
                    data.len()
                ));
            }

            ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());

            let pts = self.pts_counter;
            self.pts_counter += 1;

            let status =
                ffi::AMediaCodec_queueInputBuffer(self.codec, idx, 0, data.len() as u32, pts, 0);
            if status != ffi::AMEDIA_OK {
                // As for a missing input buffer: the frame is lost, so say so
                return Err(anyhow!("AMediaCodec: queueInputBuffer failed: {status}"));
            }
        }
        Ok(())
    }

    /// Drain all available decoded frames from the output.
    ///
    /// Hardware decoders finish asynchronously, so the first picture is waited
    /// for (up to 10 ms) and only the rest are polled: polling at 0 right after
    /// queueing returned the previous frame, so the display ran one input
    /// behind and a still share never showed its last update. The wait lasts
    /// until a picture rather than one call, because the very first one comes
    /// in behind INFO_OUTPUT_FORMAT_CHANGED.
    /// ponytail: a decode that outlasts the wait can still leave the display a
    /// picture behind for a while; waiting for the pts just queued would not.
    fn drain_output(&mut self) -> Result<Vec<DecodedFrame>> {
        let mut frames = Vec::new();
        let mut timeout_us: i64 = 10_000;

        loop {
            let mut info = ffi::AMediaCodecBufferInfo::default();
            let idx =
                unsafe { ffi::AMediaCodec_dequeueOutputBuffer(self.codec, &mut info, timeout_us) };

            if idx == ffi::AMEDIACODEC_INFO_TRY_AGAIN_LATER {
                break;
            }

            if idx == ffi::AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED {
                self.update_output_format();
                continue;
            }

            if idx == ffi::AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED {
                continue;
            }

            if idx < 0 {
                // An error code, not a hint: the codec is in trouble, and an
                // empty Ok would leave the caller showing nothing and asking
                // for nothing
                return Err(anyhow!("AMediaCodec: dequeueOutputBuffer failed: {idx}"));
            }
            timeout_us = 0;

            let idx_u = idx as usize;

            let frame = unsafe {
                let mut buf_size: usize = 0;
                let buf = ffi::AMediaCodec_getOutputBuffer(self.codec, idx_u, &mut buf_size);

                // The codec describes its own buffer; check it says something
                // that fits before making a slice of it
                let in_bounds = info.offset >= 0
                    && info.size > 0
                    && (info.offset as usize)
                        .checked_add(info.size as usize)
                        .is_some_and(|end| end <= buf_size);
                let result = if !buf.is_null() && in_bounds {
                    let offset = info.offset as usize;
                    let size = info.size as usize;
                    let raw = std::slice::from_raw_parts(buf.add(offset), size);
                    let started = std::time::Instant::now();
                    let i420 = self.convert_to_i420(raw);
                    self.copy_time += started.elapsed();
                    Some(i420)
                } else {
                    None
                };

                ffi::AMediaCodec_releaseOutputBuffer(self.codec, idx_u, false);
                result
            };

            if let Some(i420_data) = frame {
                frames.push(DecodedFrame {
                    width: self.width,
                    height: self.height,
                    i420_data,
                    full_range: self.full_range,
                    bt709: self.bt709,
                });
            }
        }

        Ok(frames)
    }

    /// Read updated width/height/stride/color_format from the output format.
    fn update_output_format(&mut self) {
        unsafe {
            let format = ffi::AMediaCodec_getOutputFormat(self.codec);
            if format.is_null() {
                return;
            }

            // A driver reporting a negative or absurd size would otherwise be
            // a multi-gigabyte allocation (or a wrapped one on 32-bit ARM)
            let sane = |v: i32, max: i32| (1..=max).contains(&v).then_some(v as u32);
            let mut val: i32 = 0;
            if ffi::AMediaFormat_getInt32(format, b"width\0".as_ptr() as *const _, &mut val) {
                if let Some(v) = sane(val, MAX_DIMENSION) {
                    self.width = v;
                }
            }
            if ffi::AMediaFormat_getInt32(format, b"height\0".as_ptr() as *const _, &mut val) {
                if let Some(v) = sane(val, MAX_DIMENSION) {
                    self.height = v;
                }
            }
            // What the stream says it carries (KEY_COLOR_RANGE: 1 full,
            // 2 limited; KEY_COLOR_STANDARD: 1 BT.709). Untagged is limited for
            // H.264/H.265 and full for VP8/VP9, as on the desktop.
            self.full_range = matches!(self.video_codec, VideoCodec::Vp8 | VideoCodec::Vp9);
            self.bt709 = false;
            if ffi::AMediaFormat_getInt32(format, b"color-range\0".as_ptr() as *const _, &mut val) {
                self.full_range = val == 1;
            }
            if ffi::AMediaFormat_getInt32(
                format,
                b"color-standard\0".as_ptr() as *const _,
                &mut val,
            ) {
                self.bt709 = val == 1;
            }
            // The configure hint was a guess (1920x1080 for anything but HEVC),
            // so its stride must not survive into the real size. Devices that
            // report stride/slice-height below overwrite these again.
            self.stride = self.width;
            self.slice_height = self.height;

            // Codecs encode in whole macroblocks, so a 854-wide share is coded
            // as 864 and carries a crop rectangle for the visible part. Without
            // this the viewer shows the padding and a slightly stretched image.
            let mut left = 0i32;
            let mut right = 0i32;
            let mut top = 0i32;
            let mut bottom = 0i32;
            if ffi::AMediaFormat_getInt32(format, b"crop-left\0".as_ptr() as *const _, &mut left)
                && ffi::AMediaFormat_getInt32(
                    format,
                    b"crop-right\0".as_ptr() as *const _,
                    &mut right,
                )
                && ffi::AMediaFormat_getInt32(format, b"crop-top\0".as_ptr() as *const _, &mut top)
                && ffi::AMediaFormat_getInt32(
                    format,
                    b"crop-bottom\0".as_ptr() as *const _,
                    &mut bottom,
                )
            {
                // The rectangle is inclusive on both edges.
                let cropped_w = right - left + 1;
                let cropped_h = bottom - top + 1;
                if cropped_w > 0
                    && cropped_h > 0
                    && cropped_w as u32 <= self.width
                    && cropped_h as u32 <= self.height
                {
                    self.width = cropped_w as u32;
                    self.height = cropped_h as u32;
                }
            }
            if ffi::AMediaFormat_getInt32(format, b"stride\0".as_ptr() as *const _, &mut val) {
                if let Some(v) = sane(val, 2 * MAX_DIMENSION) {
                    self.stride = v;
                }
            }
            if ffi::AMediaFormat_getInt32(format, b"slice-height\0".as_ptr() as *const _, &mut val)
            {
                if let Some(v) = sane(val, 2 * MAX_DIMENSION) {
                    self.slice_height = v;
                }
            }
            if ffi::AMediaFormat_getInt32(format, b"color-format\0".as_ptr() as *const _, &mut val)
            {
                self.color_format = val;
            }

            // Ensure stride/slice_height are at least width/height
            if self.stride < self.width {
                self.stride = self.width;
            }
            if self.slice_height < self.height {
                self.slice_height = self.height;
            }

            ffi::AMediaFormat_delete(format);

            tracing::info!(
                "AMediaCodec: output format changed: {}x{} stride={} slice_height={} color={}",
                self.width,
                self.height,
                self.stride,
                self.slice_height,
                self.color_format,
            );
        }
    }

    /// Convert raw MediaCodec output buffer to packed I420.
    ///
    /// Handles NV12 (most common), I420, and flexible YUV420 formats.
    fn convert_to_i420(&self, raw: &[u8]) -> Vec<u8> {
        let w = self.width as usize;
        let h = self.height as usize;
        let s = self.stride as usize;
        let sh = self.slice_height as usize;
        let uv_w = (w + 1) / 2;
        let uv_h = (h + 1) / 2;
        let y_size = w * h;
        let total = y_size + 2 * uv_w * uv_h;
        let mut i420 = vec![0u8; total];

        match self.color_format {
            ffi::COLOR_FormatYUV420Planar => {
                // Already I420 but may have stride padding
                // Y plane
                for row in 0..h {
                    let src_start = row * s;
                    let dst_start = row * w;
                    if src_start + w <= raw.len() {
                        i420[dst_start..dst_start + w]
                            .copy_from_slice(&raw[src_start..src_start + w]);
                    }
                }
                // U plane
                let u_offset = s * sh;
                let u_stride = (s + 1) / 2;
                for row in 0..uv_h {
                    let src_start = u_offset + row * u_stride;
                    let dst_start = y_size + row * uv_w;
                    if src_start + uv_w <= raw.len() {
                        i420[dst_start..dst_start + uv_w]
                            .copy_from_slice(&raw[src_start..src_start + uv_w]);
                    }
                }
                // V plane
                let v_offset = u_offset + u_stride * ((sh + 1) / 2);
                for row in 0..uv_h {
                    let src_start = v_offset + row * u_stride;
                    let dst_start = y_size + uv_w * uv_h + row * uv_w;
                    if src_start + uv_w <= raw.len() {
                        i420[dst_start..dst_start + uv_w]
                            .copy_from_slice(&raw[src_start..src_start + uv_w]);
                    }
                }
            }
            // NV12 or Flexible (treat flexible as NV12 — correct for nearly all devices)
            _ => {
                // Y plane: stride-aware copy
                for row in 0..h {
                    let src_start = row * s;
                    let dst_start = row * w;
                    if src_start + w <= raw.len() {
                        i420[dst_start..dst_start + w]
                            .copy_from_slice(&raw[src_start..src_start + w]);
                    }
                }
                // NV12 UV plane: interleaved UV starting at stride * slice_height
                let uv_offset = s * sh;
                for row in 0..uv_h {
                    let src_row_start = uv_offset + row * s;
                    for col in 0..uv_w {
                        let src_idx = src_row_start + col * 2;
                        if src_idx + 1 < raw.len() {
                            // U
                            i420[y_size + row * uv_w + col] = raw[src_idx];
                            // V
                            i420[y_size + uv_w * uv_h + row * uv_w + col] = raw[src_idx + 1];
                        }
                    }
                }
            }
        }

        i420
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe {
            if self.configured {
                ffi::AMediaCodec_stop(self.codec);
            }
            ffi::AMediaCodec_delete(self.codec);
        }
        tracing::info!("AMediaCodec: decoder destroyed");
    }
}

// ---------------------------------------------------------------------------
// Annex B helpers (H.264 and H.265)
// ---------------------------------------------------------------------------

/// Find start code positions in Annex B byte stream.
fn find_start_codes(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut i = 0;
    while i + 2 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                positions.push(i);
                i += 3;
                continue;
            } else if i + 3 < data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                positions.push(i);
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    positions
}

/// Get the HEVC NAL unit type from the first byte after the start code.
fn nal_type(video_codec: VideoCodec, data: &[u8], start_code_pos: usize) -> Option<u8> {
    let hdr_offset = if start_code_pos + 2 < data.len() && data[start_code_pos + 2] == 1 {
        start_code_pos + 3
    } else if start_code_pos + 3 < data.len() && data[start_code_pos + 3] == 1 {
        start_code_pos + 4
    } else {
        return None;
    };
    if hdr_offset < data.len() {
        // H.264: 1-byte header, 5-bit type. HEVC: 2-byte header, 6-bit type.
        Some(match video_codec {
            VideoCodec::H264 => data[hdr_offset] & 0x1F,
            _ => (data[hdr_offset] >> 1) & 0x3F,
        })
    } else {
        None
    }
}

/// Parameter-set NAL types: H.264 SPS=7/PPS=8, HEVC VPS=32/SPS=33/PPS=34.
fn is_parameter_set(video_codec: VideoCodec, nal_type: u8) -> bool {
    match video_codec {
        VideoCodec::H264 => nal_type == 7 || nal_type == 8,
        _ => (32..=34).contains(&nal_type),
    }
}

/// Extract the parameter sets from an Annex B keyframe as the CSD-0 buffer.
///
/// Returns the byte range from the first parameter-set NAL through the end
/// of the last one (before the first slice NAL).
fn extract_csd(video_codec: VideoCodec, data: &[u8]) -> &[u8] {
    let positions = find_start_codes(data);
    if positions.is_empty() {
        return &[];
    }

    let mut csd_start: Option<usize> = None;
    let mut csd_end: usize = 0;

    for (i, &pos) in positions.iter().enumerate() {
        if let Some(nal_type) = nal_type(video_codec, data, pos) {
            if is_parameter_set(video_codec, nal_type) {
                if csd_start.is_none() {
                    csd_start = Some(pos);
                }
                // End of this NAL is start of next, or end of data
                csd_end = if i + 1 < positions.len() {
                    positions[i + 1]
                } else {
                    data.len()
                };
            }
        }
    }

    match csd_start {
        Some(start) => &data[start..csd_end],
        None => &[],
    }
}

/// Split an H.264 CSD range into (SPS…, PPS…) as MediaCodec expects it for
/// `video/avc`: csd-0 carries the SPS, csd-1 the PPS. The split is the first
/// PPS start code inside the range; without one the whole range stays in csd-0.
fn split_h264_csd(csd: &[u8]) -> (&[u8], &[u8]) {
    for &pos in find_start_codes(csd).iter() {
        if nal_type(VideoCodec::H264, csd, pos) == Some(8) {
            return (&csd[..pos], &csd[pos..]);
        }
    }
    (csd, &[])
}
