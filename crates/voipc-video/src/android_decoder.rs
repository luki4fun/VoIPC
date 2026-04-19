//! H.265/HEVC decoder for Android using the NDK AMediaCodec API.
//!
//! Uses raw FFI bindings to `libmediandk.so` (available since API 21).
//! The decoder is lazily configured on the first keyframe containing
//! VPS/SPS/PPS codec-specific data (CSD).

use anyhow::{anyhow, Result};
use std::ptr;

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
    pub const COLOR_FormatYUV420Planar: i32 = 19;   // I420
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
        pub fn AMediaCodec_createDecoderByType(
            mime_type: *const c_char,
        ) -> *mut AMediaCodec;
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
        pub fn AMediaCodec_dequeueInputBuffer(
            codec: *mut AMediaCodec,
            timeout_us: i64,
        ) -> isize;
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
        pub fn AMediaCodec_getOutputFormat(
            codec: *mut AMediaCodec,
        ) -> *mut AMediaFormat;

        pub fn AMediaFormat_new() -> *mut AMediaFormat;
        pub fn AMediaFormat_delete(format: *mut AMediaFormat) -> media_status_t;
        pub fn AMediaFormat_setString(
            format: *mut AMediaFormat,
            name: *const c_char,
            value: *const c_char,
        );
        pub fn AMediaFormat_setInt32(
            format: *mut AMediaFormat,
            name: *const c_char,
            value: i32,
        );
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

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A decoded video frame in I420 format.
#[derive(Clone, Debug)]
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    /// I420 data (Y + U + V planes, total width*height*3/2 bytes).
    pub i420_data: Vec<u8>,
}

/// H.265/HEVC decoder backed by Android's hardware MediaCodec.
pub struct Decoder {
    codec: *mut ffi::AMediaCodec,
    configured: bool,
    width: u32,
    height: u32,
    stride: u32,
    slice_height: u32,
    color_format: i32,
    pts_counter: u64,
}

// SAFETY: The decoder is only used from a single blocking tokio task.
unsafe impl Send for Decoder {}

impl Decoder {
    /// Create a new H.265/HEVC decoder.
    ///
    /// The codec is allocated but not configured until the first keyframe
    /// with VPS/SPS/PPS is received.
    pub fn new() -> Result<Self> {
        let mime = b"video/hevc\0";
        let codec =
            unsafe { ffi::AMediaCodec_createDecoderByType(mime.as_ptr() as *const _) };
        if codec.is_null() {
            return Err(anyhow!("AMediaCodec: no HEVC decoder available on this device"));
        }
        tracing::info!("AMediaCodec: HEVC decoder created");
        Ok(Self {
            codec,
            configured: false,
            width: 0,
            height: 0,
            stride: 0,
            slice_height: 0,
            color_format: ffi::COLOR_FormatYUV420SemiPlanar,
            pts_counter: 0,
        })
    }

    /// Decode a H.265/HEVC encoded frame (Annex B format with start codes).
    ///
    /// On the first call, the data must be a keyframe containing VPS/SPS/PPS
    /// so that the codec can be configured.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<DecodedFrame>> {
        if !self.configured {
            self.configure_from_keyframe(data)?;
        }

        self.queue_input(data)?;
        self.drain_output()
    }

    /// Extract VPS/SPS/PPS from the first keyframe and configure the codec.
    fn configure_from_keyframe(&mut self, data: &[u8]) -> Result<()> {
        // Find CSD (everything up to the first non-VPS/SPS/PPS NAL unit)
        let csd = extract_csd(data);
        if csd.is_empty() {
            return Err(anyhow!(
                "AMediaCodec: first frame has no VPS/SPS/PPS — waiting for keyframe"
            ));
        }

        // Parse width/height from SPS if possible, otherwise use defaults
        let (w, h) = parse_sps_dimensions(data).unwrap_or((1920, 1080));

        let format = unsafe { ffi::AMediaFormat_new() };
        if format.is_null() {
            return Err(anyhow!("AMediaFormat_new returned null"));
        }

        unsafe {
            ffi::AMediaFormat_setString(
                format,
                b"mime\0".as_ptr() as *const _,
                b"video/hevc\0".as_ptr() as *const _,
            );
            ffi::AMediaFormat_setInt32(format, b"width\0".as_ptr() as *const _, w as i32);
            ffi::AMediaFormat_setInt32(
                format,
                b"height\0".as_ptr() as *const _,
                h as i32,
            );
            // Set CSD-0 (VPS+SPS+PPS concatenated with start codes)
            ffi::AMediaFormat_setBuffer(
                format,
                b"csd-0\0".as_ptr() as *const _,
                csd.as_ptr(),
                csd.len(),
            );

            let status = ffi::AMediaCodec_configure(
                self.codec,
                format,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );
            ffi::AMediaFormat_delete(format);

            if status != ffi::AMEDIA_OK {
                return Err(anyhow!(
                    "AMediaCodec_configure failed: status {}",
                    status
                ));
            }

            let status = ffi::AMediaCodec_start(self.codec);
            if status != ffi::AMEDIA_OK {
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
                // No buffer available — drop this frame
                tracing::trace!("AMediaCodec: no input buffer available, dropping frame");
                return Ok(());
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

            let status = ffi::AMediaCodec_queueInputBuffer(
                self.codec,
                idx,
                0,
                data.len() as u32,
                pts,
                0,
            );
            if status != ffi::AMEDIA_OK {
                tracing::warn!("AMediaCodec: queueInputBuffer failed: {}", status);
            }
        }
        Ok(())
    }

    /// Drain all available decoded frames from the output.
    fn drain_output(&mut self) -> Result<Vec<DecodedFrame>> {
        let mut frames = Vec::new();

        loop {
            let mut info = ffi::AMediaCodecBufferInfo::default();
            let idx =
                unsafe { ffi::AMediaCodec_dequeueOutputBuffer(self.codec, &mut info, 0) };

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
                tracing::warn!("AMediaCodec: dequeueOutputBuffer unexpected: {}", idx);
                break;
            }

            let idx_u = idx as usize;

            let frame = unsafe {
                let mut buf_size: usize = 0;
                let buf =
                    ffi::AMediaCodec_getOutputBuffer(self.codec, idx_u, &mut buf_size);

                let result = if !buf.is_null() && info.size > 0 {
                    let offset = info.offset as usize;
                    let size = info.size as usize;
                    let raw = std::slice::from_raw_parts(buf.add(offset), size);
                    Some(self.convert_to_i420(raw))
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

            let mut val: i32 = 0;
            if ffi::AMediaFormat_getInt32(format, b"width\0".as_ptr() as *const _, &mut val)
            {
                self.width = val as u32;
            }
            if ffi::AMediaFormat_getInt32(
                format,
                b"height\0".as_ptr() as *const _,
                &mut val,
            ) {
                self.height = val as u32;
            }
            if ffi::AMediaFormat_getInt32(
                format,
                b"stride\0".as_ptr() as *const _,
                &mut val,
            ) {
                self.stride = val as u32;
            }
            if ffi::AMediaFormat_getInt32(
                format,
                b"slice-height\0".as_ptr() as *const _,
                &mut val,
            ) {
                self.slice_height = val as u32;
            }
            if ffi::AMediaFormat_getInt32(
                format,
                b"color-format\0".as_ptr() as *const _,
                &mut val,
            ) {
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
                            i420[y_size + uv_w * uv_h + row * uv_w + col] =
                                raw[src_idx + 1];
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
// H.265 Annex B helpers
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
fn hevc_nal_type(data: &[u8], start_code_pos: usize) -> Option<u8> {
    let hdr_offset = if start_code_pos + 2 < data.len() && data[start_code_pos + 2] == 1 {
        start_code_pos + 3
    } else if start_code_pos + 3 < data.len() && data[start_code_pos + 3] == 1 {
        start_code_pos + 4
    } else {
        return None;
    };
    if hdr_offset < data.len() {
        Some((data[hdr_offset] >> 1) & 0x3F)
    } else {
        None
    }
}

/// Extract VPS+SPS+PPS from an Annex B keyframe as the CSD-0 buffer.
///
/// Returns the byte range from the first VPS/SPS/PPS NAL through the end
/// of the last parameter set NAL (before the first slice NAL).
fn extract_csd(data: &[u8]) -> &[u8] {
    let positions = find_start_codes(data);
    if positions.is_empty() {
        return &[];
    }

    let mut csd_start: Option<usize> = None;
    let mut csd_end: usize = 0;

    for (i, &pos) in positions.iter().enumerate() {
        if let Some(nal_type) = hevc_nal_type(data, pos) {
            // VPS=32, SPS=33, PPS=34
            if (32..=34).contains(&nal_type) {
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

/// Minimal HEVC SPS parser to extract pic_width and pic_height.
///
/// Parses just enough of the SPS NAL to reach pic_width_in_luma_samples
/// and pic_height_in_luma_samples (both exp-Golomb coded).
fn parse_sps_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    let positions = find_start_codes(data);

    // Find the SPS NAL unit
    for (i, &pos) in positions.iter().enumerate() {
        if hevc_nal_type(data, pos)? == 33 {
            // SPS NAL type
            let hdr_offset = if data[pos + 2] == 1 {
                pos + 3
            } else {
                pos + 4
            };
            let nal_end = if i + 1 < positions.len() {
                positions[i + 1]
            } else {
                data.len()
            };
            let nal_data = &data[hdr_offset..nal_end];
            return parse_sps_nal(nal_data);
        }
    }
    None
}

/// Parse width/height from raw SPS NAL unit bytes (after start code).
fn parse_sps_nal(nal: &[u8]) -> Option<(u32, u32)> {
    let mut reader = BitReader::new(nal);

    // NAL unit header: 2 bytes (already identified as SPS)
    reader.skip(16)?;

    // sps_video_parameter_set_id: u4
    reader.skip(4)?;
    // sps_max_sub_layers_minus1: u3
    let max_sub_layers = reader.read_bits(3)? as usize;
    // sps_temporal_id_nesting_flag: u1
    reader.skip(1)?;

    // profile_tier_level(1, max_sub_layers_minus1)
    skip_profile_tier_level(&mut reader, max_sub_layers)?;

    // sps_seq_parameter_set_id: ue(v)
    reader.read_ue()?;
    // chroma_format_idc: ue(v)
    let chroma_format = reader.read_ue()?;
    if chroma_format == 3 {
        // separate_colour_plane_flag: u1
        reader.skip(1)?;
    }

    // pic_width_in_luma_samples: ue(v)
    let width = reader.read_ue()?;
    // pic_height_in_luma_samples: ue(v)
    let height = reader.read_ue()?;

    if width > 0 && height > 0 && width <= 8192 && height <= 8192 {
        Some((width, height))
    } else {
        None
    }
}

/// Skip the profile_tier_level() syntax structure in the bitstream.
fn skip_profile_tier_level(reader: &mut BitReader, max_sub_layers: usize) -> Option<()> {
    // general_profile_space(2) + general_tier_flag(1) + general_profile_idc(5)
    reader.skip(8)?;
    // general_profile_compatibility_flag[32]
    reader.skip(32)?;
    // general_progressive_source_flag..general_reserved_zero_43bits (48 bits)
    reader.skip(48)?;
    // general_level_idc: u8
    reader.skip(8)?;

    if max_sub_layers > 0 {
        // sub_layer_profile_present_flag[i] + sub_layer_level_present_flag[i]
        // for i in 0..max_sub_layers-1
        let mut profile_present = Vec::new();
        let mut level_present = Vec::new();
        for _ in 0..max_sub_layers {
            profile_present.push(reader.read_bits(1)? != 0);
            level_present.push(reader.read_bits(1)? != 0);
        }
        // reserved bits to fill to 8 sub-layers
        if max_sub_layers < 8 {
            reader.skip(2 * (8 - max_sub_layers) as u32)?;
        }
        // sub_layer profile/level data
        for i in 0..max_sub_layers {
            if profile_present[i] {
                // sub_layer_profile_space..compatibility_flag..constraint (88 bits)
                reader.skip(88)?;
            }
            if level_present[i] {
                reader.skip(8)?;
            }
        }
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Minimal bitstream reader for exp-Golomb parsing
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0..8, bits consumed in current byte
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<u32> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = ((self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1) as u32;
        self.bit_pos += 1;
        if self.bit_pos >= 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
            // Handle emulation prevention bytes (0x00 0x00 0x03 → skip 0x03)
            if self.byte_pos >= 2
                && self.byte_pos < self.data.len()
                && self.data[self.byte_pos] == 0x03
                && self.data[self.byte_pos - 1] == 0x00
                && self.data[self.byte_pos - 2] == 0x00
            {
                self.byte_pos += 1;
            }
        }
        Some(bit)
    }

    fn read_bits(&mut self, n: u32) -> Option<u32> {
        let mut val = 0u32;
        for _ in 0..n {
            val = (val << 1) | self.read_bit()?;
        }
        Some(val)
    }

    fn skip(&mut self, n: u32) -> Option<()> {
        for _ in 0..n {
            self.read_bit()?;
        }
        Some(())
    }

    /// Read unsigned exp-Golomb coded value.
    fn read_ue(&mut self) -> Option<u32> {
        let mut leading_zeros = 0u32;
        while self.read_bit()? == 0 {
            leading_zeros += 1;
            if leading_zeros > 31 {
                return None;
            }
        }
        if leading_zeros == 0 {
            return Some(0);
        }
        let suffix = self.read_bits(leading_zeros)?;
        Some((1 << leading_zeros) - 1 + suffix)
    }
}
