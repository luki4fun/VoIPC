// All color conversions use integer fixed-point BT.601 arithmetic.
// This is 3-5x faster than the floating-point equivalent since it avoids
// f32 multiplies/divides on every pixel.

use anyhow::{bail, Context as _, Result};
use ffmpeg_next as ffmpeg;
pub use ffmpeg::format::Pixel;
use ffmpeg::software::scaling;
use ffmpeg::util::frame::video::Video;

/// Clamp an i32 to u8 range.
#[inline(always)]
fn clamp_u8(v: i32) -> u8 {
    v.max(0).min(255) as u8
}

// ── SIMD-accelerated conversion via FFmpeg SwsContext ─────────────────────

/// Fast BGRA/RGBA → YUV420P converter using FFmpeg's SwsContext.
///
/// This uses FFmpeg's SIMD-optimized scaling/conversion (SSE2/AVX2 on x86),
/// which is 10-20x faster than the naive per-pixel scalar code.
/// Also handles resolution scaling in the same pass if src ≠ dst dimensions.
pub struct FrameConverter {
    scaler: scaling::Context,
    input_frame: Video,
    output_frame: Video,
    src_width: u32,
    src_height: u32,
}

// SAFETY: FrameConverter is used from a single thread (the encode thread).
// The FFmpeg SwsContext and frames are not Send by default due to raw pointers.
unsafe impl Send for FrameConverter {}

impl FrameConverter {
    /// Create a new converter.
    ///
    /// `input_format` should be `Pixel::BGRA` (Windows DXGI) or `Pixel::RGBA` (Linux).
    /// If `dst_width`/`dst_height` differ from `src_width`/`src_height`, the conversion
    /// also scales in the same pass (replacing the separate `scale_i420_nearest`).
    pub fn new(
        input_format: Pixel,
        src_width: u32,
        src_height: u32,
        dst_width: u32,
        dst_height: u32,
    ) -> Result<Self> {
        let scaler = scaling::Context::get(
            input_format,
            src_width,
            src_height,
            Pixel::YUV420P,
            dst_width,
            dst_height,
            scaling::Flags::FAST_BILINEAR,
        )
        .context("failed to create SwsContext for color conversion")?;

        let input_frame = Video::new(input_format, src_width, src_height);
        let output_frame = Video::new(Pixel::YUV420P, dst_width, dst_height);

        Ok(Self {
            scaler,
            input_frame,
            output_frame,
            src_width,
            src_height,
        })
    }

    /// Convert pixel data (BGRA or RGBA) to YUV420P.
    ///
    /// `pixel_data` must be exactly `src_width * src_height * 4` bytes with no
    /// stride padding (strip it before calling). Returns a reference to the
    /// internal output frame, ready to pass to `Encoder::encode_video_frame()`.
    pub fn convert(&mut self, pixel_data: &[u8]) -> Result<&mut Video> {
        let expected = self.src_width as usize * self.src_height as usize * 4;
        if pixel_data.len() < expected {
            bail!(
                "FrameConverter: pixel data too short ({} < {})",
                pixel_data.len(),
                expected
            );
        }

        // Fill input frame — single memcpy per row (respects FFmpeg stride alignment)
        let w = self.src_width as usize;
        let h = self.src_height as usize;
        let row_bytes = w * 4;
        let stride = self.input_frame.stride(0);
        let dst = self.input_frame.data_mut(0);
        for row in 0..h {
            let src_off = row * row_bytes;
            let dst_off = row * stride;
            dst[dst_off..dst_off + row_bytes]
                .copy_from_slice(&pixel_data[src_off..src_off + row_bytes]);
        }

        self.scaler
            .run(&self.input_frame, &mut self.output_frame)
            .context("SwsContext conversion failed")?;

        Ok(&mut self.output_frame)
    }

    /// Convert pixel data with a custom stride (e.g. DXGI row padding).
    ///
    /// The input data has `stride` bytes per row (may be > width*4 due to alignment).
    /// This avoids the separate `strip_stride_padding()` copy.
    pub fn convert_strided(&mut self, pixel_data: &[u8], stride: usize) -> Result<&mut Video> {
        let w = self.src_width as usize;
        let h = self.src_height as usize;
        let row_bytes = w * 4;

        if stride == row_bytes {
            return self.convert(pixel_data);
        }

        let expected = stride * h;
        if pixel_data.len() < expected {
            bail!(
                "FrameConverter: strided data too short ({} < {})",
                pixel_data.len(),
                expected
            );
        }

        // Copy row by row, skipping stride padding
        let frame_stride = self.input_frame.stride(0);
        let dst = self.input_frame.data_mut(0);
        for row in 0..h {
            let src_off = row * stride;
            let dst_off = row * frame_stride;
            dst[dst_off..dst_off + row_bytes]
                .copy_from_slice(&pixel_data[src_off..src_off + row_bytes]);
        }

        self.scaler
            .run(&self.input_frame, &mut self.output_frame)
            .context("SwsContext conversion failed")?;

        Ok(&mut self.output_frame)
    }
}

/// Convert BGRA pixels to I420 (YUV420 planar).
///
/// Uses integer BT.601: Y = (66*R + 129*G + 25*B + 128)>>8 + 16
pub fn bgra_to_i420(bgra: &[u8], width: usize, height: usize, i420: &mut Vec<u8>) {
    let y_size = width * height;
    let uv_width = (width + 1) / 2;
    let uv_height = (height + 1) / 2;
    let total = y_size + 2 * uv_width * uv_height;

    i420.clear();
    i420.resize(total, 0);

    let (y_plane, uv_planes) = i420.split_at_mut(y_size);
    let (u_plane, v_plane) = uv_planes.split_at_mut(uv_width * uv_height);

    // Y plane
    for row in 0..height {
        let row_off = row * width;
        for col in 0..width {
            let idx = (row_off + col) * 4;
            let b = bgra[idx] as i32;
            let g = bgra[idx + 1] as i32;
            let r = bgra[idx + 2] as i32;
            y_plane[row_off + col] = clamp_u8(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
        }
    }

    // U and V planes (subsampled 2x2) — single pass
    for row in (0..height).step_by(2) {
        for col in (0..width).step_by(2) {
            let mut r_sum = 0i32;
            let mut g_sum = 0i32;
            let mut b_sum = 0i32;
            let mut count = 0i32;

            for dy in 0..2u32 {
                let py = row + dy as usize;
                if py >= height { break; }
                for dx in 0..2u32 {
                    let px = col + dx as usize;
                    if px >= width { break; }
                    let idx = (py * width + px) * 4;
                    b_sum += bgra[idx] as i32;
                    g_sum += bgra[idx + 1] as i32;
                    r_sum += bgra[idx + 2] as i32;
                    count += 1;
                }
            }

            let r = r_sum / count;
            let g = g_sum / count;
            let b = b_sum / count;
            let uv_idx = (row / 2) * uv_width + (col / 2);
            u_plane[uv_idx] = clamp_u8(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128);
            v_plane[uv_idx] = clamp_u8(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128);
        }
    }
}

/// Convert RGBA pixels to I420 (YUV420 planar).
///
/// Uses integer BT.601: Y = (66*R + 129*G + 25*B + 128)>>8 + 16
pub fn rgba_to_i420(rgba: &[u8], width: usize, height: usize, i420: &mut Vec<u8>) {
    let y_size = width * height;
    let uv_width = (width + 1) / 2;
    let uv_height = (height + 1) / 2;
    let total = y_size + 2 * uv_width * uv_height;

    i420.clear();
    i420.resize(total, 0);

    let (y_plane, uv_planes) = i420.split_at_mut(y_size);
    let (u_plane, v_plane) = uv_planes.split_at_mut(uv_width * uv_height);

    // Y plane
    for row in 0..height {
        let row_off = row * width;
        for col in 0..width {
            let idx = (row_off + col) * 4;
            let r = rgba[idx] as i32;
            let g = rgba[idx + 1] as i32;
            let b = rgba[idx + 2] as i32;
            y_plane[row_off + col] = clamp_u8(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
        }
    }

    // U and V planes (subsampled 2x2) — single pass
    for row in (0..height).step_by(2) {
        for col in (0..width).step_by(2) {
            let mut r_sum = 0i32;
            let mut g_sum = 0i32;
            let mut b_sum = 0i32;
            let mut count = 0i32;

            for dy in 0..2u32 {
                let py = row + dy as usize;
                if py >= height { break; }
                for dx in 0..2u32 {
                    let px = col + dx as usize;
                    if px >= width { break; }
                    let idx = (py * width + px) * 4;
                    r_sum += rgba[idx] as i32;
                    g_sum += rgba[idx + 1] as i32;
                    b_sum += rgba[idx + 2] as i32;
                    count += 1;
                }
            }

            let r = r_sum / count;
            let g = g_sum / count;
            let b = b_sum / count;
            let uv_idx = (row / 2) * uv_width + (col / 2);
            u_plane[uv_idx] = clamp_u8(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128);
            v_plane[uv_idx] = clamp_u8(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128);
        }
    }
}

/// Scale I420 (YUV420 planar) using nearest-neighbor interpolation.
///
/// Much faster than scaling in RGBA domain (1.5 bytes/pixel vs 4 bytes/pixel).
/// Used for screen share when capture resolution differs from target encoding resolution.
pub fn scale_i420_nearest(
    src: &[u8],
    src_w: usize,
    src_h: usize,
    dst: &mut Vec<u8>,
    dst_w: usize,
    dst_h: usize,
) {
    let src_y_size = src_w * src_h;
    let src_uv_w = (src_w + 1) / 2;
    let src_uv_h = (src_h + 1) / 2;

    let dst_y_size = dst_w * dst_h;
    let dst_uv_w = (dst_w + 1) / 2;
    let dst_uv_h = (dst_h + 1) / 2;
    let dst_total = dst_y_size + 2 * dst_uv_w * dst_uv_h;

    dst.clear();
    dst.resize(dst_total, 0);

    let src_y = &src[..src_y_size];
    let src_u = &src[src_y_size..src_y_size + src_uv_w * src_uv_h];
    let src_v = &src[src_y_size + src_uv_w * src_uv_h..];

    let (dst_y, dst_uv) = dst.split_at_mut(dst_y_size);
    let (dst_u, dst_v) = dst_uv.split_at_mut(dst_uv_w * dst_uv_h);

    // Scale Y plane (full resolution)
    for dy in 0..dst_h {
        let sy = dy * src_h / dst_h;
        let src_row = sy * src_w;
        let dst_row = dy * dst_w;
        for dx in 0..dst_w {
            let sx = dx * src_w / dst_w;
            dst_y[dst_row + dx] = src_y[src_row + sx];
        }
    }

    // Scale U and V planes (half resolution)
    for dy in 0..dst_uv_h {
        let sy = dy * src_uv_h / dst_uv_h;
        let src_row = sy * src_uv_w;
        let dst_row = dy * dst_uv_w;
        for dx in 0..dst_uv_w {
            let sx = dx * src_uv_w / dst_uv_w;
            dst_u[dst_row + dx] = src_u[src_row + sx];
            dst_v[dst_row + dx] = src_v[src_row + sx];
        }
    }
}

/// Convert I420 (YUV420 planar) to RGB pixels, writing into an existing buffer.
///
/// Integer BT.601 inverse:
///   R = clip((298*C + 409*E + 128) >> 8)
///   G = clip((298*C - 100*D - 208*E + 128) >> 8)
///   B = clip((298*C + 516*D + 128) >> 8)
pub fn i420_to_rgb_into(i420: &[u8], width: usize, height: usize, rgb: &mut Vec<u8>) {
    let rgb_size = width * height * 3;
    rgb.clear();
    rgb.resize(rgb_size, 0);

    let y_plane = &i420[..width * height];
    let uv_width = (width + 1) / 2;
    let u_offset = width * height;
    let v_offset = u_offset + uv_width * ((height + 1) / 2);

    for row in 0..height {
        let row_off = row * width;
        let uv_row = (row / 2) * uv_width;
        for col in 0..width {
            let c = y_plane[row_off + col] as i32 - 16;
            let d = i420[u_offset + uv_row + (col / 2)] as i32 - 128;
            let e = i420[v_offset + uv_row + (col / 2)] as i32 - 128;

            let out = (row_off + col) * 3;
            rgb[out] = clamp_u8((298 * c + 409 * e + 128) >> 8);
            rgb[out + 1] = clamp_u8((298 * c - 100 * d - 208 * e + 128) >> 8);
            rgb[out + 2] = clamp_u8((298 * c + 516 * d + 128) >> 8);
        }
    }
}

/// Convert I420 (YUV420 planar) to RGBA pixels.
pub fn i420_to_rgba(i420: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut rgba = vec![0u8; width * height * 4];
    i420_to_rgba_into(i420, width, height, &mut rgba);
    rgba
}

/// Convert I420 (YUV420 planar) to RGBA pixels, writing into an existing buffer.
pub fn i420_to_rgba_into(i420: &[u8], width: usize, height: usize, rgba: &mut [u8]) {
    let y_plane = &i420[..width * height];
    let uv_width = (width + 1) / 2;
    let u_offset = width * height;
    let v_offset = u_offset + uv_width * ((height + 1) / 2);

    for row in 0..height {
        let row_off = row * width;
        let uv_row = (row / 2) * uv_width;
        for col in 0..width {
            let c = y_plane[row_off + col] as i32 - 16;
            let d = i420[u_offset + uv_row + (col / 2)] as i32 - 128;
            let e = i420[v_offset + uv_row + (col / 2)] as i32 - 128;

            let out = (row_off + col) * 4;
            rgba[out] = clamp_u8((298 * c + 409 * e + 128) >> 8);
            rgba[out + 1] = clamp_u8((298 * c - 100 * d - 208 * e + 128) >> 8);
            rgba[out + 2] = clamp_u8((298 * c + 516 * d + 128) >> 8);
            rgba[out + 3] = 255;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: compute expected BT.601 Y for given R,G,B
    fn expected_y(r: i32, g: i32, b: i32) -> u8 {
        clamp_u8(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16)
    }

    // Helper: create a 2x2 BGRA image with uniform color
    fn uniform_bgra_2x2(b: u8, g: u8, r: u8) -> Vec<u8> {
        [b, g, r, 255].repeat(4)
    }

    // Helper: create a 2x2 RGBA image with uniform color
    fn uniform_rgba_2x2(r: u8, g: u8, b: u8) -> Vec<u8> {
        [r, g, b, 255].repeat(4)
    }

    #[test]
    fn bgra_to_i420_red_pixel() {
        let bgra = uniform_bgra_2x2(0, 0, 255); // pure red
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut i420);
        let y = expected_y(255, 0, 0);
        assert_eq!(i420[0], y); // first Y sample
    }

    #[test]
    fn bgra_to_i420_green_pixel() {
        let bgra = uniform_bgra_2x2(0, 255, 0); // pure green
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut i420);
        let y = expected_y(0, 255, 0);
        assert_eq!(i420[0], y);
    }

    #[test]
    fn bgra_to_i420_black() {
        let bgra = uniform_bgra_2x2(0, 0, 0);
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut i420);
        assert_eq!(i420[0], 16); // BT.601 black = Y 16
    }

    #[test]
    fn bgra_to_i420_white() {
        let bgra = uniform_bgra_2x2(255, 255, 255);
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut i420);
        assert_eq!(i420[0], 235); // BT.601 white = Y 235
    }

    #[test]
    fn rgba_to_i420_red_pixel() {
        let rgba = uniform_rgba_2x2(255, 0, 0); // pure red in RGBA
        let mut i420 = Vec::new();
        rgba_to_i420(&rgba, 2, 2, &mut i420);
        let y = expected_y(255, 0, 0);
        assert_eq!(i420[0], y);
    }

    #[test]
    fn bgra_to_i420_odd_dimensions() {
        // 3x3 image exercises the (width+1)/2 UV subsampling path
        let bgra = vec![128u8; 3 * 3 * 4];
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 3, 3, &mut i420);
        let uv_w = (3 + 1) / 2; // 2
        let uv_h = (3 + 1) / 2; // 2
        assert_eq!(i420.len(), 3 * 3 + 2 * uv_w * uv_h); // 9 + 8 = 17
    }

    #[test]
    fn bgra_to_i420_output_size() {
        let bgra = vec![0u8; 4 * 4 * 4]; // 4x4
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 4, 4, &mut i420);
        // Even dims: w*h + 2*(w/2)*(h/2) = 16 + 2*2*2 = 24 = w*h*3/2
        assert_eq!(i420.len(), 4 * 4 * 3 / 2);
    }

    #[test]
    fn i420_to_rgba_alpha_always_255() {
        let bgra = uniform_bgra_2x2(100, 150, 200);
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut i420);
        let rgba = i420_to_rgba(&i420, 2, 2);
        for pixel in rgba.chunks(4) {
            assert_eq!(pixel[3], 255);
        }
    }

    #[test]
    fn i420_to_rgb_into_output_size() {
        let bgra = vec![0u8; 4 * 4 * 4];
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 4, 4, &mut i420);
        let mut rgb = Vec::new();
        i420_to_rgb_into(&i420, 4, 4, &mut rgb);
        assert_eq!(rgb.len(), 4 * 4 * 3);
    }

    #[test]
    fn roundtrip_bgra_i420_rgba() {
        // Pure red BGRA -> I420 -> RGBA, check within rounding tolerance
        let bgra = uniform_bgra_2x2(0, 0, 255); // B=0, G=0, R=255
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut i420);
        let rgba = i420_to_rgba(&i420, 2, 2);
        // RGBA output should be close to R=255, G=0, B=0
        assert!((rgba[0] as i32 - 255).abs() <= 2, "R={}", rgba[0]);
        assert!((rgba[1] as i32).abs() <= 2, "G={}", rgba[1]);
        assert!((rgba[2] as i32).abs() <= 2, "B={}", rgba[2]);
    }

    #[test]
    fn roundtrip_rgba_i420_rgba() {
        let rgba_in = uniform_rgba_2x2(0, 255, 0); // pure green
        let mut i420 = Vec::new();
        rgba_to_i420(&rgba_in, 2, 2, &mut i420);
        let rgba_out = i420_to_rgba(&i420, 2, 2);
        assert!((rgba_out[0] as i32).abs() <= 2, "R={}", rgba_out[0]);
        assert!((rgba_out[1] as i32 - 255).abs() <= 2, "G={}", rgba_out[1]);
        assert!((rgba_out[2] as i32).abs() <= 2, "B={}", rgba_out[2]);
    }

    #[test]
    fn bgra_to_i420_1x1() {
        let bgra = vec![128, 128, 128, 255]; // 1 pixel
        let mut i420 = Vec::new();
        bgra_to_i420(&bgra, 1, 1, &mut i420);
        // 1x1: Y=1, UV_w=1, UV_h=1, total = 1 + 2*1*1 = 3
        assert_eq!(i420.len(), 3);
    }

    #[test]
    fn scale_i420_nearest_identity() {
        // 4x4 → 4x4 should produce identical output
        let bgra = vec![100u8; 4 * 4 * 4];
        let mut src = Vec::new();
        bgra_to_i420(&bgra, 4, 4, &mut src);
        let mut dst = Vec::new();
        scale_i420_nearest(&src, 4, 4, &mut dst, 4, 4);
        assert_eq!(src, dst);
    }

    #[test]
    fn scale_i420_nearest_downscale_size() {
        // 4x4 → 2x2 should produce correct buffer size
        let bgra = vec![128u8; 4 * 4 * 4];
        let mut src = Vec::new();
        bgra_to_i420(&bgra, 4, 4, &mut src);
        let mut dst = Vec::new();
        scale_i420_nearest(&src, 4, 4, &mut dst, 2, 2);
        // 2x2: Y=4, UV_w=1, UV_h=1, total = 4 + 2*1*1 = 6
        assert_eq!(dst.len(), 6);
    }

    #[test]
    fn scale_i420_nearest_uniform_color() {
        // Uniform color should remain uniform after scaling
        let bgra = uniform_bgra_2x2(0, 0, 255); // pure red 2x2
        let mut src = Vec::new();
        bgra_to_i420(&bgra, 2, 2, &mut src);

        // Scale up to 4x4
        let mut dst = Vec::new();
        scale_i420_nearest(&src, 2, 2, &mut dst, 4, 4);

        // All Y values should be the same as source
        let y_val = src[0];
        for i in 0..16 {
            assert_eq!(dst[i], y_val, "Y[{}] mismatch", i);
        }
    }

    #[test]
    fn scale_i420_nearest_1080_to_720_size() {
        // Verify correct output size for realistic resolution
        let src_w = 1920;
        let src_h = 1080;
        let dst_w = 1280;
        let dst_h = 720;
        let src = vec![128u8; src_w * src_h * 3 / 2];
        let mut dst = Vec::new();
        scale_i420_nearest(&src, src_w, src_h, &mut dst, dst_w, dst_h);
        assert_eq!(dst.len(), dst_w * dst_h * 3 / 2);
    }
}
