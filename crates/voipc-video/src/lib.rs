#[cfg(not(target_os = "android"))]
pub mod encoder;
#[cfg(not(target_os = "android"))]
pub mod decoder;
#[cfg(not(target_os = "android"))]
pub mod convert;

// Android H.265 decoder via NDK AMediaCodec
#[cfg(target_os = "android")]
mod android_decoder;
#[cfg(target_os = "android")]
pub mod decoder {
    pub use super::android_decoder::{Decoder, DecodedFrame};
}

#[cfg(target_os = "android")]
pub mod encoder {
    use anyhow::Result;

    pub struct Encoder;

    #[derive(Clone, Debug)]
    pub struct EncodedFrame {
        pub data: Vec<u8>,
        pub is_keyframe: bool,
        pub pts: i64,
    }

    // SAFETY: Stub only.
    unsafe impl Send for Encoder {}

    impl Encoder {
        pub fn new(_width: u32, _height: u32, _bitrate_kbps: u32, _fps: u32) -> Result<Self> {
            anyhow::bail!("H.265 encoder not available on Android")
        }

        pub fn encode(&mut self, _i420_data: &[u8], _pts: i64, _force_keyframe: bool) -> Result<Vec<EncodedFrame>> {
            anyhow::bail!("H.265 encoder not available on Android")
        }

        pub fn width(&self) -> u32 { 0 }
        pub fn height(&self) -> u32 { 0 }
    }
}

#[cfg(target_os = "android")]
pub mod convert {
    // Re-export the pure-Rust conversion functions that don't need FFmpeg.
    // FrameConverter (FFmpeg SwsContext) is not available on Android.

    #[inline(always)]
    fn clamp_u8(v: i32) -> u8 {
        v.max(0).min(255) as u8
    }

    pub fn bgra_to_i420(bgra: &[u8], width: usize, height: usize, i420: &mut Vec<u8>) {
        let y_size = width * height;
        let uv_width = (width + 1) / 2;
        let uv_height = (height + 1) / 2;
        let total = y_size + 2 * uv_width * uv_height;
        i420.clear();
        i420.resize(total, 0);
        let (y_plane, uv_planes) = i420.split_at_mut(y_size);
        let (u_plane, v_plane) = uv_planes.split_at_mut(uv_width * uv_height);
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

    pub fn i420_to_rgba(i420: &[u8], width: usize, height: usize) -> Vec<u8> {
        let mut rgba = vec![0u8; width * height * 4];
        i420_to_rgba_into(i420, width, height, &mut rgba);
        rgba
    }

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

    pub fn scale_i420_nearest(
        src: &[u8], src_w: usize, src_h: usize,
        dst: &mut Vec<u8>, dst_w: usize, dst_h: usize,
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
        for dy in 0..dst_h {
            let sy = dy * src_h / dst_h;
            let src_row = sy * src_w;
            let dst_row = dy * dst_w;
            for dx in 0..dst_w {
                let sx = dx * src_w / dst_w;
                dst_y[dst_row + dx] = src_y[src_row + sx];
            }
        }
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
}

/// Screen share resolution presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// 854x480
    P480,
    /// 1280x720
    P720,
    /// 1920x1080
    P1080,
}

impl Resolution {
    pub fn width(self) -> u32 {
        match self {
            Resolution::P480 => 854,
            Resolution::P720 => 1280,
            Resolution::P1080 => 1920,
        }
    }

    pub fn height(self) -> u32 {
        match self {
            Resolution::P480 => 480,
            Resolution::P720 => 720,
            Resolution::P1080 => 1080,
        }
    }

    /// Target bitrate in kilobits per second.
    pub fn bitrate_kbps(self) -> u32 {
        match self {
            Resolution::P480 => 1500,
            Resolution::P720 => 3000,
            Resolution::P1080 => 5000,
        }
    }

    /// Target frames per second.
    pub fn target_fps(self) -> u32 {
        match self {
            Resolution::P480 => 30,
            Resolution::P720 => 30,
            Resolution::P1080 => 30,
        }
    }

    pub fn from_height(h: u16) -> Option<Self> {
        match h {
            480 => Some(Resolution::P480),
            720 => Some(Resolution::P720),
            1080 => Some(Resolution::P1080),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_from_height_all_valid() {
        assert_eq!(Resolution::from_height(480), Some(Resolution::P480));
        assert_eq!(Resolution::from_height(720), Some(Resolution::P720));
        assert_eq!(Resolution::from_height(1080), Some(Resolution::P1080));
    }

    #[test]
    fn resolution_from_height_invalid() {
        assert_eq!(Resolution::from_height(0), None);
        assert_eq!(Resolution::from_height(360), None);
        assert_eq!(Resolution::from_height(1440), None);
    }

    #[test]
    fn resolution_dimensions() {
        assert_eq!((Resolution::P480.width(), Resolution::P480.height()), (854, 480));
        assert_eq!((Resolution::P720.width(), Resolution::P720.height()), (1280, 720));
        assert_eq!((Resolution::P1080.width(), Resolution::P1080.height()), (1920, 1080));
    }

    #[test]
    fn resolution_bitrate() {
        assert_eq!(Resolution::P480.bitrate_kbps(), 1500);
        assert_eq!(Resolution::P720.bitrate_kbps(), 3000);
        assert_eq!(Resolution::P1080.bitrate_kbps(), 5000);
    }

    #[test]
    fn resolution_fps() {
        assert_eq!(Resolution::P480.target_fps(), 30);
        assert_eq!(Resolution::P720.target_fps(), 30);
        assert_eq!(Resolution::P1080.target_fps(), 30);
    }

    #[test]
    fn resolution_equality() {
        assert_eq!(Resolution::P720, Resolution::P720);
        assert_ne!(Resolution::P720, Resolution::P480);
    }
}
