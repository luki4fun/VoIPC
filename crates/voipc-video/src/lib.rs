#[cfg(not(target_os = "android"))]
pub mod convert;
#[cfg(not(target_os = "android"))]
pub mod decoder;
#[cfg(not(target_os = "android"))]
pub mod encoder;

// Android video decoder via NDK AMediaCodec
#[cfg(target_os = "android")]
mod android_decoder;
#[cfg(target_os = "android")]
pub mod decoder {
    pub use super::android_decoder::{DecodedFrame, Decoder};
}

#[cfg(target_os = "android")]
pub mod encoder {
    use anyhow::Result;
    use voipc_protocol::types::VideoCodec;

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
        pub fn new(
            _codec: VideoCodec,
            _width: u32,
            _height: u32,
            _bitrate_kbps: u32,
            _fps: u32,
        ) -> Result<Self> {
            anyhow::bail!("screen share encoding is not available on Android")
        }

        pub fn encode(
            &mut self,
            _i420_data: &[u8],
            _pts: i64,
            _force_keyframe: bool,
        ) -> Result<Vec<EncodedFrame>> {
            anyhow::bail!("screen share encoding is not available on Android")
        }

        pub fn width(&self) -> u32 {
            0
        }
        pub fn height(&self) -> u32 {
            0
        }
        pub fn codec(&self) -> VideoCodec {
            VideoCodec::H264
        }
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
                    if py >= height {
                        break;
                    }
                    for dx in 0..2u32 {
                        let px = col + dx as usize;
                        if px >= width {
                            break;
                        }
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

    /// I420 to packed RGB. JPEG has no alpha channel — the `image` crate's
    /// encoder refuses an RGBA buffer outright — so the viewer converts to this.
    pub fn i420_to_rgb(i420: &[u8], width: usize, height: usize) -> Vec<u8> {
        let mut rgb = vec![0u8; width * height * 3];
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
        rgb
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

/// Seconds between the periodic IDRs the app forces, timed from the last one
/// that went out whole: a still screen captures no frames to count, so the
/// sharer re-encodes its last one when this runs out.
/// Video travels on reliable QUIC streams, so loss no longer breaks the decoder
/// chain; the periodic keyframe is only a safety net (a new viewer asks for one
/// explicitly) and costs 10–20× a delta frame.
pub const KEYFRAME_INTERVAL_SECS: u32 = 4;

/// Turn a decoded I420 frame into what JPEG means by YCbCr — full range, the
/// BT.601 matrix — in place, for the viewers that hand it to a JPEG encoder
/// (H3-03). Limited range drew black at 16 and white at 236 on every desktop
/// viewer; a BT.709 frame (a browser's H.264 share) drew its greens and reds
/// shifted. `full_range` and `bt709` are what the stream says it carries.
///
/// Run it on the frame that is shown, not on every frame decoded: it is a pass
/// over every pixel, and a phone viewer that ran it in the decoder fell behind
/// a browser's share and never showed a picture.
pub fn to_jpeg_ycbcr(i420: &mut [u8], width: usize, height: usize, full_range: bool, bt709: bool) {
    let y_len = width * height;
    let c_len = width.div_ceil(2) * height.div_ceil(2);
    if i420.len() < y_len + 2 * c_len || (full_range && !bt709) {
        return;
    }
    // Normalised: Y in 0..1, chroma in -0.5..0.5
    let (y_off, y_scale, c_scale) = if full_range {
        (0.0, 255.0, 255.0)
    } else {
        (16.0, 219.0, 224.0)
    };
    let y_of = |v: u8| (v as f32 - y_off) / y_scale;
    let c_of = |v: u8| (v as f32 - 128.0) / c_scale;
    let to_u8 = |v: f32| (v + 0.5).clamp(0.0, 255.0) as u8;
    if !bt709 {
        // Range only: two lookup tables
        let ylut: [u8; 256] = std::array::from_fn(|v| to_u8(y_of(v as u8) * 255.0));
        let clut: [u8; 256] = std::array::from_fn(|v| to_u8(c_of(v as u8) * 255.0 + 128.0));
        let (y, c) = i420.split_at_mut(y_len);
        y.iter_mut().for_each(|v| *v = ylut[*v as usize]);
        c[..2 * c_len]
            .iter_mut()
            .for_each(|v| *v = clut[*v as usize]);
        return;
    }
    // BT.709 to BT.601 in YCbCr, by way of RGB: Y gains a part of the chroma,
    // and the chroma mixes. 4:2:0 shares a chroma sample over 2×2 lumas. The
    // whole change is affine in (Y, Cb, Cr), so each output is a multiply-add
    // in fixed point that the compiler can vectorise: the float arithmetic per
    // pixel took 114 ms a 1080p frame on a phone.
    const SHIFT: u32 = 14;
    let fixed = |v: f32| (v * (1 << SHIFT) as f32).round() as i32;
    let [yu, cbu, cru] = bt709_to_bt601(0.0, 1.0, 0.0);
    let [yv, cbv, crv] = bt709_to_bt601(0.0, 0.0, 1.0);
    let (ay, ayu, ayv) = (
        fixed(255.0 / y_scale),
        fixed(yu / c_scale),
        fixed(yv / c_scale),
    );
    let (acbu, acbv, acru, acrv) = (
        fixed(cbu / c_scale),
        fixed(cbv / c_scale),
        fixed(cru / c_scale),
        fixed(crv / c_scale),
    );
    // The offsets, plus a half for rounding
    let half = 1 << (SHIFT - 1);
    let ky = half - fixed(255.0 / y_scale * y_off) - 128 * (ayu + ayv);
    let kcb = half + fixed(128.0) - 128 * (acbu + acbv);
    let kcr = half + fixed(128.0) - 128 * (acru + acrv);
    let out = |v: i32| (v >> SHIFT).clamp(0, 255) as u8;
    let cw = width.div_ceil(2);
    let (ys, cs) = i420.split_at_mut(y_len);
    let (us, vs) = cs.split_at_mut(c_len);
    // The chroma's part of each luma, for the two rows that share it
    let mut from_chroma = vec![0i32; width];
    for (row, line) in ys.chunks_exact_mut(width).enumerate() {
        if row % 2 == 0 {
            let at = (row / 2) * cw;
            for (i, c) in from_chroma.iter_mut().enumerate() {
                let (u, v) = (us[at + i / 2] as i32, vs[at + i / 2] as i32);
                *c = ayu * u + ayv * v + ky;
            }
        }
        for (y, &c) in line.iter_mut().zip(&from_chroma) {
            *y = out(ay * *y as i32 + c);
        }
    }
    for (u, v) in us.iter_mut().zip(vs.iter_mut()) {
        let (cb, cr) = (*u as i32, *v as i32);
        (*u, *v) = (
            out(acbu * cb + acbv * cr + kcb),
            out(acru * cb + acrv * cr + kcr),
        );
    }
}

/// BT.709 (Y, Cb, Cr), normalised, as BT.601 (Y, Cb, Cr) in 0..255 steps
/// (chroma around 0), by way of RGB.
fn bt709_to_bt601(y: f32, cb: f32, cr: f32) -> [f32; 3] {
    let (kr, kb) = (0.2126f32, 0.0722f32);
    let (kr6, kb6) = (0.299f32, 0.114f32);
    let r = y + 2.0 * (1.0 - kr) * cr;
    let b = y + 2.0 * (1.0 - kb) * cb;
    let g = (y - kr * r - kb * b) / (1.0 - kr - kb);
    let y6 = kr6 * r + (1.0 - kr6 - kb6) * g + kb6 * b;
    [
        y6 * 255.0,
        (b - y6) / (2.0 * (1.0 - kb6)) * 255.0,
        (r - y6) / (2.0 * (1.0 - kr6)) * 255.0,
    ]
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

    /// Target bitrate scaled for the actual frame rate: +50% at 60 fps
    /// (temporal redundancy makes doubling unnecessary).
    pub fn bitrate_kbps_at(self, fps: u32) -> u32 {
        let base = self.bitrate_kbps();
        if fps >= 60 {
            base * 3 / 2
        } else {
            base
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

    /// One 2×2 I420 frame of a single colour.
    fn solid(y: u8, u: u8, v: u8) -> Vec<u8> {
        vec![y, y, y, y, u, v]
    }

    #[test]
    fn limited_black_and_white_become_jpeg_black_and_white() {
        let mut black = solid(16, 128, 128);
        to_jpeg_ycbcr(&mut black, 2, 2, false, false);
        assert_eq!(black, solid(0, 128, 128));
        let mut white = solid(235, 128, 128);
        to_jpeg_ycbcr(&mut white, 2, 2, false, false);
        assert_eq!(white, solid(255, 128, 128));
        // Full-range BT.601 is JPEG's already: left alone
        let mut grey = solid(64, 100, 150);
        to_jpeg_ycbcr(&mut grey, 2, 2, true, false);
        assert_eq!(grey, solid(64, 100, 150));
    }

    #[test]
    fn a_bt709_green_is_still_green_in_bt601() {
        // Pure green in full-range BT.709: Y = 0.7152, Cb = -0.3854, Cr = -0.4542
        let enc = |y: f32, c: f32| ((y * 255.0 + 0.5) as u8, (c * 255.0 + 128.5) as u8);
        let (y, u) = enc(0.7152, -0.3854);
        let (_, v) = enc(0.0, -0.4542);
        let mut px = solid(y, u, v);
        to_jpeg_ycbcr(&mut px, 2, 2, true, true);
        // BT.601 green: Y = 0.587 → 150, Cb = -0.3313 → 44, Cr = -0.4187 → 21
        let near = |a: u8, b: u8| a.abs_diff(b) <= 2;
        assert!(
            near(px[0], 150) && near(px[4], 44) && near(px[5], 21),
            "{px:?}"
        );
    }

    #[test]
    fn the_bt709_tables_give_what_the_arithmetic_gives() {
        // Odd sizes, so the last chroma column and row cover one luma only
        let (w, h) = (7usize, 5usize);
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let mut seed = 0x9e37_79b9u32;
        let frame: Vec<u8> = (0..w * h + 2 * cw * ch)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                (seed >> 24) as u8
            })
            .collect();
        for full_range in [false, true] {
            let (y_off, y_scale, c_scale) = if full_range {
                (0.0, 255.0, 255.0)
            } else {
                (16.0, 219.0, 224.0)
            };
            let y_of = |v: u8| (v as f32 - y_off) / y_scale;
            let c_of = |v: u8| (v as f32 - 128.0) / c_scale;
            let to_u8 = |v: f32| (v + 0.5).clamp(0.0, 255.0) as u8;
            let mut out = frame.clone();
            to_jpeg_ycbcr(&mut out, w, h, full_range, true);
            let (u, v) = frame[w * h..].split_at(cw * ch);
            for row in 0..h {
                for col in 0..w {
                    let ci = (row / 2) * cw + col / 2;
                    let [y6, _, _] =
                        bt709_to_bt601(y_of(frame[row * w + col]), c_of(u[ci]), c_of(v[ci]));
                    assert!(
                        out[row * w + col].abs_diff(to_u8(y6)) <= 1,
                        "luma {row},{col}"
                    );
                }
            }
            for ci in 0..cw * ch {
                let [_, cb, cr] = bt709_to_bt601(0.0, c_of(u[ci]), c_of(v[ci]));
                assert!(out[w * h + ci].abs_diff(to_u8(cb + 128.0)) <= 1, "cb {ci}");
                assert!(
                    out[w * h + cw * ch + ci].abs_diff(to_u8(cr + 128.0)) <= 1,
                    "cr {ci}"
                );
            }
        }
    }

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
        assert_eq!(
            (Resolution::P480.width(), Resolution::P480.height()),
            (854, 480)
        );
        assert_eq!(
            (Resolution::P720.width(), Resolution::P720.height()),
            (1280, 720)
        );
        assert_eq!(
            (Resolution::P1080.width(), Resolution::P1080.height()),
            (1920, 1080)
        );
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
