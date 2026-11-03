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
    /// Every share VoIPC sends fits the viewer's decode cap, either way up
    /// (S-046: the cap sits just above the largest one).
    #[cfg(not(target_os = "android"))]
    #[test]
    fn every_share_resolution_fits_the_decode_cap() {
        for r in [Resolution::P480, Resolution::P720, Resolution::P1080] {
            let (w, h) = (r.width() as usize, r.height() as usize);
            // Aligned up to 16, as the codecs store them
            let area = w.div_ceil(16) * 16 * h.div_ceil(16) * 16;
            assert!(area <= crate::decoder::MAX_DECODE_PIXELS, "{w}x{h}");
            assert!(w.max(h) <= 2048, "{w}x{h} on its side");
        }
    }

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
