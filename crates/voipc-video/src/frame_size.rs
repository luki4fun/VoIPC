//! A keyframe's picture size, read from the stream before any decoder sees it: the H.264 and
//! H.265 sequence parameter sets, and the VP8 and VP9 keyframe headers. A viewer that hands a
//! peer's frames to a decoder it does not own (the WebView's, 1.13) checks it first, as the
//! desktop decoder caps what it opens (`decoder::MAX_DECODE_PIXELS`, S-047).

use voipc_protocol::types::VideoCodec;

/// Largest width or height believed.
pub const MAX_DIMENSION: u32 = 8192;
/// Largest picture a peer's keyframe may claim: per side alone, 8192×8192 is 67 million pixels.
pub const MAX_PIXELS: u64 = 2048 * 2048;

/// Whether a keyframe's picture is one a viewer may decode: its size read and within the
/// caps. A size this cannot read (an unusual parameter set) passes, for the decoder's own
/// limits to judge, as in a browser; one read and too large never does.
pub fn keyframe_fits(codec: VideoCodec, data: &[u8]) -> bool {
    match keyframe_size(codec, data) {
        Some((w, h)) => fits(w, h),
        None => true,
    }
}

pub fn fits(w: u32, h: u32) -> bool {
    w > 0 && h > 0 && w <= MAX_DIMENSION && h <= MAX_DIMENSION && w as u64 * h as u64 <= MAX_PIXELS
}

/// The coded size a keyframe says it carries, or None when it does not say or cannot be read.
pub fn keyframe_size(codec: VideoCodec, data: &[u8]) -> Option<(u32, u32)> {
    match codec {
        VideoCodec::H264 | VideoCodec::H265 => {
            let sps = find_nal(codec, data, if codec == VideoCodec::H264 { 7 } else { 33 })?;
            if codec == VideoCodec::H264 {
                h264_sps_size(sps)
            } else {
                h265_sps_size(sps)
            }
        }
        VideoCodec::Vp8 => vp8_size(data),
        VideoCodec::Vp9 => vp9_size(data),
    }
}

/// The NAL unit of type `want` in an Annex B stream, header included, up to the next start code.
fn find_nal(codec: VideoCodec, data: &[u8], want: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            let start = i + 3;
            let header = *data.get(start)?;
            let kind = match codec {
                VideoCodec::H264 => header & 0x1F,
                _ => (header >> 1) & 0x3F,
            };
            let mut end = start;
            while end + 3 <= data.len()
                && !(data[end] == 0 && data[end + 1] == 0 && data[end + 2] == 1)
            {
                end += 1;
            }
            let end = if end + 3 > data.len() {
                data.len()
            } else {
                end
            };
            if kind == want {
                return Some(&data[start..end]);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// The coded size from an H.264 SPS (header byte first): whole macroblocks, before cropping.
fn h264_sps_size(nal: &[u8]) -> Option<(u32, u32)> {
    let mut r = BitReader::new(nal, true);
    r.skip(8)?; // NAL header
    let profile = r.read_bits(8)?;
    r.skip(16)?; // constraint flags, level
    r.read_ue()?; // seq_parameter_set_id
    if matches!(
        profile,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        let chroma_format = r.read_ue()?;
        if chroma_format == 3 {
            r.skip(1)?; // separate_colour_plane_flag
        }
        r.read_ue()?; // bit_depth_luma_minus8
        r.read_ue()?; // bit_depth_chroma_minus8
        r.skip(1)?; // qpprime_y_zero_transform_bypass_flag
        if r.read_bits(1)? == 1 {
            // seq_scaling_matrix_present_flag: each list present is skipped value by value
            for i in 0..if chroma_format != 3 { 8 } else { 12 } {
                if r.read_bits(1)? == 1 {
                    let size = if i < 6 { 16 } else { 64 };
                    let (mut last, mut next) = (8i32, 8i32);
                    for _ in 0..size {
                        if next != 0 {
                            next = (last + r.read_se()? + 256) % 256;
                        }
                        if next != 0 {
                            last = next;
                        }
                    }
                }
            }
        }
    }
    r.read_ue()?; // log2_max_frame_num_minus4
    match r.read_ue()? {
        0 => {
            r.read_ue()?; // log2_max_pic_order_cnt_lsb_minus4
        }
        1 => {
            r.skip(1)?; // delta_pic_order_always_zero_flag
            r.read_se()?; // offset_for_non_ref_pic
            r.read_se()?; // offset_for_top_to_bottom_field
            let cycle = r.read_ue()?;
            if cycle > 255 {
                return None;
            }
            for _ in 0..cycle {
                r.read_se()?;
            }
        }
        _ => {}
    }
    r.read_ue()?; // max_num_ref_frames
    r.skip(1)?; // gaps_in_frame_num_value_allowed_flag
    let width_mbs = r.read_ue()? as u64 + 1;
    let height_units = r.read_ue()? as u64 + 1;
    let frame_mbs_only = r.read_bits(1)? as u64;
    let w = width_mbs * 16;
    let h = (2 - frame_mbs_only) * height_units * 16;
    Some((w.min(u32::MAX as u64) as u32, h.min(u32::MAX as u64) as u32))
}

/// The size from an H.265 SPS (two header bytes first).
fn h265_sps_size(nal: &[u8]) -> Option<(u32, u32)> {
    let mut r = BitReader::new(nal, true);
    r.skip(16)?; // NAL header
    r.skip(4)?; // sps_video_parameter_set_id
    let sub_layers = r.read_bits(3)? as usize;
    r.skip(1)?; // sps_temporal_id_nesting_flag
                // profile_tier_level: the general part, then each sub-layer's flags and parts
    r.skip(8 + 32 + 48 + 8)?;
    if sub_layers > 0 {
        let mut present = [(false, false); 8];
        for p in present.iter_mut().take(sub_layers) {
            *p = (r.read_bits(1)? != 0, r.read_bits(1)? != 0);
        }
        r.skip(2 * (8 - sub_layers) as u32)?;
        for &(profile, level) in present.iter().take(sub_layers) {
            if profile {
                r.skip(88)?;
            }
            if level {
                r.skip(8)?;
            }
        }
    }
    r.read_ue()?; // sps_seq_parameter_set_id
    if r.read_ue()? == 3 {
        r.skip(1)?; // separate_colour_plane_flag
    }
    Some((r.read_ue()?, r.read_ue()?))
}

/// A VP8 keyframe: frame tag, start code 9d 01 2a, then 14-bit width and height.
fn vp8_size(d: &[u8]) -> Option<(u32, u32)> {
    if d.len() < 10 || d[0] & 1 != 0 || d[3..6] != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let w = u16::from_le_bytes([d[6], d[7]]) & 0x3FFF;
    let h = u16::from_le_bytes([d[8], d[9]]) & 0x3FFF;
    Some((w as u32, h as u32))
}

/// A VP9 keyframe's uncompressed header: marker, profile, frame type, sync code, colour
/// config, then the size less one.
fn vp9_size(d: &[u8]) -> Option<(u32, u32)> {
    let mut r = BitReader::new(d, false);
    if r.read_bits(2)? != 2 {
        return None;
    }
    let low = r.read_bits(1)?;
    let profile = (r.read_bits(1)? << 1) | low;
    if profile == 3 {
        r.skip(1)?;
    }
    if r.read_bits(1)? == 1 || r.read_bits(1)? != 0 {
        return None; // a shown older frame, or not a keyframe
    }
    r.skip(2)?; // show_frame, error_resilient_mode
    if r.read_bits(24)? != 0x49_83_42 {
        return None;
    }
    if profile >= 2 {
        r.skip(1)?; // ten_or_twelve_bit
    }
    let rgb = r.read_bits(3)? == 7;
    if !rgb {
        r.skip(1)?; // color_range
        if profile == 1 || profile == 3 {
            r.skip(3)?; // subsampling_x, subsampling_y, reserved_zero
        }
    } else if profile == 1 || profile == 3 {
        r.skip(1)?;
    }
    Some((r.read_bits(16)? + 1, r.read_bits(16)? + 1))
}

/// Bits, most significant first; `escaped` skips H.26x emulation prevention bytes (00 00 03).
struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    bit: u8,
    escaped: bool,
    zeros: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], escaped: bool) -> Self {
        BitReader {
            data,
            byte: 0,
            bit: 0,
            escaped,
            zeros: 0,
        }
    }

    fn read_bit(&mut self) -> Option<u32> {
        if self.bit == 0 && self.escaped {
            // A 03 after two zero bytes was put in by the encoder: not part of the syntax
            if self.zeros >= 2 && *self.data.get(self.byte)? == 3 {
                self.byte += 1;
                self.zeros = 0;
            }
        }
        let b = *self.data.get(self.byte)?;
        let v = ((b >> (7 - self.bit)) & 1) as u32;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte += 1;
            self.zeros = if b == 0 {
                self.zeros.saturating_add(1)
            } else {
                0
            };
        }
        Some(v)
    }

    fn read_bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()?;
        }
        Some(v)
    }

    fn skip(&mut self, n: u32) -> Option<()> {
        for _ in 0..n {
            self.read_bit()?;
        }
        Some(())
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.read_bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        Some(((1u64 << zeros) - 1 + self.read_bits(zeros)? as u64).min(u32::MAX as u64) as u32)
    }

    fn read_se(&mut self) -> Option<i32> {
        let k = self.read_ue()? as i64;
        Some(if k % 2 == 1 { (k + 1) / 2 } else { -(k / 2) } as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // One 1366x768 frame each, from FFmpeg's encoders (x264, x265, libvpx): start code and
    // SPS, or the first bytes of the keyframe
    const H264_HIGH: &str = "0000000167640020acd94056061e6f0110000003001000000303c0f1831960";
    const H264_BASE: &str = "000000016742c020d90056061e6f0110000003001000000303c0f1832480";
    const H264_INTERLACED: &str = "0000000167640020acd940560c3cde0220000003002000000783e2c5b2c0";
    const HEVC: &str = "00000001420101016000000300900000030000030078a002ac80301d796566924caf016808000003000800000300f040";
    const VP9: &str = "824983420055502ff60638241c184a1805807fd9fa3e8be7";
    const VP8: &str = "502f029d012a56050003004708858588858488040202db15";

    #[test]
    fn sizes_of_real_keyframes() {
        // H.264 counts whole macroblocks: 1366 is 86 of them
        assert_eq!(
            keyframe_size(VideoCodec::H264, &hex(H264_HIGH)),
            Some((1376, 768))
        );
        assert_eq!(
            keyframe_size(VideoCodec::H264, &hex(H264_BASE)),
            Some((1376, 768))
        );
        assert_eq!(
            keyframe_size(VideoCodec::H264, &hex(H264_INTERLACED)),
            Some((1376, 768))
        );
        // H.265 pads to its smallest coding block, 8
        assert_eq!(
            keyframe_size(VideoCodec::H265, &hex(HEVC)),
            Some((1368, 768))
        );
        assert_eq!(keyframe_size(VideoCodec::Vp9, &hex(VP9)), Some((1366, 768)));
        assert_eq!(keyframe_size(VideoCodec::Vp8, &hex(VP8)), Some((1366, 768)));
        for (c, s) in [
            (VideoCodec::H264, H264_HIGH),
            (VideoCodec::H265, HEVC),
            (VideoCodec::Vp9, VP9),
            (VideoCodec::Vp8, VP8),
        ] {
            assert!(keyframe_fits(c, &hex(s)), "{c:?}");
        }
    }

    #[test]
    fn a_delta_or_noise_says_no_size_and_passes() {
        let mut vp8_delta = hex(VP8);
        vp8_delta[0] |= 1;
        assert_eq!(keyframe_size(VideoCodec::Vp8, &vp8_delta), None);
        let mut vp9_delta = hex(VP9);
        vp9_delta[0] |= 0b0000_0100; // frame_type 1
        assert_eq!(keyframe_size(VideoCodec::Vp9, &vp9_delta), None);
        assert_eq!(
            keyframe_size(VideoCodec::H264, &[0, 0, 1, 0x65, 1, 2, 3]),
            None,
            "a slice, no SPS"
        );
        assert_eq!(
            keyframe_size(VideoCodec::H264, &[0, 0, 0, 1, 0x67]),
            None,
            "cut short"
        );
        assert!(keyframe_fits(VideoCodec::H264, &[]));
    }

    /// Bits written most significant first, ue/se as H.264 codes them.
    struct BitWriter(Vec<bool>);
    impl BitWriter {
        fn bits(&mut self, v: u64, n: u32) -> &mut Self {
            for i in (0..n).rev() {
                self.0.push((v >> i) & 1 == 1);
            }
            self
        }
        fn ue(&mut self, v: u64) -> &mut Self {
            let n = 64 - (v + 1).leading_zeros();
            self.bits(0, n - 1).bits(v + 1, n)
        }
        fn se(&mut self, v: i64) -> &mut Self {
            self.ue(if v > 0 {
                2 * v as u64 - 1
            } else {
                (-2 * v) as u64
            })
        }
        /// Start code, then the bytes with emulation prevention put in.
        fn nal(&mut self) -> Vec<u8> {
            self.bits(1, 1);
            while !self.0.len().is_multiple_of(8) {
                self.0.push(false);
            }
            let raw: Vec<u8> = self
                .0
                .chunks(8)
                .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b as u8))
                .collect();
            let mut out = vec![0, 0, 0, 1];
            let mut zeros = 0;
            for (i, &b) in raw.iter().enumerate() {
                if i > 0 && zeros >= 2 && b <= 3 {
                    out.push(3);
                    zeros = 0;
                }
                out.push(b);
                zeros = if b == 0 { zeros + 1 } else { 0 };
            }
            out
        }
    }

    /// A High profile SPS with scaling lists and picture order type 1, of `mbs` macroblocks.
    fn h264_sps(width_mbs: u64, height_mbs: u64) -> Vec<u8> {
        let mut w = BitWriter(Vec::new());
        w.bits(0x67, 8).bits(100, 8).bits(0, 8).bits(40, 8).ue(0);
        w.ue(1).ue(0).ue(0).bits(0, 1).bits(1, 1); // 4:2:0, 8 bit, scaling matrix present
        for i in 0..8 {
            w.bits(1, 1); // each list present
            let size = if i < 6 { 16 } else { 64 };
            for j in 0..size {
                w.se(if j % 2 == 0 { 3 } else { -2 });
            }
        }
        w.ue(0)
            .ue(1)
            .bits(0, 1)
            .se(-1)
            .se(2)
            .ue(3)
            .se(1)
            .se(-1)
            .se(0); // frame num, poc type 1
        w.ue(4)
            .bits(0, 1)
            .ue(width_mbs - 1)
            .ue(height_mbs - 1)
            .bits(1, 1);
        w.bits(0, 3); // direct_8x8, cropping, vui: absent
        w.nal()
    }

    #[test]
    fn scaling_lists_and_order_offsets_are_read_past() {
        assert_eq!(
            keyframe_size(VideoCodec::H264, &h264_sps(120, 68)),
            Some((1920, 1088))
        );
        assert!(keyframe_fits(VideoCodec::H264, &h264_sps(120, 68)));
    }

    #[test]
    fn a_picture_past_the_caps_does_not_fit() {
        // 4096x2304: each side is fine, the area is not
        assert!(!keyframe_fits(VideoCodec::H264, &h264_sps(256, 144)));
        let mut vp8 = hex(VP8);
        vp8[6..10].copy_from_slice(&[0x00, 0x10, 0x00, 0x09]); // 4096x2304
        assert!(!keyframe_fits(VideoCodec::Vp8, &vp8));
        // VP9 at 16384 wide: past the side cap
        let mut vp9 = hex(VP9);
        vp9[4] = 0x03; // the width's top nibble: 0x3555 + 1
        assert_eq!(
            keyframe_size(VideoCodec::Vp9, &vp9).map(|s| s.0),
            Some(0x3556)
        );
        assert!(!keyframe_fits(VideoCodec::Vp9, &vp9));
    }
}
