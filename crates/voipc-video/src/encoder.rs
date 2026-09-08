use anyhow::{anyhow, bail, Context, Result};
use ffmpeg_next as ffmpeg;
use ffmpeg::codec::{self, encoder};
use ffmpeg::format::Pixel;
use ffmpeg::util::frame::video::Video;
use ffmpeg::{Dictionary, Rational};
use std::sync::Once;
use tracing::info;
use voipc_protocol::types::VideoCodec;

static FFMPEG_INIT: Once = Once::new();

/// Initialize FFmpeg library (must be called before using any FFmpeg APIs)
fn init_ffmpeg() {
    FFMPEG_INIT.call_once(|| {
        ffmpeg::init().expect("Failed to initialize FFmpeg");
    });
}

/// An H.264 or H.265 encoder for screen share frames.
pub struct Encoder {
    encoder: encoder::Video,
    codec: VideoCodec,
    width: u32,
    height: u32,
    frame_index: i64,
    /// Pixel format used by this encoder (YUV420P for most, NV12 for QSV).
    pixel_format: Pixel,
}

// SAFETY: The FFmpeg encoder context is not Send by default due to raw pointers,
// but FFmpeg encoding is safe to use from a single thread at a time.
unsafe impl Send for Encoder {}

/// An encoded video frame output from the encoder.
#[derive(Clone, Debug)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub pts: i64,
}

fn format_name(p: Pixel) -> &'static str {
    match p {
        Pixel::YUV420P => "yuv420p",
        Pixel::NV12 => "nv12",
        _ => "unknown",
    }
}

/// Rate-control options shared by every encoder (generic AVCodecContext
/// AVOptions — libx265 maps maxrate/bufsize to its own vbv params).
///
/// - `g`: encoder-internal keyframes are only a safety net; the app forces an
///   IDR every `KEYFRAME_INTERVAL_SECS` via `encode_video_frame(_, true)`. Twice
///   that interval (not 1×) avoids beat-frequency double keyframes when the
///   forced IDR resets the internal GOP counter.
/// - VBV: bufsize caps the largest compliant frame. The UDP wire format
///   truncates frames above 255 fragments × 1239 B ≈ 316 KB, so bufsize is
///   clamped to 2.4 Mbit (300 KB) to keep keyframes under that ceiling.
fn set_rate_control_opts(opts: &mut Dictionary, bitrate_kbps: u32, fps: u32) {
    let bits = bitrate_kbps as u64 * 1000;
    opts.set("g", &(2 * crate::KEYFRAME_INTERVAL_SECS * fps).to_string());
    opts.set("maxrate", &bits.to_string());
    opts.set("bufsize", &(bits / 2).min(2_400_000).to_string());
}

/// Hardware encoders to try before falling back to software encoding.
/// Order: NVIDIA → Intel Quick Sync → AMD, then software fallback.
const HW_ENCODERS_H264: &[(&str, &str)] = &[
    ("h264_nvenc", "NVIDIA NVENC"),
    ("h264_qsv", "Intel Quick Sync"),
    ("h264_amf", "AMD AMF"),
];
const HW_ENCODERS_H265: &[(&str, &str)] = &[
    ("hevc_nvenc", "NVIDIA NVENC"),
    ("hevc_qsv", "Intel Quick Sync"),
    ("hevc_amf", "AMD AMF"),
];

impl Encoder {
    /// Create an encoder for `codec` (H.264 or H.265).
    ///
    /// Tries hardware encoders first (NVENC, QSV, AMF) for much faster encoding,
    /// falling back to the libx264/libx265 software encoder if none are available.
    /// VP8 and VP9 are decode-only natively — only browser sharers produce them.
    ///
    /// `width` and `height` must be divisible by 2.
    /// `bitrate_kbps` is the target bitrate in kilobits per second.
    /// `fps` is the target frame rate.
    pub fn new(
        video_codec: VideoCodec,
        width: u32,
        height: u32,
        bitrate_kbps: u32,
        fps: u32,
    ) -> Result<Self> {
        let (hw_list, sw_name) = match video_codec {
            VideoCodec::H264 => (HW_ENCODERS_H264, "libx264"),
            VideoCodec::H265 => (HW_ENCODERS_H265, "libx265"),
            VideoCodec::Vp8 | VideoCodec::Vp9 => {
                bail!("{video_codec:?} is decode-only here — no native encoder")
            }
        };

        if width % 2 != 0 || height % 2 != 0 {
            bail!("{video_codec:?} encoder: width and height must be divisible by 2");
        }

        init_ffmpeg();

        // Try hardware encoders first — they're 10-50x faster than software.
        for &(name, label) in hw_list {
            if let Some(codec) = encoder::find_by_name(name) {
                match Self::try_open_hw(codec, name, video_codec, width, height, bitrate_kbps, fps)
                {
                    Ok(enc) => {
                        info!("{video_codec:?} encoder: using {label} hardware encoder ({name})");
                        return Ok(enc);
                    }
                    Err(e) => {
                        info!("{video_codec:?} encoder: {name} not usable: {e}");
                    }
                }
            }
        }

        // Fall back to the software encoder.
        let enc = Self::open_software(sw_name, video_codec, width, height, bitrate_kbps, fps)?;
        info!("{video_codec:?} encoder: using {sw_name} software encoder");
        Ok(enc)
    }

    /// Try to open a hardware encoder with low-latency settings.
    #[allow(clippy::too_many_arguments)]
    fn try_open_hw(
        codec: ffmpeg::Codec,
        name: &str,
        video_codec: VideoCodec,
        width: u32,
        height: u32,
        bitrate_kbps: u32,
        fps: u32,
    ) -> Result<Self> {
        // QSV doesn't support YUV420P — it needs NV12 (semi-planar UV).
        // We'll convert I420→NV12 in encode() when this format is used.
        let formats_to_try = if name.ends_with("_qsv") {
            &[Pixel::NV12][..]
        } else {
            &[Pixel::YUV420P, Pixel::NV12]
        };

        let mut last_err = None;
        for &pixel_format in formats_to_try {
            match Self::try_open_hw_with_format(
                codec,
                name,
                video_codec,
                width,
                height,
                bitrate_kbps,
                fps,
                pixel_format,
            ) {
                Ok(enc) => return Ok(enc),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("{}: no compatible pixel format", name)))
    }

    #[allow(clippy::too_many_arguments)]
    fn try_open_hw_with_format(
        codec: ffmpeg::Codec,
        name: &str,
        video_codec: VideoCodec,
        width: u32,
        height: u32,
        bitrate_kbps: u32,
        fps: u32,
        pixel_format: Pixel,
    ) -> Result<Self> {
        let mut encoder = codec::context::Context::new_with_codec(codec)
            .encoder()
            .video()
            .context("failed to create encoder context")?;

        encoder.set_width(width);
        encoder.set_height(height);
        encoder.set_format(pixel_format);
        encoder.set_time_base(Rational::new(1, fps as i32));
        encoder.set_frame_rate(Some(Rational::new(fps as i32, 1)));
        encoder.set_bit_rate(bitrate_kbps as usize * 1000);
        encoder.set_max_b_frames(0);

        let mut opts = Dictionary::new();
        set_rate_control_opts(&mut opts, bitrate_kbps, fps);

        // Option names are the same for the h264_* and hevc_* variants of each
        // vendor's encoder, so match on the vendor suffix.
        match name.rsplit('_').next().unwrap_or("") {
            "nvenc" => {
                opts.set("preset", "p1");           // Fastest NVENC preset
                opts.set("tune", "ull");             // Ultra low latency
                opts.set("rc", "cbr");               // Constant bitrate
                opts.set("delay", "0");              // No encoding delay
                opts.set("zerolatency", "1");
                opts.set("forced-idr", "1");         // pict_type I → real IDR
            }
            "qsv" => {
                opts.set("preset", "veryfast");
                opts.set("async_depth", "1");        // Minimal pipeline depth
                opts.set("low_power", "1");          // Use LP encode mode if available
                opts.set("forced_idr", "1");
            }
            "amf" => {
                opts.set("usage", "ultralowlatency");
                opts.set("quality", "speed");
                opts.set("rc", "cbr");
                opts.set("forced_idr", "1");
            }
            _ => {}
        }

        let encoder = encoder.open_with(opts)
            .with_context(|| format!("{} ({}): failed to open", name, format_name(pixel_format)))?;

        Ok(Self {
            encoder,
            codec: video_codec,
            width,
            height,
            frame_index: 0,
            pixel_format,
        })
    }

    /// Open the libx264/libx265 software encoder with ultrafast + zerolatency settings.
    ///
    /// `pub(crate)` for the tests: `new` prefers the hardware encoders, so on a
    /// machine with a GPU nothing would ever exercise this path.
    pub(crate) fn open_software(
        name: &str,
        video_codec: VideoCodec,
        width: u32,
        height: u32,
        bitrate_kbps: u32,
        fps: u32,
    ) -> Result<Self> {
        let codec = encoder::find_by_name(name).ok_or_else(|| {
            anyhow!("{name} codec not found (is FFmpeg built with it?)")
        })?;

        let mut encoder = codec::context::Context::new_with_codec(codec)
            .encoder()
            .video()
            .context("failed to create encoder context")?;

        encoder.set_width(width);
        encoder.set_height(height);
        encoder.set_format(Pixel::YUV420P);
        encoder.set_time_base(Rational::new(1, fps as i32));
        encoder.set_frame_rate(Some(Rational::new(fps as i32, 1)));
        encoder.set_bit_rate(bitrate_kbps as usize * 1000);
        encoder.set_max_b_frames(0);

        let mut opts = Dictionary::new();
        set_rate_control_opts(&mut opts, bitrate_kbps, fps);
        opts.set("preset", "ultrafast");
        opts.set("tune", "zerolatency");
        opts.set("forced-idr", "1");

        // keyint matches the "g" safety net; the app forces its own IDR every
        // KEYFRAME_INTERVAL_SECS. repeat-headers puts SPS/PPS (and VPS) in front
        // of every IDR: viewers decode a bare Annex B stream with no out-of-band
        // parameter sets, and a late joiner must be able to start on any IDR.
        let k = 2 * crate::KEYFRAME_INTERVAL_SECS * fps;
        let params = format!(
            "scenecut=0:me=dia:subme=0:keyint={k}:min-keyint={k}:repeat-headers=1:annexb=1"
        );
        match video_codec {
            VideoCodec::H264 => opts.set("x264-params", &params),
            _ => opts.set("x265-params", &params),
        }

        let encoder = encoder
            .open_with(opts)
            .with_context(|| format!("{name}: failed to open encoder"))?;

        Ok(Self {
            encoder,
            codec: video_codec,
            width,
            height,
            frame_index: 0,
            pixel_format: Pixel::YUV420P,
        })
    }

    /// Encode an I420 frame.
    ///
    /// `i420_data` must be width*height*3/2 bytes (Y plane + U plane + V plane).
    /// `pts` is the presentation timestamp (frame index).
    /// `force_keyframe` forces this frame to be encoded as a keyframe (IDR).
    ///
    /// If the encoder uses NV12 format (e.g. QSV), the I420 data is converted
    /// automatically by interleaving the U and V planes.
    pub fn encode(&mut self, i420_data: &[u8], pts: i64, force_keyframe: bool) -> Result<Vec<EncodedFrame>> {
        let expected_size = (self.width as usize) * (self.height as usize) * 3 / 2;
        if i420_data.len() < expected_size {
            bail!(
                "{:?} encoder: I420 data too short (got {}, expected {})",
                self.codec,
                i420_data.len(),
                expected_size
            );
        }

        let mut frame = Video::new(self.pixel_format, self.width, self.height);
        frame.set_pts(Some(pts));

        if force_keyframe {
            frame.set_kind(ffmpeg::picture::Type::I);
        }

        let w = self.width as usize;
        let h = self.height as usize;
        let uv_w = (w + 1) / 2;
        let uv_h = (h + 1) / 2;
        let y_size = w * h;
        let uv_size = uv_w * uv_h;

        // Y plane (same layout for both YUV420P and NV12)
        let y_stride = frame.stride(0);
        let y_dst = frame.data_mut(0);
        for row in 0..h {
            let src_off = row * w;
            let dst_off = row * y_stride;
            y_dst[dst_off..dst_off + w].copy_from_slice(&i420_data[src_off..src_off + w]);
        }

        if self.pixel_format == Pixel::NV12 {
            // NV12: single UV plane with interleaved U,V pairs.
            // Convert from I420's separate U and V planes.
            let uv_stride = frame.stride(1);
            let uv_dst = frame.data_mut(1);
            let u_src = &i420_data[y_size..y_size + uv_size];
            let v_src = &i420_data[y_size + uv_size..];
            for row in 0..uv_h {
                let dst_row = row * uv_stride;
                let src_row = row * uv_w;
                for col in 0..uv_w {
                    uv_dst[dst_row + col * 2] = u_src[src_row + col];
                    uv_dst[dst_row + col * 2 + 1] = v_src[src_row + col];
                }
            }
        } else {
            // YUV420P: separate U and V planes.
            let u_stride = frame.stride(1);
            let u_dst = frame.data_mut(1);
            let u_src_base = y_size;
            for row in 0..uv_h {
                let src_off = u_src_base + row * uv_w;
                let dst_off = row * u_stride;
                u_dst[dst_off..dst_off + uv_w].copy_from_slice(&i420_data[src_off..src_off + uv_w]);
            }

            let v_stride = frame.stride(2);
            let v_dst = frame.data_mut(2);
            let v_src_base = y_size + uv_size;
            for row in 0..uv_h {
                let src_off = v_src_base + row * uv_w;
                let dst_off = row * v_stride;
                v_dst[dst_off..dst_off + uv_w].copy_from_slice(&i420_data[src_off..src_off + uv_w]);
            }
        }

        self.encoder
            .send_frame(&frame)
            .with_context(|| format!("{:?} encoder: failed to send frame", self.codec))?;

        let mut frames = Vec::new();
        let mut packet = ffmpeg::Packet::empty();

        while self.encoder.receive_packet(&mut packet).is_ok() {
            let data = packet.data().unwrap_or(&[]).to_vec();
            let is_keyframe = packet.is_key();

            frames.push(EncodedFrame {
                data,
                is_keyframe,
                pts: packet.pts().unwrap_or(pts),
            });
        }

        self.frame_index += 1;
        Ok(frames)
    }

    /// Encode a pre-converted YUV420P video frame directly.
    ///
    /// This avoids copying I420 data into an intermediate FFmpeg frame — the
    /// `FrameConverter` output frame is passed straight to the encoder. Use this
    /// instead of `encode()` in the hot path for maximum performance.
    ///
    /// The caller must set PTS on the frame before calling. `force_keyframe`
    /// forces this frame to be encoded as an IDR keyframe.
    pub fn encode_video_frame(
        &mut self,
        frame: &mut Video,
        force_keyframe: bool,
    ) -> Result<Vec<EncodedFrame>> {
        let pts = self.frame_index;
        frame.set_pts(Some(pts));

        if force_keyframe {
            frame.set_kind(ffmpeg::picture::Type::I);
        } else {
            frame.set_kind(ffmpeg::picture::Type::None);
        }

        self.encoder
            .send_frame(frame)
            .with_context(|| format!("{:?} encoder: failed to send frame", self.codec))?;

        let mut frames = Vec::new();
        let mut packet = ffmpeg::Packet::empty();

        while self.encoder.receive_packet(&mut packet).is_ok() {
            let data = packet.data().unwrap_or(&[]).to_vec();
            let is_keyframe = packet.is_key();

            frames.push(EncodedFrame {
                data,
                is_keyframe,
                pts: packet.pts().unwrap_or(pts),
            });
        }

        self.frame_index += 1;
        Ok(frames)
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// The codec this encoder produces.
    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    /// The pixel format this encoder was opened with (YUV420P or NV12).
    /// Frames passed to `encode_video_frame` must match it.
    pub fn pixel_format(&self) -> Pixel {
        self.pixel_format
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        // Flush encoder
        let _ = self.encoder.send_eof();
        let mut packet = ffmpeg::Packet::empty();
        while self.encoder.receive_packet(&mut packet).is_ok() {
            // Drain remaining packets
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::Decoder;

    /// Both codecs a native client can encode.
    const NATIVE: [VideoCodec; 2] = [VideoCodec::H264, VideoCodec::H265];

    #[test]
    fn encoder_new_valid() {
        for codec in NATIVE {
            let enc = Encoder::new(codec, 640, 480, 1000, 30).unwrap();
            assert_eq!(enc.width(), 640);
            assert_eq!(enc.height(), 480);
            assert_eq!(enc.codec(), codec);
        }
    }

    #[test]
    fn encoder_odd_dimensions_fails() {
        assert!(Encoder::new(VideoCodec::H264, 641, 480, 1000, 30).is_err());
    }

    #[test]
    fn encoder_rejects_browser_only_codecs() {
        assert!(Encoder::new(VideoCodec::Vp8, 64, 64, 500, 30).is_err());
        assert!(Encoder::new(VideoCodec::Vp9, 64, 64, 500, 30).is_err());
    }

    #[test]
    fn encoder_encode_gray_frame() {
        for codec in NATIVE {
            let mut enc = Encoder::new(codec, 64, 64, 500, 30).unwrap();
            // Gray I420 frame: Y=128, U=128, V=128
            let y_size = 64 * 64;
            let uv_size = 32 * 32;
            let i420 = vec![128u8; y_size + 2 * uv_size];
            let frames = enc.encode(&i420, 0, true).unwrap();
            assert!(!frames.is_empty());
            assert!(!frames[0].data.is_empty());
            assert!(frames[0].is_keyframe);
        }
    }

    #[test]
    fn decoder_new() {
        // Every codec a viewer can be asked to decode
        for codec in [VideoCodec::H264, VideoCodec::H265, VideoCodec::Vp8, VideoCodec::Vp9] {
            assert!(Decoder::new(codec).is_ok(), "no decoder for {codec:?}");
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        for codec in NATIVE {
            let mut enc = Encoder::new(codec, 64, 64, 500, 30).unwrap();
            let y_size = 64 * 64;
            let uv_size = 32 * 32;
            let i420 = vec![128u8; y_size + 2 * uv_size];
            let encoded = enc.encode(&i420, 0, true).unwrap();
            assert!(!encoded.is_empty());

            let mut dec = Decoder::new(codec).unwrap();
            let decoded = dec.decode(&encoded[0].data).unwrap();
            assert!(!decoded.is_empty(), "{codec:?}: no frame decoded");
            assert_eq!(decoded[0].width, 64);
            assert_eq!(decoded[0].height, 64);

            // Verify pixel data is not all zeros (black screen regression)
            let y_plane = &decoded[0].i420_data[..y_size];
            let avg_y: f64 = y_plane.iter().map(|&b| b as f64).sum::<f64>() / y_size as f64;
            // Input Y=128, lossy compression should keep it in range ~110-145
            assert!(avg_y > 100.0 && avg_y < 160.0,
                "{codec:?}: decoded Y average {avg_y} is way off from input 128 — data likely corrupt");
        }
    }

    /// The software encoders are the fallback every machine without a usable
    /// GPU encoder lands on, and `Encoder::new` hides them behind the hardware
    /// list — so open them directly and check the same properties.
    #[test]
    fn software_encoders_work() {
        init_ffmpeg();
        for (name, codec) in [("libx264", VideoCodec::H264), ("libx265", VideoCodec::H265)] {
            let mut enc = Encoder::open_software(name, codec, 64, 64, 500, 30)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(enc.codec(), codec);
            let i420 = vec![128u8; 64 * 64 + 2 * 32 * 32];
            let frames = enc.encode(&i420, 0, true).unwrap();
            assert!(!frames.is_empty(), "{name}: no frame came out");
            assert!(frames[0].is_keyframe);
            assert!(sps_present(codec, &frames[0].data), "{name}: keyframe has no SPS");

            let mut dec = Decoder::new(codec).unwrap();
            assert!(!dec.decode(&frames[0].data).unwrap().is_empty());
        }
    }

    /// nal type 7 (H.264 SPS) / 33 (HEVC SPS) somewhere in an Annex B frame.
    fn sps_present(codec: VideoCodec, data: &[u8]) -> bool {
        data.windows(4).any(|w| {
            w[0] == 0
                && w[1] == 0
                && w[2] == 1
                && match codec {
                    VideoCodec::H264 => w[3] & 0x1f == 7,
                    _ => (w[3] >> 1) & 0x3f == 33,
                }
        })
    }

    /// A keyframe must carry its parameter sets: browsers and the native
    /// decoder alike start from a bare Annex B keyframe with nothing out of band.
    #[test]
    fn keyframes_carry_parameter_sets() {
        for codec in NATIVE {
            let mut enc = Encoder::new(codec, 64, 64, 500, 30).unwrap();
            let i420 = vec![128u8; 64 * 64 + 2 * 32 * 32];
            // Encode a few frames, then force a second IDR
            let mut key_frames = Vec::new();
            for pts in 0..5 {
                for f in enc.encode(&i420, pts, pts == 0 || pts == 4).unwrap() {
                    if f.is_keyframe {
                        key_frames.push(f.data);
                    }
                }
            }
            assert!(key_frames.len() >= 2, "{codec:?}: expected a second forced IDR");
            for (i, kf) in key_frames.iter().enumerate() {
                assert!(sps_present(codec, kf), "{codec:?}: keyframe {i} has no SPS");
            }
        }
    }
}
