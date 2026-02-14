use anyhow::{anyhow, bail, Context, Result};
use ffmpeg_next as ffmpeg;
use ffmpeg::codec::{self, encoder};
use ffmpeg::format::Pixel;
use ffmpeg::util::frame::video::Video;
use ffmpeg::{Dictionary, Rational};
use std::sync::Once;
use tracing::info;

static FFMPEG_INIT: Once = Once::new();

/// Initialize FFmpeg library (must be called before using any FFmpeg APIs)
fn init_ffmpeg() {
    FFMPEG_INIT.call_once(|| {
        ffmpeg::init().expect("Failed to initialize FFmpeg");
    });
}

/// A H.265/HEVC encoder for screen share frames.
pub struct Encoder {
    encoder: encoder::Video,
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

/// Hardware encoders to try before falling back to libx265 software encoding.
/// Order: NVIDIA → Intel Quick Sync → AMD, then software fallback.
const HW_ENCODERS: &[(&str, &str)] = &[
    ("hevc_nvenc", "NVIDIA NVENC"),
    ("hevc_qsv", "Intel Quick Sync"),
    ("hevc_amf", "AMD AMF"),
];

impl Encoder {
    /// Create a new H.265/HEVC encoder.
    ///
    /// Tries hardware encoders first (NVENC, QSV, AMF) for much faster encoding,
    /// falling back to libx265 software encoding if none are available.
    ///
    /// `width` and `height` must be divisible by 2.
    /// `bitrate_kbps` is the target bitrate in kilobits per second.
    /// `fps` is the target frame rate.
    pub fn new(width: u32, height: u32, bitrate_kbps: u32, fps: u32) -> Result<Self> {
        if width % 2 != 0 || height % 2 != 0 {
            bail!("H.265 encoder: width and height must be divisible by 2");
        }

        init_ffmpeg();

        // Try hardware encoders first — they're 10-50x faster than software.
        for &(name, label) in HW_ENCODERS {
            if let Some(codec) = encoder::find_by_name(name) {
                match Self::try_open_hw(codec, name, width, height, bitrate_kbps, fps) {
                    Ok(enc) => {
                        info!("H.265 encoder: using {} hardware encoder ({})", label, name);
                        return Ok(enc);
                    }
                    Err(e) => {
                        info!("H.265 encoder: {} not usable: {}", name, e);
                    }
                }
            }
        }

        // Fall back to libx265 software encoder.
        let enc = Self::open_x265(width, height, bitrate_kbps, fps)?;
        info!("H.265 encoder: using libx265 software encoder");
        Ok(enc)
    }

    /// Try to open a hardware HEVC encoder with low-latency settings.
    fn try_open_hw(
        codec: ffmpeg::Codec,
        name: &str,
        width: u32,
        height: u32,
        bitrate_kbps: u32,
        fps: u32,
    ) -> Result<Self> {
        // QSV doesn't support YUV420P — it needs NV12 (semi-planar UV).
        // We'll convert I420→NV12 in encode() when this format is used.
        let formats_to_try = if name == "hevc_qsv" {
            &[Pixel::NV12][..]
        } else {
            &[Pixel::YUV420P, Pixel::NV12]
        };

        let mut last_err = None;
        for &pixel_format in formats_to_try {
            match Self::try_open_hw_with_format(codec, name, width, height, bitrate_kbps, fps, pixel_format) {
                Ok(enc) => return Ok(enc),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("{}: no compatible pixel format", name)))
    }

    fn try_open_hw_with_format(
        codec: ffmpeg::Codec,
        name: &str,
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

        match name {
            "hevc_nvenc" => {
                opts.set("preset", "p1");           // Fastest NVENC preset
                opts.set("tune", "ull");             // Ultra low latency
                opts.set("rc", "cbr");               // Constant bitrate
                opts.set("delay", "0");              // No encoding delay
                opts.set("zerolatency", "1");
            }
            "hevc_qsv" => {
                opts.set("preset", "veryfast");
                opts.set("async_depth", "1");        // Minimal pipeline depth
                opts.set("low_power", "1");          // Use LP encode mode if available
            }
            "hevc_amf" => {
                opts.set("usage", "ultralowlatency");
                opts.set("quality", "speed");
                opts.set("rc", "cbr");
            }
            _ => {}
        }

        let encoder = encoder.open_with(opts)
            .with_context(|| format!("{} ({}): failed to open", name, format_name(pixel_format)))?;

        Ok(Self {
            encoder,
            width,
            height,
            frame_index: 0,
            pixel_format,
        })
    }

    /// Open the libx265 software encoder with ultrafast + zerolatency settings.
    fn open_x265(width: u32, height: u32, bitrate_kbps: u32, fps: u32) -> Result<Self> {
        let codec = encoder::find_by_name("libx265")
            .ok_or_else(|| anyhow!("libx265 codec not found (is FFmpeg built with x265?)"))?;

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
        opts.set("preset", "ultrafast");
        opts.set("tune", "zerolatency");

        let x265_params = [
            "scenecut=0",
            "me=dia",
            "subme=0",
            "keyint=30",
            "min-keyint=30",
        ].join(":");
        opts.set("x265-params", &x265_params);

        let encoder = encoder.open_with(opts)
            .context("libx265: failed to open encoder")?;

        Ok(Self {
            encoder,
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
                "H.265 encoder: I420 data too short (got {}, expected {})",
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

        self.encoder.send_frame(&frame)
            .context("H.265 encoder: failed to send frame")?;

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
            .context("H.265 encoder: failed to send frame")?;

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

    #[test]
    fn encoder_new_valid() {
        let enc = Encoder::new(640, 480, 1000, 30);
        assert!(enc.is_ok());
        let enc = enc.unwrap();
        assert_eq!(enc.width(), 640);
        assert_eq!(enc.height(), 480);
    }

    #[test]
    fn encoder_odd_dimensions_fails() {
        let enc = Encoder::new(641, 480, 1000, 30);
        assert!(enc.is_err());
    }

    #[test]
    fn encoder_encode_gray_frame() {
        let mut enc = Encoder::new(64, 64, 500, 30).unwrap();
        // Gray I420 frame: Y=128, U=128, V=128
        let y_size = 64 * 64;
        let uv_size = 32 * 32;
        let i420 = vec![128u8; y_size + 2 * uv_size];
        let frames = enc.encode(&i420, 0, true).unwrap();
        assert!(!frames.is_empty());
        assert!(!frames[0].data.is_empty());
        assert!(frames[0].is_keyframe);
    }

    #[test]
    fn decoder_new() {
        let dec = Decoder::new();
        assert!(dec.is_ok());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut enc = Encoder::new(64, 64, 500, 30).unwrap();
        let y_size = 64 * 64;
        let uv_size = 32 * 32;
        let i420 = vec![128u8; y_size + 2 * uv_size];
        let encoded = enc.encode(&i420, 0, true).unwrap();
        assert!(!encoded.is_empty());

        let mut dec = Decoder::new().unwrap();
        let decoded = dec.decode(&encoded[0].data).unwrap();
        assert!(!decoded.is_empty());
        assert_eq!(decoded[0].width, 64);
        assert_eq!(decoded[0].height, 64);

        // Verify pixel data is not all zeros (black screen regression)
        let y_plane = &decoded[0].i420_data[..y_size];
        let avg_y: f64 = y_plane.iter().map(|&b| b as f64).sum::<f64>() / y_size as f64;
        // Input Y=128, lossy compression should keep it in range ~110-145
        assert!(avg_y > 100.0 && avg_y < 160.0,
            "decoded Y average {avg_y} is way off from input 128 — data likely corrupt");
    }
}
