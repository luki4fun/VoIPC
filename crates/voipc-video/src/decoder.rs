use anyhow::{anyhow, Context, Result};
use ffmpeg::codec::{self, decoder};
use ffmpeg::format::Pixel;
use ffmpeg::util::frame::video::Video;
use ffmpeg_next as ffmpeg;
use std::sync::Once;
use voipc_protocol::types::VideoCodec;

static FFMPEG_INIT: Once = Once::new();

/// Initialize FFmpeg library (must be called before using any FFmpeg APIs)
fn init_ffmpeg() {
    FFMPEG_INIT.call_once(|| {
        ffmpeg::init().expect("Failed to initialize FFmpeg");
    });
}

/// Largest frame a viewer decodes: 2048×2048, which holds every share VoIPC
/// sends (1080p at most, `Resolution`) either way up, with room to spare. The
/// size comes from the sharer's own parameter sets, so without this FFmpeg
/// allocates whatever a peer claims — up to its own limit of about 262 million
/// pixels per reference frame — and one keyframe is an out of memory on every
/// viewer. The cap is per frame and a decoder keeps several reference frames,
/// so it sits near the largest real share, not far above it (S-046). Raise it
/// with any larger `Resolution`.
pub const MAX_DECODE_PIXELS: usize = 2048 * 2048;

/// A decoder for screen share frames, in whatever codec the sharer announced.
pub struct Decoder {
    decoder: decoder::Video,
    video_codec: VideoCodec,
    /// Conversion to I420 for frames that arrive in another format — the
    /// sharer's encoder picks it, and full-range yuvj420p is common. Kept
    /// with its output frame for as long as format and size stay the same,
    /// instead of a scaler setup and a frame allocation per frame.
    scaler: Option<(Pixel, u32, u32, Scaler, Video)>,
}

type Scaler = ffmpeg::software::scaling::context::Context;

// SAFETY: The FFmpeg decoder context is not Send by default due to raw pointers,
// but FFmpeg decoding is safe to use from a single thread at a time.
unsafe impl Send for Decoder {}

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

impl Decoder {
    /// Create a decoder for `video_codec`. All four are built into FFmpeg
    /// (H.264/HEVC/VP8/VP9 decoders need no external library), so a viewer can
    /// watch a browser sharer's VP9 as easily as a desktop sharer's H.264.
    pub fn new(video_codec: VideoCodec) -> Result<Self> {
        Self::with_max_pixels(video_codec, MAX_DECODE_PIXELS)
    }

    pub(crate) fn with_max_pixels(video_codec: VideoCodec, max_pixels: usize) -> Result<Self> {
        init_ffmpeg();

        let id = match video_codec {
            VideoCodec::H264 => codec::Id::H264,
            VideoCodec::H265 => codec::Id::HEVC,
            VideoCodec::Vp8 => codec::Id::VP8,
            VideoCodec::Vp9 => codec::Id::VP9,
        };
        let codec = decoder::find(id)
            .ok_or_else(|| anyhow!("{video_codec:?} decoder: codec not found in this FFmpeg"))?;

        // Create decoder context with codec-specific defaults
        let mut context = codec::context::Context::new_with_codec(codec);
        // SAFETY: a context we just allocated and own, set before it is opened.
        // Every decoder checks this when the stream sets its size and again
        // when it asks for a frame buffer.
        unsafe { (*context.as_mut_ptr()).max_pixels = max_pixels as i64 };
        let decoder = context
            .decoder()
            .open_as(codec)
            .with_context(|| format!("{video_codec:?} decoder: failed to open decoder"))?
            .video();

        Ok(Self {
            decoder: decoder?,
            video_codec,
            scaler: None,
        })
    }

    /// The codec this decoder was opened for.
    pub fn codec(&self) -> VideoCodec {
        self.video_codec
    }

    /// Decode one encoded frame.
    ///
    /// Returns a list of decoded frames (usually one, but the decoder can buffer).
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<DecodedFrame>> {
        // Create packet from raw data
        let packet = ffmpeg::Packet::copy(data);

        // Send packet to decoder
        self.decoder
            .send_packet(&packet)
            .with_context(|| format!("{:?} decoder: failed to send packet", self.video_codec))?;

        // Collect decoded frames
        let mut frames = Vec::new();
        let mut decoded_frame = Video::empty();

        while self.decoder.receive_frame(&mut decoded_frame).is_ok() {
            let width = decoded_frame.width();
            let height = decoded_frame.height();

            // Convert to I420 if needed
            let extracted = decoded_frame.format() == Pixel::YUV420P;
            let i420_data = if extracted {
                // Already I420, just copy planes
                Self::extract_i420_from_frame(&decoded_frame)
            } else {
                // Need to convert to I420
                self.convert_to_i420(&decoded_frame)?
            };
            // Then to JPEG's YCbCr, from what the frame says it carries. sws
            // hands over limited range; an untagged frame is limited for
            // H.264/H.265, as 0.12 senders send it, and full for VP8/VP9, as
            // browsers send those.
            use ffmpeg::util::color::{Range, Space};
            let full_range = extracted
                && match decoded_frame.color_range() {
                    Range::JPEG => true,
                    Range::MPEG => false,
                    _ => matches!(self.video_codec, VideoCodec::Vp8 | VideoCodec::Vp9),
                };
            let bt709 = decoded_frame.color_space() == Space::BT709;

            frames.push(DecodedFrame {
                width,
                height,
                i420_data,
                full_range,
                bt709,
            });
        }

        Ok(frames)
    }

    /// Extract I420 data from a frame that's already in YUV420P format
    fn extract_i420_from_frame(frame: &Video) -> Vec<u8> {
        let width = frame.width() as usize;
        let height = frame.height() as usize;
        let y_size = width * height;
        let uv_size = width.div_ceil(2) * height.div_ceil(2);

        let mut i420_data = Vec::with_capacity(y_size + 2 * uv_size);

        // Y plane
        let y_stride = frame.stride(0);
        let y_plane = frame.data(0);
        for row in 0..height {
            let start = row * y_stride;
            let end = start + width;
            i420_data.extend_from_slice(&y_plane[start..end]);
        }

        // U plane
        let uv_height = height.div_ceil(2);
        let uv_width = width.div_ceil(2);
        let u_stride = frame.stride(1);
        let u_plane = frame.data(1);
        for row in 0..uv_height {
            let start = row * u_stride;
            let end = start + uv_width;
            i420_data.extend_from_slice(&u_plane[start..end]);
        }

        // V plane
        let v_stride = frame.stride(2);
        let v_plane = frame.data(2);
        for row in 0..uv_height {
            let start = row * v_stride;
            let end = start + uv_width;
            i420_data.extend_from_slice(&v_plane[start..end]);
        }

        i420_data
    }

    /// Convert a frame to I420 format using software scaling
    fn convert_to_i420(&mut self, frame: &Video) -> Result<Vec<u8>> {
        let key = (frame.format(), frame.width(), frame.height());
        let (scaler, i420_frame) = match &mut self.scaler {
            Some((f, w, h, scaler, out)) if (*f, *w, *h) == key => (scaler, out),
            slot => {
                let (format, width, height) = key;
                let scaler = Scaler::get(
                    format,
                    width,
                    height,
                    Pixel::YUV420P,
                    width,
                    height,
                    ffmpeg::software::scaling::flag::Flags::BILINEAR,
                )
                .context("decoder: failed to create scaler context")?;
                let (.., scaler, out) =
                    slot.insert((format, width, height, scaler, Video::empty()));
                (scaler, out)
            }
        };
        scaler
            .run(frame, i420_frame)
            .context("decoder: failed to convert to I420")?;
        Ok(Self::extract_i420_from_frame(i420_frame))
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // Flush decoder
        let _ = self.decoder.send_eof();
        let mut frame = Video::empty();
        while self.decoder.receive_frame(&mut frame).is_ok() {
            // Drain remaining frames
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conversion a non-I420 frame takes: one scaler for a run of frames
    /// in the same format and size, a new one when either changes.
    #[test]
    fn other_formats_convert_with_one_scaler_per_shape() {
        let mut dec = Decoder::new(VideoCodec::H264).unwrap();
        let frame = |w, h| {
            let mut f = Video::new(Pixel::YUVJ420P, w, h);
            for plane in 0..3 {
                f.data_mut(plane).fill(128);
            }
            f
        };
        let a = dec.convert_to_i420(&frame(64, 48)).unwrap();
        assert_eq!(a.len(), 64 * 48 + 2 * 32 * 24);
        let b = dec.convert_to_i420(&frame(64, 48)).unwrap();
        assert_eq!(a, b);
        let c = dec.convert_to_i420(&frame(33, 17)).unwrap();
        assert_eq!(c.len(), 33 * 17 + 2 * 17 * 9);
        assert!(matches!(dec.scaler, Some((_, 33, 17, ..))));
    }
}
