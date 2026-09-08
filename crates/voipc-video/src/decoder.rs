use anyhow::{anyhow, Context, Result};
use ffmpeg_next as ffmpeg;
use ffmpeg::codec::{self, decoder};
use ffmpeg::format::Pixel;
use ffmpeg::util::frame::video::Video;
use std::sync::Once;
use voipc_protocol::types::VideoCodec;

static FFMPEG_INIT: Once = Once::new();

/// Initialize FFmpeg library (must be called before using any FFmpeg APIs)
fn init_ffmpeg() {
    FFMPEG_INIT.call_once(|| {
        ffmpeg::init().expect("Failed to initialize FFmpeg");
    });
}

/// A decoder for screen share frames, in whatever codec the sharer announced.
pub struct Decoder {
    decoder: decoder::Video,
    video_codec: VideoCodec,
}

// SAFETY: The FFmpeg decoder context is not Send by default due to raw pointers,
// but FFmpeg decoding is safe to use from a single thread at a time.
unsafe impl Send for Decoder {}

/// A decoded video frame in I420 format.
#[derive(Clone, Debug)]
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    /// I420 data (Y + U + V planes, total width*height*3/2 bytes).
    pub i420_data: Vec<u8>,
}

impl Decoder {
    /// Create a decoder for `video_codec`. All four are built into FFmpeg
    /// (H.264/HEVC/VP8/VP9 decoders need no external library), so a viewer can
    /// watch a browser sharer's VP9 as easily as a desktop sharer's H.264.
    pub fn new(video_codec: VideoCodec) -> Result<Self> {
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
        let decoder = codec::context::Context::new_with_codec(codec)
            .decoder()
            .open_as(codec)
            .with_context(|| format!("{video_codec:?} decoder: failed to open decoder"))?
            .video();

        Ok(Self {
            decoder: decoder?,
            video_codec,
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
        self.decoder.send_packet(&packet)
            .with_context(|| format!("{:?} decoder: failed to send packet", self.video_codec))?;

        // Collect decoded frames
        let mut frames = Vec::new();
        let mut decoded_frame = Video::empty();

        while self.decoder.receive_frame(&mut decoded_frame).is_ok() {
            let width = decoded_frame.width();
            let height = decoded_frame.height();

            // Convert to I420 if needed
            let i420_data = if decoded_frame.format() == Pixel::YUV420P {
                // Already I420, just copy planes
                self.extract_i420_from_frame(&decoded_frame)
            } else {
                // Need to convert to I420
                self.convert_to_i420(&decoded_frame)?
            };

            frames.push(DecodedFrame {
                width,
                height,
                i420_data,
            });
        }

        Ok(frames)
    }

    /// Extract I420 data from a frame that's already in YUV420P format
    fn extract_i420_from_frame(&self, frame: &Video) -> Vec<u8> {
        let width = frame.width() as usize;
        let height = frame.height() as usize;
        let y_size = width * height;
        let uv_size = y_size / 4;

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
        let uv_height = (height + 1) / 2;
        let uv_width = (width + 1) / 2;
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
    fn convert_to_i420(&self, frame: &Video) -> Result<Vec<u8>> {
        let width = frame.width();
        let height = frame.height();

        // Create scaler context
        let mut scaler = ffmpeg::software::scaling::context::Context::get(
            frame.format(),
            width,
            height,
            Pixel::YUV420P,
            width,
            height,
            ffmpeg::software::scaling::flag::Flags::BILINEAR,
        ).context("decoder: failed to create scaler context")?;

        // Create output frame
        let mut i420_frame = Video::empty();

        // Scale/convert
        scaler.run(frame, &mut i420_frame)
            .context("decoder: failed to convert to I420")?;

        // Extract data
        Ok(self.extract_i420_from_frame(&i420_frame))
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
