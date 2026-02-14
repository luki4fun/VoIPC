use anyhow::{anyhow, Context, Result};
use ffmpeg_next as ffmpeg;
use ffmpeg::codec::{self, decoder};
use ffmpeg::format::Pixel;
use ffmpeg::util::frame::video::Video;
use std::sync::Once;

static FFMPEG_INIT: Once = Once::new();

/// Initialize FFmpeg library (must be called before using any FFmpeg APIs)
fn init_ffmpeg() {
    FFMPEG_INIT.call_once(|| {
        ffmpeg::init().expect("Failed to initialize FFmpeg");
    });
}

/// A H.265/HEVC decoder for screen share frames.
pub struct Decoder {
    decoder: decoder::Video,
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
    /// Create a new H.265/HEVC decoder.
    pub fn new() -> Result<Self> {
        init_ffmpeg();

        // Find H.265/HEVC software decoder
        let codec = decoder::find(codec::Id::HEVC)
            .ok_or_else(|| anyhow!("H.265 decoder: HEVC codec not found"))?;

        // Create decoder context with codec-specific defaults
        let decoder = codec::context::Context::new_with_codec(codec)
            .decoder()
            .open_as(codec)
            .context("H.265 decoder: failed to open decoder")?
            .video();

        Ok(Self { decoder: decoder? })
    }

    /// Decode a H.265/HEVC encoded frame.
    ///
    /// Returns a list of decoded frames (usually one, but H.265 can buffer).
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<DecodedFrame>> {
        // Create packet from raw data
        let packet = ffmpeg::Packet::copy(data);

        // Send packet to decoder
        self.decoder.send_packet(&packet)
            .context("H.265 decoder: failed to send packet")?;

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
        ).context("H.265 decoder: failed to create scaler context")?;

        // Create output frame
        let mut i420_frame = Video::empty();

        // Scale/convert
        scaler.run(frame, &mut i420_frame)
            .context("H.265 decoder: failed to convert to I420")?;

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
