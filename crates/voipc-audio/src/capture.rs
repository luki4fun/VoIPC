use anyhow::Result;
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use ringbuf::traits::{Producer, Split};
use ringbuf::HeapRb;
use tracing::{error, info, warn};

use crate::device;

/// The sample rate Opus expects. We force the capture device to this rate
/// so samples match the encoder without resampling.
const TARGET_SAMPLE_RATE: u32 = 48_000;

/// Handle to an active audio capture stream.
///
/// Captures PCM f32 samples from the microphone and writes them
/// into a lock-free ring buffer that the encoder thread reads from.
pub struct CaptureStream {
    stream: cpal::Stream,
    sample_rate: u32,
}

/// Size of the capture ring buffer in samples (~200ms at 48kHz).
const CAPTURE_BUFFER_SIZE: usize = 48_000 / 5;

/// Start capturing audio from the given device (or default).
///
/// Returns the capture stream handle and a ring buffer consumer
/// that provides the raw PCM f32 samples.
pub fn start_capture(
    device_name: Option<&str>,
) -> Result<(CaptureStream, ringbuf::HeapCons<f32>)> {
    let device = device::get_input_device(device_name)?;
    let config = device.default_input_config()?;
    let channels = config.channels() as usize;
    let sample_format = config.sample_format();

    let rb = HeapRb::<f32>::new(CAPTURE_BUFFER_SIZE);
    let (mut producer, consumer) = rb.split();

    // Try 48kHz first (matches Opus), fall back to device default
    let (stream_config, actual_rate) = {
        let preferred = StreamConfig {
            channels: config.channels(),
            sample_rate: cpal::SampleRate(TARGET_SAMPLE_RATE),
            buffer_size: cpal::BufferSize::Default,
        };
        let fallback_rate = config.sample_rate().0;
        if fallback_rate == TARGET_SAMPLE_RATE {
            (preferred, TARGET_SAMPLE_RATE)
        } else {
            // Try building a test config at 48kHz — if it fails, use device default
            let test = StreamConfig {
                channels: config.channels(),
                sample_rate: cpal::SampleRate(TARGET_SAMPLE_RATE),
                buffer_size: cpal::BufferSize::Default,
            };
            // Check if device supports 48kHz by trying to build; on failure, fall back
            match device.build_input_stream(
                &test,
                |_: &[f32], _: &cpal::InputCallbackInfo| {},
                |_| {},
                None,
            ) {
                Ok(_dropped) => {
                    info!(
                        "device default is {}Hz, overriding to {}Hz",
                        fallback_rate, TARGET_SAMPLE_RATE
                    );
                    (preferred, TARGET_SAMPLE_RATE)
                }
                Err(_) => {
                    warn!(
                        "device does not support {}Hz, using default {}Hz — audio quality may be degraded",
                        TARGET_SAMPLE_RATE, fallback_rate
                    );
                    let fallback = StreamConfig {
                        channels: config.channels(),
                        sample_rate: config.sample_rate(),
                        buffer_size: cpal::BufferSize::Default,
                    };
                    (fallback, fallback_rate)
                }
            }
        }
    };

    info!(
        device = device.name().unwrap_or_default(),
        sample_rate = actual_rate,
        channels,
        "starting audio capture"
    );

    let stream = match sample_format {
        SampleFormat::F32 => device.build_input_stream(
            &stream_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                // If stereo or multi-channel, take only the first channel
                if channels == 1 {
                    let _ = producer.push_slice(data);
                } else {
                    for chunk in data.chunks(channels) {
                        let _ = producer.push_iter(std::iter::once(chunk[0]));
                    }
                }
            },
            move |err| {
                error!("audio capture error: {}", err);
            },
            None,
        )?,
        SampleFormat::I16 => device.build_input_stream(
            &stream_config,
            move |data: &[i16], _: &cpal::InputCallbackInfo| {
                if channels == 1 {
                    for &sample in data {
                        let _ = producer.push_iter(std::iter::once(
                            sample as f32 / i16::MAX as f32,
                        ));
                    }
                } else {
                    for chunk in data.chunks(channels) {
                        let _ = producer.push_iter(std::iter::once(
                            chunk[0] as f32 / i16::MAX as f32,
                        ));
                    }
                }
            },
            move |err| {
                error!("audio capture error: {}", err);
            },
            None,
        )?,
        format => anyhow::bail!("unsupported sample format: {:?}", format),
    };

    stream.play()?;

    Ok((CaptureStream { stream, sample_rate: actual_rate }, consumer))
}

impl CaptureStream {
    /// The hardware sample rate of the capture device.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Pause the capture stream (e.g., when PTT is released).
    pub fn pause(&self) -> Result<()> {
        self.stream.pause()?;
        Ok(())
    }

    /// Resume the capture stream (e.g., when PTT is pressed).
    pub fn play(&self) -> Result<()> {
        self.stream.play()?;
        Ok(())
    }
}
