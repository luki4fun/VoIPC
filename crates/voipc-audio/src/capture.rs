use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use ringbuf::traits::{Producer, Split};
use ringbuf::HeapRb;
use tracing::{error, info, warn};

use crate::device;
use crate::resample::LinearResampler;

/// The sample rate Opus expects. We prefer this on the capture device;
/// if unsupported, samples are resampled to 48kHz before hitting the ring.
const TARGET_SAMPLE_RATE: u32 = 48_000;

/// Handle to an active audio capture stream.
///
/// Captures PCM f32 samples from the microphone and writes them (always at
/// 48kHz mono) into a lock-free ring buffer that the encoder thread reads from.
pub struct CaptureStream {
    stream: cpal::Stream,
    sample_rate: u32,
}

/// Size of the capture ring buffer in samples (~200ms at 48kHz).
const CAPTURE_BUFFER_SIZE: usize = 48_000 / 5;

/// Downmix to channel 0, apply gain, resample to 48kHz if needed, and push
/// to the ring. `mono` samples must already be at the device rate; pass
/// `channels == 1` for pre-monoized input.
fn push_input(
    producer: &mut ringbuf::HeapProd<f32>,
    data: &[f32],
    channels: usize,
    gain: f32,
    resampler: &mut Option<LinearResampler>,
    mono: &mut Vec<f32>,
    resampled: &mut Vec<f32>,
) {
    let samples: &[f32] = if channels == 1 && gain == 1.0 {
        data
    } else if channels == 1 {
        mono.clear();
        mono.extend(data.iter().map(|s| (s * gain).clamp(-1.0, 1.0)));
        mono
    } else {
        // If stereo or multi-channel, take only the first channel
        mono.clear();
        mono.extend(
            data.chunks(channels)
                .map(|c| (c[0] * gain).clamp(-1.0, 1.0)),
        );
        mono
    };
    match resampler {
        Some(r) => {
            resampled.clear();
            r.process(samples, resampled);
            let _ = producer.push_slice(resampled);
        }
        None => {
            let _ = producer.push_slice(samples);
        }
    }
}

/// Start capturing audio from the given device (or default).
///
/// Returns the capture stream handle and a ring buffer consumer that
/// provides raw PCM f32 samples at 48kHz mono. `error_flag` is set when the
/// stream reports an error (e.g. the device disappeared) so the owner can
/// rebuild it. `gain` (f32 bits, 1.0 = unity) is read per callback so it
/// applies live.
pub fn start_capture(
    device_name: Option<&str>,
    error_flag: Arc<AtomicBool>,
    gain: Arc<std::sync::atomic::AtomicU32>,
) -> Result<(CaptureStream, ringbuf::HeapCons<f32>)> {
    let device = device::get_input_device(device_name)?;
    let config = device.default_input_config()?;
    let channels = config.channels() as usize;
    let sample_format = config.sample_format();

    let rb = HeapRb::<f32>::new(CAPTURE_BUFFER_SIZE);
    let (mut producer, consumer) = rb.split();

    let default_rate = config.sample_rate().0;
    let actual_rate = if default_rate == TARGET_SAMPLE_RATE
        || device::input_supports_rate(&device, sample_format, config.channels(), TARGET_SAMPLE_RATE)
    {
        TARGET_SAMPLE_RATE
    } else {
        warn!(
            "input device does not support {}Hz, using {}Hz with resampling",
            TARGET_SAMPLE_RATE, default_rate
        );
        default_rate
    };
    let stream_config = StreamConfig {
        channels: config.channels(),
        sample_rate: cpal::SampleRate(actual_rate),
        buffer_size: cpal::BufferSize::Default,
    };

    info!(
        device = device.name().unwrap_or_default(),
        sample_rate = actual_rate,
        channels,
        format = ?sample_format,
        "starting audio capture"
    );

    let mut resampler =
        (actual_rate != TARGET_SAMPLE_RATE).then(|| LinearResampler::new(actual_rate, TARGET_SAMPLE_RATE));
    let mut mono: Vec<f32> = Vec::new();
    let mut resampled: Vec<f32> = Vec::new();

    let error_cb = {
        let flag = error_flag.clone();
        move |err| {
            error!("audio capture error: {}", err);
            flag.store(true, Ordering::Relaxed);
        }
    };

    let stream = match sample_format {
        SampleFormat::F32 => device.build_input_stream(
            &stream_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                let g = f32::from_bits(gain.load(Ordering::Relaxed));
                push_input(&mut producer, data, channels, g, &mut resampler, &mut mono, &mut resampled);
            },
            error_cb,
            None,
        )?,
        SampleFormat::I16 => {
            let mut converted: Vec<f32> = Vec::new();
            device.build_input_stream(
                &stream_config,
                move |data: &[i16], _: &cpal::InputCallbackInfo| {
                    converted.clear();
                    if channels == 1 {
                        converted.extend(data.iter().map(|&s| s as f32 / i16::MAX as f32));
                    } else {
                        converted
                            .extend(data.chunks(channels).map(|c| c[0] as f32 / i16::MAX as f32));
                    }
                    let g = f32::from_bits(gain.load(Ordering::Relaxed));
                    push_input(&mut producer, &converted, 1, g, &mut resampler, &mut mono, &mut resampled);
                },
                error_cb,
                None,
            )?
        }
        format => anyhow::bail!("unsupported sample format: {:?}", format),
    };

    stream.play()?;

    Ok((CaptureStream { stream, sample_rate: actual_rate }, consumer))
}

impl CaptureStream {
    /// The hardware sample rate of the capture device.
    #[allow(dead_code)]
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
