use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use ringbuf::traits::{Consumer, Split};
use ringbuf::HeapRb;
use tracing::{error, info, warn};

use crate::device;

/// The sample rate Opus produces. We prefer this on the playback device;
/// if unsupported, the mixer resamples to the device rate before pushing.
const TARGET_SAMPLE_RATE: u32 = 48_000;

/// Handle to an active audio playback stream.
pub struct PlaybackStream {
    #[allow(dead_code)] // held to keep the stream alive
    stream: cpal::Stream,
    sample_rate: u32,
}

/// Fill an interleaved output buffer from the mono ring buffer, duplicating
/// each sample to all channels and fading out on underrun to avoid clicks.
fn fill_output(
    consumer: &mut ringbuf::HeapCons<f32>,
    data: &mut [f32],
    channels: usize,
    scratch: &mut Vec<f32>,
) {
    let frames = data.len() / channels;
    scratch.clear();
    scratch.resize(frames, 0.0);
    let read = consumer.pop_slice(scratch);
    if read < frames && read > 0 {
        let fade_len = read.min(32);
        let fade_start = read - fade_len;
        for i in 0..fade_len {
            scratch[fade_start + i] *= 1.0 - (i as f32 / fade_len as f32);
        }
    }
    if channels == 1 {
        data.copy_from_slice(scratch);
    } else {
        for (frame, &sample) in data.chunks_mut(channels).zip(scratch.iter()) {
            for ch in frame.iter_mut() {
                *ch = sample;
            }
        }
    }
}

/// Start playing audio through the given device (or default).
///
/// Returns the playback stream handle and a ring buffer producer that the
/// mixer writes PCM samples into **at the stream's sample rate** (query it
/// via [`PlaybackStream::sample_rate`]; 48kHz unless the device can't).
/// `error_flag` is set when the stream reports an error (e.g. the device
/// disappeared) so the owner can rebuild it.
pub fn start_playback(
    device_name: Option<&str>,
    error_flag: Arc<AtomicBool>,
) -> Result<(PlaybackStream, ringbuf::HeapProd<f32>)> {
    let device = device::get_output_device(device_name)?;
    let config = device.default_output_config()?;
    let channels = config.channels() as usize;
    let sample_format = config.sample_format();

    let default_rate = config.sample_rate().0;
    let actual_rate = if default_rate == TARGET_SAMPLE_RATE
        || device::output_supports_rate(&device, sample_format, config.channels(), TARGET_SAMPLE_RATE)
    {
        TARGET_SAMPLE_RATE
    } else {
        warn!(
            "output device does not support {}Hz, using {}Hz with resampling",
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
        "starting audio playback"
    );

    // ~200ms of mono samples at the stream rate
    let rb = HeapRb::<f32>::new((actual_rate / 5) as usize);
    let (producer, mut consumer) = rb.split();

    let error_cb = {
        let flag = error_flag.clone();
        move |err| {
            error!("audio playback error: {}", err);
            flag.store(true, Ordering::Relaxed);
        }
    };

    let stream = match sample_format {
        SampleFormat::F32 => {
            let mut scratch: Vec<f32> = Vec::new();
            device.build_output_stream(
                &stream_config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    fill_output(&mut consumer, data, channels, &mut scratch);
                },
                error_cb,
                None,
            )?
        }
        SampleFormat::I16 => {
            let mut scratch: Vec<f32> = Vec::new();
            let mut frames_f32: Vec<f32> = Vec::new();
            device.build_output_stream(
                &stream_config,
                move |data: &mut [i16], _: &cpal::OutputCallbackInfo| {
                    frames_f32.clear();
                    frames_f32.resize(data.len(), 0.0);
                    fill_output(&mut consumer, &mut frames_f32, channels, &mut scratch);
                    for (out, &s) in data.iter_mut().zip(frames_f32.iter()) {
                        *out = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                    }
                },
                error_cb,
                None,
            )?
        }
        format => anyhow::bail!("unsupported output sample format: {:?}", format),
    };

    stream.play()?;

    Ok((PlaybackStream { stream, sample_rate: actual_rate }, producer))
}

// SAFETY: PlaybackStream only holds the cpal::Stream handle to keep it alive.
// We never call methods on it from multiple threads. The cpal Stream's !Send/!Sync
// markers are overly conservative for our use case (hold-only, no cross-thread access).
unsafe impl Send for PlaybackStream {}
unsafe impl Sync for PlaybackStream {}

impl PlaybackStream {
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
}
