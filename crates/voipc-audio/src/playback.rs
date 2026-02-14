use anyhow::Result;
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use ringbuf::traits::{Consumer, Split};
use ringbuf::HeapRb;
use tracing::{error, info, warn};

use crate::device;

/// The sample rate Opus produces. We force the playback device to this rate
/// so decoded samples play back at the correct speed.
const TARGET_SAMPLE_RATE: u32 = 48_000;

/// Handle to an active audio playback stream.
pub struct PlaybackStream {
    #[allow(dead_code)] // held to keep the stream alive
    stream: cpal::Stream,
    sample_rate: u32,
}

/// Size of the playback ring buffer in samples (~200ms at 48kHz).
const PLAYBACK_BUFFER_SIZE: usize = 48_000 / 5;

/// Start playing audio through the given device (or default).
///
/// Returns the playback stream handle and a ring buffer producer
/// that the mixer writes decoded PCM samples into.
pub fn start_playback(
    device_name: Option<&str>,
) -> Result<(PlaybackStream, ringbuf::HeapProd<f32>)> {
    let device = device::get_output_device(device_name)?;
    let config = device.default_output_config()?;
    let channels = config.channels() as usize;

    // Try 48kHz first (matches Opus), fall back to device default
    let (stream_config, actual_rate) = {
        let fallback_rate = config.sample_rate().0;
        if fallback_rate == TARGET_SAMPLE_RATE {
            let cfg = StreamConfig {
                channels: config.channels(),
                sample_rate: cpal::SampleRate(TARGET_SAMPLE_RATE),
                buffer_size: cpal::BufferSize::Default,
            };
            (cfg, TARGET_SAMPLE_RATE)
        } else {
            let test = StreamConfig {
                channels: config.channels(),
                sample_rate: cpal::SampleRate(TARGET_SAMPLE_RATE),
                buffer_size: cpal::BufferSize::Default,
            };
            match device.build_output_stream(
                &test,
                |_: &mut [f32], _: &cpal::OutputCallbackInfo| {},
                |_| {},
                None,
            ) {
                Ok(_dropped) => {
                    info!(
                        "device default is {}Hz, overriding to {}Hz",
                        fallback_rate, TARGET_SAMPLE_RATE
                    );
                    let cfg = StreamConfig {
                        channels: config.channels(),
                        sample_rate: cpal::SampleRate(TARGET_SAMPLE_RATE),
                        buffer_size: cpal::BufferSize::Default,
                    };
                    (cfg, TARGET_SAMPLE_RATE)
                }
                Err(_) => {
                    warn!(
                        "device does not support {}Hz, using default {}Hz — audio quality may be degraded",
                        TARGET_SAMPLE_RATE, fallback_rate
                    );
                    let cfg = StreamConfig {
                        channels: config.channels(),
                        sample_rate: config.sample_rate(),
                        buffer_size: cpal::BufferSize::Default,
                    };
                    (cfg, fallback_rate)
                }
            }
        }
    };

    info!(
        device = device.name().unwrap_or_default(),
        sample_rate = actual_rate,
        channels,
        "starting audio playback"
    );

    let rb = HeapRb::<f32>::new(PLAYBACK_BUFFER_SIZE);
    let (producer, mut consumer) = rb.split();

    let stream = match config.sample_format() {
        SampleFormat::F32 => device.build_output_stream(
            &stream_config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if channels == 1 {
                    let read = consumer.pop_slice(data);
                    // Fade out last samples to avoid click on underrun
                    if read < data.len() && read > 0 {
                        let fade_len = read.min(32);
                        let fade_start = read - fade_len;
                        for i in 0..fade_len {
                            data[fade_start + i] *= 1.0 - (i as f32 / fade_len as f32);
                        }
                    }
                    for sample in &mut data[read..] {
                        *sample = 0.0;
                    }
                } else {
                    // Duplicate mono to all channels, with fade-out on underrun
                    let mono_frames = data.len() / channels;
                    let mut last_sample = 0.0f32;
                    let mut underrun_at = mono_frames; // index where underrun starts

                    for (i, frame) in data.chunks_mut(channels).enumerate() {
                        let sample = match consumer.pop_iter().next() {
                            Some(s) => {
                                last_sample = s;
                                s
                            }
                            None => {
                                if underrun_at == mono_frames {
                                    underrun_at = i;
                                }
                                // Fade out over 32 samples from the underrun point
                                let fade_i = i - underrun_at;
                                if fade_i < 32 {
                                    last_sample * (1.0 - fade_i as f32 / 32.0)
                                } else {
                                    0.0
                                }
                            }
                        };
                        for ch in frame.iter_mut() {
                            *ch = sample;
                        }
                    }
                }
            },
            move |err| {
                error!("audio playback error: {}", err);
            },
            None,
        )?,
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
