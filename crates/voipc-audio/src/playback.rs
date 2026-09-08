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

/// Fill the device's interleaved output buffer from the ring buffer, which
/// carries interleaved **stereo** since proximity chat needs a stereo image.
///
/// A mono device gets the downmix, a stereo device the pair as-is, and a
/// surround device gets L and R on the front pair with the downmix behind, so
/// nobody loses a channel. On underrun the tail fades out to avoid a click.
fn fill_output(
    consumer: &mut ringbuf::HeapCons<f32>,
    data: &mut [f32],
    channels: usize,
    scratch: &mut Vec<f32>,
) {
    let frames = data.len() / channels;
    scratch.clear();
    scratch.resize(frames * 2, 0.0);
    let read_frames = consumer.pop_slice(scratch) / 2;
    if read_frames < frames && read_frames > 0 {
        let fade_len = read_frames.min(32);
        let fade_start = read_frames - fade_len;
        for i in 0..fade_len {
            let factor = 1.0 - (i as f32 / fade_len as f32);
            scratch[2 * (fade_start + i)] *= factor;
            scratch[2 * (fade_start + i) + 1] *= factor;
        }
    }
    for (frame, pair) in data.chunks_mut(channels).zip(scratch.chunks_exact(2)) {
        let (l, r) = (pair[0], pair[1]);
        match channels {
            1 => frame[0] = 0.5 * (l + r),
            _ => {
                frame[0] = l;
                frame[1] = r;
                // ponytail: extra channels get the downmix; proper surround
                // placement if anyone ever asks for it
                for ch in frame[2..].iter_mut() {
                    *ch = 0.5 * (l + r);
                }
            }
        }
    }
}

/// Start playing audio through the given device (or default).
///
/// Returns the playback stream handle and a ring buffer producer that the
/// mixer writes **interleaved stereo** PCM into, at the stream's sample rate
/// (query it via [`PlaybackStream::sample_rate`]; 48kHz unless the device
/// can't).
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

    // ~200ms of interleaved stereo samples at the stream rate
    let rb = HeapRb::<f32>::new((actual_rate / 5) as usize * 2);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ringbuf::traits::Producer;

    /// Feeds `pairs` into a ring buffer and renders one callback of `frames`
    /// frames for a device with `channels` channels.
    fn render(pairs: &[(f32, f32)], frames: usize, channels: usize) -> Vec<f32> {
        let rb = HeapRb::<f32>::new(4096);
        let (mut producer, mut consumer) = rb.split();
        for &(l, r) in pairs {
            producer.try_push(l).unwrap();
            producer.try_push(r).unwrap();
        }
        let mut data = vec![0.0f32; frames * channels];
        let mut scratch = Vec::new();
        fill_output(&mut consumer, &mut data, channels, &mut scratch);
        data
    }

    #[test]
    fn stereo_device_gets_the_pair_unchanged() {
        let out = render(&[(0.25, 0.75), (-0.5, 0.5)], 2, 2);
        assert_eq!(out, vec![0.25, 0.75, -0.5, 0.5]);
    }

    #[test]
    fn mono_device_gets_the_downmix() {
        let out = render(&[(0.25, 0.75), (1.0, -1.0)], 2, 1);
        assert_eq!(out, vec![0.5, 0.0]);
    }

    #[test]
    fn surround_device_keeps_the_front_pair() {
        let out = render(&[(0.2, 0.8)], 1, 6);
        assert_eq!(out[0], 0.2);
        assert_eq!(out[1], 0.8);
        for &s in &out[2..] {
            assert!((s - 0.5).abs() < 1e-6);
        }
    }

    #[test]
    fn underrun_fades_the_tail_and_leaves_silence() {
        // 40 frames available, 100 asked for: the last 32 fade out
        let pairs: Vec<(f32, f32)> = (0..40).map(|_| (1.0, 1.0)).collect();
        let out = render(&pairs, 100, 2);
        assert_eq!(out[0], 1.0, "the head is untouched");
        assert!(out[2 * 39] < 0.05, "the tail should have faded");
        assert!(out[2 * 39] >= 0.0);
        for &s in &out[80..] {
            assert_eq!(s, 0.0, "past the data it must be silent");
        }
    }

    #[test]
    fn a_dry_ring_is_silence_not_noise() {
        let out = render(&[], 8, 2);
        assert!(out.iter().all(|&s| s == 0.0));
    }
}
