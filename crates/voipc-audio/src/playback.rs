use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use ringbuf::traits::{Consumer, Producer, Split};
use ringbuf::HeapRb;
use tokio::sync::Notify;
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
///
/// `report` feeds the process-wide playback stats, which only the voice
/// mixer's stream may do; `first` marks a stream's first callback.
fn fill_output(
    consumer: &mut ringbuf::HeapCons<f32>,
    data: &mut [f32],
    channels: usize,
    scratch: &mut Vec<f32>,
    report: bool,
    first: bool,
) {
    let frames = data.len() / channels;
    // What the mixer has to keep in front of this device, in the ring's own
    // units. Devices differ by an order of magnitude here: cpal's ALSA backend
    // hands over every free frame per wake (42.7 ms in steady state on the
    // author's machine), WASAPI asks for about 10 ms, and Oboe for a couple.
    // The first callback asks for the device's whole buffer (100 ms here) and
    // is left out: the prime already covers it, and counting it would inflate
    // the cushion for seconds after every device switch.
    if report && !first {
        crate::note_request(frames * 2);
    }
    scratch.clear();
    scratch.resize(frames * 2, 0.0);
    let read_frames = consumer.pop_slice(scratch) / 2;
    if read_frames < frames && read_frames > 0 {
        if report {
            crate::note_underrun();
        }
        let fade_len = read_frames.min(32);
        let fade_start = read_frames - fade_len;
        for i in 0..fade_len {
            let factor = 1.0 - (i as f32 / fade_len as f32);
            scratch[2 * (fade_start + i)] *= factor;
            scratch[2 * (fade_start + i) + 1] *= factor;
        }
    }
    for (frame, &[l, r]) in data.chunks_mut(channels).zip(scratch.as_chunks::<2>().0) {
        match channels {
            1 => frame[0] = 0.5 * (l + r),
            _ => {
                frame[0] = l;
                frame[1] = r;
                // bernd: extra channels get the downmix; proper surround
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
/// disappeared) so the owner can rebuild it. `wake` is for the voice mixer:
/// it is notified after every callback, so the producer can run on the
/// device's clock and top the ring up right after it was drained instead of
/// guessing with a timer, and only such a stream reports into the playback
/// stats the mixer sizes its cushion from. `None` (a mic monitor, a speaker
/// test) plays without touching them.
pub fn start_playback(
    device_name: Option<&str>,
    error_flag: Arc<AtomicBool>,
    wake: Option<Arc<Notify>>,
) -> Result<(PlaybackStream, ringbuf::HeapProd<f32>)> {
    let device = device::get_output_device(device_name)?;
    let config = device.default_output_config()?;
    let channels = config.channels() as usize;
    let sample_format = config.sample_format();

    let default_rate = config.sample_rate().0;
    let actual_rate = if default_rate == TARGET_SAMPLE_RATE
        || device::output_supports_rate(
            &device,
            sample_format,
            config.channels(),
            TARGET_SAMPLE_RATE,
        ) {
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

    // A new device asks for its own callback size and starves differently;
    // what the last one did says nothing about it.
    let report = wake.is_some();
    if report {
        crate::reset_playback_stats();
    }

    // ~200ms of interleaved stereo samples at the stream rate
    let rb = HeapRb::<f32>::new((actual_rate / 5) as usize * 2);
    let (mut producer, mut consumer) = rb.split();

    // The first callback of a fresh stream asks for the device's whole buffer
    // — 100ms on ALSA here, against 42.7ms in steady state — and it arrives
    // before anything has had a chance to learn that. Nobody can fill that in
    // time, so hand it silence up front rather than a hole: without this there
    // is one audible click every time playback starts or the output device is
    // switched. It costs no lasting latency, since the mixer stops topping up
    // until the device has eaten back down to its cushion.
    let prime = vec![0.0f32; (actual_rate / 10) as usize * 2];
    let _ = producer.push_slice(&prime);

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
            let mut first = true;
            device.build_output_stream(
                &stream_config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    let first = std::mem::take(&mut first);
                    fill_output(&mut consumer, data, channels, &mut scratch, report, first);
                    if let Some(wake) = &wake {
                        wake.notify_one();
                    }
                },
                error_cb,
                None,
            )?
        }
        SampleFormat::I16 => {
            let mut scratch: Vec<f32> = Vec::new();
            let mut frames_f32: Vec<f32> = Vec::new();
            let mut first = true;
            device.build_output_stream(
                &stream_config,
                move |data: &mut [i16], _: &cpal::OutputCallbackInfo| {
                    frames_f32.clear();
                    frames_f32.resize(data.len(), 0.0);
                    let first = std::mem::take(&mut first);
                    fill_output(
                        &mut consumer,
                        &mut frames_f32,
                        channels,
                        &mut scratch,
                        report,
                        first,
                    );
                    for (out, &s) in data.iter_mut().zip(frames_f32.iter()) {
                        *out = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                    }
                    if let Some(wake) = &wake {
                        wake.notify_one();
                    }
                },
                error_cb,
                None,
            )?
        }
        format => anyhow::bail!("unsupported output sample format: {:?}", format),
    };

    stream.play()?;

    Ok((
        PlaybackStream {
            stream,
            sample_rate: actual_rate,
        },
        producer,
    ))
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

    /// The playback stats are process-wide, so every test that renders
    /// through them holds this: a render beside a read skews it.
    static STATS: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        fill_output(
            &mut consumer,
            &mut data,
            channels,
            &mut scratch,
            true,
            false,
        );
        data
    }

    #[test]
    fn stereo_device_gets_the_pair_unchanged() {
        let _guard = STATS.lock().unwrap_or_else(|p| p.into_inner());
        let out = render(&[(0.25, 0.75), (-0.5, 0.5)], 2, 2);
        assert_eq!(out, vec![0.25, 0.75, -0.5, 0.5]);
    }

    #[test]
    fn mono_device_gets_the_downmix() {
        let _guard = STATS.lock().unwrap_or_else(|p| p.into_inner());
        let out = render(&[(0.25, 0.75), (1.0, -1.0)], 2, 1);
        assert_eq!(out, vec![0.5, 0.0]);
    }

    #[test]
    fn surround_device_keeps_the_front_pair() {
        let _guard = STATS.lock().unwrap_or_else(|p| p.into_inner());
        let out = render(&[(0.2, 0.8)], 1, 6);
        assert_eq!(out[0], 0.2);
        assert_eq!(out[1], 0.8);
        for &s in &out[2..] {
            assert!((s - 0.5).abs() < 1e-6);
        }
    }

    /// Runs `feeder` against a device that asks for `ask` frames per callback
    /// and returns how many callbacks it starved. The real default device on
    /// the author's machine asks for 2048 frames (42.7 ms) at a time, which is
    /// more than one 20 ms frame — so a producer that keeps one frame in hand
    /// starves on every single callback.
    fn drive(
        ask: usize,
        callbacks: usize,
        mut feeder: impl FnMut(&mut ringbuf::HeapProd<f32>),
    ) -> u32 {
        let rb = HeapRb::<f32>::new(48_000 / 5 * 2); // the real ring: 200 ms
        let (mut producer, mut consumer) = rb.split();
        let mut data = vec![0.0f32; ask * 2];
        let mut scratch = Vec::new();
        crate::reset_playback_stats();
        for _ in 0..callbacks {
            feeder(&mut producer);
            fill_output(&mut consumer, &mut data, 2, &mut scratch, true, false);
        }
        crate::take_underruns()
    }

    #[test]
    fn the_feed_policy_keeps_a_greedy_device_fed() {
        use ringbuf::traits::Observer;
        let _guard = STATS.lock().unwrap_or_else(|p| p.into_inner());
        const FRAME: usize = 960 * 2; // one 20 ms frame, interleaved stereo
        const ASK: usize = 2048; // what the author's default device takes

        // What the mixer does: top up to a cushion sized from the device's own
        // appetite, and push silence rather than let the ring run dry.
        let fed = drive(ASK, 200, |p| {
            let want = crate::take_request_max() as usize;
            let cushion = (want + FRAME).clamp(3 * FRAME, 8 * FRAME);
            while p.occupied_len() < cushion {
                let _ = p.push_slice(&[0.5f32; FRAME]);
            }
        });
        assert_eq!(fed, 0, "the device starved {fed} times");

        // And the tripwire bites: one frame in hand is less than this device
        // swallows per callback, which is exactly the bug that shipped.
        let starved = drive(ASK, 200, |p| {
            while p.occupied_len() < FRAME {
                let _ = p.push_slice(&[0.5f32; FRAME]);
            }
        });
        assert!(
            starved > 100,
            "a one-frame cushion should starve, got {starved}"
        );
    }

    #[test]
    fn underrun_fades_the_tail_and_leaves_silence() {
        // One test for both renders: the stats are process-wide, and this is
        // the only test that produces a partial read.
        let _guard = STATS.lock().unwrap_or_else(|p| p.into_inner());
        crate::reset_playback_stats();
        let out = render(&[], 8, 2);
        assert!(
            out.iter().all(|&s| s == 0.0),
            "a dry ring is silence, not noise"
        );
        assert_eq!(crate::take_underruns(), 0, "a dry ring is not a gap");

        // 40 frames available, 100 asked for: the last 32 fade out
        let pairs: Vec<(f32, f32)> = (0..40).map(|_| (1.0, 1.0)).collect();
        let out = render(&pairs, 100, 2);
        assert_eq!(out[0], 1.0, "the head is untouched");
        assert!(out[2 * 39] < 0.05, "the tail should have faded");
        assert!(out[2 * 39] >= 0.0);
        for &s in &out[80..] {
            assert_eq!(s, 0.0, "past the data it must be silent");
        }
        assert_eq!(
            crate::take_underruns(),
            1,
            "a partial read is the audible gap"
        );
        // And the device's appetite is reported in the ring's own units
        assert_eq!(
            crate::take_request_max(),
            200,
            "100 frames as stereo samples"
        );
    }

    #[test]
    fn only_the_mixers_stream_reports_and_never_its_first_ask() {
        let _guard = STATS.lock().unwrap_or_else(|p| p.into_inner());
        let rb = HeapRb::<f32>::new(4096);
        let (mut producer, mut consumer) = rb.split();
        let mut data = vec![0.0f32; 100 * 2];
        let mut scratch = Vec::new();
        // Every callback is a partial read: 40 frames there, 100 asked for
        let mut callback = |report: bool, first: bool| {
            let _ = producer.push_slice(&[1.0f32; 80]);
            fill_output(&mut consumer, &mut data, 2, &mut scratch, report, first);
        };
        crate::reset_playback_stats();
        callback(false, false);
        assert_eq!(
            crate::take_underruns(),
            0,
            "a speaker test is not the mixer's"
        );
        assert_eq!(
            crate::take_request_max(),
            0,
            "a speaker test is not the mixer's"
        );
        callback(true, true);
        assert_eq!(
            crate::take_request_max(),
            0,
            "the prime covers the first ask"
        );
        assert_eq!(crate::take_underruns(), 1, "a gap is a gap, first or not");
    }
}
