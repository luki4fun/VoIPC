//! End-to-end pipeline test: Opus encode → lossy/reordering network →
//! jitter buffer → FEC/PLC decode, consuming frames the way the client's
//! clocked mixer task does (one pop per 20ms tick).

use voipc_audio::decoder::Decoder;
use voipc_audio::encoder::Encoder;
use voipc_audio::jitter::{JitterBuffer, JitterFrame};
use voipc_protocol::voice::OPUS_FRAME_SIZE;

fn tone_frame(phase: &mut f32) -> Vec<f32> {
    let step = 2.0 * std::f32::consts::PI * 440.0 / 48_000.0;
    (0..OPUS_FRAME_SIZE)
        .map(|_| {
            let s = 0.3 * phase.sin();
            *phase += step;
            s
        })
        .collect()
}

/// Pop one frame the way the mixer tick does: FEC from the next packet when
/// available, otherwise PLC. Returns decoded samples, or None while buffering.
fn mixer_pop(jitter: &mut JitterBuffer, decoder: &mut Decoder) -> Option<Vec<f32>> {
    match jitter.pop()? {
        JitterFrame::Ready(data) => decoder.decode(&data).ok(),
        JitterFrame::Lost => match jitter.peek_next() {
            Some(next) => decoder.decode_fec(next).ok(),
            None => decoder.decode_lost().ok(),
        },
    }
}

#[test]
fn survives_loss_and_reordering() {
    let mut encoder = Encoder::new().unwrap();
    let mut phase = 0.0f32;

    const FRAMES: usize = 300;
    // One delivery slot per 20ms tick; None = the packet was lost in transit
    let mut schedule: Vec<Option<(u32, Vec<u8>)>> = (0..FRAMES as u32)
        .map(|seq| Some((seq, encoder.encode(&tone_frame(&mut phase)).unwrap())))
        .collect();

    // Impair the channel: drop every 10th packet (10% loss), swap every
    // 7th adjacent pair (reordering).
    for slot in schedule.iter_mut().skip(9).step_by(10) {
        *slot = None;
    }
    for i in (0..schedule.len() - 1).step_by(7) {
        schedule.swap(i, i + 1);
    }

    // One tick = deliver the slot (if anything arrives) + pop one frame,
    // then drain the tail.
    let mut jitter = JitterBuffer::new(2);
    let mut decoder = Decoder::new().unwrap();
    let mut decoded_frames = 0usize;
    let mut decoded_samples = 0usize;
    for slot in schedule {
        if let Some((seq, data)) = slot {
            jitter.push(seq, data);
        }
        if let Some(pcm) = mixer_pop(&mut jitter, &mut decoder) {
            decoded_frames += 1;
            decoded_samples += pcm.len();
        }
    }
    while let Some(pcm) = mixer_pop(&mut jitter, &mut decoder) {
        decoded_frames += 1;
        decoded_samples += pcm.len();
    }

    // Every lost packet is concealed (FEC or PLC), so the output should be
    // one frame per original sequence slot, minus at most the initial jitter
    // target, re-buffering pauses after loss-induced underruns, and losses
    // at the very tail.
    assert!(
        decoded_frames >= FRAMES - 15,
        "decoded {decoded_frames} of {FRAMES} frames"
    );
    assert_eq!(decoded_samples, decoded_frames * OPUS_FRAME_SIZE);
}

#[test]
fn burst_stall_recovers_with_rebuffer() {
    let mut encoder = Encoder::new().unwrap();
    let mut phase = 0.0f32;
    let mut jitter = JitterBuffer::new(2);
    let mut decoder = Decoder::new().unwrap();

    // Normal flow for 50 frames
    for seq in 0..50u32 {
        jitter.push(seq, encoder.encode(&tone_frame(&mut phase)).unwrap());
        mixer_pop(&mut jitter, &mut decoder);
    }
    // Network stall: 10 ticks with no arrivals — the buffer drains its last
    // frame, underruns, and re-enters buffering
    for _ in 0..10 {
        mixer_pop(&mut jitter, &mut decoder);
    }
    assert!(jitter.is_empty());
    // The delayed burst arrives at once; playback resumes in order
    for seq in 50..60u32 {
        jitter.push(seq, encoder.encode(&tone_frame(&mut phase)).unwrap());
    }
    let mut resumed = 0;
    while mixer_pop(&mut jitter, &mut decoder).is_some() {
        resumed += 1;
    }
    assert!(resumed >= 8, "only {resumed} frames after stall");
}
