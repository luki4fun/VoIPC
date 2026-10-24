//! The browser's Opus decoder, run inside the mixer's AudioWorklet (H3-05).
//!
//! WebCodecs decodes on arrival: a reordered packet reaches the decoder out of
//! order, and a lost one plays as silence — it has no FEC or PLC to ask for.
//! Here the worklet keeps the packets in its jitter buffer and decodes each at
//! the moment it plays, in order; a lost one is rebuilt from the next packet's
//! in-band FEC, or concealed, exactly as `network.rs` does on the desktop.
//!
//! A raw C ABI rather than wasm-bindgen: an AudioWorklet has no glue to run,
//! and the module stays small. One [`Slot`] per voice: the worklet writes a
//! packet at [`opus_input`], calls [`opus_decode`], and reads the samples at
//! [`opus_output`].

use rusty_opus::OpusDecoder;

/// One 20 ms frame at 48 kHz, the only frame size VoIPC sends.
pub const FRAME: usize = 960;
/// The largest packet taken: one Opus frame is at most 1275 bytes, and a
/// longer packet is refused as malformed rather than cut.
pub const MAX_PACKET: usize = 1275;

/// One voice's decoder and the buffers the worklet reads and writes.
pub struct Slot {
    decoder: OpusDecoder,
    input: [u8; MAX_PACKET],
    output: [f32; FRAME],
}

/// What [`opus_decode`] does with the packet in the input buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Decode it.
    Packet,
    /// It is the packet *after* a lost one: rebuild the lost frame from its
    /// in-band FEC (concealment when it carries none).
    Fec,
    /// Nothing arrived and nothing follows: conceal.
    Conceal,
}

/// Decode into `out`; the number of samples written, or `None` when the
/// packet is refused. Never more than [`FRAME`].
pub fn decode(decoder: &mut OpusDecoder, packet: &[u8], mode: Mode, out: &mut [f32; FRAME]) -> Option<usize> {
    if packet.len() > MAX_PACKET {
        return None;
    }
    let n = match mode {
        Mode::Packet if !packet.is_empty() => decoder.decode(packet, FRAME, out),
        Mode::Fec if !packet.is_empty() => decoder.decode_fec(packet, FRAME, out),
        _ => decoder.decode(&[], FRAME, out),
    }
    .ok()?;
    (n <= FRAME).then_some(n)
}

/// A new voice, or null if the decoder could not be made.
#[no_mangle]
pub extern "C" fn opus_new() -> *mut Slot {
    match OpusDecoder::new(48_000, 1) {
        Ok(decoder) => Box::into_raw(Box::new(Slot {
            decoder,
            input: [0; MAX_PACKET],
            output: [0.0; FRAME],
        })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Forget a voice.
///
/// # Safety
/// `slot` came from [`opus_new`] and is not used again.
#[no_mangle]
pub unsafe extern "C" fn opus_free(slot: *mut Slot) {
    if !slot.is_null() {
        drop(Box::from_raw(slot));
    }
}

/// Where the worklet writes a packet ([`MAX_PACKET`] bytes).
///
/// # Safety
/// `slot` came from [`opus_new`].
#[no_mangle]
pub unsafe extern "C" fn opus_input(slot: *mut Slot) -> *mut u8 {
    (*slot).input.as_mut_ptr()
}

/// Where the decoded samples are ([`FRAME`] f32s).
///
/// # Safety
/// `slot` came from [`opus_new`].
#[no_mangle]
pub unsafe extern "C" fn opus_output(slot: *mut Slot) -> *const f32 {
    (*slot).output.as_ptr()
}

/// Decode the `len` bytes at [`opus_input`]: `mode` 0 a packet, 1 FEC from
/// the next packet, 2 concealment. The samples written, or -1 when the packet
/// is refused (the output is then left as it was).
///
/// # Safety
/// `slot` came from [`opus_new`].
#[no_mangle]
pub unsafe extern "C" fn opus_decode(slot: *mut Slot, len: usize, mode: u32) -> i32 {
    let slot = &mut *slot;
    let mode = match mode {
        0 => Mode::Packet,
        1 => Mode::Fec,
        _ => Mode::Conceal,
    };
    let len = len.min(MAX_PACKET);
    match decode(&mut slot.decoder, &slot.input[..len], mode, &mut slot.output) {
        Some(n) => n as i32,
        None => -1,
    }
}

/// The fuzz target (fuzz/fuzz_targets/opus_decode.rs), and its replay on
/// stable: arbitrary bytes, cut into packets, through every mode on one
/// decoder, as a hostile peer would feed it.
#[cfg(any(test, fuzzing))]
pub fn fuzz_decode(data: &[u8]) {
    let mut decoder = OpusDecoder::new(48_000, 1).expect("48 kHz mono");
    let mut out = [0.0f32; FRAME];
    let mut rest = data;
    // Each record: a mode byte, a little-endian u16 length, the packet
    while let [mode, lo, hi, tail @ ..] = rest {
        let mode = match mode & 3 {
            0 | 3 => Mode::Packet,
            1 => Mode::Fec,
            _ => Mode::Conceal,
        };
        let len = (u16::from_le_bytes([*lo, *hi]) as usize).min(tail.len());
        let (packet, after) = tail.split_at(len);
        if let Some(n) = decode(&mut decoder, packet, mode, &mut out) {
            assert!(n <= FRAME);
            assert!(out[..n].iter().all(|s| s.is_finite()), "a decoded sample is not finite");
        }
        rest = after;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusty_opus::{Application, OpusEncoder};

    fn packets(n: usize) -> Vec<Vec<u8>> {
        let mut enc = OpusEncoder::new(48_000, 1, Application::Voip).unwrap();
        (0..n)
            .map(|k| {
                let pcm: Vec<f32> = (0..FRAME)
                    .map(|i| 0.3 * ((k * FRAME + i) as f32 * 2.0 * std::f32::consts::PI * 300.0 / 48_000.0).sin())
                    .collect();
                let mut out = vec![0u8; MAX_PACKET];
                let len = enc.encode(&pcm, FRAME, &mut out).unwrap();
                out.truncate(len);
                out
            })
            .collect()
    }

    #[test]
    fn packets_fec_and_concealment_all_come_out_as_one_frame() {
        let pk = packets(20);
        let slot = opus_new();
        assert!(!slot.is_null());
        let mut energy = 0.0f32;
        for (k, p) in pk.iter().enumerate() {
            let mode = match k {
                7 => 2,  // conceal
                12 => 1, // FEC from the packet after
                _ => 0,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(p.as_ptr(), opus_input(slot), p.len());
                assert_eq!(opus_decode(slot, p.len(), mode), FRAME as i32, "frame {k}");
                let out = std::slice::from_raw_parts(opus_output(slot), FRAME);
                energy += out.iter().map(|s| s * s).sum::<f32>();
            }
        }
        assert!(energy > 1.0, "decoded silence");
        unsafe { opus_free(slot) };
    }

    #[test]
    fn a_garbage_packet_is_refused_not_a_panic() {
        let slot = opus_new();
        unsafe {
            for b in [0x00u8, 0xff, 0x7c, 0x03] {
                std::ptr::write_bytes(opus_input(slot), b, MAX_PACKET);
                let n = opus_decode(slot, MAX_PACKET, 0);
                assert!(n == -1 || (0..=FRAME as i32).contains(&n));
            }
            // An oversized length is cut to the buffer, never read past it
            assert!(opus_decode(slot, usize::MAX, 0) <= FRAME as i32);
            opus_free(slot);
        }
    }

    #[test]
    fn the_fuzz_target_runs_on_stable() {
        fuzz_decode(&[0, 1, 2, 3, 255, 0xfc, 0x80, 0x41]);
        let records: Vec<u8> = packets(3)
            .iter()
            .enumerate()
            .flat_map(|(i, p)| {
                let len = (p.len() as u16).to_le_bytes();
                [vec![i as u8, len[0], len[1]], p.clone()].concat()
            })
            .collect();
        fuzz_decode(&records);
        // and every input the nightly fuzz run kept (fuzz/README.md)
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions/opus_decode");
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            fuzz_decode(&std::fs::read(file.path()).unwrap());
        }
    }
}
