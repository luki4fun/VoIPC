//! Fuzz targets: what a peer's packets and a game mod's socket put in front of
//! this crate. `fuzz/fuzz_targets/<name>.rs` calls `fuzz_<name>` under
//! cargo-fuzz; the test below replays `fuzz/regressions/<name>/*` on stable,
//! so an input that once crashed stays a test.

use crate::decoder::Decoder;
use crate::game::{self, GameMessage};
use crate::jitter::JitterBuffer;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A sender's sequence numbers in any order, wrapping included: records of
/// (op, sequence) that push, pop or peek. The buffer stays within its cap,
/// and draining it ends.
pub fn fuzz_jitter(data: &[u8]) {
    let Some((&delay, ops)) = data.split_first() else {
        return;
    };
    let mut jb = JitterBuffer::new(delay as usize % 10);
    for record in ops.as_chunks::<5>().0 {
        let seq = u32::from_be_bytes([record[1], record[2], record[3], record[4]]);
        match record[0] % 4 {
            0 | 1 => jb.push(seq, vec![record[0]]),
            2 => drop(jb.pop()),
            _ => {
                let _ = jb.peek_next();
                let _ = jb.take_surplus();
            }
        }
        assert!(jb.len() <= 32, "the jitter buffer outgrew its cap");
    }
    let mut pops = 0;
    while jb.pop().is_some() {
        pops += 1;
        assert!(pops < 10_000, "pop never runs dry");
    }
}

/// Peer Opus packets through the native decoder, as records of (mode, u16
/// length, packet): decode, FEC from the next packet, or concealment. An
/// error, never a panic, and never more than 120 ms of audio.
pub fn fuzz_opus(data: &[u8]) {
    let mut decoder = Decoder::new().expect("an Opus decoder");
    let mut rest = data;
    while let [mode, lo, hi, tail @ ..] = rest {
        let len = (u16::from_le_bytes([*lo, *hi]) as usize).min(tail.len());
        let (packet, after) = tail.split_at(len);
        let out = match mode % 3 {
            0 => decoder.decode(packet),
            1 => decoder.decode_fec(packet),
            _ => decoder.decode_lost(),
        };
        if let Ok(pcm) = out {
            assert!(pcm.len() <= 48_000 / 1000 * 120 * 2);
        }
        rest = after;
    }
}

/// What a game mod (any local process, or a web page if the origin check
/// fails) sends: SDK frames, JSON messages and an update's players, the
/// browser Origin, a name, and a MumbleLink block.
pub fn fuzz_game(data: &[u8]) {
    let mut buf = data;
    while let Ok(Some((_, used))) = game::parse_frame(buf) {
        assert!(used > 0 && used <= buf.len());
        buf = &buf[used..];
    }
    if let Some(link) = game::parse_link(data) {
        assert!(link.pos.iter().chain(&link.fwd).all(|c| c.is_finite()));
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // H4-01: nothing but FiveM's exact shape and the default hosts gets in
    if game::origin_allowed(text, &[]) {
        let o = text.trim();
        assert!(
            o.starts_with(game::FIVEM_ORIGIN_PREFIX)
                || game::DEFAULT_ORIGIN_HOSTS
                    .iter()
                    .any(|h| o == *h || o.starts_with(&format!("{h}:"))),
            "origin {o:?} was allowed"
        );
    }
    let name = game::short_name(text, "fallback");
    assert!(!name.is_empty() && name.chars().count() <= game::MAX_NAME);
    if let Ok(GameMessage::Update(update)) = serde_json::from_str::<GameMessage>(text) {
        let Ok(placed) = game::sources_from(
            update.players,
            &HashMap::new(),
            Duration::from_millis(50),
            Instant::now(),
        ) else {
            return;
        };
        assert!(placed.layers.values().all(|l| l.len() <= game::MAX_LAYERS));
        for s in placed
            .sources
            .values()
            .chain(placed.layers.values().flatten())
        {
            assert!(s.pos.iter().all(|c| c.is_finite()));
            assert!(
                s.range >= 0.01 && (0.0..=2.0).contains(&s.volume) && (-1.0..=1.0).contains(&s.pan)
            );
            assert!(u32::from(s.delay_frames) <= game::MAX_DELAY_MS / game::FRAME_MS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edge inputs, a valid one, and every file in fuzz/regressions/<target>/.
    fn replay(target: &str, valid: &[u8], f: fn(&[u8])) {
        for input in [&[][..], &[0xff; 64], &[0; 64], valid] {
            f(input);
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/regressions")
            .join(target);
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            f(&std::fs::read(file.path()).unwrap());
        }
    }

    #[test]
    fn the_fuzz_targets_replay_on_stable() {
        // push 1, 3, 2, a wrapped 0xffffffff, then pops
        let jitter = [
            2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff,
            0xff,
        ];
        replay("jitter", &jitter, fuzz_jitter);
        replay("opus", &[0, 3, 0, 0xfc, 0xff, 0xfe, 2, 0, 0], fuzz_opus);
        let update = br#"{"type":"update","players":[{"id":1,"pos":[1,2,3],"range":1e30,"volume":9,"pan":-7,"delay":99999,"layers":[{},{},{},{}]}]}"#;
        replay("game", update, fuzz_game);
    }
}
