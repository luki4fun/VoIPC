use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Frame ready to be decoded from the jitter buffer.
pub enum JitterFrame {
    /// Opus data available for this sequence number.
    Ready(Vec<u8>),
    /// Packet was lost — caller should use FEC from the next packet
    /// (see [`JitterBuffer::peek_next`]) or `decoder.decode_lost()` for PLC.
    Lost,
}

/// Largest sequence gap bridged with PLC frames; beyond this we resync
/// to the buffered data instead (guards against a sender counter jump
/// producing billions of PLC frames).
const MAX_PLC_RUN: u32 = 50;
/// Consecutive late-discarded packets before assuming the sender restarted
/// its sequence counter (e.g. lost EndOfTransmission) and resyncing.
const MAX_LATE_DISCARDS: u32 = 25;
/// Frames of concealment played while waiting for a packet that has not
/// arrived yet. A network hiccup shorter than this is stretched over rather
/// than cut: the stream keeps playing, the late packet is still played when
/// it lands, and the cushion is permanently deeper by the size of the hiccup.
/// Beyond it the pause is treated as the speaker having stopped.
const MAX_STALL_PLC: u8 = 3;
const MIN_TARGET_DELAY: usize = 2;
const MAX_TARGET_DELAY: usize = 8;
const MAX_BUFFER_CAP: usize = 32;
/// Trouble-free time before the adaptive delay decays one step.
const DECAY_QUIET: Duration = Duration::from_secs(10);
/// Minimum time between adaptive-delay growth steps.
const GROW_COOLDOWN: Duration = Duration::from_secs(1);
/// Frames above the target a stream may hold standing before one is shed.
/// Bursty senders and device-clocked pulls swing the depth by a frame or
/// two on their own; only a surplus beyond that is latency nobody asked for.
const SHED_MARGIN: usize = 2;
/// Consecutive pops (50 = 1 s) the surplus must stand before a frame is shed,
/// and so the most that is ever shed: one frame a second.
const SHED_AFTER: u8 = 50;

/// Per-user jitter buffer that reorders packets and detects losses.
///
/// Buffers incoming Opus packets (keyed by sequence number) and delivers
/// them in order. Introduces a small adaptive delay (`target_delay` frames)
/// to absorb network jitter: it grows when packets arrive too late to play
/// and decays after a quiet period. Missing packets are reported as
/// [`JitterFrame::Lost`] so the caller can invoke FEC or packet loss
/// concealment.
pub struct JitterBuffer {
    /// Buffered packets: sequence number → opus data.
    buffer: BTreeMap<u32, Vec<u8>>,
    /// Next sequence number we expect to emit.
    next_seq: Option<u32>,
    /// How many frames to accumulate before starting playback.
    target_delay: usize,
    /// True while accumulating the initial burst of packets.
    buffering: bool,
    /// Maximum number of frames to buffer before force-draining.
    max_buffer: usize,
    /// Consecutive packets discarded as late (sender-restart detection).
    late_discards: u32,
    /// Last time the adaptive delay changed or lateness was observed.
    last_change: Option<Instant>,
    /// Consecutive concealment frames played while the buffer sat empty.
    plc_run: u8,
    /// Fewest frames still waiting whenever a packet arrived during playback
    /// this phrase: whether the cushion ever had to be spent down to nothing.
    min_depth: Option<usize>,
    /// Consecutive pops that left more than `SHED_MARGIN` frames above target.
    deep_pops: u8,
}

impl JitterBuffer {
    /// Create a new jitter buffer.
    ///
    /// `target_delay` is the number of 20ms frames to buffer before playback
    /// begins (e.g. 3 = 60ms). A higher value absorbs more jitter but adds
    /// latency; it adapts upward under observed lateness (up to 160ms).
    pub fn new(target_delay: usize) -> Self {
        // `max_buffer` comes from it, and 0 there evicts every packet on arrival
        let target_delay = target_delay.clamp(1, MAX_TARGET_DELAY);
        Self {
            buffer: BTreeMap::new(),
            next_seq: None,
            target_delay,
            buffering: true,
            max_buffer: (target_delay * 4).min(MAX_BUFFER_CAP),
            late_discards: 0,
            last_change: None,
            plc_run: 0,
            min_depth: None,
            deep_pops: 0,
        }
    }

    /// A packet arrived too late to play: grow the delay (rate-limited).
    fn note_trouble(&mut self) {
        match self.last_change {
            Some(t) if t.elapsed() < GROW_COOLDOWN => {}
            _ => self.target_delay = (self.target_delay + 1).min(MAX_TARGET_DELAY),
        }
        self.last_change = Some(Instant::now());
        self.max_buffer = (self.target_delay * 4).min(MAX_BUFFER_CAP);
    }

    /// On (re-)entering buffering: shrink the delay after a quiet period, but
    /// only if the phrase just played never needed all of it. Bursty senders
    /// and device-clocked receivers run a 2-frame cushion dry early in most
    /// phrases; decaying anyway would drop the 3rd frame every other phrase
    /// only for lateness to grow it straight back.
    fn maybe_decay(&mut self) {
        let spare = self.min_depth.take().is_some_and(|d| d >= 1);
        if spare
            && self.target_delay > MIN_TARGET_DELAY
            && self.last_change.is_none_or(|t| t.elapsed() >= DECAY_QUIET)
        {
            self.target_delay -= 1;
            self.last_change = Some(Instant::now());
            self.max_buffer = (self.target_delay * 4).min(MAX_BUFFER_CAP);
        }
    }

    /// Enqueue an incoming Opus packet.
    pub fn push(&mut self, sequence: u32, opus_data: Vec<u8>) {
        if let Some(next) = self.next_seq {
            // Discard packets we've already played past (wraparound-safe)
            let distance = next.wrapping_sub(sequence);
            if distance > 0 && distance < 1000 {
                self.late_discards += 1;
                if self.late_discards >= MAX_LATE_DISCARDS {
                    // Sustained lateness = sender restarted its counter
                    // (e.g. its EndOfTransmission was lost). Resync.
                    self.late_discards = 0;
                    self.next_seq = None;
                    self.buffering = true;
                } else {
                    if distance <= MAX_PLC_RUN {
                        // Genuinely late recent packet: buffer was too shallow.
                        self.note_trouble();
                    }
                    return;
                }
            } else {
                self.late_discards = 0;
            }
        }

        // Measured at arrival, not after pops: every phrase's tail drains to
        // zero, so only what was left when the next packet landed shows
        // whether the cushion had a frame to spare.
        if !self.buffering {
            let depth = self.buffer.len();
            self.min_depth = Some(self.min_depth.map_or(depth, |d| d.min(depth)));
        }
        self.buffer.insert(sequence, opus_data);

        // Prevent unbounded growth; fast-forward past dropped frames so the
        // backlog is skipped instead of played as a run of PLC frames.
        while self.buffer.len() > self.max_buffer {
            self.buffer.pop_first();
            self.next_seq = self.buffer.keys().next().copied();
        }
    }

    /// Try to pop the next frame for decoding.
    ///
    /// Returns `Some(JitterFrame::Ready(data))` if the next expected packet is available,
    /// `Some(JitterFrame::Lost)` if the packet is missing but we have later packets
    /// (caller should use FEC/PLC), or `None` if still buffering / no data available.
    pub fn pop(&mut self) -> Option<JitterFrame> {
        if self.buffering {
            if self.buffer.len() >= self.target_delay {
                self.buffering = false;
                // Start from the smallest sequence in the buffer
                if let Some(&first_seq) = self.buffer.keys().next() {
                    self.next_seq = Some(first_seq);
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }

        let next = self.next_seq?;

        if let Some(data) = self.buffer.remove(&next) {
            if self.plc_run > 0 {
                // It arrived, just late: the cushion was too shallow for this
                // link, so the next burst starts one frame deeper.
                self.note_trouble();
                self.plc_run = 0;
            }
            self.next_seq = Some(next.wrapping_add(1));
            self.deep_pops = if self.buffer.len() > self.target_delay + SHED_MARGIN {
                self.deep_pops.saturating_add(1)
            } else {
                0
            };
            Some(JitterFrame::Ready(data))
        } else if !self.buffer.is_empty() {
            self.plc_run = 0;
            let smallest = *self.buffer.keys().next().expect("buffer not empty");
            let gap = smallest.wrapping_sub(next);
            if gap > MAX_PLC_RUN {
                // Discontinuity too large to conceal (e.g. sender counter
                // jump): skip straight to the buffered data, marking it
                // with a single PLC frame.
                self.next_seq = Some(smallest);
                return Some(JitterFrame::Lost);
            }
            // We have later packets but not the one we need — it's lost
            self.next_seq = Some(next.wrapping_add(1));
            Some(JitterFrame::Lost)
        } else if self.plc_run < MAX_STALL_PLC {
            // The packet is not here *yet*. Conceal this frame and keep
            // next_seq where it is, so a hiccup shorter than MAX_STALL_PLC is
            // stretched over instead of played as a hole with hard edges —
            // and the late packet is still played when it lands.
            self.plc_run += 1;
            Some(JitterFrame::Lost)
        } else {
            // Long enough that the speaker has stopped, not stalled. Re-arm
            // buffering so playback resumes with a full jitter cushion instead
            // of repeated micro-drops; next_seq is kept so stale stragglers
            // are still discarded. This is the end of a phrase just like an
            // end-of-transmission, and streams that never send one (screen
            // audio, always-on voice, browser VAD) only ever end here, so
            // the delay decays here too or it stays at its peak for good.
            self.plc_run = 0;
            self.buffering = true;
            self.maybe_decay();
            None
        }
    }

    /// Opus data for the packet after a [`JitterFrame::Lost`], if buffered.
    /// That packet carries in-band FEC for the lost frame.
    pub fn peek_next(&self) -> Option<&[u8]> {
        self.buffer.get(&self.next_seq?).map(|v| v.as_slice())
    }

    /// Reset the buffer state (e.g. on EndOfTransmission).
    /// The learned adaptive delay is kept across talk bursts.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_seq = None;
        self.buffering = true;
        self.late_discards = 0;
        self.plc_run = 0;
        self.deep_pops = 0;
        self.maybe_decay();
    }

    /// Whether a standing surplus asks the caller to play one frame fewer;
    /// true at most once per `SHED_AFTER` pops. A continuous stream never
    /// reaches `reset`, so latency added by a burst or a bridged stall would
    /// otherwise stay for good. The caller pops the extra frame itself: it
    /// has the decoded audio to pick the quieter of the two to drop.
    pub fn take_surplus(&mut self) -> bool {
        let due = self.deep_pops >= SHED_AFTER;
        if due {
            self.deep_pops = 0;
        }
        due
    }

    /// Number of packets currently buffered.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pretend the quiet/cooldown windows have fully elapsed.
    fn force_quiet(jb: &mut JitterBuffer) {
        jb.last_change = None;
    }

    #[test]
    fn in_order_delivery() {
        let mut jb = JitterBuffer::new(2);

        jb.push(0, vec![10]);
        assert!(jb.pop().is_none()); // len=1 < target=2

        jb.push(1, vec![11]);
        // len=2 >= target=2, buffering ends, next_seq starts at 0
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![10]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![11]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
        // Empty: the stall is concealed before playback gives up
        for _ in 0..MAX_STALL_PLC {
            assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        }
        assert!(jb.pop().is_none());
    }

    #[test]
    fn detects_packet_loss() {
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(2, vec![12]); // seq 1 is missing

        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![10]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
        // seq 1 is missing, but seq 2 exists → Lost
        match jb.pop().unwrap() {
            JitterFrame::Lost => {} // correct
            JitterFrame::Ready(_) => panic!("expected Lost"),
        }
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![12]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
    }

    #[test]
    fn discards_late_packets() {
        let mut jb = JitterBuffer::new(1);
        jb.push(5, vec![50]);

        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![50]),
            JitterFrame::Lost => panic!("expected Ready"),
        }

        // Push a packet older than next_seq (6) — should be discarded
        jb.push(3, vec![30]);
        // The buffer is empty, so the next pops conceal the stall and only
        // then fall through to rebuffering
        for _ in 0..MAX_STALL_PLC {
            assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        }
        assert!(jb.pop().is_none());
    }

    #[test]
    fn reset_clears_state() {
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(1, vec![11]);
        jb.reset();

        assert!(jb.is_empty());
        assert!(jb.pop().is_none());

        // Should work again after reset
        jb.push(100, vec![100]);
        jb.push(101, vec![101]);
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![100]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
    }

    #[test]
    fn out_of_order_reordering() {
        let mut jb = JitterBuffer::new(3);
        // Packets arrive out of order
        jb.push(2, vec![12]);
        jb.push(0, vec![10]);
        jb.push(1, vec![11]);

        // Should deliver in order: 0, 1, 2
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![10]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![11]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![12]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
    }

    #[test]
    fn underrun_rebuffers_then_resumes() {
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(1, vec![11]);
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        // The stall is concealed first, then the buffer re-arms
        for _ in 0..MAX_STALL_PLC {
            assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        }
        assert!(jb.pop().is_none()); // underrun → re-enters buffering

        // One packet is not enough to leave buffering again
        jb.push(2, vec![12]);
        assert!(jb.pop().is_none());

        // Second packet completes the cushion; playback resumes in order
        jb.push(3, vec![13]);
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![12]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
    }

    #[test]
    fn overflow_fast_forwards_without_plc_run() {
        let mut jb = JitterBuffer::new(2); // max_buffer = 8
        for seq in 0..10u32 {
            jb.push(seq, vec![seq as u8]);
        }
        // Oldest two were dropped; playback starts at the fast-forwarded seq
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![2]),
            JitterFrame::Lost => panic!("expected Ready after fast-forward"),
        }
        // Rest drains with no Lost frames
        for seq in 3..10u32 {
            match jb.pop().unwrap() {
                JitterFrame::Ready(d) => assert_eq!(d, vec![seq as u8]),
                JitterFrame::Lost => panic!("unexpected Lost at seq {seq}"),
            }
        }
    }

    #[test]
    fn giant_gap_resyncs_quickly() {
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(1, vec![11]);
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));

        // Sender jumps far ahead (or wrapped backwards): resync in ≤2 pops
        jb.push(5000, vec![50]);
        jb.push(5001, vec![51]);
        assert!(matches!(jb.pop(), Some(JitterFrame::Lost))); // marks the gap
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![50]),
            JitterFrame::Lost => panic!("expected Ready after resync"),
        }
    }

    #[test]
    fn sustained_late_discards_resync() {
        let mut jb = JitterBuffer::new(2);
        jb.push(100, vec![1]);
        jb.push(101, vec![2]);
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));

        // Sender restarted at 0 (lost EOT): everything looks "late" at first,
        // but sustained discards trigger a resync.
        for seq in 0..MAX_LATE_DISCARDS {
            jb.push(seq, vec![seq as u8]);
        }
        jb.push(MAX_LATE_DISCARDS, vec![MAX_LATE_DISCARDS as u8]);
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![(MAX_LATE_DISCARDS - 1) as u8]),
            JitterFrame::Lost => panic!("expected Ready after resync"),
        }
    }

    #[test]
    fn peek_next_after_lost_returns_fec_source() {
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(2, vec![12]); // seq 1 missing
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        // The packet after the loss carries FEC for it
        assert_eq!(jb.peek_next(), Some(&[12u8][..]));
    }

    #[test]
    fn a_short_stall_is_bridged_and_the_late_packet_still_plays() {
        // The hole this closes: one delayed packet used to end the burst, so
        // playback stopped dead and restarted 40ms later with a hard edge.
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(1, vec![11]);
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        let delay_before = jb.target_delay;

        // Two ticks with nothing there: concealed, and still expecting seq 2
        assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        assert_eq!(jb.next_seq, Some(2), "the late packet was given up on");

        // It lands late and is played, not skipped
        force_quiet(&mut jb);
        jb.push(2, vec![12]);
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![12]),
            JitterFrame::Lost => panic!("the late packet was dropped"),
        }
        assert_eq!(
            jb.target_delay,
            delay_before + 1,
            "a bridged stall must deepen the cushion"
        );
    }

    #[test]
    fn a_stall_that_runs_out_rebuffers_without_growing() {
        // A speaker who simply stopped is not a network problem: conceal the
        // tail, then go quiet, and leave the cushion where it was.
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![10]);
        jb.push(1, vec![11]);
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        let delay_before = jb.target_delay;

        for _ in 0..MAX_STALL_PLC {
            assert!(matches!(jb.pop(), Some(JitterFrame::Lost)));
        }
        assert!(jb.pop().is_none(), "the concealment never ends");
        assert!(jb.pop().is_none(), "and stays ended");
        assert_eq!(jb.target_delay, delay_before, "a pause is not lateness");

        // Speaking again resumes normally
        force_quiet(&mut jb);
        jb.push(2, vec![12]);
        jb.push(3, vec![13]);
        match jb.pop().unwrap() {
            JitterFrame::Ready(d) => assert_eq!(d, vec![12]),
            JitterFrame::Lost => panic!("expected Ready"),
        }
    }

    #[test]
    fn adaptive_delay_grows_capped_and_decays() {
        let mut jb = JitterBuffer::new(2);
        for _ in 0..2 * MAX_TARGET_DELAY {
            force_quiet(&mut jb);
            jb.note_trouble();
        }
        assert_eq!(jb.target_delay, MAX_TARGET_DELAY);
        assert_eq!(jb.max_buffer, MAX_BUFFER_CAP);

        // Decays one step per buffering entry once quiet, down to the floor
        for expected in (MIN_TARGET_DELAY..MAX_TARGET_DELAY).rev() {
            force_quiet(&mut jb);
            jb.min_depth = Some(1);
            jb.reset();
            assert_eq!(jb.target_delay, expected);
        }
        force_quiet(&mut jb);
        jb.min_depth = Some(1);
        jb.reset();
        assert_eq!(jb.target_delay, MIN_TARGET_DELAY); // floor holds
    }

    #[test]
    fn only_a_phrase_with_a_frame_to_spare_decays() {
        let mut jb = JitterBuffer::new(3);
        for seq in 0..3 {
            jb.push(seq, vec![seq as u8]);
        }
        for _ in 0..3 {
            assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        }
        jb.push(3, vec![3]); // lands on an empty buffer: the cushion ran dry
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        force_quiet(&mut jb);
        jb.reset();
        assert_eq!(jb.target_delay, 3, "a phrase that used it all keeps it");

        for seq in 10..13 {
            jb.push(seq, vec![seq as u8]);
        }
        assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        jb.push(13, vec![13]); // two still waiting
        for _ in 0..3 {
            assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
        }
        force_quiet(&mut jb);
        jb.reset();
        assert_eq!(jb.target_delay, 2, "a phrase with a frame to spare decays");
    }

    #[test]
    fn a_standing_surplus_is_shed_a_frame_a_second() {
        let mut jb = JitterBuffer::new(2);
        for seq in 0..7 {
            jb.push(seq, vec![seq as u8]);
        }
        for seq in 7..7 + SHED_AFTER as u32 {
            assert!(!jb.take_surplus());
            assert!(matches!(jb.pop(), Some(JitterFrame::Ready(_))));
            jb.push(seq, vec![seq as u8]);
        }
        assert!(jb.take_surplus());
        assert!(!jb.take_surplus(), "once per second, not every pop");
    }
}
