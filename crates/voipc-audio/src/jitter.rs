use std::collections::BTreeMap;

/// Frame ready to be decoded from the jitter buffer.
pub enum JitterFrame {
    /// Opus data available for this sequence number.
    Ready(Vec<u8>),
    /// Packet was lost — caller should use `decoder.decode_lost()` for PLC.
    Lost,
}

/// Per-user jitter buffer that reorders packets and detects losses.
///
/// Buffers incoming Opus packets (keyed by sequence number) and delivers
/// them in order. Introduces a small fixed delay (`target_delay` frames)
/// to absorb network jitter. Missing packets are reported as [`JitterFrame::Lost`]
/// so the caller can invoke Opus packet loss concealment.
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
}

impl JitterBuffer {
    /// Create a new jitter buffer.
    ///
    /// `target_delay` is the number of 20ms frames to buffer before playback
    /// begins (e.g. 3 = 60ms). A higher value absorbs more jitter but adds latency.
    pub fn new(target_delay: usize) -> Self {
        Self {
            buffer: BTreeMap::new(),
            next_seq: None,
            target_delay,
            buffering: true,
            max_buffer: target_delay * 4,
        }
    }

    /// Enqueue an incoming Opus packet.
    pub fn push(&mut self, sequence: u32, opus_data: Vec<u8>) {
        // During buffering phase, accept all packets (out-of-order included)
        if !self.buffering {
            if let Some(next) = self.next_seq {
                // Discard packets we've already played past
                if sequence < next && next.wrapping_sub(sequence) < 1000 {
                    return;
                }
            }
        }

        self.buffer.insert(sequence, opus_data);

        // Prevent unbounded growth
        while self.buffer.len() > self.max_buffer {
            self.buffer.pop_first();
        }
    }

    /// Try to pop the next frame for decoding.
    ///
    /// Returns `Some(JitterFrame::Ready(data))` if the next expected packet is available,
    /// `Some(JitterFrame::Lost)` if the packet is missing but we have later packets
    /// (caller should use PLC), or `None` if still buffering / no data available.
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
            self.next_seq = Some(next.wrapping_add(1));
            Some(JitterFrame::Ready(data))
        } else if !self.buffer.is_empty() {
            // We have later packets but not the one we need — it's lost
            self.next_seq = Some(next.wrapping_add(1));
            Some(JitterFrame::Lost)
        } else {
            // Buffer empty — underrun, wait for more data.
            // Don't re-enter buffering mid-stream; just resume immediately
            // when the next packet arrives.
            None
        }
    }

    /// Reset the buffer state (e.g. on EndOfTransmission).
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_seq = None;
        self.buffering = true;
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
        assert!(jb.pop().is_none()); // empty
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
}
