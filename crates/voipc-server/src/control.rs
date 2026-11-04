//! A connection's control messages on their way to its writer task.
//!
//! Bounded by bytes, not by messages. A join is told to everybody, so a server's
//! worth of people joining at once (after a restart, say) is that many small
//! messages for every connection within a moment. A limit of 256 messages dropped
//! the rest without a word, and a member missing from a roster never gets anybody's
//! keys. Memory is what the limit is for, and 16 MiB is what 256 of the largest
//! frame came to.
//!
//! Past that a client is not reading, and its connection ends. It does not lose
//! messages quietly: it could not tell what it missed from what never happened,
//! while a reconnect gives it the whole state again.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Notify};
use tracing::warn;
use voipc_protocol::codec::MAX_MSG_SIZE;

/// What one connection may have waiting for its writer.
pub const MAX_QUEUED_BYTES: usize = 256 * MAX_MSG_SIZE as usize;

/// Why a message was not queued.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlError {
    /// Over `MAX_QUEUED_BYTES`: the connection has been told to end.
    Overflow,
    /// The connection is over, or not started yet.
    Closed,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ControlError::Overflow => {
                "control queue full (client not reading): ending its connection"
            }
            ControlError::Closed => "control queue closed",
        })
    }
}

impl std::error::Error for ControlError {}

/// The sending half, one clone per place that talks to the connection.
#[derive(Clone)]
pub struct ControlTx {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    /// The connection's own close handle (`UserSession::close`).
    close: Arc<Notify>,
    /// Told once: a client past its budget stays past it until its connection ends.
    overflowed: Arc<AtomicBool>,
}

/// The writer task's half.
pub struct ControlRx {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

/// A queue for the connection that `close` ends.
pub fn control_queue(close: Arc<Notify>) -> (ControlTx, ControlRx) {
    let (tx, rx) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    (
        ControlTx {
            tx,
            queued: queued.clone(),
            close,
            overflowed: Arc::default(),
        },
        ControlRx { rx, queued },
    )
}

impl ControlTx {
    /// What a session holds until its connection's writer task is up: anything
    /// sent to it goes nowhere, and the first roster the writer sends has it all.
    pub fn placeholder() -> ControlTx {
        control_queue(Arc::default()).0
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Never waits: callers hold shard guards of the session map.
    pub fn try_send(&self, data: Vec<u8>) -> Result<(), ControlError> {
        let len = data.len();
        if self.queued.fetch_add(len, Ordering::Relaxed) + len > MAX_QUEUED_BYTES {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            if !self.overflowed.swap(true, Ordering::Relaxed) {
                warn!("a client stopped reading its control messages: ending its connection");
                self.close.notify_one();
            }
            return Err(ControlError::Overflow);
        }
        self.tx.send(data).map_err(|_| {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            ControlError::Closed
        })
    }
}

impl ControlRx {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let data = self.rx.recv().await?;
        self.queued.fetch_sub(data.len(), Ordering::Relaxed);
        Some(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn small_messages_wait_their_turn_however_many_there_are() {
        let (tx, mut rx) = control_queue(Arc::default());
        for i in 0..100_000u32 {
            tx.try_send(i.to_le_bytes().to_vec()).unwrap();
        }
        for i in 0..100_000u32 {
            assert_eq!(
                rx.recv().await.unwrap(),
                i.to_le_bytes(),
                "in order, none lost"
            );
        }
        assert_eq!(tx.queued.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn past_the_budget_the_connection_is_told_to_end_and_nothing_queued_is_lost() {
        let close = Arc::new(Notify::new());
        let (tx, mut rx) = control_queue(close.clone());
        let frame = vec![0u8; MAX_MSG_SIZE as usize];
        for _ in 0..256 {
            tx.try_send(frame.clone()).unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close.notified())
                .await
                .is_err(),
            "exactly the budget is within it"
        );
        assert_eq!(tx.try_send(vec![0]), Err(ControlError::Overflow));
        tokio::time::timeout(Duration::from_secs(1), close.notified())
            .await
            .expect("told to end");
        for _ in 0..256 {
            assert_eq!(rx.recv().await.unwrap().len(), frame.len());
        }
        assert_eq!(
            tx.queued.load(Ordering::Relaxed),
            0,
            "a refused message is not counted"
        );
    }

    #[tokio::test]
    async fn what_was_read_makes_room_again() {
        let (tx, mut rx) = control_queue(Arc::default());
        let frame = vec![0u8; MAX_MSG_SIZE as usize];
        for _ in 0..256 {
            tx.try_send(frame.clone()).unwrap();
        }
        rx.recv().await.unwrap();
        tx.try_send(frame).unwrap();
    }

    #[test]
    fn a_queue_nobody_reads_says_closed_and_counts_nothing() {
        let tx = ControlTx::placeholder();
        assert_eq!(tx.try_send(vec![0; 10]), Err(ControlError::Closed));
        assert_eq!(tx.queued.load(Ordering::Relaxed), 0);
    }
}
