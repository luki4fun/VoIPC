//! What a connect is told before its join that seldom changes (Round C, W2-16): the groups'
//! styles, the server's profile, the removal marks. Each is read once and kept, encoded, for
//! `KEPT_FOR` or until a change made here drops it; the connects that come meanwhile take
//! that copy. A restart's crowd costs one read of each, not one per connect. A change made
//! elsewhere (the server's shell) reaches those who connect within `KEPT_FOR`.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const KEPT_FOR: Duration = Duration::from_secs(10);

/// Frames ready to send.
pub type Frames = Arc<Vec<Vec<u8>>>;

/// One of them.
#[derive(Default)]
pub struct Kept {
    /// Moved by each change: an answer read across one is not kept.
    changes: AtomicU64,
    held: tokio::sync::Mutex<Option<(u64, Instant, Frames)>>,
}

impl Kept {
    /// What it says changed (call after the write is in): the next connect reads again.
    pub fn changed(&self) {
        self.changes.fetch_add(1, Ordering::SeqCst);
    }

    /// The frames, read by `read` when none are kept or they are old. One read at a time:
    /// the connects behind it wait for that one and take its copy. None: the read failed,
    /// and nothing is kept.
    pub async fn frames<F, Fut>(&self, read: F) -> Option<Frames>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<Vec<Vec<u8>>>>,
    {
        let mut held = self.held.lock().await;
        let now = self.changes.load(Ordering::SeqCst);
        if let Some((seen, at, frames)) = held.as_ref() {
            if *seen == now && at.elapsed() < KEPT_FOR {
                return Some(frames.clone());
            }
        }
        let frames: Frames = Arc::new(read().await?);
        *held = (self.changes.load(Ordering::SeqCst) == now)
            .then(|| (now, Instant::now(), frames.clone()));
        Some(frames)
    }
}

#[derive(Default)]
pub struct AtConnect {
    pub styles: Kept,
    pub profile: Kept,
    pub marks: Kept,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn one_read_serves_a_crowd_and_a_change_reads_again() {
        let kept = Arc::new(Kept::default());
        let reads = Arc::new(AtomicUsize::new(0));
        let read = |reads: Arc<AtomicUsize>, say: u8| async move {
            reads.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some(vec![vec![say]])
        };
        let mut crowd = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let (kept, reads) = (kept.clone(), reads.clone());
            crowd.spawn(async move { kept.frames(|| read(reads, 1)).await });
        }
        while let Some(f) = crowd.join_next().await {
            assert_eq!(*f.unwrap().unwrap(), [vec![1]]);
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1, "one read for fifty");
        kept.changed();
        let f = kept.frames(|| read(reads.clone(), 2)).await.unwrap();
        assert_eq!(*f, [vec![2]]);
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_answer_read_across_a_change_is_not_kept() {
        let kept = Arc::new(Kept::default());
        let during = {
            let kept = kept.clone();
            kept.clone()
                .frames(|| async move {
                    // The write lands while this reads what was there before it
                    kept.changed();
                    Some(vec![vec![1]])
                })
                .await
                .unwrap()
        };
        assert_eq!(*during, [vec![1]], "that connect still gets what was read");
        let after = kept.frames(|| async { Some(vec![vec![2]]) }).await.unwrap();
        assert_eq!(*after, [vec![2]], "the next one reads again");
        // A failed read keeps nothing
        kept.changed();
        assert!(kept.frames(|| async { None }).await.is_none());
        let again = kept.frames(|| async { Some(vec![vec![3]]) }).await.unwrap();
        assert_eq!(*again, [vec![3]]);
    }
}
