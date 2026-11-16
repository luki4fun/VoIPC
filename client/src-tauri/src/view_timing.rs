//! What watching a share costs, stage by stage (1.13): one `share view:` line every 10 s
//! while frames come in, nothing otherwise. The WebView's side, the frames it drew and how
//! long each took from emit to paint, comes in through `report_view_timing` and joins the
//! same line. One share is watched at a time, so one tally serves.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::info;

const WINDOW: Duration = Duration::from_secs(10);

/// Samples kept a window: past 90 fps for 10 s, so a flood cannot grow it.
const MOST_SAMPLES: usize = 1024;

/// Durations in microseconds, for their percentiles.
#[derive(Default)]
pub(crate) struct Tally(Vec<u32>);

impl Tally {
    const fn new() -> Self {
        Tally(Vec::new())
    }

    pub(crate) fn add(&mut self, d: Duration) {
        if self.0.len() < MOST_SAMPLES {
            self.0.push(d.as_micros().min(u32::MAX as u128) as u32);
        }
    }

    /// The nearest-rank p50, p95 and the max, in ms; None when empty.
    pub(crate) fn summary(&mut self) -> Option<[f64; 3]> {
        let n = self.0.len();
        if n == 0 {
            return None;
        }
        self.0.sort_unstable();
        let rank = |q: f64| self.0[((q * n as f64).ceil() as usize).clamp(1, n) - 1];
        let ms = |us: u32| us as f64 / 1000.0;
        Some([ms(rank(0.5)), ms(rank(0.95)), ms(self.0[n - 1])])
    }
}

/// The WebView's last couple of seconds: frames that reached it, frames it drew, sequence
/// numbers that never reached it, and each drawn frame's emit-to-paint time in ms.
#[derive(Debug, serde::Deserialize)]
pub struct ViewReport {
    pub span_ms: u32,
    pub arrived: u32,
    pub drawn: u32,
    pub missing: u32,
    pub paint_ms: Vec<f64>,
    /// `(width << 16) | height` of what a WebView that decodes the share itself drew; 0 else.
    #[serde(default)]
    pub resolution: u32,
}

struct Window {
    start: Option<Instant>,
    assembled: u32,
    decoded: u32,
    rendered: u32,
    assemble: Tally,
    decode: Tally,
    copy: Tally,
    convert: Tally,
    jpeg: Tally,
    emit: Tally,
    view_span: Duration,
    arrived: u32,
    drawn: u32,
    missing: u32,
    paint: Tally,
}

impl Window {
    const fn new() -> Self {
        Window {
            start: None,
            assembled: 0,
            decoded: 0,
            rendered: 0,
            assemble: Tally::new(),
            decode: Tally::new(),
            copy: Tally::new(),
            convert: Tally::new(),
            jpeg: Tally::new(),
            emit: Tally::new(),
            view_span: Duration::ZERO,
            arrived: 0,
            drawn: 0,
            missing: 0,
            paint: Tally::new(),
        }
    }

    /// The line, after `secs` of it.
    fn line(&mut self, secs: f64) -> String {
        let mut s = format!(
            "share view: {secs:.1} s, assembled {} decoded {} rendered {}",
            self.assembled, self.decoded, self.rendered
        );
        for (name, t) in [
            ("assemble", &mut self.assemble),
            ("decode", &mut self.decode),
            ("copy", &mut self.copy),
            ("convert", &mut self.convert),
            ("jpeg", &mut self.jpeg),
            ("emit", &mut self.emit),
        ] {
            if let Some([p50, p95, max]) = t.summary() {
                s += &format!(", {name} {p50:.1}/{p95:.1}/{max:.1}");
            }
        }
        s += " ms (p50/p95/max)";
        if !self.view_span.is_zero() {
            let per_sec = |n: u32| n as f64 / self.view_span.as_secs_f64();
            s += &format!(
                "; webview arrived {:.1} drawn {:.1} fps, missing {}",
                per_sec(self.arrived),
                per_sec(self.drawn),
                self.missing
            );
            if let Some([p50, p95, max]) = self.paint.summary() {
                s += &format!(", emit to paint {p50:.0}/{p95:.0}/{max:.0} ms");
            }
        }
        s
    }
}

static TIMING: Mutex<Window> = Mutex::new(Window::new());
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A frame stage's numbers go in; a window that is over is logged and starts again. Only a
/// frame starts one: a WebView's report alone does not.
fn record(starts: bool, f: impl FnOnce(&mut Window)) {
    let now = Instant::now();
    let mut w = TIMING.lock().unwrap_or_else(PoisonError::into_inner);
    match w.start {
        None if !starts => return,
        None => w.start = Some(now),
        Some(_) => {}
    }
    f(&mut w);
    let since = now.saturating_duration_since(w.start.unwrap_or(now));
    if since >= WINDOW {
        info!("{}", w.line(since.as_secs_f64()));
        *w = Window::new();
    }
}

/// A frame came whole, `took` after its first fragment.
pub(crate) fn assembled(took: Duration) {
    record(true, |w| {
        w.assembled += 1;
        w.assemble.add(took);
    });
}

/// A frame went through the decoder; on Android, `copy` of it was copying its picture out.
pub(crate) fn decoded(took: Duration, copy: Option<Duration>) {
    record(true, |w| {
        w.decoded += 1;
        w.decode.add(took);
        if let Some(c) = copy {
            w.copy.add(c);
        }
    });
}

/// A frame shown: colour conversion, JPEG, and the base64 and event that carry it.
pub(crate) fn rendered(convert: Duration, jpeg: Duration, emit: Duration) {
    record(true, |w| {
        w.rendered += 1;
        w.convert.add(convert);
        w.jpeg.add(jpeg);
        w.emit.add(emit);
    });
}

pub(crate) fn view(r: ViewReport) {
    record(false, |w| {
        w.view_span += Duration::from_millis(r.span_ms.into());
        w.arrived += r.arrived;
        w.drawn += r.drawn;
        w.missing += r.missing;
        for ms in r
            .paint_ms
            .into_iter()
            .filter(|ms| ms.is_finite() && *ms >= 0.0)
        {
            w.paint
                .add(Duration::from_secs_f64(ms.min(60_000.0) / 1000.0));
        }
    });
}

/// The number and wall-clock time (ms) a shown frame's event carries, for the WebView's
/// gaps and its emit-to-paint time (the same device's clock at both ends).
pub(crate) fn stamp() -> (u64, u64) {
    let at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    (SEQ.fetch_add(1, Ordering::Relaxed), at_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(ms: &[u64]) -> Tally {
        let mut t = Tally::default();
        for &m in ms {
            t.add(Duration::from_millis(m));
        }
        t
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        assert_eq!(Tally::default().summary(), None);
        assert_eq!(tally(&[7]).summary(), Some([7.0, 7.0, 7.0]));
        // 1..=20 shuffled: p50 is the 10th, p95 the 19th
        let mut ms: Vec<u64> = (1..=20).collect();
        ms.reverse();
        ms.swap(3, 11);
        assert_eq!(tally(&ms).summary(), Some([10.0, 19.0, 20.0]));
        // One slow frame of a hundred shows in the max, not the p95
        let mut ms = vec![5; 99];
        ms.push(400);
        assert_eq!(tally(&ms).summary(), Some([5.0, 5.0, 400.0]));
    }

    #[test]
    fn a_window_keeps_at_most_its_cap() {
        let mut t = Tally::default();
        for _ in 0..MOST_SAMPLES + 50 {
            t.add(Duration::from_millis(1));
        }
        assert_eq!(t.0.len(), MOST_SAMPLES);
    }

    #[test]
    fn the_line_names_each_stage_and_the_webview() {
        let mut w = Window::new();
        w.assembled = 300;
        w.decoded = 300;
        w.rendered = 150;
        w.decode.add(Duration::from_millis(4));
        w.view_span = Duration::from_secs(10);
        w.arrived = 150;
        w.drawn = 140;
        w.paint.add(Duration::from_millis(30));
        let line = w.line(10.0);
        assert!(line.starts_with("share view: 10.0 s, assembled 300 decoded 300 rendered 150"));
        assert!(line.contains("decode 4.0/4.0/4.0"), "{line}");
        assert!(
            !line.contains("jpeg"),
            "a stage with no samples is left out: {line}"
        );
        assert!(
            line.contains("arrived 15.0 drawn 14.0 fps, missing 0, emit to paint 30/30/30 ms"),
            "{line}"
        );
    }
}
