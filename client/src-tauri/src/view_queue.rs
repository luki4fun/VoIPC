//! A watched share's frames for a WebView that decodes them itself (1.13): put together,
//! decrypted and size-checked here, pulled by the WebView over a URI scheme of the app's own,
//! decoded there with WebCodecs. Tauri's IPC carries no binary on Android (events are JSON in
//! an eval, a raw response a number array), so a scheme is the one way in for bytes.
//!
//! The WebView says once which codecs it decodes (`set_view_decoder`). Each watch of one of
//! them takes this path from its first frame, under a generation its pulls name; any other
//! watch, or one the WebView gave up on (`view_fallback`), goes to the native decoder.
//! One share is watched at a time, so one queue serves.

use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::http::{header, Request, Response, StatusCode};
use tokio::sync::Notify;
use voipc_protocol::types::VideoCodec;

/// The scheme: `voipcframe://localhost/next` on Linux and macOS, `http://voipcframe.localhost/next`
/// on Android and Windows (`convertFileSrc` picks).
pub const SCHEME: &str = "voipcframe";
/// Frames held for a WebView that has not pulled: past it the oldest goes.
const MOST_QUEUED: usize = 8;
/// How long a pull with nothing to take waits for a frame before 204.
const PULL_WAIT: Duration = Duration::from_millis(250);

/// A keyframe.
pub const KEY: u8 = 1;
/// A frame went missing just before this one: the decoder's chain is broken.
pub const GAP: u8 = 2;
/// `[u32 len][u8 flags][u32 seq][u64 assembled_ms]`, little-endian, then `len` bytes.
pub const HEADER: usize = 17;

struct Frame {
    flags: u8,
    seq: u32,
    assembled_ms: u64,
    data: Vec<u8>,
}

/// What `push` did with a frame.
#[derive(Debug, PartialEq)]
pub enum Pushed {
    Queued,
    /// A keyframe whose picture is past the caps (`frame_size`): dropped.
    TooLarge,
    /// Not watched through the WebView: the frame back, for the native decoder.
    Native(Vec<u8>),
}

#[derive(Default)]
struct Queue {
    /// The watch the queue belongs to; 0 while frames go to the native decoder.
    gen: u64,
    last_gen: u64,
    codec: Option<VideoCodec>,
    frames: VecDeque<Frame>,
    /// The next frame queued follows one that went missing.
    gap: bool,
    seq: u32,
    /// The WebView's last pull asked for a keyframe.
    want_key: bool,
    /// Codecs the WebView decodes, a bit per `VideoCodec as u8`.
    codecs: u8,
}

impl Queue {
    fn watch(&mut self, codec: VideoCodec) -> Option<u64> {
        self.frames.clear();
        self.gap = false;
        self.want_key = false;
        if self.codecs & (1 << codec as u8) == 0 {
            self.gen = 0;
            return None;
        }
        self.last_gen += 1;
        self.gen = self.last_gen;
        self.codec = Some(codec);
        Some(self.gen)
    }

    fn native(&mut self) {
        self.gen = 0;
        self.frames.clear();
        self.want_key = false;
    }

    fn push(&mut self, data: Vec<u8>, key: bool, gap: bool, assembled_ms: u64) -> Pushed {
        let Some(codec) = self.codec.filter(|_| self.gen != 0) else {
            return Pushed::Native(data);
        };
        if key && !voipc_video::frame_size::keyframe_fits(codec, &data) {
            self.gap = true;
            return Pushed::TooLarge;
        }
        if self.frames.len() >= MOST_QUEUED {
            self.frames.pop_front();
            if let Some(next) = self.frames.front_mut() {
                next.flags |= GAP;
            } else {
                self.gap = true;
            }
        }
        let flags = if key { KEY } else { 0 } | if gap || self.gap { GAP } else { 0 };
        self.gap = false;
        self.seq = self.seq.wrapping_add(1);
        self.frames.push_back(Frame {
            flags,
            seq: self.seq,
            assembled_ms,
            data,
        });
        Pushed::Queued
    }

    /// Everything queued for watch `gen`, as one body; Err for a watch that is over.
    fn take(&mut self, gen: u64) -> Result<Option<Vec<u8>>, ()> {
        if gen == 0 || gen != self.gen {
            return Err(());
        }
        if self.frames.is_empty() {
            return Ok(None);
        }
        let len = self.frames.iter().map(|f| HEADER + f.data.len()).sum();
        let mut body = Vec::with_capacity(len);
        for f in self.frames.drain(..) {
            body.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
            body.push(f.flags);
            body.extend_from_slice(&f.seq.to_le_bytes());
            body.extend_from_slice(&f.assembled_ms.to_le_bytes());
            body.extend_from_slice(&f.data);
        }
        Ok(Some(body))
    }
}

static QUEUE: LazyLock<Mutex<Queue>> = LazyLock::new(Default::default);
static ARRIVED: LazyLock<Notify> = LazyLock::new(Notify::new);

fn queue() -> std::sync::MutexGuard<'static, Queue> {
    QUEUE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The codecs the WebView decodes, by `VideoCodec` name; unknown names are left out.
pub fn set_codecs(names: &[String]) {
    let mut bits = 0u8;
    for name in names {
        let c = match name.as_str() {
            "H264" => VideoCodec::H264,
            "H265" => VideoCodec::H265,
            "Vp8" => VideoCodec::Vp8,
            "Vp9" => VideoCodec::Vp9,
            _ => continue,
        };
        bits |= 1 << c as u8;
    }
    queue().codecs = bits;
}

/// A watch of `codec` starts: the generation its pulls name when the WebView decodes it.
pub fn watch(codec: VideoCodec) -> Option<u64> {
    queue().watch(codec)
}

/// The watch ended, or the WebView gave up on it: frames go to the native decoder.
pub fn native() {
    queue().native();
}

/// Whether frames go to the WebView now.
pub fn active() -> bool {
    queue().gen != 0
}

/// Whether the WebView waits for a keyframe (the receiver asks the sharer for one).
pub fn wants_key() -> bool {
    let q = queue();
    q.gen != 0 && q.want_key
}

/// A frame put together: queued for the WebView, or handed back for the native decoder.
pub fn push(data: Vec<u8>, key: bool, gap: bool) -> Pushed {
    let assembled_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let pushed = queue().push(data, key, gap, assembled_ms);
    if pushed == Pushed::Queued {
        ARRIVED.notify_one();
    }
    pushed
}

fn reply(status: StatusCode, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        // The page is http://tauri.localhost or tauri://localhost: another origin
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(body)
        .unwrap_or_default()
}

/// `GET /next?gen=<watch>&key=0|1`: every frame queued for that watch in one body, or, after
/// a short wait for one, 204. 410 for a watch that is over: the WebView stops pulling.
pub async fn serve(request: Request<Vec<u8>>) -> Response<Vec<u8>> {
    if request.uri().path() != "/next" {
        return reply(StatusCode::NOT_FOUND, Vec::new());
    }
    let (mut gen, mut key) = (0u64, false);
    for pair in request.uri().query().unwrap_or("").split('&') {
        match pair.split_once('=') {
            Some(("gen", v)) => gen = v.parse().unwrap_or(0),
            Some(("key", v)) => key = v == "1",
            _ => {}
        }
    }
    {
        let mut q = queue();
        if q.gen == gen && gen != 0 {
            q.want_key = key;
        }
    }
    let deadline = Instant::now() + PULL_WAIT;
    loop {
        match queue().take(gen) {
            Err(()) => return reply(StatusCode::GONE, Vec::new()),
            Ok(Some(body)) => return reply(StatusCode::OK, body),
            Ok(None) => {}
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return reply(StatusCode::NO_CONTENT, Vec::new());
        }
        let _ = tokio::time::timeout(left, ARRIVED.notified()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watching(codecs: &[VideoCodec]) -> (Queue, u64) {
        let mut q = Queue::default();
        for c in codecs {
            q.codecs |= 1 << *c as u8;
        }
        let gen = q.watch(codecs[0]).unwrap();
        (q, gen)
    }

    /// The body as (flags, seq, assembled_ms, data) per frame.
    fn frames(body: &[u8]) -> Vec<(u8, u32, u64, Vec<u8>)> {
        let mut out = Vec::new();
        let mut p = 0;
        while p < body.len() {
            let len = u32::from_le_bytes(body[p..p + 4].try_into().unwrap()) as usize;
            let seq = u32::from_le_bytes(body[p + 5..p + 9].try_into().unwrap());
            let at = u64::from_le_bytes(body[p + 9..p + 17].try_into().unwrap());
            out.push((
                body[p + 4],
                seq,
                at,
                body[p + HEADER..p + HEADER + len].to_vec(),
            ));
            p += HEADER + len;
        }
        out
    }

    #[test]
    fn a_codec_the_webview_does_not_decode_stays_native() {
        let mut q = Queue {
            codecs: 1 << VideoCodec::Vp9 as u8,
            ..Default::default()
        };
        assert_eq!(q.watch(VideoCodec::H264), None);
        assert_eq!(q.push(vec![1], false, false, 0), Pushed::Native(vec![1]));
        assert!(q.take(0).is_err());
        assert!(q.watch(VideoCodec::Vp9).is_some());
    }

    #[test]
    fn a_pull_takes_everything_queued_in_order() {
        let (mut q, gen) = watching(&[VideoCodec::Vp8]);
        assert_eq!(q.take(gen), Ok(None));
        assert_eq!(q.push(vec![1, 2], false, false, 7), Pushed::Queued);
        assert_eq!(q.push(vec![3], false, true, 8), Pushed::Queued);
        let got = frames(&q.take(gen).unwrap().unwrap());
        assert_eq!(got, vec![(0, 1, 7, vec![1, 2]), (GAP, 2, 8, vec![3])]);
        assert_eq!(q.take(gen), Ok(None), "taken once");
    }

    #[test]
    fn an_overflow_drops_the_oldest_and_marks_the_gap() {
        let (mut q, gen) = watching(&[VideoCodec::Vp8]);
        for i in 0..MOST_QUEUED as u8 + 2 {
            q.push(vec![i], false, false, 0);
        }
        let got = frames(&q.take(gen).unwrap().unwrap());
        assert_eq!(got.len(), MOST_QUEUED);
        assert_eq!(got[0].3, vec![2], "the two oldest went");
        assert_eq!(got[0].0, GAP, "and the first left says so");
        assert!(got[1..].iter().all(|f| f.0 == 0));
    }

    #[test]
    fn a_keyframe_past_the_caps_never_reaches_the_webview() {
        let (mut q, gen) = watching(&[VideoCodec::Vp8]);
        // A VP8 keyframe claiming 4096x2304
        let huge = vec![
            0x50, 0x2f, 0x02, 0x9d, 0x01, 0x2a, 0x00, 0x10, 0x00, 0x09, 0, 0,
        ];
        assert_eq!(q.push(huge, true, false, 0), Pushed::TooLarge);
        let ok = vec![
            0x50, 0x2f, 0x02, 0x9d, 0x01, 0x2a, 0x56, 0x05, 0x00, 0x03, 0, 0,
        ];
        assert_eq!(q.push(ok.clone(), true, false, 0), Pushed::Queued);
        assert_eq!(
            frames(&q.take(gen).unwrap().unwrap()),
            vec![(KEY | GAP, 1, 0, ok)]
        );
    }

    #[test]
    fn a_pull_of_an_earlier_watch_is_over() {
        let (mut q, gen) = watching(&[VideoCodec::Vp8]);
        q.push(vec![1], false, false, 0);
        let next = q.watch(VideoCodec::Vp8).unwrap();
        assert_ne!(next, gen);
        assert!(q.take(gen).is_err(), "the old watch");
        assert_eq!(q.take(next), Ok(None), "its frames went with it");
        q.native();
        assert!(q.take(next).is_err());
        assert_eq!(q.push(vec![1], false, false, 0), Pushed::Native(vec![1]));
    }
}
