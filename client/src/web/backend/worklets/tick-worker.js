// Frame clock for the browser screen sharer (share.ts).
//
// Why a worker: a sharer's VoIPC tab is in the background almost by definition
// — they are showing another window. Hidden documents skip the rendering update,
// so requestVideoFrameCallback and requestAnimationFrame stop, and page timers
// are clamped to about one tick per second (Chromium goes to one per minute
// after five minutes hidden). Worker timers are not throttled that way, so the
// share keeps its frame rate while the tab sits in the background.
//
// Only the Firefox path uses this: Chromium reads the capture track directly
// through MediaStreamTrackProcessor, which is not throttled either.
//
// Protocol: postMessage({ type: "start", intervalMs }) begins ticking,
// { type: "stop" } ends it. Each tick is an empty message — the main thread
// paces itself against its own clock.

let timer = null;

self.onmessage = (e) => {
  const msg = e.data;
  if (!msg) return;
  if (msg.type === "start") {
    if (timer !== null) clearInterval(timer);
    const interval = Math.max(1, Math.round(msg.intervalMs));
    timer = setInterval(() => self.postMessage(0), interval);
  } else if (msg.type === "stop") {
    if (timer !== null) clearInterval(timer);
    timer = null;
  }
};
