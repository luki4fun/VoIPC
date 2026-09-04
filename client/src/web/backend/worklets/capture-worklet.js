// Capture worklet: accumulates the (gain-adjusted) microphone signal into
// 960-sample mono frames (20 ms at 48 kHz, the Opus frame size) and posts each
// frame with its RMS level in dBFS to the main thread, which runs the VAD and
// the Opus encoder. Input gain is applied by a GainNode upstream; samples are
// clamped here like the native capture path (crates/voipc-audio/src/capture.rs).

const FRAME = 960;

class CaptureProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.buf = new Float32Array(FRAME);
    this.pos = 0;
  }

  process(inputs) {
    const input = inputs[0];
    if (!input || input.length === 0) return true;
    const ch = input[0];
    for (let i = 0; i < ch.length; i++) {
      const s = ch[i];
      this.buf[this.pos++] = s > 1 ? 1 : s < -1 ? -1 : s;
      if (this.pos === FRAME) this.flush();
    }
    // Output stays silent; the node is only connected so the graph pulls it.
    return true;
  }

  flush() {
    let sumSq = 0;
    for (let i = 0; i < FRAME; i++) sumSq += this.buf[i] * this.buf[i];
    const rms = Math.sqrt(sumSq / FRAME);
    const levelDb = rms > 0 ? Math.max(-96, 20 * Math.log10(rms)) : -96;
    const pcm = this.buf;
    this.buf = new Float32Array(FRAME);
    this.pos = 0;
    this.port.postMessage({ pcm, levelDb }, [pcm.buffer]);
  }
}

registerProcessor("voipc-capture", CaptureProcessor);
