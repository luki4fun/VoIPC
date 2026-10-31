// Whether this system draws a joined emoji (❤️‍🔥 is ❤️ + ZWJ + 🔥) as one.
//
// A single emoji the system lacks is drawn by app.css's "VoIPC Emoji". A
// joined one is not: the system's font has both halves, so the browser keeps
// it and draws them side by side (Windows 10 shows ❤🔥). Those are left out
// of the picker and the `:` list rather than offered broken. Measured once per
// sequence: as wide as one emoji is one emoji.

const ZWJ = "‍";
const known = new Map<string, boolean>();
let ctx: CanvasRenderingContext2D | null | undefined;

export function drawsAsOne(emoji: string): boolean {
  if (!emoji.includes(ZWJ)) return true;
  const seen = known.get(emoji);
  if (seen !== undefined) return seen;
  if (ctx === undefined) {
    ctx = typeof document === "undefined" ? null : document.createElement("canvas").getContext("2d");
    if (ctx) ctx.font = `32px ${getComputedStyle(document.body).fontFamily}`;
  }
  // No canvas to ask (a test, a worker): offered, as before
  if (!ctx) return true;
  const one = ctx.measureText("😀").width;
  const ok = one > 0 && ctx.measureText(emoji).width < one * 1.5;
  known.set(emoji, ok);
  return ok;
}
