// What a loaded file is, from its own first bytes: the only thing that
// decides how it is shown. The type a message claims (`file.mime`) is the
// sender's word, good for a card and nothing more. A picture is drawn, a
// video or a sound gets its controls (it never starts by itself), and
// anything else (SVG, HTML, PDF, scripts, archives, HEIC) is only saved.
//
// Pure, so file-sniff.test.ts runs it under Node's own test runner.

/** How a file may be shown, and the type its object URL is made with. */
export interface Shown {
  kind: "image" | "video" | "audio";
  mime: string;
}

function bytesAt(b: Uint8Array, i: number, sig: readonly number[]): boolean {
  return b.length >= i + sig.length && sig.every((x, k) => b[i + k] === x);
}

function textAt(b: Uint8Array, i: number, s: string): boolean {
  return bytesAt(b, i, Array.from(s, (c) => c.charCodeAt(0)));
}

const image = (mime: string): Shown => ({ kind: "image", mime });
const video = (mime: string): Shown => ({ kind: "video", mime });
const audio = (mime: string): Shown => ({ kind: "audio", mime });

/** ISO media (`ftyp`) brands that are still pictures no web view draws (HEIC). */
const HEIF = new Set(["heic", "heix", "hevc", "hevx", "heim", "heis", "hevm", "hevs", "mif1", "mif2", "msf1", "avci", "avcs"]);
/** ISO media brands a video player takes: anything else under `ftyp` (camera
 *  raw, say) is only saved. */
const VIDEO = new Set(["isom", "iso2", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1", "dash", "mmp4", "M4V ", "M4VP", "MSNV", "3gp4", "3gp5", "3gp6", "3g2a"]);

/** How `b` may be shown, or null: then it is only ever saved. */
export function sniff(b: Uint8Array): Shown | null {
  if (bytesAt(b, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return image("image/png");
  if (bytesAt(b, 0, [0xff, 0xd8, 0xff])) return image("image/jpeg");
  if (textAt(b, 0, "GIF87a") || textAt(b, 0, "GIF89a")) return image("image/gif");
  if (textAt(b, 0, "RIFF") && textAt(b, 8, "WEBP")) return image("image/webp");
  if (textAt(b, 0, "RIFF") && textAt(b, 8, "WAVE")) return audio("audio/wav");
  if (textAt(b, 4, "ftyp") && b.length >= 12) {
    const brand = String.fromCharCode(...b.subarray(8, 12));
    if (brand === "avif" || brand === "avis") return image("image/avif");
    if (HEIF.has(brand)) return null;
    if (brand.startsWith("M4A") || brand === "M4B ") return audio("audio/mp4");
    if (brand === "qt  ") return video("video/quicktime");
    return VIDEO.has(brand) ? video("video/mp4") : null;
  }
  if (bytesAt(b, 0, [0x1a, 0x45, 0xdf, 0xa3])) return video("video/webm");
  if (textAt(b, 0, "OggS")) return audio("audio/ogg");
  if (textAt(b, 0, "fLaC")) return audio("audio/flac");
  if (textAt(b, 0, "ID3")) return audio("audio/mpeg");
  // A bare MPEG audio frame: 11 sync bits. Layer 0 is AAC in ADTS. FF FE is
  // a text file's byte-order mark (UTF-16), not a frame
  if (b.length >= 2 && b[0] === 0xff && (b[1] & 0xe0) === 0xe0 && b[1] !== 0xfe) {
    return audio((b[1] & 0x06) === 0 ? "audio/aac" : "audio/mpeg");
  }
  return null;
}

/** A HEIF/HEIC picture: a photo no web view draws, so it cannot be cleaned
 *  of its location and camera data here. */
export function isHeif(b: Uint8Array): boolean {
  return textAt(b, 4, "ftyp") && b.length >= 12 && HEIF.has(String.fromCharCode(...b.subarray(8, 12)));
}

/** Whether a picture moves: every GIF counts (it goes as it is anyway), a
 *  WebP with its animation flag, a PNG with an `acTL` chunk (APNG). */
export function isAnimated(b: Uint8Array): boolean {
  const shown = sniff(b);
  if (shown?.mime === "image/gif") return true;
  if (shown?.mime === "image/webp") return textAt(b, 12, "VP8X") && b.length > 20 && (b[20] & 0x02) !== 0;
  if (shown?.mime === "image/png") {
    // Chunks after the signature: length (4) ‖ type (4) ‖ data ‖ CRC (4)
    for (let i = 8; i + 8 <= b.length; ) {
      const len = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
      if (textAt(b, i + 4, "acTL")) return true;
      if (textAt(b, i + 4, "IDAT")) return false;
      i += 12 + len;
    }
  }
  return false;
}
