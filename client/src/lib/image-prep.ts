// Getting a file ready to send, in the page (both clients run it): a photo
// made smaller and clean of its location and camera data, the 16×16 preview
// its message carries, a picture's or a video's size and length.
//
// Only the sender's own file is decoded here. A receiver decodes nothing
// before a click: the preview is drawn from its raw pixels (FileCard).

import { isAnimated, isHeif, sniff } from "./file-sniff";
import { PHOTO_MAX_SIDE, PREVIEW_SIDE, fitWithin, previewOf, withExtension } from "./file-rules";
import { cleanFileName } from "./chat-rules";

/** A file ready to seal, and what its message says about it. */
export interface Prepared {
  bytes: Uint8Array;
  name: string;
  mime?: string;
  w?: number;
  h?: number;
  dur?: number;
  px?: string;
  /** Deflate before sealing: not for what is compressed already. */
  compress: boolean;
}

/** A photo that cannot be decoded here (HEIC, mostly): it can only go as it
 *  is, location and camera data included, so the person is asked first. */
export class CannotClean extends Error {
  constructor() {
    super("This photo cannot be made smaller here");
  }
}

/** Still photos, the ones the compressed / original choice is for. */
const STILL = new Set(["image/png", "image/jpeg", "image/webp", "image/avif"]);
/** voipc_crypto::file::MAX_FILE_PLAIN */
const MAX_FILE_PLAIN = 64 * 1024 * 1024;

/** Whether `head` (a file's first bytes) is a photo the choice applies to. */
export function isPhoto(head: Uint8Array, claimed = ""): boolean {
  const shown = sniff(head);
  return (shown !== null && STILL.has(shown.mime) && !isAnimated(head)) || isHeif(head) || /^image\/hei[cf]/i.test(claimed);
}

/** The 16×16 preview of what `source` shows. */
function previewFrom(source: CanvasImageSource): string | undefined {
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = PREVIEW_SIDE;
  const ctx = canvas.getContext("2d");
  if (!ctx) return undefined;
  ctx.drawImage(source, 0, 0, PREVIEW_SIDE, PREVIEW_SIDE);
  return previewOf(ctx.getImageData(0, 0, PREVIEW_SIDE, PREVIEW_SIDE).data);
}

function toBlob(canvas: HTMLCanvasElement, type: string, quality?: number): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob(resolve, type, quality));
}

/** A still picture redrawn at most `PHOTO_MAX_SIDE` on its long side: WebP
 *  (JPEG where the page cannot write WebP), or PNG for a PNG, losslessly.
 *  Redrawn, it keeps none of the original's metadata. */
async function recode(bitmap: ImageBitmap, png: boolean): Promise<{ blob: Blob; w: number; h: number }> {
  const { w, h } = fitWithin(bitmap.width, bitmap.height, PHOTO_MAX_SIDE);
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new CannotClean();
  ctx.drawImage(bitmap, 0, 0, w, h);
  let blob = png ? await toBlob(canvas, "image/png") : await toBlob(canvas, "image/webp", 0.85);
  // A page that cannot write WebP hands back a PNG instead
  if (!png && blob?.type !== "image/webp") blob = await toBlob(canvas, "image/jpeg", 0.85);
  if (!blob) throw new CannotClean();
  return { blob, w, h };
}

/** A video's or a sound's size and length, and a video's preview from the
 *  frame at 0.1 s, where the page can play it; nothing where it cannot. */
function mediaMeta(bytes: Uint8Array, kind: "video" | "audio", mime: string): Promise<Partial<Prepared>> {
  const url = URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type: mime }));
  const el = document.createElement(kind);
  el.muted = true;
  el.preload = "metadata";
  return new Promise<Partial<Prepared>>((resolve) => {
    const meta: Partial<Prepared> = {};
    const done = () => {
      clearTimeout(timer);
      el.removeAttribute("src");
      el.load();
      URL.revokeObjectURL(url);
      resolve(meta);
    };
    const timer = setTimeout(done, 3000);
    el.onerror = done;
    el.onloadedmetadata = () => {
      if (Number.isFinite(el.duration)) meta.dur = Math.round(el.duration);
      if (el instanceof HTMLVideoElement && el.videoWidth > 0) {
        meta.w = el.videoWidth;
        meta.h = el.videoHeight;
        el.onseeked = () => {
          meta.px = previewFrom(el);
          done();
        };
        el.currentTime = Math.min(0.1, el.duration || 0.1);
      } else {
        done();
      }
    };
    el.src = url;
  });
}

/**
 * `file` as it is to be sent. A still photo is sent compressed unless
 * `original`: smaller, and without its location and camera data. GIFs and
 * other moving pictures, videos and sounds go as they are; any other file is
 * deflated while sealing where that helps.
 */
/** The picture turned as its EXIF says. `"from-image"` is Chrome 111's name
 *  for that; an older engine (Android WebView 109 has been seen) refuses the
 *  value with a TypeError, and its default already reads the EXIF. */
async function decodeOriented(blob: Blob): Promise<ImageBitmap> {
  try {
    return await createImageBitmap(blob, { imageOrientation: "from-image" });
  } catch (e) {
    if (!(e instanceof TypeError)) throw e;
    return createImageBitmap(blob);
  }
}

export async function prepare(file: File, original: boolean): Promise<Prepared> {
  // Before reading any of it: a file this large is not read into the page
  if (file.size > MAX_FILE_PLAIN) throw new Error("Larger than 64 MB, the most a file can be");
  const bytes = new Uint8Array(await file.arrayBuffer());
  const name = cleanFileName(file.name) || "file";
  const shown = sniff(bytes);
  if (shown?.kind === "image") {
    let bitmap: ImageBitmap;
    try {
      bitmap = await decodeOriented(new Blob([bytes], { type: shown.mime }));
    } catch {
      if (!original && STILL.has(shown.mime)) throw new CannotClean();
      return { bytes, name, mime: shown.mime, compress: false };
    }
    try {
      const px = previewFrom(bitmap);
      if (original || !STILL.has(shown.mime) || isAnimated(bytes)) {
        return { bytes, name, mime: shown.mime, w: bitmap.width, h: bitmap.height, px, compress: false };
      }
      const png = shown.mime === "image/png";
      const { blob, w, h } = await recode(bitmap, png);
      const ext = blob.type === "image/png" ? "png" : blob.type === "image/webp" ? "webp" : "jpg";
      return { bytes: new Uint8Array(await blob.arrayBuffer()), name: withExtension(name, ext), mime: blob.type, w, h, px, compress: false };
    } finally {
      bitmap.close();
    }
  }
  if (isHeif(bytes) || /^image\/hei[cf]/i.test(file.type)) {
    if (!original) throw new CannotClean();
    return { bytes, name, mime: "image/heic", compress: false };
  }
  if (shown?.kind === "video" || shown?.kind === "audio") {
    return { bytes, name, mime: shown.mime, ...(await mediaMeta(bytes, shown.kind, shown.mime)), compress: false };
  }
  return { bytes, name, mime: file.type || undefined, compress: true };
}
