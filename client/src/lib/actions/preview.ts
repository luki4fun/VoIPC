// The 16 × 16 preview a file's message carries, drawn from its raw pixels: an
// ImageData, no decoder (file-rules.ts `previewPixels`). For a canvas of
// PREVIEW_SIDE × PREVIEW_SIDE; CSS makes it bigger.

import { previewPixels, PREVIEW_SIDE } from "../file-rules.js";

export function preview(canvas: HTMLCanvasElement, px: string | undefined) {
  const draw = (p: string | undefined) => {
    const rgba = p ? previewPixels(p) : null;
    if (rgba) canvas.getContext("2d")?.putImageData(new ImageData(rgba, PREVIEW_SIDE, PREVIEW_SIDE), 0, 0);
  };
  draw(px);
  return { update: draw };
}
