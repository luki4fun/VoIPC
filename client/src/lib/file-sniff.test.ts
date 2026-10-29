import { test } from "node:test";
import assert from "node:assert/strict";
import { isAnimated, sniff } from "./file-sniff.ts";

const bytes = (...parts: (number[] | string)[]) =>
  Uint8Array.from(parts.flatMap((p) => (typeof p === "string" ? Array.from(p, (c) => c.charCodeAt(0)) : p)));

test("pictures, videos and sounds are known by their first bytes", () => {
  const cases: [Uint8Array, string | null][] = [
    [bytes([0x89], "PNG\r\n\x1a\n", [0, 0]), "image/png"],
    [bytes([0xff, 0xd8, 0xff, 0xe0]), "image/jpeg"],
    [bytes("GIF89a"), "image/gif"],
    [bytes("RIFF", [1, 2, 3, 4], "WEBPVP8 "), "image/webp"],
    [bytes("RIFF", [1, 2, 3, 4], "WAVEfmt "), "audio/wav"],
    [bytes([0, 0, 0, 0x20], "ftypisom"), "video/mp4"],
    [bytes([0, 0, 0, 0x20], "ftypqt  "), "video/quicktime"],
    [bytes([0, 0, 0, 0x20], "ftypM4A "), "audio/mp4"],
    [bytes([0, 0, 0, 0x20], "ftypavif"), "image/avif"],
    [bytes([0x1a, 0x45, 0xdf, 0xa3]), "video/webm"],
    [bytes("OggS"), "audio/ogg"],
    [bytes("fLaC"), "audio/flac"],
    [bytes("ID3", [4]), "audio/mpeg"],
    [bytes([0xff, 0xfb, 0x90]), "audio/mpeg"],
    [bytes([0xff, 0xf1, 0x50]), "audio/aac"],
  ];
  for (const [b, mime] of cases) assert.equal(sniff(b)?.mime ?? null, mime, mime ?? "none");
});

test("whatever could run or be drawn as a page is never shown, only saved", () => {
  for (const b of [
    bytes("<svg xmlns='http://www.w3.org/2000/svg'>"),
    bytes("<?xml version='1.0'?><svg>"),
    bytes("<!DOCTYPE html><script>"),
    bytes("%PDF-1.7"),
    bytes("PK", [3, 4]),
    bytes([0, 0, 0, 0x20], "ftypheic"),
    bytes([0, 0, 0, 0x20], "ftypmif1"),
    bytes(""),
    bytes([0xff]),
    bytes("RIFF"),
    bytes([0xff, 0xfe], "H\0i\0"),
    bytes([0, 0, 0, 0x20], "ftypcrx "),
    bytes([0, 0, 0, 0x20], "ftyphevx"),
  ]) {
    assert.equal(sniff(b), null, String.fromCharCode(...b.subarray(0, 12)));
  }
});

test("a moving picture is told apart from a still one", () => {
  assert.equal(isAnimated(bytes("GIF89a")), true);
  const webp = (flags: number) => bytes("RIFF", [0, 0, 0, 0], "WEBPVP8X", [10, 0, 0, 0, flags]);
  assert.equal(isAnimated(webp(0x02)), true);
  assert.equal(isAnimated(webp(0x10)), false);
  const chunk = (type: string, len = 0) => bytes([0, 0, 0, len], type, new Array(len + 4).fill(0));
  const png = (...chunks: Uint8Array[]) => Uint8Array.from([...bytes([0x89], "PNG\r\n\x1a\n"), ...chunks.flatMap((c) => [...c])]);
  assert.equal(isAnimated(png(chunk("IHDR", 13), chunk("acTL", 8), chunk("IDAT"))), true);
  assert.equal(isAnimated(png(chunk("IHDR", 13), chunk("IDAT"), chunk("acTL", 8))), false);
  assert.equal(isAnimated(bytes([0xff, 0xd8, 0xff])), false);
});
