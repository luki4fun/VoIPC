// The browser sharer's pacing and keyframe rules, and a viewer's on a media edge.
// Pure functions only.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  KEYFRAME_INTERVAL_MS,
  paceFrame,
  shouldForceKey,
  frameTooLarge,
  MAX_DECODE_PIXELS,
  EDGE_SILENT_MS,
  edgeFailedDue,
  validEdgeView,
  lossMajority,
} from "./share-rules.ts";

/** One frame at 60 fps, in µs. */
const I = 16667;

test("frames are paced on the capture clock", () => {
  assert.equal(paceFrame(-Infinity, 5000, I), 5000, "the first frame is always on time");
  // A little early is on time, and the deadline steps from the last one
  assert.equal(paceFrame(100000, 96000, I), 116667);
  assert.equal(paceFrame(100000, 90000, I), null, "too early: held back");
  // Late: the deadline restarts from the frame, not a run of catch-up frames
  assert.equal(paceFrame(100000, 150000, I), 150000);
  assert.equal(paceFrame(5000000, 1000, I), 1000, "a clock that went back is a new clock");
});

test("a backed-up uplink gets one keyframe a second, not one a frame", () => {
  assert.equal(shouldForceKey(false, 1000, 5000, 0), false, "nothing asked, nothing due");
  assert.equal(shouldForceKey(true, 1000, 200, 0), true, "asked, uplink clear");
  assert.equal(shouldForceKey(true, 1000, 200, 12), false, "the storm");
  assert.equal(shouldForceKey(true, 1000, 1000, 12), true, "spaced out, still sent");
  assert.equal(shouldForceKey(false, KEYFRAME_INTERVAL_MS, 5000, 3), true, "the periodic IDR");
});

test("a viewer stops on a picture larger than the desktop viewer decodes", () => {
  const frame = (cw: number, ch: number, dw = cw, dh = ch) => ({ codedWidth: cw, codedHeight: ch, displayWidth: dw, displayHeight: dh });
  // Every share resolution, either way up, and the coded padding of 1080p
  for (const [w, h] of [[1920, 1080], [1080, 1920], [1920, 1088], [1280, 720], [2048, 2048]]) {
    assert.equal(frameTooLarge(frame(w, h)), false, `${w}x${h}`);
  }
  assert.equal(frameTooLarge(frame(2049, 2048)), true);
  assert.equal(frameTooLarge(frame(4096, 2160)), true);
  assert.equal(frameTooLarge(frame(16, 16384)), false, "counted by its pixels, as FFmpeg's max_pixels is");
  assert.equal(frameTooLarge(frame(1024, 4097)), true);
  // Small in pixels, but asking for a huge canvas
  assert.equal(frameTooLarge(frame(1920, 1080, 8192, 4320)), true);
  assert.equal(MAX_DECODE_PIXELS, 2048 * 2048);
});

test("edgeFailedDue: 10 s without a whole frame, and again 10 s after the last word", () => {
  const ready = 1_000;
  assert.equal(edgeFailedDue(ready + EDGE_SILENT_MS - 1, ready, true), false);
  assert.equal(edgeFailedDue(ready + EDGE_SILENT_MS, ready, true), true, "silent since the Ready");
  // A frame 3 s ago moved the mark; the caller moves it to its last EdgeFailed too
  const frame = ready + 8_000;
  assert.equal(edgeFailedDue(ready + EDGE_SILENT_MS, frame, true), false);
  const told = ready + EDGE_SILENT_MS;
  assert.equal(edgeFailedDue(told + EDGE_SILENT_MS - 1, told, true), false, "no more often than every 10 s");
  assert.equal(edgeFailedDue(told + EDGE_SILENT_MS, told, true), true, "the relay did not answer: again");
  assert.equal(edgeFailedDue(ready + 60_000, ready, false), false, "a connect has bounds of its own");
  assert.ok(EDGE_SILENT_MS > 2 * KEYFRAME_INTERVAL_MS, "a still screen's keyframes keep a working edge quiet");
});

/** An edge the app connects to: every field at a bound it may reach. */
const edge = () => ({
  host: "edge-1.example.org",
  port: 9991,
  cert_hashes: [Array(32).fill(7), new Uint8Array(32)],
  ticket: Array(256).fill(1),
});

test("validEdgeView takes a host name or IP, a port, 1 to 4 hashes and a short ticket", () => {
  assert.equal(validEdgeView(edge()), true);
  for (const host of ["localhost", "a", "x-1.y", "192.0.2.10", "0.0.0.0", "::1", "2001:db8::7", "::ffff:192.0.2.1", `${"a".repeat(63)}.org`]) {
    assert.equal(validEdgeView({ ...edge(), host }), true, host);
  }
  assert.equal(validEdgeView({ ...edge(), port: 1 }), true);
  assert.equal(validEdgeView({ ...edge(), port: 65535 }), true);
  assert.equal(validEdgeView({ ...edge(), cert_hashes: Array(4).fill(Array(32).fill(0)) }), true);
  assert.equal(validEdgeView({ ...edge(), ticket: [] }), true, "the edge refuses it, not the app");
});

test("validEdgeView refuses what no connect could use, so the app says the edge failed", () => {
  const bad: [string, Record<string, unknown>][] = [
    ["no host", { host: "" }],
    ["brackets", { host: "[::1]" }],
    ["a path in the host", { host: "edge.example.org/x" }],
    ["a port in the host", { host: "edge.example.org:9991" }],
    ["a URL closing its brackets", { host: "::1]/x?[" }],
    ["a zone", { host: "fe80::1%eth0" }],
    ["not IPv6", { host: "1:2:3" }],
    ["an octet past 255", { host: "192.0.2.256" }],
    ["three octets", { host: "192.0.2" }],
    ["a leading zero", { host: "192.0.2.010" }],
    ["a number as top-level name", { host: "edge.123" }],
    ["a label past 63", { host: `${"a".repeat(64)}.org` }],
    ["a name past 253", { host: `${"a.".repeat(127)}org` }],
    ["a dash at a label's end", { host: "edge-.example.org" }],
    ["an empty label", { host: "edge..org" }],
    ["not ASCII", { host: "bücher.example" }],
    ["a space", { host: "edge example" }],
    ["not a string", { host: 7 }],
    ["port 0", { port: 0 }],
    ["port past 65535", { port: 65536 }],
    ["a fractional port", { port: 9991.5 }],
    ["no hash", { cert_hashes: [] }],
    ["five hashes", { cert_hashes: Array(5).fill(Array(32).fill(0)) }],
    ["a short hash", { cert_hashes: [Array(31).fill(0)] }],
    ["a long hash", { cert_hashes: [new Uint8Array(33)] }],
    ["a hash of no bytes", { cert_hashes: [Array(32).fill(256)] }],
    ["hashes not a list", { cert_hashes: "00" }],
    ["a ticket past 256 bytes", { ticket: Array(257).fill(0) }],
    ["a ticket of no bytes", { ticket: [1, -1] }],
    ["no ticket", { ticket: undefined }],
  ];
  for (const [why, change] of bad) assert.equal(validEdgeView({ ...edge(), ...change }), false, why);
  assert.equal(validEdgeView(null), false);
  assert.equal(validEdgeView("edge.example.org"), false);
});

test("lossMajority: half of the viewers or more step the share down, as the native sharer counts", () => {
  // network.rs majority_of_viewers_steps_the_share_down, the same cases
  assert.equal(lossMajority(1, 1), true);
  assert.equal(lossMajority(1, 2), true);
  assert.equal(lossMajority(1, 3), false);
  assert.equal(lossMajority(2, 3), true);
  assert.equal(lossMajority(2, 5), false);
  assert.equal(lossMajority(3, 5), true);
  assert.equal(lossMajority(1, 0), true);
  assert.equal(lossMajority(0, 0), false);
  // What a summary says: 9 viewers and up
  assert.equal(lossMajority(4, 9), false);
  assert.equal(lossMajority(5, 9), true);
  assert.equal(lossMajority(499, 1000), false);
  assert.equal(lossMajority(500, 1000), true);
});
