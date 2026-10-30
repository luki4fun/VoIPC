import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Asks,
  MAX_ASKS,
  asksAgain,
  base64Chunks,
  fitWithin,
  formatSize,
  loadKey,
  sealedLen,
  previewOf,
  previewPixels,
  referencedHashes,
  refersTo,
  runsCode,
  saveName,
  withExtension,
} from "./file-rules.ts";
import type { ChatMessage } from "./types.ts";

const T = 1_700_000_000_000;
const A = "a".repeat(64);
const B = "b".repeat(64);
function m(over: Partial<ChatMessage> = {}): ChatMessage {
  return { user_id: 1, username: "Zoë#1234", content: "", timestamp: T, ...over };
}
const file = (hash: string) => ({ hash, key: "c".repeat(64), size: 3, z: false });

test("a conversation refers to a blob only through a message still here", () => {
  const msgs = [m({ content: "text" }), m({ file: file(A) }), m({ file: file(B), expires_at: T + 10 })];
  assert.equal(refersTo(msgs, A, T), true);
  assert.equal(refersTo(msgs, B, T), true);
  assert.equal(refersTo(msgs, B, T + 10), false, "its timer has run out");
  assert.equal(refersTo(msgs, "d".repeat(64), T), false);
  assert.equal(refersTo(undefined, A, T), false, "no such conversation");
});

test("every live blob across conversations, once each", () => {
  const channels = new Map([
    ["h:1/general", [m({ file: file(A) }), m({ file: file(A) })]],
    ["h:1/old", [m({ file: file(B), expires_at: T - 1 })]],
  ]);
  const dms = new Map([["h:1/bob", [m({ file: file(B) }), m()]]]);
  assert.deepEqual(referencedHashes([channels], T), [A]);
  assert.deepEqual(referencedHashes([channels, dms], T).sort(), [A, B]);
  assert.deepEqual(referencedHashes([new Map()], T), []);
});

test("the 16x16 preview travels as 768 bytes of RGB and comes back opaque", () => {
  const rgba = Array.from({ length: 16 * 16 * 4 }, (_, i) => (i % 4 === 3 ? 7 : i % 251));
  const px = previewOf(rgba);
  assert.equal(px.length, 1024);
  const back = previewPixels(px)!;
  assert.equal(back.length, 1024);
  for (let i = 0; i < 256; i++) {
    assert.deepEqual([...back.subarray(i * 4, i * 4 + 4)], [rgba[i * 4], rgba[i * 4 + 1], rgba[i * 4 + 2], 255]);
  }
  assert.equal(previewPixels(px.slice(4)), null, "not 768 bytes");
  assert.equal(previewPixels("!!!!"), null, "not base64");
});

test("a photo is brought down, never up, and keeps its shape", () => {
  assert.deepEqual(fitWithin(4000, 3000, 2560), { w: 2560, h: 1920 });
  assert.deepEqual(fitWithin(3000, 4000, 2560), { w: 1920, h: 2560 });
  assert.deepEqual(fitWithin(800, 600, 2560), { w: 800, h: 600 });
  assert.equal(withExtension("IMG_1.HEIC.jpeg", "webp"), "IMG_1.HEIC.webp");
  assert.equal(withExtension("noext", "png"), "noext.png");
  assert.deepEqual([formatSize(512), formatSize(2048), formatSize(3.4 * 1024 * 1024), formatSize(40 * 1024 * 1024), formatSize(1024 ** 3)], ["512 B", "2 KB", "3.4 MB", "40 MB", "1.0 GB"]);
});

test("a sender's name is saved as a name, on every system", () => {
  assert.equal(saveName("../../.ssh/authorized_keys"), "_.._.ssh_authorized_keys");
  assert.equal(saveName("C:\\Windows\\x.dll"), "C__Windows_x.dll");
  assert.equal(saveName("con.txt"), "_con.txt");
  assert.equal(saveName("LPT1"), "_LPT1");
  assert.equal(saveName("report.   "), "report");
  assert.equal(saveName("\u202egnp.exe"), "_gnp.exe");
  assert.equal(saveName(".hidden"), "hidden");
  assert.equal(saveName(".con.txt"), "_con.txt");
  assert.equal(saveName("..aux"), "_aux");
  assert.equal(saveName("COM\u00b9.log"), "_COM\u00b9.log");
  assert.equal(saveName("CONOUT$"), "_CONOUT$");
  assert.equal(saveName("\ufeffa.txt"), "_a.txt");
  assert.ok(!/[. ]$/.test(saveName("a".repeat(118) + ". b".repeat(10))), "no dot left at the cut");
  assert.equal(saveName("   "), "file");
  const long = saveName("a".repeat(300) + ".tar.gz");
  assert.equal(long.length, 120);
  assert.ok(long.endsWith(".gz"));
});

test("a sealed blob's length is file.rs's, for the cap", () => {
  assert.equal(sealedLen(0), 32 + 16);
  assert.equal(sealedLen(65_536), 32 + 65_536 + 16);
  assert.equal(sealedLen(65_537), 32 + 65_537 + 32);
  // An incompressible 10 MiB file does not fit a 10 MiB cap (the handoff's 10,488,352)
  assert.equal(sealedLen(10 * 1024 * 1024), 10_488_352);
});

test("staged chunks are base64 of at most the chunk size, and join back to the file", () => {
  const bytes = Uint8Array.from({ length: 100_003 }, (_, i) => (i * 7) % 256);
  const chunks = base64Chunks(bytes, 40_000);
  assert.equal(chunks.length, 3);
  const back = Buffer.concat(chunks.map((c) => Buffer.from(c, "base64")));
  assert.deepEqual(new Uint8Array(back), bytes);
  assert.ok(chunks.every((c) => Buffer.from(c, "base64").length <= 40_000));
  assert.deepEqual(base64Chunks(new Uint8Array(0)), [""]);
  // The default chunk on a 2.5 MiB file: three calls, nothing lost
  const big = new Uint8Array(2.5 * 1024 * 1024).fill(0xab);
  const parts = base64Chunks(big);
  assert.equal(parts.length, 3);
  assert.equal(parts.reduce((n, c) => n + Buffer.from(c, "base64").length, 0), big.length);
});

test("a message that copies a file's id with another key loads on its own (R3-02)", () => {
  const real = file(A);
  assert.equal(loadKey("s", real), loadKey("s", { ...real }), "two cards of one file share a load");
  for (const other of [{ ...real, key: "d".repeat(64) }, { ...real, size: 4 }, { ...real, z: true }]) {
    assert.notEqual(loadKey("s", other), loadKey("s", real));
  }
  assert.notEqual(loadKey("t", real), loadKey("s", real), "another server");
});

test("refusals from 100 that may pass later are asked again; the rest end it (R3-04)", () => {
  for (const code of [100, 102, 103, 104]) assert.equal(asksAgain(code), true, String(code));
  for (const code of [1, 2, 3, 4, 5, 101, 105]) assert.equal(asksAgain(code), false, String(code));
});

test("a download whose tickets bring bytes never runs out of asks (R3-05)", () => {
  const idle = new Asks();
  let n = 0;
  while (idle.next() && n < 10) n++;
  assert.equal(n, MAX_ASKS);
  const moving = new Asks();
  for (let i = 0; i < 100; i++) {
    assert.equal(moving.next(), true);
    moving.moved();
  }
});

test("a file a system can run is known by its extension, whatever its case", () => {
  for (const name of ["setup.exe", "RUN.BAT", "x.ps1", "game.AppImage", "evil.desktop", "a.tar.lnk", "app.apk ", "patch.msp", "launch.jnlp"]) {
    assert.equal(runsCode(name), true, name);
  }
  for (const name of ["photo.jpg", "notes.txt", "exe", "archive.zip", "song.mp3", "README", ".bashrc.txt"]) {
    assert.equal(runsCode(name), false, name);
  }
});
