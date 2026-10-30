import { test } from "node:test";
import assert from "node:assert/strict";
import { crc32, storedZip } from "./zip.ts";

test("CRC-32 as everyone computes it", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
  assert.equal(crc32(new Uint8Array()), 0);
});

test("a stored zip whose directory names every file where it is", () => {
  const files = [
    { name: "pog.png", bytes: new Uint8Array([1, 2, 3]) },
    { name: "käse.gif", bytes: new Uint8Array(1000).fill(7) },
  ];
  const zip = storedZip(files);
  const v = new DataView(zip.buffer);
  const end = zip.length - 22;
  assert.equal(v.getUint32(end, true), 0x06054b50);
  assert.equal(v.getUint16(end + 10, true), 2);
  let at = v.getUint32(end + 16, true);
  for (const f of files) {
    assert.equal(v.getUint32(at, true), 0x02014b50);
    const len = v.getUint32(at + 24, true);
    const nameLen = v.getUint16(at + 28, true);
    const local = v.getUint32(at + 42, true);
    assert.equal(new TextDecoder().decode(zip.subarray(at + 46, at + 46 + nameLen)), f.name);
    assert.equal(v.getUint32(local, true), 0x04034b50);
    const data = local + 30 + v.getUint16(local + 26, true);
    assert.deepEqual(zip.subarray(data, data + len), f.bytes);
    assert.equal(v.getUint32(at + 16, true), crc32(f.bytes));
    at += 46 + nameLen;
  }
});
