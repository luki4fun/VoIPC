// A .zip of whole files, stored as they are (no deflate): what an emote pack
// is exported as. Pictures are compressed already, and any unzip, and this
// app's own importer (crates/voipc-media `read_pack`), reads this layout.
// Pure, so zip.test.ts runs it under Node's own test runner.

const TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

/** The zip's checksum (CRC-32, as in PNG and gzip). */
export function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) c = TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** `files` as one stored .zip; names in UTF-8. shortcut: no zip64, so at most
 *  65 535 files under 4 GiB in all, far past any pack. */
export function storedZip(files: readonly { name: string; bytes: Uint8Array }[]): Uint8Array {
  const enc = new TextEncoder();
  const local: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let at = 0;
  for (const f of files) {
    const name = enc.encode(f.name);
    const crc = crc32(f.bytes);
    // version 2.0, flag 11 (UTF-8 names), stored, 1980-01-01 00:00
    const head = (sig: number, extra: number) => {
      const h = new DataView(new ArrayBuffer(extra));
      h.setUint32(0, sig, true);
      return h;
    };
    const l = head(0x04034b50, 30);
    l.setUint16(4, 20, true);
    l.setUint16(6, 0x0800, true);
    l.setUint16(12, 0x21, true);
    l.setUint32(14, crc, true);
    l.setUint32(18, f.bytes.length, true);
    l.setUint32(22, f.bytes.length, true);
    l.setUint16(26, name.length, true);
    const c = head(0x02014b50, 46);
    c.setUint16(4, 20, true);
    c.setUint16(6, 20, true);
    c.setUint16(8, 0x0800, true);
    c.setUint16(14, 0x21, true);
    c.setUint32(16, crc, true);
    c.setUint32(20, f.bytes.length, true);
    c.setUint32(24, f.bytes.length, true);
    c.setUint16(28, name.length, true);
    c.setUint32(42, at, true);
    local.push(new Uint8Array(l.buffer), name, f.bytes);
    central.push(new Uint8Array(c.buffer), name);
    at += 30 + name.length + f.bytes.length;
  }
  const size = central.reduce((n, p) => n + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, files.length, true);
  end.setUint16(10, files.length, true);
  end.setUint32(12, size, true);
  end.setUint32(16, at, true);
  const parts = [...local, ...central, new Uint8Array(end.buffer)];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
