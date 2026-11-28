// The browser's store of an account's group-key counters (dive 1 F1): sealed under the
// remembered devices' wrapping key, bound to its row, read back by a later page, merged with
// another tab's, forgotten with its device. IndexedDB is a stand-in here, with what the store
// and devices.ts use of it; the wasm's merge is a stand-in too (voipc-web gk.rs tests its own).
// The last case runs commands.ts `forget_device` with session.ts's live connections stood in
// for (session.ts itself, which `Session`'s writes come from, loads as it is).

import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";
import { fileURLToPath } from "node:url";

/** One request: its callbacks fire after the caller set them, as IndexedDB's do. */
function req<T>(run: () => T): IDBRequest<T> {
  const r = { result: undefined as T, error: null as unknown, onsuccess: null as null | (() => void), onerror: null as null | (() => void) };
  setTimeout(() => {
    try {
      r.result = run();
      r.onsuccess?.();
    } catch (e) {
      r.error = e;
      r.onerror?.();
    }
  });
  return r as unknown as IDBRequest<T>;
}

const clone = <T>(v: T): T => (v instanceof CryptoKey ? v : structuredClone(v));

class FakeStore {
  rows = new Map<string, unknown>();
  get = (k: string) => req(() => this.rows.get(k));
  put = (v: unknown, k: string) => req(() => void this.rows.set(k, clone(v)));
  add = (v: unknown, k: string) =>
    req(() => {
      if (this.rows.has(k)) throw new Error("ConstraintError");
      this.rows.set(k, clone(v));
    });
  delete = (k: string) => req(() => void this.rows.delete(k));
  getAll = () => req(() => [...this.rows.values()].map(clone));
  openCursor() {
    const keys = [...this.rows.keys()].sort();
    let at = 0;
    const r = { result: null as unknown, onsuccess: null as null | (() => void), onerror: null };
    const step = () =>
      setTimeout(() => {
        const k = keys[at++];
        r.result = k === undefined ? null : { key: k, value: clone(this.rows.get(k)), continue: step };
        r.onsuccess?.();
      });
    step();
    return r;
  }
}

class FakeDb {
  stores = new Map<string, FakeStore>();
  version = 0;
  createObjectStore(name: string) {
    this.stores.set(name, new FakeStore());
  }
  transaction(name: string) {
    return { objectStore: () => this.stores.get(name)! };
  }
}

class FakeIdb {
  dbs = new Map<string, FakeDb>();
  open(name: string, version: number) {
    const r = { result: undefined as unknown, onupgradeneeded: null as null | ((e: { oldVersion: number }) => void), onsuccess: null as null | (() => void), onerror: null };
    setTimeout(() => {
      let db = this.dbs.get(name);
      if (!db) this.dbs.set(name, (db = new FakeDb()));
      r.result = db;
      if (db.version < version) {
        r.onupgradeneeded?.({ oldVersion: db.version });
        db.version = version;
      }
      r.onsuccess?.();
    });
    return r;
  }
}

const idb = new FakeIdb();
(globalThis as any).indexedDB = idb;
(globalThis as any).localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
await import("../../lib/stores/node-stores.mjs");
// commands.ts's session.ts: its live connections, as the case sets them (`live`)
const LIVE = `
  export const forgetKept = () => {};
  export const forgetMirrorOf = (server, name) => globalThis.__live?.(server, name) ?? null;
`;
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === "./session" && context.parentURL?.endsWith("/web/backend/commands.ts")) return { url: "live-stand-in:session", shortCircuit: true };
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url === "live-stand-in:session") return { format: "module", source: LIVE, shortCircuit: true };
    // What commands.ts and session.ts load, some of it TypeScript that stripping alone does not run
    if (url.startsWith("file:") && url.endsWith(".ts")) {
      return { format: "module", source: stripTypeScriptTypes(readFileSync(fileURLToPath(url), "utf8"), { mode: "transform" }), shortCircuit: true };
    }
    return next(url, context);
  },
});

/** A fresh page's copy of the store: its own memory, the same IndexedDB. */
let pages = 0;
const page = (): Promise<typeof import("./gk-mirror.ts")> => import(new URL(`./gk-mirror.ts?page=${pages++}`, import.meta.url).href);

const KEY = "0909|writer";
const mirrorRows = () => idb.dbs.get("voipc-gk-mirror")!.stores.get("mirrors")!.rows as Map<string, { iv: Uint8Array; ct: ArrayBuffer }>;
const wrap = () => idb.dbs.get("voipc-accounts")!.stores.get("keys")!.rows.get("wrap") as CryptoKey;
/** The wasm's merge, as far as the store sees it: which two it was handed, and its answer. */
const merges: [number[], number[]][] = [];
const merge = (stored: Uint8Array, ours: Uint8Array) => {
  merges.push([[...stored], [...ours]]);
  return new Uint8Array([...stored, ...ours]);
};

// Each case from an empty store
beforeEach(() => idb.dbs.get("voipc-gk-mirror")?.stores.get("mirrors")?.rows.clear());

test("a row is the relay's id and the account's name", async () => {
  const { mirrorKey } = await page();
  assert.equal(mirrorKey([9, 9], "writer"), KEY);
});

test("a kept row is sealed under the devices' wrapping key, to its own id, and a later page reads it back", async () => {
  const first = await page();
  await first.saveMirror(KEY, new Uint8Array([1, 2, 3, 4]), merge);
  const row = mirrorRows().get(KEY)!;
  assert.ok(row, "kept");
  assert.equal(row.ct.byteLength, 4 + 16, "the bytes and an AES-GCM tag, none of it plain");
  const label = (id: string) => new TextEncoder().encode(`voipc-gk-mirror|${id}`);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: row.iv as Uint8Array<ArrayBuffer>, additionalData: label(KEY) }, wrap(), row.ct);
  assert.deepEqual([...new Uint8Array(plain)], [1, 2, 3, 4]);
  await assert.rejects(crypto.subtle.decrypt({ name: "AES-GCM", iv: row.iv as Uint8Array<ArrayBuffer>, additionalData: label("0808|writer") }, wrap(), row.ct), "bound to its row");
  assert.equal(wrap().extractable, false, "the key does not leave the browser");

  const next = await page();
  assert.equal(next.mirrorOf(KEY), undefined, "a new page has nothing before it reads");
  await next.loadMirrors();
  assert.deepEqual([...next.mirrorOf(KEY)!], [1, 2, 3, 4]);
});

test("what another tab kept meanwhile is merged in, not written over", async () => {
  const other = await page();
  await other.saveMirror(KEY, new Uint8Array([7]), merge);
  const mine = await page();
  merges.length = 0;
  await mine.saveMirror(KEY, new Uint8Array([8]), merge);
  assert.deepEqual(merges, [[[7], [8]]], "the row as it stood, and ours");
  const reader = await page();
  await reader.loadMirrors();
  assert.deepEqual([...reader.mirrorOf(KEY)!], [7, 8]);
  // A row a newer VoIPC wrote (the merge says write nothing): it is left as it is
  await mine.saveMirror(KEY, new Uint8Array([9]), () => undefined);
  await reader.loadMirrors();
  assert.deepEqual([...reader.mirrorOf(KEY)!], [7, 8], "not written over");
  assert.deepEqual([...mine.mirrorOf(KEY)!], [7, 8], "nor taken as written");
});

test("while another server's sign-in reads the rows again, every row stays readable", async () => {
  const writer = await page();
  // Rows that open before this one (the cursor goes in key order), each a decrypt to wait on
  for (let i = 0; i < 6; i++) await writer.saveMirror(`0${i}00|other${i}`, new Uint8Array(4096).fill(i), merge);
  await writer.saveMirror(KEY, new Uint8Array([5]), merge);
  const p = await page();
  await p.loadMirrors(); // this server's sign-in
  assert.deepEqual([...p.mirrorOf(KEY)!], [5]);
  // Another server's sign-in: this one's GroupKeys may be handled at any task meanwhile
  let done = false;
  const second = p.loadMirrors().then(() => (done = true));
  let looks = 0;
  let missing = 0;
  while (!done) {
    await new Promise((r) => setImmediate(r));
    looks++;
    if (p.mirrorOf(KEY) === undefined) missing++;
  }
  await second;
  assert.ok(looks > 6, "looked while the read ran");
  assert.equal(missing, 0, `the row was missing at ${missing} of ${looks} tasks`);
  assert.deepEqual([...p.mirrorOf(KEY)!], [5]);
});

test("a row moved under another's id does not open, and the others still do", async () => {
  const p = await page();
  await p.saveMirror(KEY, new Uint8Array([5]), merge);
  mirrorRows().set("0808|other", structuredClone(mirrorRows().get(KEY)!));
  const next = await page();
  await next.loadMirrors();
  assert.equal(next.mirrorOf("0808|other"), undefined);
  assert.deepEqual([...next.mirrorOf(KEY)!], [5]);
});

test("a forgotten row goes, after a write already asked for it lands", async () => {
  const p = await page();
  const written = p.saveMirror(KEY, new Uint8Array([6]), merge);
  await p.forgetMirror(KEY);
  await written;
  assert.equal(mirrorRows().has(KEY), false, "the write landed first, and then went");
  assert.equal(p.mirrorOf(KEY), undefined);
  const next = await page();
  await next.loadMirrors();
  assert.equal(next.mirrorOf(KEY), undefined);
});

test("with no IndexedDB the counters last the page, and nothing throws", async () => {
  (globalThis as any).indexedDB = undefined;
  try {
    const p = await page();
    await p.loadMirrors();
    await p.saveMirror(KEY, new Uint8Array([1]), merge);
    assert.deepEqual([...p.mirrorOf(KEY)!], [1], "for this page's next sign-in");
    await p.saveMirror(KEY, new Uint8Array([2]), merge);
    assert.deepEqual([...p.mirrorOf(KEY)!], [1, 2], "merged as a stored row would be");
    // Another account's, or a newer VoIPC's (the merge says write nothing): left as a stored row is
    await p.saveMirror(KEY, new Uint8Array([3]), () => undefined);
    assert.deepEqual([...p.mirrorOf(KEY)!], [1, 2], "not written over");
    await p.forgetMirror(KEY);
    assert.equal(p.mirrorOf(KEY), undefined);
  } finally {
    (globalThis as any).indexedDB = idb;
  }
});

test("a forgotten device's row stays gone though its account is still connected, with a device record or none", async () => {
  const { dispatch } = await import("./commands.ts");
  const { Session } = await import("./session.ts");
  const { saveDevice } = await import("./devices.ts");
  // The store the connection writes to (commands.ts's and session.ts's copy), opened
  await (await import("./gk-mirror.ts")).loadMirrors();
  const SERVER = "relay.example:4433";
  // A signed-in connection to SERVER as `writer` (a session.ts `Session`), its counters moved
  // at each write
  let moved = 0;
  const live = Object.assign(Object.create(Session.prototype), {
    gkMirrorKey: null as string | null,
    gkMirrorTimer: undefined,
    signal: { gkMirror: () => new Uint8Array([++moved]) },
  });
  (globalThis as any).__live = (server: string, name: string) => (server === SERVER ? live.gkMirrorForget(name) : null);
  const until = async (done: () => boolean) => {
    for (let i = 0; i < 500 && !done(); i++) await new Promise((r) => setTimeout(r, 1));
  };
  try {
    for (const record of [true, false]) {
      const how = record ? "with a device record" : "signed in by password, no record";
      live.gkMirrorKey = KEY;
      if (record) await saveDevice({ server: SERVER, name: "writer", relay_id: [9, 9], device_id: [1], device_key: [2], dek: [3] });
      live.gkMirrorSave();
      await until(() => mirrorRows().has(KEY));
      assert.ok(mirrorRows().has(KEY), `${how}: the connection kept its counters`);
      await dispatch("forget_device", { server: SERVER, name: "other" });
      assert.ok(mirrorRows().has(KEY), `${how}: another account forgotten, this one's row stays`);
      await dispatch("forget_device", { server: SERVER, name: "writer" });
      assert.equal(mirrorRows().has(KEY), false, `${how}: forgotten`);
      // Its counters move again: the 1 s timer, a hidden page, pagehide, the connection's end
      live.gkMirrorSave();
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(mirrorRows().has(KEY), false, `${how}: the live connection does not write it back`);
    }
  } finally {
    delete (globalThis as any).__live;
  }
});
