// What this browser keeps of a signed-in account's seat-key counters past the page (dive 1
// F1): every counter its pages checked or raised (voipc-web gk.rs `Gk::mirror`). The vault's
// group-key pages hold them too, and a relay that withholds those at the next sign-in would
// otherwise take them with it, and rule 8 with them: an account's old seat keys seated again
// past a page that saw its newer ones.
//
// In IndexedDB, one row per relay and account name, as the read cursors go by. Each row is
// sealed (AES-GCM, its id as the additional data) under the key the remembered devices are
// (devices.ts `wrappingKey`): whoever can open one opens the other, so nothing new is laid
// open. The bytes name the relay and account themselves, and the wasm takes none of another's.
// A database of its own: a store added to `voipc-accounts` would raise its version, which an
// older page cannot open. Where the browser keeps no IndexedDB, the counters last the page, as
// the floors do (session.ts `keptGk`).

import { toHex } from "../../lib/hex";
import { wrappingKey } from "./devices";

const DB = "voipc-gk-mirror";
const STORE = "mirrors";

/** A row as IndexedDB holds it. */
interface Row {
  iv: Uint8Array<ArrayBuffer>;
  ct: ArrayBuffer;
}

/** A row's id: the relay's id and the account's name (`cursorStorageKey`'s pair). */
export function mirrorKey(relayId: ArrayLike<number>, name: string): string {
  return `${toHex(relayId)}|${name}`;
}

/** What a row is sealed to: its id, so a row moved under another's id does not open. */
const label = (key: string) => new TextEncoder().encode(`voipc-gk-mirror|${key}`);

let db: Promise<IDBDatabase | null> | null = null;

/** The store, or null where this browser keeps none. */
function store(): Promise<IDBDatabase | null> {
  db ??= new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = (e) => {
        if (e.oldVersion < 1) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return db;
}

function request<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

/** Every row, opened, as `loadMirrors` last read them and this page wrote them since. */
const held = new Map<string, Uint8Array>();

async function open(key: CryptoKey, id: string, row: Row): Promise<Uint8Array | null> {
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: row.iv, additionalData: label(id) }, key, row.ct));
  } catch {
    // Sealed under a key that changed (site data partly cleared), or not this row's
    return null;
  }
}

/**
 * Every row, read and opened: before each sign-in (account.ts `AccountDriver.create`), so the
 * `GroupKeys` that comes right after it finds its own at once, before any header is checked.
 * Again at each sign-in: another tab may have kept more since. The rows go in all at once,
 * once every one is open: another server's `GroupKeys` may be handled while this reads, and
 * finds its row there all along. Never throws.
 */
export async function loadMirrors(): Promise<void> {
  const d = await store();
  if (!d) return;
  try {
    const rows = await new Promise<[string, Row][]>((resolve, reject) => {
      const out: [string, Row][] = [];
      const r = d.transaction(STORE).objectStore(STORE).openCursor();
      r.onsuccess = () => {
        const c = r.result;
        if (!c) return resolve(out);
        out.push([String(c.key), c.value as Row]);
        c.continue();
      };
      r.onerror = () => reject(r.error);
    });
    const key = rows.length > 0 ? await wrappingKey() : null;
    const opened: [string, Uint8Array][] = [];
    for (const [id, row] of rows) {
      const plain = key && (await open(key, id, row));
      if (plain) opened.push([id, plain]);
    }
    held.clear();
    for (const [id, plain] of opened) held.set(id, plain);
  } catch (e) {
    console.warn("the group key's kept counters are unavailable:", e);
  }
}

/** The row kept for `key`, opened (`gkStart`'s `mirror`), as the last `loadMirrors` found it. */
export function mirrorOf(key: string): Uint8Array | undefined {
  return held.get(key);
}

/** Each row's writes, one after another in the order they were asked. */
const writing = new Map<string, Promise<void>>();

/**
 * Keeps `bytes` (`gkMirror`'s) as `key`'s row, merged with the row as it stands: `merge`
 * (`gkMirrorMerge`) keeps what another tab wrote meanwhile, and says what to write; undefined
 * from it writes nothing (another account's row, which one sign-in the relay named under
 * another id would otherwise have written over, or a newer VoIPC's). A row that does not open
 * is written over. Never throws; a write that fails waits for the next.
 */
export function saveMirror(key: string, bytes: Uint8Array, merge: (stored: Uint8Array, ours: Uint8Array) => Uint8Array | undefined): Promise<void> {
  const next = (writing.get(key) ?? Promise.resolve())
    .then(() => write(key, bytes, merge))
    .catch((e) => console.warn("could not keep the group key's counters:", e));
  writing.set(key, next);
  void next.then(() => {
    if (writing.get(key) === next) writing.delete(key);
  });
  return next;
}

async function write(key: string, bytes: Uint8Array, merge: (stored: Uint8Array, ours: Uint8Array) => Uint8Array | undefined): Promise<void> {
  const d = await store();
  if (!d) {
    // No IndexedDB: for this page's next sign-in only, by the same rule
    const old = held.get(key);
    const plain = old ? merge(old, bytes) : bytes;
    if (plain) held.set(key, plain);
    return;
  }
  const wrap = await wrappingKey();
  const stored = (await request(d.transaction(STORE).objectStore(STORE).get(key))) as Row | undefined;
  const old = stored && (await open(wrap, key, stored));
  const plain = old ? merge(old, bytes) : bytes;
  if (!plain) return;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: label(key) }, wrap, plain as Uint8Array<ArrayBuffer>);
  await request(d.transaction(STORE, "readwrite").objectStore(STORE).put({ iv, ct } satisfies Row, key));
  held.set(key, plain);
}

/** `key`'s row goes (its device forgotten, devices.ts): after a write already asked lands. */
export async function forgetMirror(key: string): Promise<void> {
  await writing.get(key);
  held.delete(key);
  const d = await store();
  if (!d) return;
  try {
    await request(d.transaction(STORE, "readwrite").objectStore(STORE).delete(key));
  } catch {
    // Storage off: nothing was kept either.
  }
}
