// Who this browser has named as readers of each channel's log, and the bucket lists it has
// named (`LogMemory`). In IndexedDB, apart from the rest of that memory: at thousands of
// seats these alone fill localStorage's 5 MiB, whose failure goes unseen, and with it would go
// the vault's generations, which are what notices a rollback.

const DB = "voipc-log-named";
const STORE = "named";

let db: Promise<IDBDatabase | null> | null = null;

/** The store, or null where this browser keeps none (a private window): then who was
 *  named lasts this page, and a reload names them again. */
function store(): Promise<IDBDatabase | null> {
  db ??= new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return db;
}

/** All of it, read once a page, so a sign-in finds it without waiting. */
const held = new Map<string, string>();
let loaded: Promise<void> | null = null;

export function loadNamed(): Promise<void> {
  loaded ??= store().then(
    (d) =>
      new Promise<void>((resolve) => {
        if (!d) return resolve();
        const r = d.transaction(STORE).objectStore(STORE).openCursor();
        r.onsuccess = () => {
          const c = r.result;
          if (!c) return resolve();
          if (typeof c.value === "string") held.set(String(c.key), c.value);
          c.continue();
        };
        r.onerror = () => resolve();
      }),
  );
  return loaded;
}

export function namedOf(key: string): string | null {
  return held.get(key) ?? null;
}

export function saveNamed(key: string, json: string): void {
  held.set(key, json);
  void store().then((d) => {
    try {
      d?.transaction(STORE, "readwrite").objectStore(STORE).put(json, key);
    } catch (e) {
      console.warn("could not keep who was named:", e);
    }
  });
}

export function forgetNamed(key: string): void {
  held.delete(key);
  void store().then((d) => {
    try {
      d?.transaction(STORE, "readwrite").objectStore(STORE).delete(key);
    } catch {
      // Storage off: nothing was kept either.
    }
  });
}
