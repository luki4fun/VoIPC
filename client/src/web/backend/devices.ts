// The devices relays with accounts remember this browser as: the device key
// that stands in for the password there, and the vault key (DEK) kept with it
// (client/src-tauri/src/crypto.rs DeviceRecord is the desktop's copy).
//
// In IndexedDB, each record encrypted (AES-GCM) under a key the page cannot
// export: copying the browser profile's files elsewhere does not carry the
// keys along. It does not keep them from a page this origin serves — the
// relay serves this page, so a relay that wants them can take them; the
// README says so.

import { toHex } from "../../lib/hex";

export interface DeviceRecord {
  /** The address it was remembered at, as the connection's server id. */
  server: string;
  /** The account name, normalised. */
  name: string;
  relay_id: number[];
  device_id: number[];
  /** PKCS#8 Ed25519. */
  device_key: number[];
  dek: number[];
}

const DB = "voipc-accounts";
const KEYS = "keys";
const DEVICES = "devices";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(KEYS);
      req.result.createObjectStore(DEVICES);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function request<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function wrapKey(db: IDBDatabase): Promise<CryptoKey> {
  const existing = await request(db.transaction(KEYS).objectStore(KEYS).get("wrap"));
  if (existing) return existing as CryptoKey;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  // `add`, not `put`: two first uses at once (two tabs) keep one key — the
  // later one reads the first one's back instead of writing over it, which
  // would leave every record sealed under the first undecryptable.
  try {
    await request(db.transaction(KEYS, "readwrite").objectStore(KEYS).add(key, "wrap"));
    return key;
  } catch {
    return (await request(db.transaction(KEYS).objectStore(KEYS).get("wrap"))) as CryptoKey;
  }
}

/** Where this browser keeps what it read of an account's stored log (account.ts). */
export function cursorStorageKey(relayId: ArrayLike<number>, name: string): string {
  return `voipc.cursors.${toHex(relayId)}|${name}`;
}

const idOf = (server: string, name: string) => `${server}|${name}`;

/** Every remembered device; one that does not decrypt is skipped. */
export async function listDevices(): Promise<DeviceRecord[]> {
  try {
    const db = await open();
    const key = await wrapKey(db);
    const rows = (await request(db.transaction(DEVICES).objectStore(DEVICES).getAll())) as { iv: Uint8Array<ArrayBuffer>; ct: ArrayBuffer }[];
    const out: DeviceRecord[] = [];
    for (const row of rows) {
      try {
        const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: row.iv }, key, row.ct);
        out.push(JSON.parse(new TextDecoder().decode(plain)) as DeviceRecord);
      } catch {
        // A key that changed under it (site data partly cleared): useless now.
      }
    }
    return out;
  } catch (e) {
    console.warn("remembered devices unavailable:", e);
    return [];
  }
}

export async function findDevice(server: string, name: string): Promise<DeviceRecord | undefined> {
  return (await listDevices()).find((d) => d.server === server && d.name === name);
}

export async function saveDevice(rec: DeviceRecord): Promise<void> {
  const db = await open();
  const key = await wrapKey(db);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(rec)));
  await request(db.transaction(DEVICES, "readwrite").objectStore(DEVICES).put({ iv, ct }, idOf(rec.server, rec.name)));
}

export async function forgetDevice(server: string, name: string): Promise<void> {
  const known = await findDevice(server, name);
  const db = await open();
  await request(db.transaction(DEVICES, "readwrite").objectStore(DEVICES).delete(idOf(server, name)));
  // What it read there, and who it named as readers, goes with it.
  if (known) {
    try {
      localStorage.removeItem(cursorStorageKey(known.relay_id, name));
    } catch {
      // Storage off: nothing was kept either.
    }
  }
}
