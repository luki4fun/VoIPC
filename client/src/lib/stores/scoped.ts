// State kept per server, and a view of the server on screen.
//
// Several servers are open at once, and each has its own channel list, its own
// member list, its own user id for us. A store of that kind is one writable per
// server, kept here by server id. The bare store is the one a component reads
// with `$channels`: it follows `serverAddress`, the server on screen, so the
// markup of both layouts did not have to change to become multi-server.
//
// **The bare store is read-only.** Every write names its server through
// `.of(server)`. An event handler writing to "whichever server is on screen"
// is the bug this shape exists to rule out: the event came from one server,
// the user may be looking at another, and after an `await` the answer to "which
// one is on screen" may have changed under the handler anyway. Without a `set`
// on the bare store the compiler lists every such write.
//
// Pure — only `svelte/store` — so scoped.test.ts can load it under Node.

import { derived, readable, writable, type Readable, type Writable } from "svelte/store";

/**
 * The server on screen: the id of the one whose channels and members are shown
 * (see `serverId` in servers.ts), or `""` before there is one.
 *
 * Only ever the *view*. It says nothing about where voice is — that is
 * `voice` in channels.ts, and the two differ whenever the user reads one
 * server while talking on another.
 */
export const serverAddress = writable<string>("");

export interface Scoped<T> extends Readable<T> {
  /** That server's store. The only way to write. */
  of(server: string): Writable<T>;
  /**
   * That server's store to read, without making one: a server with none
   * reads as the initial value. `get(x.peek(server))` left a ghost entry behind
   * for "" or a dropped server, which `all()` then carried (H5-16).
   */
  peek(server: string): Readable<T>;
  /** Follows whichever server `server` names; the initial value while it names none. */
  at(server: Readable<string | null>): Readable<T>;
  /** Every server's value, for whatever draws all of them at once (the rail). */
  all(): Readable<Map<string, T>>;
  /** Forget a server: its value goes back to the initial one and the entry goes. */
  drop(server: string): void;
}

/**
 * Every scoped store there is, so closing a server can forget it everywhere at
 * once. A list kept by hand in the disconnect path is a list that misses the
 * next store somebody adds.
 */
const everyScoped = new Set<Scoped<unknown>>();

/** A store that re-subscribes to whichever store `pick` currently names. */
function follow<T>(pick: Readable<Readable<T>>): Readable<T> {
  return readable<T>(undefined as T, (set) => {
    let current: Readable<T> | null = null;
    let stopInner: (() => void) | null = null;
    const stopOuter = pick.subscribe((store) => {
      if (store === current) return;
      current = store;
      stopInner?.();
      stopInner = store.subscribe(set);
    });
    return () => {
      stopOuter();
      stopInner?.();
    };
  });
}

export function scoped<T>(init: () => T): Scoped<T> {
  // The servers' stores. A plain Map, written the moment `of` needs a store:
  // `of` is also how a helper *reads* one server's value, and that read may
  // happen inside a component's `$derived` or markup, where writing a store
  // the component depends on is an error Svelte throws (state_unsafe_mutation)
  // and the window never repaints again.
  const entries = new Map<string, Writable<T>>();
  // So views can follow `entries` coming and going. A server gaining a store
  // is told a microtask later, outside whatever read created it; one going
  // away is told at once, since `drop` only runs where writing is allowed.
  const version = writable(0);
  let bumpQueued = false;
  function bumpSoon(): void {
    if (bumpQueued) return;
    bumpQueued = true;
    queueMicrotask(() => {
      bumpQueued = false;
      version.update((n) => n + 1);
    });
  }
  // What a server with no store yet reads as. Reading never creates one, so a
  // component looking at a server cannot bring its state back after a `drop`.
  const blank = readable(init());

  function of(server: string): Writable<T> {
    let store = entries.get(server);
    if (!store) {
      store = writable(init());
      entries.set(server, store);
      bumpSoon();
    }
    return store;
  }

  function peek(server: string): Readable<T> {
    // A fresh initial value, not `blank`'s: a caller may mutate what it read
    return entries.get(server) ?? readable(init());
  }

  function at(server: Readable<string | null>): Readable<T> {
    return follow(
      derived([server, version], ([$server]) => ($server ? entries.get($server) : undefined) ?? blank),
    );
  }

  function all(): Readable<Map<string, T>> {
    return follow(
      derived(version, () => {
        const ids = [...entries.keys()];
        return derived([...entries.values()], (values) => new Map(ids.map((id, i) => [id, values[i]])));
      }),
    );
  }

  function drop(server: string): void {
    const store = entries.get(server);
    if (!store) return;
    // Reset before letting go: a subscriber still holding this instance (a
    // view that has not re-subscribed yet) sees an empty server, not a stale one.
    store.set(init());
    entries.delete(server);
    version.update((n) => n + 1);
  }

  const view = at(serverAddress);
  const store: Scoped<T> = { subscribe: view.subscribe, of, peek, at, all, drop };
  everyScoped.add(store as Scoped<unknown>);
  return store;
}

/** Forget one server in every scoped store. */
export function dropServer(server: string): void {
  for (const store of everyScoped) store.drop(server);
}
