// Event bus replacing Tauri's emit/listen on the web build.
// The backend emits the same event names and payload shapes as the Rust
// backend (see client/src-tauri/src/network.rs `app_handle.emit(...)`), so the
// Svelte layer stays unchanged.

type Handler = (payload: unknown) => void;

const handlers = new Map<string, Set<Handler>>();

export function emit(name: string, payload: unknown = null): void {
  const set = handlers.get(name);
  if (!set) return;
  // Value semantics, like Tauri's IPC: a handler gets its own copy, so no
  // backend cache and no Svelte store can ever alias the same object. (The
  // session once cached the ChannelList array it also emitted; the store kept
  // that array, a later in-place push duplicated a channel and the keyed
  // {#each} threw each_key_duplicate.) Payloads are plain JSON-like values.
  const value = payload !== null && typeof payload === "object" ? structuredClone(payload) : payload;
  for (const h of Array.from(set)) {
    try {
      h(value);
    } catch (e) {
      console.error(`event handler for "${name}" failed:`, e);
    }
  }
}

/** Returns an unlisten function, like @tauri-apps/api/event `listen`. */
export function subscribe(name: string, handler: Handler): () => void {
  let set = handlers.get(name);
  if (!set) {
    set = new Set();
    handlers.set(name, set);
  }
  set.add(handler);
  return () => {
    set!.delete(handler);
  };
}
