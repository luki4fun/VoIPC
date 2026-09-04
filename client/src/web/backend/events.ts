// Event bus replacing Tauri's emit/listen on the web build.
// The backend emits the same event names and payload shapes as the Rust
// backend (see client/src-tauri/src/network.rs `app_handle.emit(...)`), so the
// Svelte layer stays unchanged.

type Handler = (payload: unknown) => void;

const handlers = new Map<string, Set<Handler>>();

export function emit(name: string, payload: unknown = null): void {
  const set = handlers.get(name);
  if (!set) return;
  for (const h of Array.from(set)) {
    try {
      h(payload);
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
