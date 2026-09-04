// Web replacement for @tauri-apps/api/window. The browser has no secondary
// windows; the calls the app makes on a Window resolve without doing anything.

import type { EventCallback, UnlistenFn } from "./event";

export class Window {
  async destroy(): Promise<void> {}
  async close(): Promise<void> {}
  async setFocus(): Promise<void> {}
  async once<T>(_event: string, _handler: EventCallback<T>): Promise<UnlistenFn> {
    return () => {};
  }
}

const current = new Window();

export function getCurrentWindow(): Window {
  return current;
}
