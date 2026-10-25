import { get, writable } from "svelte/store";

export interface Notification {
  id: number;
  message: string;
  type: "info" | "warning" | "error";
  /** Stays until closed (`duration` 0). */
  sticky?: boolean;
}

/**
 * Most toasts on screen at once. Servers decide how often some of them come
 * (an identity change, a disconnect), and a sticky one never goes by itself.
 */
const MAX_TOASTS = 8;

export const notifications = writable<Notification[]>([]);

let nextId = 0;

/**
 * Show a toast. `duration` in ms; 0 = sticky (stays until manually closed).
 */
export function addNotification(
  message: string,
  type: "info" | "warning" | "error" = "info",
  duration = 5000,
) {
  const sticky = duration <= 0;
  // The same warning still up needs no second copy
  const shown = sticky ? get(notifications).find((n) => n.sticky && n.message === message) : undefined;
  if (shown) return shown.id;
  const id = nextId++;
  notifications.update((n) => {
    const next = [...n, { id, message, type, sticky }];
    while (next.length > MAX_TOASTS) {
      const passing = next.findIndex((x) => !x.sticky);
      next.splice(passing >= 0 ? passing : 0, 1);
    }
    return next;
  });
  if (duration > 0) {
    setTimeout(
      () => notifications.update((n) => n.filter((x) => x.id !== id)),
      duration,
    );
  }
  return id;
}

export function removeNotification(id: number) {
  notifications.update((n) => n.filter((x) => x.id !== id));
}
