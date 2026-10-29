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

/** The running timers, so a hovered toast can wait for its reader. */
const timers = new Map<number, { left: number; started: number; handle: ReturnType<typeof setTimeout> | null }>();

function arm(id: number, ms: number) {
  const handle = setTimeout(() => {
    timers.delete(id);
    notifications.update((n) => n.filter((x) => x.id !== id));
  }, ms);
  timers.set(id, { left: ms, started: Date.now(), handle });
}

/**
 * Show a toast. `duration` in ms; 0 = sticky (stays until manually closed).
 *
 * An error stays by default: it is the one toast somebody has to read, and
 * five seconds is not long enough for a certificate warning or a reason a
 * connection failed. News still goes by itself.
 */
export function addNotification(
  message: string,
  type: "info" | "warning" | "error" = "info",
  duration = type === "error" ? 0 : 5000,
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
  if (duration > 0) arm(id, duration);
  return id;
}

export function removeNotification(id: number) {
  const t = timers.get(id);
  if (t?.handle) clearTimeout(t.handle);
  timers.delete(id);
  notifications.update((n) => n.filter((x) => x.id !== id));
}

/** A pointer or the keyboard is on the toast: its clock stops. */
export function pauseNotification(id: number) {
  const t = timers.get(id);
  if (!t?.handle) return;
  clearTimeout(t.handle);
  t.left = Math.max(0, t.left - (Date.now() - t.started));
  t.handle = null;
}

/** ...and starts again when they leave, with what it had left (at least 2 s). */
export function resumeNotification(id: number) {
  const t = timers.get(id);
  if (!t || t.handle) return;
  arm(id, Math.max(2000, t.left));
}
