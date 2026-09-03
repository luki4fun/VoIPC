import { writable } from "svelte/store";

export interface Notification {
  id: number;
  message: string;
  type: "info" | "warning" | "error";
}

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
  const id = nextId++;
  notifications.update((n) => [...n, { id, message, type }]);
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
