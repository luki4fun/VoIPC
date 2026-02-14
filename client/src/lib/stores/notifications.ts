import { writable } from "svelte/store";

export interface Notification {
  id: number;
  message: string;
  type: "info" | "warning" | "error";
}

export const notifications = writable<Notification[]>([]);

let nextId = 0;

export function addNotification(
  message: string,
  type: "info" | "warning" | "error" = "info",
) {
  const id = nextId++;
  notifications.update((n) => [...n, { id, message, type }]);
  setTimeout(
    () => notifications.update((n) => n.filter((x) => x.id !== id)),
    5000,
  );
}

export function removeNotification(id: number) {
  notifications.update((n) => n.filter((x) => x.id !== id));
}
