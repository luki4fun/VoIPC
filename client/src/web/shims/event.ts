// Web replacement for @tauri-apps/api/event over the backend event bus.

import { emit as emitEvent, subscribe } from "../backend/events";

export interface Event<T> {
  event: string;
  id: number;
  payload: T;
}

export type EventCallback<T> = (event: Event<T>) => void;
export type UnlistenFn = () => void;

let nextId = 1;

export async function listen<T>(event: string, handler: EventCallback<T>): Promise<UnlistenFn> {
  const id = nextId++;
  return subscribe(event, (payload) => handler({ event, id, payload: payload as T }));
}

export async function emit<T>(event: string, payload?: T): Promise<void> {
  emitEvent(event, payload ?? null);
}
