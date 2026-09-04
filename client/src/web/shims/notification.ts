// Web replacement for @tauri-apps/plugin-notification over the browser
// Notification API.

export interface Options {
  title: string;
  body?: string;
  icon?: string;
}

const supported = typeof Notification !== "undefined";

export async function isPermissionGranted(): Promise<boolean> {
  return supported && Notification.permission === "granted";
}

export async function requestPermission(): Promise<NotificationPermission> {
  if (!supported) return "denied";
  return Notification.requestPermission();
}

export function sendNotification(options: Options | string): void {
  if (!supported || Notification.permission !== "granted") return;
  const { title, body, icon } = typeof options === "string" ? { title: options } : options;
  try {
    new Notification(title, { body, icon });
  } catch (e) {
    console.warn("notification failed:", e);
  }
}
