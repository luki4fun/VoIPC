// Web replacement for @tauri-apps/api/core: invoke() runs the command in the
// TypeScript backend instead of the Rust process.

import { dispatch } from "../backend/commands";

export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return (await dispatch(cmd, args ?? {})) as T;
}
