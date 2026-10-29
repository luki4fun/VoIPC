// Web replacement for @tauri-apps/api/core: invoke() runs the command in the
// TypeScript backend instead of the Rust process.

import { dispatch } from "../backend/commands";

/**
 * Like Tauri's: `args` is the arguments, or the raw body of a command that
 * reads its request (send_file), whose other arguments are in `headers`.
 */
export async function invoke<T>(
  cmd: string,
  args?: Record<string, unknown> | Uint8Array | ArrayBuffer | number[],
  options?: { headers?: Record<string, string> },
): Promise<T> {
  const raw =
    args instanceof Uint8Array
      ? args
      : args instanceof ArrayBuffer
        ? new Uint8Array(args)
        : Array.isArray(args)
          ? Uint8Array.from(args)
          : null;
  const call = raw ? { body: raw, headers: options?.headers ?? {} } : (args as Record<string, unknown> | undefined);
  return (await dispatch(cmd, call ?? {})) as T;
}
